import os
import sys
import signal
import atexit
import time
import logging
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from utils.performance_monitor import PerformanceMonitor
from models.dashboard_state import DashboardState
from models.log_reader import OptimizedLogReader
from models.alert_processor import AlertProcessor
from models.database_manager import DatabaseManager
from routes.api import api_bp
from routes.views import views_bp
from utils.security_headers import add_security_headers

def setup_logging():
    """Setup enhanced logging for the application"""
    app_logger = logging.getLogger('suricata_dashboard')
    app_logger.setLevel(logging.INFO)

    os.makedirs('logs', exist_ok=True)

    log_handler = logging.handlers.RotatingFileHandler(
        'logs/suricata_dashboard.log',
        maxBytes=500*1024*1024,  
        backupCount=10,
        encoding='utf-8'
    )

    log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    log_handler.setFormatter(log_formatter)
    app_logger.addHandler(log_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    app_logger.addHandler(console_handler)
    
    return app_logger

def parse_suricata_log(config, dashboard_state, log_reader, alert_processor, performance_monitor, app_logger):
    """Enhanced log parsing with better performance"""
    start_time = time.time()
    
    try:
        log_exists = os.path.exists(config.LOG_FILE)
        log_size = os.path.getsize(config.LOG_FILE) if log_exists else 0
        file_size_mb = round(log_size / (1024 * 1024), 1) if log_exists else 0
        
        recent_lines = log_reader.read_recent_lines(config.MAX_LINES_TO_READ)
        new_alerts = []
        
        for line in recent_lines:
            alert = alert_processor.process_event(line)
            if alert:
                new_alerts.append(alert)
                performance_monitor.metrics['alerts_processed'] += 1
        
        dashboard_state.update_alerts(new_alerts)
        
        processing_time = (time.time() - start_time) * 1000
        alerts_per_second = len(new_alerts) / max(processing_time / 1000, 0.001)
        
        performance_monitor.record_alert_rate(alerts_per_second)
        
        dashboard_state.stats.update({
            'processing_time_ms': round(processing_time, 1),
            'alerts_per_second': round(alerts_per_second, 2),
            'log_file_size_mb': file_size_mb,
            'trend': performance_monitor.get_alert_trend(),
            'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
        })
        
        if new_alerts:
            app_logger.info(f"Processed {len(new_alerts)} alerts in {processing_time:.1f}ms, Log: {file_size_mb}MB")
        
    except Exception as e:
        app_logger.error(f"Log parsing error: {e}")
        performance_monitor.metrics['parse_errors'] += 1

def log_monitor(config, dashboard_state, log_reader, alert_processor, performance_monitor, app_logger):
    """Enhanced background log monitoring with better error handling"""
    app_logger.info(f"Starting log monitor (refresh: {config.REFRESH_INTERVAL}s)")
    
    consecutive_errors = 0
    max_errors = 10
    
    while True:
        cycle_start = time.time()
        
        try:
            if log_reader.has_file_changed() or consecutive_errors > 0:
                parse_suricata_log(config, dashboard_state, log_reader, alert_processor, performance_monitor, app_logger)
                consecutive_errors = 0
            
            performance_monitor.update_metrics()
            
        except Exception as e:
            consecutive_errors += 1
            app_logger.error(f"Log monitor error #{consecutive_errors}: {e}")
            
            if consecutive_errors >= max_errors:
                app_logger.critical("Too many consecutive errors, pausing monitoring")
                time.sleep(300)  
                consecutive_errors = 0
        
        cycle_time = time.time() - cycle_start
        sleep_time = max(0, config.REFRESH_INTERVAL - cycle_time)
        
        if sleep_time > 0:
            time.sleep(sleep_time)

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    app_logger = setup_logging()
    
    config = Config()
    
    db_manager = DatabaseManager(config.DB_PATH)
    
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["2000 per day", "500 per hour"],
        storage_uri="memory://",
    )
    
    performance_monitor = PerformanceMonitor(config, app_logger)
    dashboard_state = DashboardState()
    log_reader = OptimizedLogReader(config.LOG_FILE, performance_monitor, app_logger)
    alert_processor = AlertProcessor(config, performance_monitor, app_logger, db_manager)
    
    app.config['dashboard_state'] = dashboard_state
    app.config['performance_monitor'] = performance_monitor
    app.config['log_reader'] = log_reader
    app.config['alert_processor'] = alert_processor
    app.config['db_manager'] = db_manager  
    app.config['app_config'] = config
    app.config['app_logger'] = app_logger
    
    app.register_blueprint(api_bp)
    app.register_blueprint(views_bp)
    
    app.after_request(add_security_headers)
    
    @app.route('/debug-static')
    def debug_static():
        """Debug route to check static file serving"""
        import os
        static_path = os.path.join(app.root_path, 'static')
        style_css_path = os.path.join(static_path, 'style.css')
        
        return jsonify({
            'static_folder_exists': os.path.exists(static_path),
            'style_css_exists': os.path.exists(style_css_path),
            'static_path': static_path,
            'style_css_path': style_css_path,
            'app_root_path': app.root_path,
            'static_url_path': app.static_url_path,
            'static_folder': app.static_folder
        })
    
    @app.route('/test-db')
    def test_database():
        """Test database creation and functionality"""
        db_manager = app.config['db_manager']
        
        test_alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'signature': 'TEST: Database connectivity test',
            'category': 'Test',
            'priority': 'low',
            'src_ip': '192.168.1.100',
            'src_port': 12345,
            'dest_ip': '192.168.1.1', 
            'dest_port': 80,
            'proto': 'TCP',
            'event_type': 'test',
            'severity_num': 3
        }
        
        success = db_manager.store_alert(test_alert)
        
        db_health = db_manager.health_check()
        
        return jsonify({
            'database_enabled': db_manager.enabled,
            'test_alert_stored': success,
            'database_path': db_manager.db_path if db_manager.enabled else None,
            'database_health': db_health,
            'message': 'Database test completed'
        })
    
    if db_manager.enabled:
        try:
            test_alert = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'signature': 'SYSTEM: Database initialized on startup',
                'category': 'System',
                'priority': 'low',
                'src_ip': '127.0.0.1',
                'src_port': 0,
                'dest_ip': '127.0.0.1',
                'dest_port': 0,
                'proto': 'TCP',
                'event_type': 'system',
                'severity_num': 3
            }
            success = db_manager.store_alert(test_alert)
            if success:
                app_logger.info("✅ Database initialized with test record")
            else:
                app_logger.warning("⚠️ Database test record storage failed")
        except Exception as e:
            app_logger.warning(f"⚠️ Database initialization failed: {e}")
    
    monitor_thread = threading.Thread(
        target=log_monitor, 
        args=(config, dashboard_state, log_reader, alert_processor, performance_monitor, app_logger),
        daemon=True
    )
    monitor_thread.start()
    
    app_logger.info("Performing initial log parse...")
    parse_suricata_log(config, dashboard_state, log_reader, alert_processor, performance_monitor, app_logger)
    
    app_logger.info("=" * 50)
    app_logger.info("🚀 Suricata IDS Dashboard v2.2 Ready")
    app_logger.info(f"📊 Dashboard URL: http://{config.HOST}:{config.PORT}")
    app_logger.info(f"📁 Log file: {config.LOG_FILE}")
    app_logger.info(f"🗄️ Database: {config.DB_PATH} ({'Enabled' if db_manager.enabled else 'Disabled'})")
    app_logger.info(f"⚡ Refresh interval: {config.REFRESH_INTERVAL}s")
    app_logger.info(f"🔍 Max lines: {config.MAX_LINES_TO_READ:,}")
    app_logger.info(f"⚠️ High priority threshold: {config.HIGH_PRIORITY_THRESHOLD}")
    app_logger.info("=" * 50)
    
    return app

app = create_app()

def graceful_shutdown(signum=None, frame=None):
    """Enhanced graceful shutdown with cleanup"""
    app.logger.info("Initiating graceful shutdown...")
    
    try:
        performance_monitor = app.config['performance_monitor']
        db_manager = app.config['db_manager']
        
        final_stats = {
            'uptime': time.time() - performance_monitor.start_time,
            'alerts_processed': performance_monitor.metrics['alerts_processed'],
            'memory_usage_mb': performance_monitor.metrics['memory_usage_mb'],
            'parse_errors': performance_monitor.metrics['parse_errors']
        }
        
        app.logger.info(f"Final statistics: {final_stats}")
        
        if db_manager.enabled:
            db_manager.close()
            app.logger.info("Database connections closed")
        
    except Exception as e:
        print(f"Error during shutdown: {e}")
    
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)
atexit.register(graceful_shutdown)

if __name__ == '__main__':
    try:
        config = app.config['app_config']
        app.run(
            host=config.HOST,
            port=config.PORT,
            debug=False,
            threaded=True,
            use_reloader=False
        )
    except KeyboardInterrupt:
        app.logger.info("Received interrupt signal")
        graceful_shutdown()
    except Exception as e:
        app.logger.error(f"Application failed to start: {e}")
        sys.exit(1)