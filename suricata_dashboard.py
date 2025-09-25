#!/usr/bin/env python3

import json
import time
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
import os
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from functools import lru_cache
import hashlib

load_dotenv()

# Setup application logging with rotation optimized for your volume
app_logger = logging.getLogger('suricata_dashboard')
app_logger.setLevel(logging.INFO)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Rotating file handler - 50MB per file, keep 7 backups
log_handler = RotatingFileHandler(
    'logs/suricata_dashboard.log', 
    maxBytes=50*1024*1024,
    backupCount=7,
    encoding='utf-8'
)
log_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
log_handler.setFormatter(log_formatter)
app_logger.addHandler(log_handler)

# Also log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
app_logger.addHandler(console_handler)

# Configurable parameters optimized for 122MB+ log files
LOG_FILE = os.getenv('SURICATA_LOG_FILE', '/var/log/suricata/eve.json')
MAX_LINES_TO_READ = int(os.getenv('DASHBOARD_MAX_LINES', '10000'))  # Optimized for 122MB
REFRESH_INTERVAL = int(os.getenv('DASHBOARD_REFRESH_INTERVAL', '20'))  # Less frequent for large files
HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')
PORT = int(os.getenv('DASHBOARD_PORT', '8080'))
HIGH_PRIORITY_THRESHOLD = int(os.getenv('HIGH_PRIORITY_THRESHOLD', '10'))

app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://",
)

# Global variables to store alerts and file position
alerts = []
alert_history = []  # Keep last 1000 alerts for history
stats = {
    'total_alerts': 0,
    'high_priority': 0,
    'medium_priority': 0,
    'low_priority': 0,
    'last_updated': None,
    'log_file_size_mb': 0,
    'processing_time_ms': 0,
    'alerts_per_second': 0,
    'file_read_speed_mbps': 0,
    'trend': 'stable'
}

# Performance tracking
last_alert_count = 0
last_stats_time = time.time()
performance_metrics = {
    'last_file_read_time': 0,
    'average_processing_time': 0,
    'read_errors': 0
}

def validate_config():
    """Validate configuration at startup"""
    app_logger.info("🔧 Validating configuration...")
    
    if not os.path.exists(LOG_FILE):
        app_logger.warning(f"⚠️ Log file does not exist: {LOG_FILE}")
    else:
        file_size = os.path.getsize(LOG_FILE) / (1024 * 1024)
        app_logger.info(f"📁 Log file size: {file_size:.1f}MB")
    
    if MAX_LINES_TO_READ > 50000:
        app_logger.warning("⚠️ MAX_LINES_TO_READ is very high, may impact performance")
    elif MAX_LINES_TO_READ < 1000:
        app_logger.warning("⚠️ MAX_LINES_TO_READ is very low, may miss alerts")
    
    if REFRESH_INTERVAL < 10:
        app_logger.warning("⚠️ Very short refresh interval may cause high I/O load")
    
    app_logger.info("✅ Configuration validation complete")

def get_priority_level(priority):
    """Convert numeric priority to text and color class"""
    if priority <= 1:
        return 'high'
    elif priority <= 2:
        return 'medium'
    else:
        return 'low'

def read_file_tail(file_path, max_lines):
    """Efficiently read the last N lines of a large file with robust error handling"""
    if not os.path.exists(file_path):
        app_logger.error(f"❌ File not found: {file_path}")
        performance_metrics['read_errors'] += 1
        return []
    
    file_size = os.path.getsize(file_path)
    if file_size == 0:
        app_logger.warning(f"⚠️ File is empty: {file_path}")
        return []
    
    start_time = time.time()
    
    try:
        with open(file_path, 'rb') as f:
            # Go to end of file
            f.seek(0, 2)
            file_size = f.tell()
            start_pos = max(0, file_size - (1024 * 1024 * 5))  # Start 5MB from end for large files
            
            # Read file in chunks from the calculated position
            lines = []
            buffer = b''
            chunk_size = 8192 * 4  # Larger chunks for better performance
            pos = file_size
            
            while len(lines) < max_lines and pos > start_pos:
                # Read chunk
                read_size = min(chunk_size, pos - start_pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                
                # Prepend to buffer
                buffer = chunk + buffer
                
                # Split into lines
                lines_in_buffer = buffer.split(b'\n')
                
                # Keep the incomplete line at the beginning for next iteration
                if pos > start_pos:
                    buffer = lines_in_buffer[0]
                    lines = lines_in_buffer[1:] + lines
                else:
                    lines = lines_in_buffer + lines
                
                # Remove empty lines and limit size
                lines = [line for line in lines if line.strip()]
                if len(lines) > max_lines * 2:  # Prevent memory explosion
                    lines = lines[-max_lines:]
                    break
            
            # Calculate read speed
            read_time = time.time() - start_time
            read_speed = (file_size / (1024 * 1024)) / read_time if read_time > 0 else 0
            
            # Convert bytes to strings and return last max_lines
            result = [line.decode('utf-8', errors='ignore') for line in lines[-max_lines:]]
            
            app_logger.debug(f"📖 Read {len(result)} lines in {read_time:.2f}s ({read_speed:.1f} MB/s)")
            return result
            
    except PermissionError as e:
        app_logger.error(f"❌ Permission denied reading {file_path}: {e}")
        performance_metrics['read_errors'] += 1
        return []
    except IOError as e:
        app_logger.error(f"❌ I/O error reading {file_path}: {e}")
        performance_metrics['read_errors'] += 1
        return []
    except Exception as e:
        app_logger.error(f"❌ Unexpected error reading {file_path}: {e}")
        performance_metrics['read_errors'] += 1
        return []

def parse_suricata_log():
    """Parse Suricata eve.json log file with performance optimizations"""
    global alerts, stats, last_alert_count, last_stats_time, alert_history
    
    start_time = time.time()
    
    if not os.path.exists(LOG_FILE):
        app_logger.error(f"❌ Log file {LOG_FILE} not found")
        return
    
    # Performance optimization: skip if file hasn't changed much (0.1MB threshold)
    current_size = os.path.getsize(LOG_FILE)
    if (hasattr(parse_suricata_log, 'last_size') and 
        current_size - parse_suricata_log.last_size < 1024 * 50):  # Less than 0.1MB change
        # Update last check time but skip parsing
        if hasattr(parse_suricata_log, 'last_check'):
            parse_suricata_log.last_check = time.time()
        return
    
    parse_suricata_log.last_size = current_size
    parse_suricata_log.last_check = time.time()
    
    try:
        file_size_mb = round(current_size / (1024 * 1024), 1)
        recent_lines = read_file_tail(LOG_FILE, MAX_LINES_TO_READ)
        
        new_alerts = []
        high_count = medium_count = low_count = suspicious_count = 0
        alert_count = 0
        
        for line in recent_lines:
            try:
                event = json.loads(line.strip())
                
                if event.get('event_type') == 'alert':
                    alert_count += 1
                    alert_data = event.get('alert', {})
                    priority = alert_data.get('severity', 3)
                    priority_level = get_priority_level(priority)
                    
                    if priority_level == 'high': high_count += 1
                    elif priority_level == 'medium': medium_count += 1
                    else: low_count += 1
                    
                    new_alerts.append({
                        'timestamp': event.get('timestamp', '')[:19],
                        'signature': alert_data.get('signature', 'Unknown')[:100],
                        'category': alert_data.get('category', 'Unknown'),
                        'priority': priority_level,
                        'src_ip': event.get('src_ip', 'Unknown'),
                        'src_port': event.get('src_port', 'Unknown'),
                        'dest_ip': event.get('dest_ip', 'Unknown'),
                        'dest_port': event.get('dest_port', 'Unknown'),
                        'proto': event.get('proto', 'Unknown'),
                        'event_type': 'alert'
                    })
                
                elif event.get('event_type') == 'flow':
                    flow_data = event.get('flow', {})
                    tcp_data = event.get('tcp', {})
                    dest_port = event.get('dest_port', 0)
                    src_ip = event.get('src_ip', '')
                    
                    # Detect suspicious TCP connections
                    if (tcp_data.get('syn') and not tcp_data.get('ack') and 
                        flow_data.get('pkts_toclient', 0) == 0 and
                        flow_data.get('pkts_toserver', 0) <= 2):
                        
                        suspicious_ports = {4899, 10242, 4444, 1337, 2323, 5555, 9999, 12345, 31337, 54321}
                        high_risk_ports = {4899, 10242, 4444, 1337}
                        
                        if dest_port in high_risk_ports:
                            priority_level, category = 'high', "Port Scan"
                            high_count += 1
                        elif dest_port in suspicious_ports or dest_port > 40000:
                            priority_level, category = 'medium', "Network Reconnaissance"
                            medium_count += 1
                        else:
                            priority_level, category = 'low', "Unusual Activity"
                            low_count += 1
                        
                        suspicious_count += 1
                        new_alerts.append({
                            'timestamp': event.get('timestamp', '')[:19],
                            'signature': f"Suspicious connection to port {dest_port}",
                            'category': category,
                            'priority': priority_level,
                            'src_ip': src_ip,
                            'src_port': event.get('src_port', 'Unknown'),
                            'dest_ip': event.get('dest_ip', 'Unknown'),
                            'dest_port': dest_port,
                            'proto': event.get('proto', 'Unknown'),
                            'event_type': 'suspicious_flow'
                        })
                    
                    # Detect failed UDP services
                    elif (event.get('proto') == 'UDP' and event.get('app_proto') == 'failed' and
                          flow_data.get('pkts_toclient', 0) == 0):
                          
                        suspicious_count += 1
                        low_count += 1
                        new_alerts.append({
                            'timestamp': event.get('timestamp', '')[:19],
                            'signature': f"Failed UDP service on port {dest_port}",
                            'category': "Service Scan",
                            'priority': 'low',
                            'src_ip': src_ip,
                            'src_port': event.get('src_port', 'Unknown'),
                            'dest_ip': event.get('dest_ip', 'Unknown'),
                            'dest_port': dest_port,
                            'proto': 'UDP',
                            'event_type': 'suspicious_flow'
                        })
                        
            except json.JSONDecodeError:
                continue
            except Exception:
                continue
        
        # Update stats and alerts
        current_time = time.time()
        time_diff = current_time - last_stats_time
        total_events = alert_count + suspicious_count
        
        alerts_per_second = (total_events - last_alert_count) / time_diff if time_diff > 0 else 0
        trend = 'rising' if alerts_per_second > 5 else 'falling' if alerts_per_second < 0.1 else 'stable'
        
        alert_history.extend(new_alerts)
        alert_history = alert_history[-1000:]
        alerts = sorted(new_alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:100]
        
        processing_time = round((time.time() - start_time) * 1000, 1)
        
        # Update performance metrics
        performance_metrics['last_file_read_time'] = processing_time
        performance_metrics['average_processing_time'] = (
            performance_metrics['average_processing_time'] * 0.7 + processing_time * 0.3
        )
        
        stats.update({
            'total_alerts': len(new_alerts),
            'high_priority': high_count,
            'medium_priority': medium_count,
            'low_priority': low_count,
            'suspicious_flows': suspicious_count,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'log_file_size_mb': file_size_mb,
            'processing_time_ms': processing_time,
            'alerts_per_second': round(alerts_per_second, 2),
            'file_read_speed_mbps': round(file_size_mb / (processing_time / 1000), 1) if processing_time > 0 else 0,
            'trend': trend,
            'high_priority_threshold': HIGH_PRIORITY_THRESHOLD,
            'read_errors': performance_metrics['read_errors']
        })
        
        last_alert_count = total_events
        last_stats_time = current_time
        
        # Log every parse cycle
        app_logger.info(
            f"📊 Parsed {alert_count} alerts + {suspicious_count} suspicious flows in {processing_time}ms | "
            f"File: {file_size_mb}MB | Rate: {alerts_per_second:.1f}/s | Trend: {trend}"
        )
        
    except Exception as e:
        app_logger.error(f"❌ Error reading log file: {e}")
        performance_metrics['read_errors'] += 1

@lru_cache(maxsize=10)
def get_cached_data(refresh_hash, query=None):
    """Cache alerts and stats for 5 seconds to reduce disk I/O"""
    if query:
        # Search results caching
        results = []
        query_lower = query.lower()
        for alert in alerts:
            if (query_lower in alert['signature'].lower() or 
                query_lower in alert['src_ip'].lower() or 
                query_lower in alert['dest_ip'].lower() or 
                query_lower in alert['category'].lower()):
                results.append(alert)
        return results[:50]
    else:
        # Regular alerts caching
        return {
            'alerts': alerts[:50],
            'stats': stats.copy()
        }

def log_monitor():

    """Background thread with accurate timing"""
    app_logger.info(f"🚀 Starting log monitor (refresh: {REFRESH_INTERVAL}s)")
    
    error_count = 0
    while True:
        cycle_start = time.time()
        
        try:
            parse_suricata_log()
            error_count = 0
        except Exception as e:
            error_count += 1
            if error_count % 5 == 0:  # Log every 5th error
                app_logger.error(f"❌ Log monitor error #{error_count}: {e}")
            if error_count >= 5:
                time.sleep(60)
                error_count = 0
        
        cycle_time = time.time() - cycle_start
        sleep_time = max(0, REFRESH_INTERVAL - cycle_time)
        if sleep_time > 0:
            time.sleep(sleep_time)               

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/health')
@limiter.limit("10 per minute")
def health_check():
    """Health check endpoint for monitoring"""
    log_exists = os.path.exists(LOG_FILE)
    log_size = os.path.getsize(LOG_FILE) if log_exists else 0
    
    # Calculate uptime
    if 'start_time' not in health_check.__dict__:
        health_check.start_time = time.time()
    
    uptime_seconds = time.time() - health_check.start_time
    uptime_str = str(timedelta(seconds=int(uptime_seconds)))
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime': uptime_str,
        'alerts_loaded': len(alerts),
        'performance': {
            'average_processing_time_ms': round(performance_metrics['average_processing_time'], 1),
            'read_errors': performance_metrics['read_errors'],
            'last_file_read_time_ms': performance_metrics['last_file_read_time']
        },
        'log_file': {
            'exists': log_exists,
            'path': LOG_FILE,
            'size_bytes': log_size,
            'size_mb': round(log_size / (1024 * 1024), 2) if log_exists else 0
        },
        'stats': stats,
        'config': {
            'max_lines_to_read': MAX_LINES_TO_READ,
            'refresh_interval': REFRESH_INTERVAL,
            'high_priority_threshold': HIGH_PRIORITY_THRESHOLD
        }
    })

@app.route('/')
@limiter.limit("30 per minute")
def dashboard():
    """Main dashboard page"""
    refresh_hash = int(time.time()) // 5  # Cache for 5 seconds
    cached_data = get_cached_data(refresh_hash)
    
    return render_template_string(HTML_TEMPLATE, 
                                alerts=cached_data['alerts'][:30], 
                                stats=cached_data['stats'], 
                                MAX_LINES_TO_READ=MAX_LINES_TO_READ,
                                HIGH_PRIORITY_THRESHOLD=HIGH_PRIORITY_THRESHOLD)

@app.route('/api/alerts')
@limiter.limit("20 per minute")
def api_alerts():
    """API endpoint for getting alerts data"""
    refresh_hash = int(time.time()) // 5  # Cache for 5 seconds
    cached_data = get_cached_data(refresh_hash)
    
    return jsonify(cached_data)

@app.route('/api/alerts/search')
@limiter.limit("30 per minute")
def search_alerts():
    """Enhanced search with multiple filters and better performance"""
    try:
        # Get search parameters with defaults
        query = request.args.get('q', '').strip()
        priority_filter = request.args.get('priority', '').strip().lower()
        category_filter = request.args.get('category', '').strip()
        ip_filter = request.args.get('ip', '').strip()
        protocol_filter = request.args.get('protocol', '').strip().upper()
        port_filter = request.args.get('port', '').strip()
        limit = min(int(request.args.get('limit', '100')), 500)
        
        # Validation
        if not any([query, priority_filter, category_filter, ip_filter, protocol_filter, port_filter]):
            return jsonify({
                'error': 'Please provide at least one search criterion',
                'available_filters': ['q', 'priority', 'category', 'ip', 'protocol', 'port']
            }), 400
        
        if query and len(query) < 2:
            return jsonify({'error': 'Search query must be at least 2 characters'}), 400
        
        start_time = time.time()
        results = []
        query_lower = query.lower()
        
        # Search through alerts with multiple filters
        for alert in alerts:
            match = True
            
            # Text search across multiple fields
            if query:
                text_match = (
                    query_lower in alert['signature'].lower() or 
                    query_lower in alert['src_ip'].lower() or 
                    query_lower in alert['dest_ip'].lower() or 
                    query_lower in alert['category'].lower() or
                    query_lower in str(alert.get('src_port', '')).lower() or
                    query_lower in str(alert.get('dest_port', '')).lower() or
                    query_lower in alert.get('proto', '').lower()
                )
                if not text_match:
                    match = False
            
            # Priority filter
            if match and priority_filter:
                if alert['priority'] != priority_filter:
                    match = False
            
            # Category filter (partial match)
            if match and category_filter:
                if category_filter.lower() not in alert['category'].lower():
                    match = False
            
            # IP filter (source or destination)
            if match and ip_filter:
                if (ip_filter not in alert['src_ip'] and 
                    ip_filter not in alert['dest_ip']):
                    match = False
            
            # Protocol filter
            if match and protocol_filter:
                if alert.get('proto', '').upper() != protocol_filter:
                    match = False
            
            # Port filter (source or destination)
            if match and port_filter:
                if (port_filter != str(alert.get('src_port', '')) and 
                    port_filter != str(alert.get('dest_port', ''))):
                    match = False
            
            if match:
                # Add search highlights to help users see what matched
                alert_with_highlights = alert.copy()
                alert_with_highlights['_search_matches'] = get_search_matches(alert, query)
                results.append(alert_with_highlights)
        
        # Sort by timestamp (newest first) and apply limit
        results = sorted(results, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
        
        search_time = round((time.time() - start_time) * 1000, 2)
        
        response_data = {
            'query': query,
            'filters': {
                'priority': priority_filter,
                'category': category_filter,
                'ip': ip_filter,
                'protocol': protocol_filter,
                'port': port_filter
            },
            'results': results,
            'total_found': len(results),
            'search_time_ms': search_time,
            'search_completed_at': datetime.now().isoformat()
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        app_logger.error(f"❌ Search error: {e}")
        return jsonify({'error': 'Search failed due to internal error'}), 500
def get_search_matches(alert, query):
    """Identify which fields matched the search query"""
    if not query:
        return []
    
    query_lower = query.lower()
    matches = []
    
    fields_to_check = [
        ('signature', 'Signature'),
        ('src_ip', 'Source IP'),
        ('dest_ip', 'Destination IP'),
        ('category', 'Category'),
        ('src_port', 'Source Port'),
        ('dest_port', 'Destination Port'),
        ('proto', 'Protocol')
    ]
    
    for field_key, field_name in fields_to_check:
        field_value = str(alert.get(field_key, ''))
        if query_lower in field_value.lower():
            matches.append({
                'field': field_name,
                'value': field_value,
                'matches': query_lower
            })
    
    return matches

@app.route('/api/search/suggestions')
@limiter.limit("20 per minute")
def search_suggestions():
    """Provide search suggestions based on existing data"""
    field = request.args.get('field', 'signature')
    query = request.args.get('q', '').lower().strip()
    
    if not query or len(query) < 2:
        return jsonify({'suggestions': []})
    
    suggestions = set()
    
    for alert in alerts:
        value = str(alert.get(field, ''))
        if query in value.lower():
            suggestions.add(value)
    
    return jsonify({
        'field': field,
        'query': query,
        'suggestions': sorted(list(suggestions))[:10]  # Limit to 10 suggestions
    })

@app.route('/api/search/stats')
@limiter.limit("10 per minute")
def search_statistics():
    """Provide statistics for search optimization"""
    total_alerts = len(alerts)
    
    # Count by priority
    priority_counts = {}
    for alert in alerts:
        priority = alert['priority']
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
    
    # Count by category (top 10)
    category_counts = {}
    for alert in alerts:
        category = alert['category']
        category_counts[category] = category_counts.get(category, 0) + 1
    
    top_categories = dict(sorted(category_counts.items(), 
                               key=lambda x: x[1], reverse=True)[:10])
    
    return jsonify({
        'total_alerts': total_alerts,
        'priority_distribution': priority_counts,
        'top_categories': top_categories,
        'last_updated': stats.get('last_updated', 'Unknown')
    })
@app.route('/api/stats/history')
@limiter.limit("10 per minute")
def stats_history():
    """Return historical stats for trending"""
    return jsonify({
        'alert_history_count': len(alert_history),
        'performance_metrics': performance_metrics,
        'trends': {
            'current_trend': stats.get('trend', 'stable'),
            'high_priority_count': stats.get('high_priority', 0),
            'alert_rate': stats.get('alerts_per_second', 0)
        }
    })

@app.route('/api/alerts/export')
@limiter.limit("5 per minute")
def export_alerts():
    """Export alerts as JSON"""
    format_type = request.args.get('format', 'json')
    limit = min(int(request.args.get('limit', '100')), 1000)  # Max 1000 alerts
    
    export_alerts = alerts[:limit]
    
    if format_type.lower() == 'csv':
        # Simple CSV export implementation
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Signature', 'Priority', 'Source IP', 'Dest IP', 'Protocol'])
        
        for alert in export_alerts:
            writer.writerow([
                alert['timestamp'],
                alert['signature'],
                alert['priority'],
                alert['src_ip'],
                alert['dest_ip'],
                alert['proto']
            ])
        
        return output.getvalue(), 200, {'Content-Type': 'text/csv'}
    else:
        # JSON export
        return jsonify({
            'exported_at': datetime.now().isoformat(),
            'total_alerts': len(export_alerts),
            'alerts': export_alerts
        })

# HTML Template with enhanced UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Suricata IDS Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --high-priority: #e74c3c;
            --medium-priority: #f39c12;
            --low-priority: #27ae60;
            --dark-bg: #1a1a1a;
            --card-bg: #2c3e50;
            --header-bg: #34495e;
        }
        
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: var(--dark-bg); 
            color: #fff;
            line-height: 1.6;
        }
        
        .header { 
            background: var(--header-bg); 
            padding: 25px; 
            border-radius: 12px; 
            margin-bottom: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 25px; 
        }
        
        .stat-card { 
            background: var(--card-bg); 
            padding: 20px; 
            border-radius: 10px; 
            text-align: center;
            transition: transform 0.2s;
            border-left: 4px solid #3498db;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
        }
        
        .stat-card.high { border-left-color: var(--high-priority); }
        .stat-card.medium { border-left-color: var(--medium-priority); }
        .stat-card.low { border-left-color: var(--low-priority); }
        
        .stat-number { 
            font-size: 2.2em; 
            font-weight: bold; 
            margin: 10px 0;
        }
        
        .stat-high { color: var(--high-priority); }
        .stat-medium { color: var(--medium-priority); }
        .stat-low { color: var(--low-priority); }
        .stat-total { color: #3498db; }
        
        .alerts-container { 
            background: var(--card-bg); 
            border-radius: 12px; 
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .alert { 
            padding: 15px; 
            border-bottom: 1px solid #3a506b; 
            margin: 4px 0;
            border-left: 4px solid;
            transition: background-color 0.2s;
        }
        
        .alert:hover {
            background: #3a506b;
        }
        
        .alert-high { border-left-color: var(--high-priority); background: rgba(231, 76, 60, 0.1); }
        .alert-medium { border-left-color: var(--medium-priority); background: rgba(243, 156, 18, 0.1); }
        .alert-low { border-left-color: var(--low-priority); background: rgba(39, 174, 96, 0.1); }
        
        .timestamp { 
            font-size: 0.8em; 
            color: #bdc3c7;
            font-family: 'Courier New', monospace;
        }
        
        .signature { 
            font-weight: 600; 
            margin: 8px 0; 
            font-size: 1em;
            line-height: 1.4;
        }
        
        .details { 
            font-size: 0.85em; 
            color: #ecf0f1;
            font-family: 'Courier New', monospace;
        }
        
        h1, h2 { 
            color: #3498db; 
            margin: 0 0 10px 0;
        }
        
        .refresh-btn { 
            background: #3498db; 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 6px; 
            cursor: pointer; 
            margin-left: 15px; 
            font-size: 0.95em;
            transition: background 0.2s;
        }
        
        .refresh-btn:hover { background: #2980b9; }
        
        .performance-info {
            font-size: 0.85em;
            color: #95a5a6;
            margin-top: 10px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }
        
        .trend-indicator {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .trend-rising { background: rgba(231, 76, 60, 0.2); color: var(--high-priority); }
        .trend-falling { background: rgba(39, 174, 96, 0.2); color: var(--low-priority); }
        .trend-stable { background: rgba(52, 152, 219, 0.2); color: #3498db; }
        
        .search-box {
            padding: 10px;
            background: var(--header-bg);
            border-radius: 6px;
            margin: 15px 0;
        }
        
        .search-input {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid #4a6572;
            border-radius: 4px;
            background: #2c3e50;
            color: white;
            font-size: 0.9em;
        }
        
        .search-panel {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .search-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .search-header h3 {
            margin: 0;
            color: #3498db;
        }

        .btn-toggle {
            background: #34495e;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            transition: background 0.2s;
        }

        .btn-toggle:hover {
            background: #4a6572;
        }

        .search-input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }

        .search-input {
            flex: 1;
            padding: 10px 15px;
            border: 1px solid #4a6572;
            border-radius: 6px;
            background: #2c3e50;
            color: white;
            font-size: 1em;
        }

        .search-input:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
        }

        .search-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            transition: background 0.2s;
            white-space: nowrap;
        }

        .search-btn:hover {
            background: #2980b9;
        }

        .search-filters {
            background: #34495e;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .filter-group label {
            font-size: 0.9em;
            color: #bdc3c7;
            font-weight: 600;
        }

        .filter-group select,
        .filter-group input {
            padding: 8px 12px;
            border: 1px solid #4a6572;
            border-radius: 4px;
            background: #2c3e50;
            color: white;
        }

        .filter-actions {
            display: flex;
            align-items: end;
        }

        .clear-filters {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
        }

        .clear-filters:hover {
            background: #c0392b;
        }

        .search-results {
            margin-top: 20px;
        }

        .search-stats {
            background: #34495e;
            padding: 10px 15px;
            border-radius: 6px;
            margin-bottom: 15px;
            font-weight: 600;
            color: #ecf0f1;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .export-btn {
            background: #27ae60;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
        }

        .export-btn:hover {
            background: #219a52;
        }

        .highlight {
            background-color: #f39c12;
            color: #2c3e50;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: bold;
        }

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }

        .search-highlight {
            font-size: 0.8em;
            color: #bdc3c7;
            background: rgba(52, 152, 219, 0.2);
            padding: 2px 6px;
            border-radius: 3px;
        }

        .no-results {
            text-align: center;
            padding: 40px;
            color: #95a5a6;
        }

        .no-results i {
            font-size: 3em;
            margin-bottom: 15px;
            color: #7f8c8d;
        }

        .search-message {
            padding: 10px 15px;
            border-radius: 4px;
            margin-bottom: 15px;
            font-weight: 600;
        }

        .search-message.info {
            background: rgba(52, 152, 219, 0.2);
            color: #3498db;
        }

        .search-message.success {
            background: rgba(39, 174, 96, 0.2);
            color: #27ae60;
        }

        .search-message.warning {
            background: rgba(243, 156, 18, 0.2);
            color: #f39c12;
        }

        .search-message.error {
            background: rgba(231, 76, 60, 0.2);
            color: #e74c3c;
        }

        @media (max-width: 768px) {
            .search-input-group {
                flex-direction: column;
            }
            
            .search-filters {
                grid-template-columns: 1fr;
            }
            
            .search-stats {
                flex-direction: column;
                gap: 10px;
                align-items: stretch;
            }
            
            .alert-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }
        }
        @media (max-width: 768px) {
            body { padding: 10px; }
            .stats-grid { grid-template-columns: 1fr; }
            .header { padding: 15px; }
        }
    </style>
    <script>
        let autoRefresh = true;
        let currentSearchResults = [];
        let searchFiltersVisible = false;
        let searchMessageTimeout;
        let refreshInterval = null;

        // Core refresh function - must be defined first
        function refreshData() {
            console.log('Manual refresh triggered');
            const startTime = Date.now();
            
            const statusIndicator = document.getElementById('status-indicator');
            if (statusIndicator) {
                statusIndicator.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
            }
            
            fetch('/api/alerts')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network error: ' + response.status);
                    }
                    return response.json();
                })
                .then(data => {
                    updateStats(data.stats);
                    updateAlerts(data.alerts);
                    
                    const loadTime = Date.now() - startTime;
                    const loadTimeEl = document.getElementById('load-time');
                    if (loadTimeEl) loadTimeEl.textContent = loadTime + 'ms';
                    
                    const lastUpdatedEl = document.getElementById('last-updated');
                    if (lastUpdatedEl && data.stats.last_updated) {
                        lastUpdatedEl.textContent = data.stats.last_updated;
                    }
                    
                    console.log('Dashboard refreshed successfully in ' + loadTime + 'ms');
                })
                .catch(error => {
                    console.error('Refresh error:', error);
                    const loadTimeEl = document.getElementById('load-time');
                    if (loadTimeEl) {
                        loadTimeEl.textContent = 'Error';
                        loadTimeEl.style.color = '#e74c3c';
                    }
                });
        }

        function updateStats(stats) {
            if (!stats) return;
            
            const elements = {
                'total-alerts': (stats.total_alerts || 0).toLocaleString(),
                'high-priority': (stats.high_priority || 0).toLocaleString(),
                'medium-priority': (stats.medium_priority || 0).toLocaleString(),
                'low-priority': (stats.low_priority || 0).toLocaleString(),
                'log-size': (stats.log_file_size_mb || 0) + 'MB',
                'processing-time': (stats.processing_time_ms || 0) + 'ms',
                'alerts-per-second': (stats.alerts_per_second || 0) + '/s',
                'read-speed': (stats.file_read_speed_mbps || 0) + ' MB/s'
            };
            
            for (const [id, value] of Object.entries(elements)) {
                const el = document.getElementById(id);
                if (el) el.textContent = value;
            }
            
            // Update trend indicator
            const trendEl = document.getElementById('status-indicator');
            if (trendEl && stats.trend) {
                const icons = { rising: 'arrow-up', falling: 'arrow-down', stable: 'arrows-alt-h' };
                trendEl.className = 'trend-indicator trend-' + stats.trend;
                trendEl.innerHTML = '<i class="fas fa-' + icons[stats.trend] + '"></i> ' + stats.trend.toUpperCase();
            }
        }

        function updateAlerts(alertList) {
            const container = document.getElementById('recent-alerts-list');
            if (!container) return;
            
            container.innerHTML = '';
            
            if (!alertList || alertList.length === 0) {
                container.innerHTML = '<div class="alert" style="text-align: center; color: #95a5a6; padding: 40px;"><i class="fas fa-info-circle" style="font-size: 2em; margin-bottom: 10px;"></i><div>No recent alerts found</div></div>';
                return;
            }
            
            const alertsHtml = alertList.map(alert => {
                const priorityIcon = alert.priority === 'high' ? 'skull-crossbones' : 
                                   alert.priority === 'medium' ? 'exclamation-triangle' : 'info-circle';
                
                // Simple HTML escaping
                const signature = (alert.signature || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                
                return '<div class="alert alert-' + alert.priority + '">' +
                       '<div class="timestamp"><i class="far fa-clock"></i> ' + alert.timestamp + 
                       ' <span style="margin-left: 10px;"><i class="fas fa-' + priorityIcon + '"></i> ' + alert.priority.toUpperCase() + '</span></div>' +
                       '<div class="signature">' + signature + '</div>' +
                       '<div class="details"><i class="fas fa-network-wired"></i> ' + alert.src_ip + ':' + alert.src_port + ' → ' + alert.dest_ip + ':' + alert.dest_port +
                       ' | <i class="fas fa-project-diagram"></i> ' + alert.proto + ' | <i class="fas fa-tag"></i> ' + alert.category +
                       (alert.event_type === 'suspicious_flow' ? ' | <i class="fas fa-eye"></i> Custom Detection' : '') + '</div></div>';
            }).join('');
            
            container.innerHTML = alertsHtml;
            console.log('Updated ' + alertList.length + ' alerts');
        }

        function toggleAutoRefresh() {
            autoRefresh = !autoRefresh;
            const btn = document.getElementById('auto-refresh-btn');
            if (!btn) return;
            
            if (autoRefresh) {
                btn.innerHTML = '<i class="fas fa-pause"></i> Pause Auto-Refresh';
                btn.style.background = '#27ae60';
                startAutoRefresh();
            } else {
                btn.innerHTML = '<i class="fas fa-play"></i> Resume Auto-Refresh';
                btn.style.background = '#e74c3c';
                stopAutoRefresh();
            }
        }

        function startAutoRefresh() {
            if (refreshInterval) clearInterval(refreshInterval);
            refreshInterval = setInterval(function() {
                if (autoRefresh) {
                    console.log('Auto-refreshing...');
                    refreshData();
                }
            }, 15000);
            console.log('Auto-refresh started');
        }

        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
                refreshInterval = null;
            }
            console.log('Auto-refresh stopped');
        }

        // Search functions (simplified)
        function toggleSearchFilters() {
            const filters = document.getElementById('search-filters');
            const btn = document.querySelector('.btn-toggle');
            if (!filters || !btn) return;
            
            searchFiltersVisible = !searchFiltersVisible;
            filters.style.display = searchFiltersVisible ? 'grid' : 'none';
            btn.innerHTML = '<i class="fas fa-sliders-h"></i> ' + (searchFiltersVisible ? 'Hide' : 'Show') + ' Filters';
        }

        function performSearch() {
            const query = document.getElementById('search-input')?.value.trim() || '';
            const priority = document.getElementById('priority-filter')?.value || '';
            
            if (!query && !priority) {
                alert('Please enter a search term or select a filter.');
                return;
            }
            
            const params = new URLSearchParams({ q: query, priority: priority });
            
            fetch('/api/alerts/search?' + params.toString())
                .then(response => response.json())
                .then(data => {
                    currentSearchResults = data.results || [];
                    displaySearchResults(data);
                })
                .catch(error => {
                    console.error('Search error:', error);
                    alert('Search failed: ' + error.message);
                });
        }

        function displaySearchResults(data) {
            const container = document.getElementById('search-results-container');
            const stats = document.getElementById('search-stats');
            if (!container || !stats) return;
            
            if (!data.results || data.results.length === 0) {
                container.innerHTML = '<div class="no-results"><i class="fas fa-search"></i><h3>No alerts found</h3></div>';
                stats.style.display = 'none';
                return;
            }
            
            const countEl = document.getElementById('results-count');
            if (countEl) countEl.textContent = data.total_found.toLocaleString();
            stats.style.display = 'flex';
            
            container.innerHTML = data.results.map(alert => 
                '<div class="alert alert-' + alert.priority + '">' +
                '<div class="timestamp"><i class="far fa-clock"></i> ' + alert.timestamp + '</div>' +
                '<div class="signature">' + alert.signature.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>' +
                '<div class="details">' + alert.src_ip + ':' + alert.src_port + ' → ' + alert.dest_ip + ':' + alert.dest_port + '</div>' +
                '</div>'
            ).join('');
        }

        function clearFilters() {
            ['priority-filter', 'category-filter', 'ip-filter', 'protocol-filter', 'port-filter', 'search-input']
                .forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.value = '';
                });
        }

        function exportSearchResults() {
            if (currentSearchResults.length === 0) {
                alert('No search results to export.');
                return;
            }
            alert('Export functionality simplified - check console for data');
            console.log('Search results:', currentSearchResults);
        }

        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Dashboard initializing...');
            
            // Set up search enter key
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') performSearch();
                });
            }
            
            // Load initial data
            refreshData();
            
            // Start auto-refresh
            startAutoRefresh();
            
            console.log('Dashboard ready');
        });
    </script>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-shield-alt"></i> Suricata IDS Dashboard</h1>
        <div style="display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
            <span>Real-time network intrusion detection monitoring</span>
            <button class="refresh-btn" onclick="refreshData()"><i class="fas fa-sync-alt"></i> Refresh</button>
            <button class="refresh-btn" id="auto-refresh-btn" onclick="toggleAutoRefresh()">
                <i class="fas fa-pause"></i> Pause Auto-Refresh
            </button>
            <span id="status-indicator" class="trend-indicator trend-stable"><i class="fas fa-arrows-alt-h"></i> STABLE</span>
        </div>
        <div class="performance-info">
            <div><i class="fas fa-tachometer-alt"></i> Load: <span id="load-time">-</span></div>
            <div><i class="fas fa-cogs"></i> Processing: <span id="processing-time">{{ stats.processing_time_ms }}ms</span></div>
            <div><i class="fas fa-hdd"></i> Log: <span id="log-size">{{ stats.log_file_size_mb }}MB</span></div>
            <div><i class="fas fa-bolt"></i> Rate: <span id="alerts-per-second">{{ stats.alerts_per_second }}/s</span></div>
            <div><i class="fas fa-download"></i> Read Speed: <span id="read-speed">{{ stats.file_read_speed_mbps }} MB/s</span></div>
        </div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div><i class="fas fa-exclamation-triangle"></i> Total Alerts</div>
            <div class="stat-number stat-total" id="total-alerts">{{ stats.total_alerts }}</div>
            <div>Last {{ MAX_LINES_TO_READ }} lines</div>
        </div>
        <div class="stat-card high">
            <div><i class="fas fa-skull-crossbones"></i> High Priority</div>
            <div class="stat-number stat-high" id="high-priority">{{ stats.high_priority }}</div>
            <div>Threshold: {{ HIGH_PRIORITY_THRESHOLD }}+ alerts</div>
        </div>
        <div class="stat-card medium">
            <div><i class="fas fa-exclamation-circle"></i> Medium Priority</div>
            <div class="stat-number stat-medium" id="medium-priority">{{ stats.medium_priority }}</div>
            <div>Requires monitoring</div>
        </div>
        <div class="stat-card low">
            <div><i class="fas fa-info-circle"></i> Low Priority</div>
            <div class="stat-number stat-low" id="low-priority">{{ stats.low_priority }}</div>
            <div>Informational only</div>
        </div>
    </div>
    
    <div class="search-panel">
        <div class="search-header">
            <h3><i class="fas fa-search"></i> Advanced Alert Search</h3>
            <button class="btn-toggle" onclick="toggleSearchFilters()">
                <i class="fas fa-sliders-h"></i> Filters
            </button>
        </div>
        
        <div class="search-controls">
            <div class="search-input-group">
                <input type="text" id="search-input" class="search-input" 
                    placeholder="Search by signature, IP, port, or category...">
                <button class="search-btn" onclick="performSearch()">
                    <i class="fas fa-search"></i> Search
                </button>
            </div>
            
            <div id="search-filters" class="search-filters" style="display: none;">
                <div class="filter-group">
                    <label>Priority:</label>
                    <select id="priority-filter">
                        <option value="">All Priorities</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label>Category:</label>
                    <input type="text" id="category-filter" placeholder="Filter by category...">
                </div>
                
                <div class="filter-group">
                    <label>IP Address:</label>
                    <input type="text" id="ip-filter" placeholder="Source or destination IP...">
                </div>
                
                <div class="filter-group">
                    <label>Protocol:</label>
                    <select id="protocol-filter">
                        <option value="">All Protocols</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ICMP">ICMP</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label>Port:</label>
                    <input type="text" id="port-filter" placeholder="Source or destination port...">
                </div>
                
                <div class="filter-actions">
                    <button class="clear-filters" onclick="clearFilters()">
                        <i class="fas fa-times"></i> Clear Filters
                    </button>
                </div>
            </div>
        </div>
        
        <div id="search-results" class="search-results">
            <div id="search-stats" class="search-stats" style="display: none;">
                <span id="results-count">0</span> alerts found
                <button class="export-btn" onclick="exportSearchResults()" style="margin-left: 15px;">
                    <i class="fas fa-download"></i> Export Results
                </button>
            </div>
            <div id="search-results-container"></div>
        </div>
    </div>        
    
    <div class="alerts-container">
        <h2 style="padding: 20px; margin: 0;"><i class="fas fa-bell"></i> Recent Alerts</h2>
        <div id="recent-alerts-list">
            {% for alert in alerts %}
            <div class="alert alert-{{ alert.priority }}">
                <div class="timestamp"><i class="far fa-clock"></i> {{ alert.timestamp }}</div>
                <div class="signature">{{ alert.signature }}</div>
                <div class="details">
                    <i class="fas fa-network-wired"></i> {{ alert.src_ip }}:{{ alert.src_port }} → {{ alert.dest_ip }}:{{ alert.dest_port }}
                    | <i class="fas fa-project-diagram"></i> {{ alert.proto }} | <i class="fas fa-tag"></i> {{ alert.category }}
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    
    <div style="text-align: center; margin-top: 25px; color: #7f8c8d; font-size: 0.9em;">
        <i class="far fa-clock"></i> Last Updated: <span id="last-updated">{{ stats.last_updated }}</span> |
        <i class="fas fa-database"></i> Monitoring: {{ MAX_LINES_TO_READ }} lines |
        <i class="fas fa-shield-alt"></i> Suricata IDS Dashboard v2.0
    </div>
</body>
</html>
"""

#def create_app():
    # Validate configuration first
    #validate_config()
    
    # Start background log monitoring
    #monitor_thread = threading.Thread(target=log_monitor, daemon=True)
    #monitor_thread.start()
    
    #app_logger.info("🚀 Suricata IDS Dashboard v2.0 Starting...")
    #app_logger.info(f"📁 Log file: {LOG_FILE}")
    #app_logger.info(f"📊 Max lines to read: {MAX_LINES_TO_READ}")
    #app_logger.info(f"⏱️ Refresh interval: {REFRESH_INTERVAL}s")
    #app_logger.info(f"🔔 High priority threshold: {HIGH_PRIORITY_THRESHOLD} alerts")
    #app_logger.info(f"🌐 Dashboard URL: http://{HOST}:{PORT}")
    #app_logger.info(f"📝 App logs: logs/suricata_dashboard.log (50MB rotation)")
    
    # Initial log parse
    #parse_suricata_log()
    
    #return app


# For gunicorn to see:
#app = create_app()

#if __name__ == '__main__':
    #app.run(host=HOST, port=PORT, debug=False)

# =================== #
# Validate configuration first
validate_config()

# Start background log monitoring
monitor_thread = threading.Thread(target=log_monitor, daemon=True)
monitor_thread.start()

app_logger.info("🚀 Suricata IDS Dashboard v2.0 Starting...")
app_logger.info(f"📁 Log file: {LOG_FILE}")
app_logger.info(f"📊 Max lines to read: {MAX_LINES_TO_READ}")
app_logger.info(f"⏱️ Refresh interval: {REFRESH_INTERVAL}s")
app_logger.info(f"🔔 High priority threshold: {HIGH_PRIORITY_THRESHOLD} alerts")
app_logger.info(f"🌐 Dashboard URL: http://{HOST}:{PORT}")
app_logger.info(f"📝 App logs: logs/suricata_dashboard.log (50MB rotation)")

# Initial log parse
parse_suricata_log()

# Run Flask app
app.run(host=HOST, port=PORT, debug=False)
