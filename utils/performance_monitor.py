import psutil
import time
from collections import deque

class PerformanceMonitor:
    """Enhanced system performance monitoring"""
    
    def __init__(self, config, app_logger=None):
        self.config = config
        self.app_logger = app_logger
        self.process = psutil.Process()
        self.metrics = {
            'memory_usage_mb': 0,
            'cpu_percent': 0,
            'disk_usage_percent': 0,
            'file_read_errors': 0,
            'parse_errors': 0,
            'alerts_processed': 0,
            'uptime_seconds': 0
        }
        self.start_time = time.time()
        self.alert_rate_history = deque(maxlen=60)  
    
    def update_metrics(self):
        """Update all performance metrics"""
        try:
            memory_info = self.process.memory_info()
            self.metrics['memory_usage_mb'] = memory_info.rss / (1024 * 1024)
            self.metrics['cpu_percent'] = self.process.cpu_percent()
            
            disk_usage = psutil.disk_usage('/')
            self.metrics['disk_usage_percent'] = (disk_usage.used / disk_usage.total) * 100
            
            self.metrics['uptime_seconds'] = time.time() - self.start_time
            
            if self.metrics['memory_usage_mb'] > self.config.MAX_MEMORY_MB:
                if self.app_logger:
                    self.app_logger.warning(f"High memory usage: {self.metrics['memory_usage_mb']:.1f}MB")
            
            if self.metrics['disk_usage_percent'] > 90:
                if self.app_logger:
                    self.app_logger.warning(f"High disk usage: {self.metrics['disk_usage_percent']:.1f}%")
                
        except Exception as e:
            if self.app_logger:
                self.app_logger.error(f"Performance monitoring error: {e}")
    
    def record_alert_rate(self, rate):
        """Record alert processing rate for trending"""
        self.alert_rate_history.append((time.time(), rate))
    
    def get_alert_trend(self):
        """Calculate alert trend from recent history"""
        if len(self.alert_rate_history) < 2:
            return 'stable'
        
        recent_rates = [rate for _, rate in list(self.alert_rate_history)[-5:]]
        if not recent_rates:
            return 'stable'
        
        avg_rate = sum(recent_rates) / len(recent_rates)
        if avg_rate > 10:
            return 'rising'
        elif avg_rate < 1:
            return 'falling'
        return 'stable'