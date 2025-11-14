import threading
from collections import deque

class DashboardState:
    """Centralized state management for the dashboard"""
    
    def __init__(self):
        self.alerts = deque(maxlen=1000)  
        self.alert_history = deque(maxlen=5000)
        self.stats = {
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
        self.lock = threading.RLock()  
    
    def update_alerts(self, new_alerts):
        """Thread-safe update of alerts"""
        with self.lock:
            self.alerts.extend(new_alerts)
            self.alert_history.extend(new_alerts)
            
            self.stats['high_priority'] = sum(1 for a in self.alerts if a['priority'] == 'high')
            self.stats['medium_priority'] = sum(1 for a in self.alerts if a['priority'] == 'medium')
            self.stats['low_priority'] = sum(1 for a in self.alerts if a['priority'] == 'low')
            self.stats['total_alerts'] = len(new_alerts)
    
    def get_recent_alerts(self, limit=50):
        """Get recent alerts thread-safely"""
        with self.lock:
            return list(self.alerts)[-limit:]
    
    def search_alerts(self, query_params):
        """Enhanced search functionality - FIXED ORDER"""
        with self.lock:
            results = []
            search_fields = ['signature', 'src_ip', 'dest_ip', 'category']
            
            for alert in self.alerts:
                if self._matches_criteria(alert, query_params, search_fields):
                    results.append(alert)
            
            return sorted(results, key=lambda x: x.get('timestamp', ''), reverse=True)
    
    def _matches_criteria(self, alert, query_params, search_fields):
        """Check if alert matches search criteria"""
        query = query_params.get('q', '').lower()
        
        if query:
            text_match = any(query in str(alert.get(field, '')).lower() 
                           for field in search_fields)
            if not text_match:
                return False
        
        if query_params.get('priority') and alert['priority'] != query_params['priority']:
            return False
        
        if query_params.get('ip'):
            ip = query_params['ip']
            if ip not in alert.get('src_ip', '') and ip not in alert.get('dest_ip', ''):
                return False
        
        return True