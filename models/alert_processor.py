import json
import os
from .geoip_service import GeoIPService

class AlertProcessor:
    """Processes and analyzes Suricata alerts with enhanced detection"""
    
    def __init__(self, config, performance_monitor=None, app_logger=None, db_manager=None):
        self.config = config
        self.performance_monitor = performance_monitor
        self.app_logger = app_logger
        self.db_manager = db_manager  
        self.suspicious_patterns = {
            'port_scan': lambda event: self._detect_port_scan(event),
            'brute_force': lambda event: self._detect_brute_force(event),
            'data_exfiltration': lambda event: self._detect_data_exfiltration(event),
            'geo_anomaly': lambda event: self._detect_geo_anomaly(event)
        }
        self.geoip = GeoIPService()
        
    def process_event(self, event_line):
        """Process a single event line and return alert data"""
        try:
            event = json.loads(event_line)
            event_type = event.get('event_type', '')
            
            alert = None
            if event_type == 'alert':
                alert = self._process_alert(event)
            elif event_type == 'flow':
                alert = self._process_flow(event)
            elif event_type == 'dns':
                alert = self._process_dns(event)
            
            if alert and hasattr(self, 'db_manager') and self.db_manager and self.db_manager.enabled:
                try:
                    self.db_manager.store_alert(alert)
                except Exception as db_error:
                    if self.app_logger:
                        self.app_logger.warning(f"Failed to store alert in database: {db_error}")
            
            return alert
            
        except json.JSONDecodeError:
            if self.performance_monitor:
                self.performance_monitor.metrics['parse_errors'] += 1
            return None
        except Exception as e:
            if self.app_logger:
                self.app_logger.debug(f"Event processing error: {e}")
            return None  
            
    def _process_alert(self, event):
        """Process standard Suricata alerts with GeoIP enhancement"""
        alert_data = event.get('alert', {})
        priority = alert_data.get('severity', 3)
        
        src_ip = event.get('src_ip', 'Unknown')
        dest_ip = event.get('dest_ip', 'Unknown')
        
        alert = {
            'timestamp': event.get('timestamp', '')[:19],
            'signature': alert_data.get('signature', 'Unknown')[:150],
            'category': alert_data.get('category', 'Unknown'),
            'priority': self._get_priority_level(priority),
            'src_ip': src_ip,
            'src_port': event.get('src_port', 'Unknown'),
            'dest_ip': dest_ip,
            'dest_port': event.get('dest_port', 'Unknown'),
            'proto': event.get('proto', 'Unknown'),
            'event_type': 'alert',
            'severity_num': priority
        }
        
        if self.geoip.reader:
            src_geo = self.geoip.get_location(src_ip)
            dest_geo = self.geoip.get_location(dest_ip)
            
            alert['src_geo'] = src_geo
            alert['dest_geo'] = dest_geo
            
            if src_geo and dest_geo:
                distance = self.geoip.get_distance(src_ip, dest_ip)
                if distance:
                    alert['geo_distance_km'] = round(distance, 1)
        
        return alert
    
    def _detect_geo_anomaly(self, event):
        """Detect geographical anomalies that might indicate threats"""
        if not self.geoip.reader:
            return None
        
        src_ip = event.get('src_ip', '')
        dest_ip = event.get('dest_ip', '')
        
        src_geo = self.geoip.get_location(src_ip)
        dest_geo = self.geoip.get_location(dest_ip)
        
        if not src_geo or not dest_geo:
            return None
        
        suspicious_countries = {'CN', 'RU', 'KP', 'IR'}  
        
        if (src_geo.get('country_code') in suspicious_countries or 
            dest_geo.get('country_code') in suspicious_countries):
            
            distance = self.geoip.get_distance(src_ip, dest_ip)
            
            return {
                'timestamp': event.get('timestamp', '')[:19],
                'signature': f"Suspicious geographic connection: {src_geo.get('country', 'Unknown')} → {dest_geo.get('country', 'Unknown')}",
                'category': "Geographic Anomaly",
                'priority': 'medium',
                'src_ip': src_ip,
                'src_port': event.get('src_port', 'Unknown'),
                'dest_ip': dest_ip,
                'dest_port': event.get('dest_port', 'Unknown'),
                'proto': event.get('proto', 'Unknown'),
                'event_type': 'geo_anomaly',
                'src_geo': src_geo,
                'dest_geo': dest_geo,
                'geo_distance_km': round(distance, 1) if distance else None
            }
        
        return None
    
    def _process_flow(self, event):
        """Process flow events for suspicious activity"""
        for pattern_name, detector in self.suspicious_patterns.items():
            alert = detector(event)
            if alert:
                alert['pattern_type'] = pattern_name
                return alert
        
        return None
    
    def _process_dns(self, event):
        """Process DNS events for suspicious queries"""
        dns_data = event.get('dns', {})
        query = dns_data.get('rrname', '').lower()
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        suspicious_patterns = ['dga-', 'malware', 'botnet', 'c2-']
        
        is_suspicious = any(tld in query for tld in suspicious_tlds) or \
                       any(pattern in query for pattern in suspicious_patterns) or \
                       len(query.split('.')[0]) > 20  
        
        if is_suspicious:
            return {
                'timestamp': event.get('timestamp', '')[:19],
                'signature': f"Suspicious DNS query: {query}",
                'category': "DNS Anomaly",
                'priority': 'medium',
                'src_ip': event.get('src_ip', 'Unknown'),
                'src_port': event.get('src_port', 53),
                'dest_ip': event.get('dest_ip', 'Unknown'),
                'dest_port': event.get('dest_port', 53),
                'proto': 'UDP',
                'event_type': 'suspicious_dns'
            }
        
        return None
    
    def _detect_port_scan(self, event):
        """Enhanced port scan detection"""
        flow_data = event.get('flow', {})
        tcp_data = event.get('tcp', {})
        dest_port = event.get('dest_port', 0)
        
        if (tcp_data.get('syn') and not tcp_data.get('ack') and 
            flow_data.get('pkts_toclient', 0) == 0):
            
            if dest_port in self.config.HIGH_RISK_PORTS:
                priority = 'high'
                category = "High-Risk Port Scan"
            elif dest_port in self.config.SUSPICIOUS_PORTS or dest_port > 40000:
                priority = 'medium'
                category = "Port Scan"
            else:
                priority = 'low'
                category = "Network Probe"
            
            return {
                'timestamp': event.get('timestamp', '')[:19],
                'signature': f"Port scan detected on port {dest_port}",
                'category': category,
                'priority': priority,
                'src_ip': event.get('src_ip', 'Unknown'),
                'src_port': event.get('src_port', 'Unknown'),
                'dest_ip': event.get('dest_ip', 'Unknown'),
                'dest_port': dest_port,
                'proto': event.get('proto', 'Unknown'),
                'event_type': 'port_scan'
            }
        
        return None
    
    def _detect_brute_force(self, event):
        """Detect potential brute force attacks"""
        dest_port = event.get('dest_port', 0)
        flow_data = event.get('flow', {})
        
        brute_force_ports = {22, 23, 21, 3389, 1433, 3306, 5432}
        
        if (dest_port in brute_force_ports and 
            flow_data.get('pkts_toserver', 0) > 10 and 
            flow_data.get('pkts_toclient', 0) == 0):
            
            return {
                'timestamp': event.get('timestamp', '')[:19],
                'signature': f"Possible brute force attempt on port {dest_port}",
                'category': "Brute Force",
                'priority': 'high',
                'src_ip': event.get('src_ip', 'Unknown'),
                'src_port': event.get('src_port', 'Unknown'),
                'dest_ip': event.get('dest_ip', 'Unknown'),
                'dest_port': dest_port,
                'proto': event.get('proto', 'Unknown'),
                'event_type': 'brute_force'
            }
        
        return None
    
    def _detect_data_exfiltration(self, event):
        """Detect potential data exfiltration"""
        flow_data = event.get('flow', {})
        bytes_toserver = flow_data.get('bytes_toserver', 0)
        bytes_toclient = flow_data.get('bytes_toclient', 0)
        
        if bytes_toclient > 10 * 1024 * 1024:  
            return {
                'timestamp': event.get('timestamp', '')[:19],
                'signature': f"Large data transfer detected ({bytes_toclient/1024/1024:.1f}MB)",
                'category': "Data Exfiltration",
                'priority': 'medium',
                'src_ip': event.get('src_ip', 'Unknown'),
                'src_port': event.get('src_port', 'Unknown'),
                'dest_ip': event.get('dest_ip', 'Unknown'),
                'dest_port': event.get('dest_port', 'Unknown'),
                'proto': event.get('proto', 'Unknown'),
                'event_type': 'data_exfiltration'
            }
        
        return None
    
    def _get_priority_level(self, priority):
        """Convert numeric priority to text level"""
        if priority <= 1:
            return 'high'
        elif priority <= 2:
            return 'medium'
        else:
            return 'low'