import sqlite3
import threading
import os
from contextlib import contextmanager

class DatabaseManager:
    """SQLite database manager with graceful fallback - CONSISTENT VERSION"""
    
    def __init__(self, db_path=None, app_logger=None):  
        self.db_path = db_path
        self.enabled = False
        self.lock = threading.RLock()
        self.app_logger = app_logger  
        
        if not db_path:
            if self.app_logger:
                self.app_logger.info("Database path not provided - persistence disabled")
            return
        
        try:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            self._initialize_database()
            self.enabled = True
            if self.app_logger:
                self.app_logger.info(f"Database initialized: {db_path}")
        except Exception as e:
            if self.app_logger:
                self.app_logger.warning(f"Database initialization failed: {e}. Continuing without persistence.")
            self.enabled = False
    
    def _initialize_database(self):
        """Initialize database schema using context manager"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    category TEXT NOT NULL,
                    priority TEXT NOT NULL CHECK(priority IN ('high', 'medium', 'low')),
                    src_ip TEXT NOT NULL,
                    src_port INTEGER CHECK(src_port >= 0 AND src_port <= 65535),
                    dest_ip TEXT NOT NULL,
                    dest_port INTEGER CHECK(dest_port >= 0 AND dest_port <= 65535),
                    proto TEXT NOT NULL CHECK(proto IN ('TCP', 'UDP', 'ICMP', 'Unknown')),
                    event_type TEXT NOT NULL,
                    severity_num INTEGER CHECK(severity_num >= 1 AND severity_num <= 3),
                    src_geo_country TEXT,
                    src_geo_city TEXT,
                    src_geo_org TEXT,
                    dest_geo_country TEXT,
                    dest_geo_city TEXT,
                    dest_geo_org TEXT,
                    geo_distance_km REAL CHECK(geo_distance_km >= 0),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_priority ON alerts(priority)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_dest_ip ON alerts(dest_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_category ON alerts(category)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON alerts(event_type)')
            
            conn.commit()
            if self.app_logger:  
                self.app_logger.info("Database schema initialized successfully")
    
    @contextmanager
    def get_db(self):
        """Context manager for database connections - CONSISTENT APPROACH"""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _safe_int(self, value, default=0):
        """Safely convert to integer with default"""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    
    def _safe_float(self, value, default=0.0):
        """Safely convert to float with default"""
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    
    def store_alert(self, alert):
        """Store alert in database if enabled"""
        if not self.enabled:
            return False
        
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                
                src_geo = alert.get('src_geo', {}) or {}
                dest_geo = alert.get('dest_geo', {}) or {}
                
                cursor.execute('''
                    INSERT INTO alerts (
                        timestamp, signature, category, priority, 
                        src_ip, src_port, dest_ip, dest_port, proto, event_type, severity_num,
                        src_geo_country, src_geo_city, src_geo_org,
                        dest_geo_country, dest_geo_city, dest_geo_org,
                        geo_distance_km
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(alert.get('timestamp', ''))[:19],
                    str(alert.get('signature', ''))[:500],
                    str(alert.get('category', 'Unknown')),
                    str(alert.get('priority', 'low')),
                    str(alert.get('src_ip', 'Unknown')),
                    self._safe_int(alert.get('src_port'), 0),
                    str(alert.get('dest_ip', 'Unknown')),
                    self._safe_int(alert.get('dest_port'), 0),
                    str(alert.get('proto', 'Unknown')).upper(),
                    str(alert.get('event_type', 'alert')),
                    self._safe_int(alert.get('severity_num'), 3),
                    str(src_geo.get('country', ''))[:100],
                    str(src_geo.get('city', ''))[:100],
                    str(src_geo.get('org', ''))[:200],
                    str(dest_geo.get('country', ''))[:100],
                    str(dest_geo.get('city', ''))[:100],
                    str(dest_geo.get('org', ''))[:200],
                    self._safe_float(alert.get('geo_distance_km'))
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            if self.app_logger:  
                self.app_logger.error(f"Failed to store alert in database: {e}")
            return False
    
    def get_recent_alerts(self, limit=100, hours=24):
        """Get recent alerts from database"""
        if not self.enabled:
            return []
        
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                
                safe_limit = max(1, min(limit, 1000))
                safe_hours = max(1, min(hours, 720))  
                
                cursor.execute('''
                    SELECT * FROM alerts 
                    WHERE datetime(timestamp) >= datetime('now', ?) 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (f'-{safe_hours} hours', safe_limit))
                
                rows = cursor.fetchall()
                return [self._row_to_alert(row) for row in rows]
                
        except Exception as e:
            if self.app_logger:  
                self.app_logger.error(f"Failed to fetch alerts from database: {e}")
            return []
    
    def search_alerts(self, query_params, limit=100):
        """Search alerts in database with filters - SECURE VERSION"""
        if not self.enabled:
            return []
        
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                
                query_parts = ["SELECT * FROM alerts WHERE 1=1"]
                params = []
                
                if query_params.get('q'):
                    query_parts.append(" AND (signature LIKE ? OR category LIKE ? OR src_ip LIKE ? OR dest_ip LIKE ?)")
                    search_term = f"%{query_params['q']}%"
                    params.extend([search_term, search_term, search_term, search_term])
                
                if query_params.get('priority') and query_params['priority'] in ['high', 'medium', 'low']:
                    query_parts.append(" AND priority = ?")
                    params.append(query_params['priority'])
                
                if query_params.get('ip'):
                    from utils.validation import validate_ip_address  
                    if validate_ip_address(query_params['ip']):
                        query_parts.append(" AND (src_ip = ? OR dest_ip = ?)")
                        params.extend([query_params['ip'], query_params['ip']])
                
                if query_params.get('protocol'):
                    protocol = query_params['protocol'].upper()
                    if protocol in ['TCP', 'UDP', 'ICMP']:
                        query_parts.append(" AND proto = ?")
                        params.append(protocol)
                
                if query_params.get('port'):
                    try:
                        port = int(query_params['port'])
                        if 1 <= port <= 65535:
                            query_parts.append(" AND (src_port = ? OR dest_port = ?)")
                            params.extend([port, port])
                    except ValueError:
                        pass  
                
                if query_params.get('category'):
                    query_parts.append(" AND category LIKE ?")
                    params.append(f"%{query_params['category']}%")
                
                safe_limit = max(1, min(limit, 1000))
                query_parts.append(" ORDER BY timestamp DESC LIMIT ?")
                params.append(safe_limit)
                
                query = " ".join(query_parts)
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [self._row_to_alert(row) for row in rows]
                
        except Exception as e:
            if self.app_logger:  
                self.app_logger.error(f"Database search failed: {e}")
            return []
    
    def get_alert_stats(self, hours=24):
        """Get alert statistics from database"""
        if not self.enabled:
            return {}
        
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                
                stats = {}
                safe_hours = max(1, min(hours, 720))
                
                cursor.execute('''
                    SELECT priority, COUNT(*) as count 
                    FROM alerts 
                    WHERE datetime(timestamp) >= datetime('now', ?)
                    GROUP BY priority
                ''', (f'-{safe_hours} hours',))
                
                for row in cursor.fetchall():
                    stats[f"{row['priority']}_priority"] = row['count']
                
                cursor.execute('''
                    SELECT COUNT(*) as total 
                    FROM alerts 
                    WHERE datetime(timestamp) >= datetime('now', ?)
                ''', (f'-{safe_hours} hours',))
                
                stats['total_alerts'] = cursor.fetchone()['total']
                
                cursor.execute('''
                    SELECT category, COUNT(*) as count
                    FROM alerts 
                    WHERE datetime(timestamp) >= datetime('now', ?)
                    GROUP BY category 
                    ORDER BY count DESC 
                    LIMIT 10
                ''', (f'-{safe_hours} hours',))
                
                stats['top_categories'] = {row['category']: row['count'] for row in cursor.fetchall()}
                
                return stats
                
        except Exception as e:
            if self.app_logger:  
                self.app_logger.error(f"Failed to get alert stats: {e}")
            return {}
    
    def cleanup_old_alerts(self, retention_days=30):
        """Remove alerts older than retention period"""
        if not self.enabled:
            return 0
        
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                
                safe_retention_days = max(1, min(retention_days, 365))  
                
                cursor.execute('''
                    SELECT COUNT(*) as count 
                    FROM alerts 
                    WHERE datetime(timestamp) < datetime('now', ?)
                ''', (f'-{safe_retention_days} days',))
                
                count_before = cursor.fetchone()['count']
                
                cursor.execute('''
                    DELETE FROM alerts 
                    WHERE datetime(timestamp) < datetime('now', ?)
                ''', (f'-{safe_retention_days} days',))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0 and self.app_logger:
                    self.app_logger.info(f"Cleaned up {deleted_count} old alerts from database (older than {safe_retention_days} days)")
                
                return deleted_count
                
        except Exception as e:
            if self.app_logger:  
                self.app_logger.error(f"Failed to cleanup old alerts: {e}")
            return 0
    
    def _row_to_alert(self, row):
        """Convert database row to alert dictionary"""
        alert = {
            'timestamp': row['timestamp'],
            'signature': row['signature'],
            'category': row['category'],
            'priority': row['priority'],
            'src_ip': row['src_ip'],
            'src_port': row['src_port'],
            'dest_ip': row['dest_ip'],
            'dest_port': row['dest_port'],
            'proto': row['proto'],
            'event_type': row['event_type'],
            'severity_num': row['severity_num']
        }
        
        if row['src_geo_country']:
            alert['src_geo'] = {
                'country': row['src_geo_country'],
                'city': row['src_geo_city'],
                'org': row['src_geo_org']
            }
        
        if row['dest_geo_country']:
            alert['dest_geo'] = {
                'country': row['dest_geo_country'],
                'city': row['dest_geo_city'],
                'org': row['dest_geo_org']
            }
        
        if row['geo_distance_km']:
            alert['geo_distance_km'] = float(row['geo_distance_km'])
        
        return alert
    
    def health_check(self):
        """Check database health and connection"""
        if not self.enabled:
            return {'status': 'disabled'}
        
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM alerts")
                total_alerts = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM sqlite_master WHERE type='table'")
                table_count = cursor.fetchone()['count']
                
                return {
                    'status': 'healthy',
                    'total_alerts': total_alerts,
                    'table_count': table_count,
                    'path': self.db_path
                }
        except Exception as e:
            if self.app_logger:  
                self.app_logger.error(f"Database health check failed: {e}")
            return {'status': 'unhealthy', 'error': str(e)}
    
    def close(self):
        """Close database connection - No longer needed with context manager"""
        if self.app_logger:  
            self.app_logger.info("Database manager shutdown - connections managed per operation")