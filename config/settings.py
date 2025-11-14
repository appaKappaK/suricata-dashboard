import os
import sys
from pathlib import Path
from dotenv import load_dotenv

class Config:
    """Environment-aware configuration with validation and utilities"""
    
    def __init__(self, env=None):
        self.environment = env or os.getenv('DASHBOARD_ENV', 'development')
        self._load_environment()
        
        self.EVE_LOG_PATH = os.getenv('SURICATA_LOG_FILE', '/var/log/suricata/eve.json')
        self.MAX_LOG_LINES = int(os.getenv('DASHBOARD_MAX_LINES', 15000))
        self.REFRESH_INTERVAL = int(os.getenv('DASHBOARD_REFRESH_INTERVAL', 15))
        self.HOST = os.getenv('DASHBOARD_HOST', '0.0.0.0')
        self.PORT = int(os.getenv('DASHBOARD_PORT', 8080))
        
        self.HIGH_PRIORITY_THRESHOLD = int(os.getenv('HIGH_PRIORITY_THRESHOLD', 10))
        self.LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', 30))
        self.MAX_MEMORY_MB = int(os.getenv('MAX_MEMORY_MB', 1000))
        self.GEOIP_DATABASE = os.getenv('GEOIP_DATABASE', '/usr/share/GeoIP/GeoLite2-City.mmdb')
        
        self.RATE_LIMIT = os.getenv('RATE_LIMIT', '1000 per hour')
        
        self.ENABLE_RATE_LIMITING = os.getenv('ENABLE_RATE_LIMITING', 'true').lower() == 'true'
        self.ENABLE_GEOIP = os.getenv('ENABLE_GEOIP', 'true').lower() == 'true'
        self.DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
        
        self.SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
        
        self.HIGH_RISK_PORTS = {22, 23, 3389, 5900, 5901}  
        self.SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337}  
        
        self.validate()
    
    def _load_environment(self):
        """Load environment variables with proper precedence"""
        if Path('.env').exists():
            load_dotenv('.env')
        
        env_file = f'.env.{self.environment}'
        if Path(env_file).exists():
            load_dotenv(env_file)
            print(f"📁 Loaded environment: {self.environment}")
        else:
            print(f"ℹ️  No {env_file} found, using base configuration")
    
    def validate(self):
        """Validate configuration and check dependencies"""
        print("🔧 Validating configuration...")
        
        if not self.check_dependencies():
            sys.exit(1)
        
        self._validate_paths()
        
        self._validate_numbers()
        
        print("✅ Configuration validated successfully")
        return True
    
    def check_dependencies(self):
        """Verify all required dependencies are available"""
        dependencies = {
            'Flask': 'flask',
            'psutil': 'psutil', 
            'geoip2': 'geoip2',
            'python-dotenv': 'dotenv',
            'Flask-Limiter': 'flask_limiter'
        }
        
        missing = []
        for name, package in dependencies.items():
            try:
                __import__(package)
            except ImportError:
                missing.append(name)
        
        if missing:
            print(f"❌ Missing dependencies: {', '.join(missing)}")
            print("💡 Install with: pip install -r requirements.txt")
            return False
        
        print("✅ All dependencies available")
        return True
    
    def _validate_paths(self):
        """Validate file and directory paths"""
        log_dir = Path(self.EVE_LOG_PATH).parent
        if not log_dir.exists():
            print(f"⚠️  Log directory doesn't exist: {log_dir}")
            print(f"   Creating directory: {log_dir}")
            log_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            test_file = log_dir / '.write_test'
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            print(f"❌ Cannot write to log directory: {log_dir}")
            print("   Check permissions or run with appropriate user")
            sys.exit(1)
        
        if self.ENABLE_GEOIP and self.GEOIP_DATABASE:
            if not Path(self.GEOIP_DATABASE).exists():
                print(f"⚠️  GeoIP database not found: {self.GEOIP_DATABASE}")
                print("   Geo location features will be disabled")
                self.ENABLE_GEOIP = False
    
    def _validate_numbers(self):
        """Validate numeric configuration values"""
        if self.MAX_LOG_LINES <= 0:
            print("❌ DASHBOARD_MAX_LINES must be positive")
            sys.exit(1)
        
        if self.REFRESH_INTERVAL < 1:
            print("❌ DASHBOARD_REFRESH_INTERVAL must be at least 1 second")
            sys.exit(1)
        
        if self.PORT < 1 or self.PORT > 65535:
            print("❌ DASHBOARD_PORT must be between 1 and 65535")
            sys.exit(1)
        
        if self.MAX_MEMORY_MB < 10:
            print("❌ MAX_MEMORY_MB must be at least 10MB")
            sys.exit(1)
    
    def get_flask_config(self):
        """Get configuration dictionary for Flask app"""
        return {
            'DEBUG': self.DEBUG,
            'SECRET_KEY': self.SECRET_KEY,
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  
        }
    
    def get_database_url(self):
        """Get database connection URL (for future use with other databases)"""
        return f"sqlite:///alerts.db"
    
    def __str__(self):
        """String representation for debugging"""
        return f"""
Suricata Dashboard Configuration ({self.environment.upper()})
============================================
📁 Environment: {self.environment}
🌐 Web Interface: http://{self.HOST}:{self.PORT}
📊 Log File: {self.EVE_LOG_PATH}
⚡ Refresh: {self.REFRESH_INTERVAL}s
📈 Max Lines: {self.MAX_LOG_LINES}
⚠️  High Priority Threshold: {self.HIGH_PRIORITY_THRESHOLD}
🗄️  Retention: {self.LOG_RETENTION_DAYS} days
💾 Memory Limit: {self.MAX_MEMORY_MB}MB
🌍 GeoIP: {self.ENABLE_GEOIP} ({self.GEOIP_DATABASE})
🔒 Rate Limiting: {self.ENABLE_RATE_LIMITING}
🐛 Debug Mode: {self.DEBUG}
============================================
"""
    
    def to_dict(self):
        """Return configuration as dictionary (for API endpoints)"""
        return {
            'environment': self.environment,
            'eve_log_path': self.EVE_LOG_PATH,
            'max_log_lines': self.MAX_LOG_LINES,
            'refresh_interval': self.REFRESH_INTERVAL,
            'host': self.HOST,
            'port': self.PORT,
            'high_priority_threshold': self.HIGH_PRIORITY_THRESHOLD,
            'log_retention_days': self.LOG_RETENTION_DAYS,
            'max_memory_mb': self.MAX_MEMORY_MB,
            'enable_geoip': self.ENABLE_GEOIP,
            'enable_rate_limiting': self.ENABLE_RATE_LIMITING,
            'debug': self.DEBUG
        }