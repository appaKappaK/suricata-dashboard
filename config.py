import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Centralized configuration with validation"""
    
    def __init__(self):
        self.LOG_FILE = os.getenv('SURICATA_LOG_FILE', '/var/log/suricata/eve.json')
        self.MAX_LINES_TO_READ = int(os.getenv('DASHBOARD_MAX_LINES', '15000'))
        self.REFRESH_INTERVAL = int(os.getenv('DASHBOARD_REFRESH_INTERVAL', '15'))
        self.HOST = os.getenv('DASHBOARD_HOST', '10.8.0.7')
        self.PORT = int(os.getenv('DASHBOARD_PORT', '8080'))
        self.HIGH_PRIORITY_THRESHOLD = int(os.getenv('HIGH_PRIORITY_THRESHOLD', '10'))
        self.LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '30'))
        self.MAX_MEMORY_MB = int(os.getenv('MAX_MEMORY_MB', '1000'))
        self.ENABLE_PERSISTENCE = os.getenv('ENABLE_PERSISTENCE', 'false').lower() == 'true'
        self.DB_PATH = os.getenv('DB_PATH', 'alerts.db')
        self.ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')
        
        self.SUSPICIOUS_PORTS = {4899, 10242, 4444, 1337, 2323, 5555, 9999, 12345, 31337, 54321}
        self.HIGH_RISK_PORTS = {4899, 10242, 4444, 1337}
        
        self.validate()
    
    def validate(self):
        """Validate configuration parameters"""
        if self.REFRESH_INTERVAL < 5:
            raise ValueError("REFRESH_INTERVAL must be at least 5 seconds")
        if self.MAX_LINES_TO_READ > 50000:
            raise ValueError("MAX_LINES_TO_READ should not exceed 50000 for memory safety")
        if self.PORT < 1024 or self.PORT > 65535:
            raise ValueError("PORT must be between 1024 and 65535")

class DevelopmentConfig(Config):
    """Development-specific configuration"""
    def __init__(self):
        super().__init__()
        self.MAX_LINES_TO_READ = 1000
        self.REFRESH_INTERVAL = 30
        self.DEBUG = True
        self.ENABLE_PERSISTENCE = True

class ProductionConfig(Config):
    """Production-specific configuration"""
    def __init__(self):
        super().__init__()
        self.DEBUG = False
        self.ENABLE_PERSISTENCE = True

if os.getenv('ENVIRONMENT', 'production') == 'development':
    config = DevelopmentConfig()
else:
    config = ProductionConfig()