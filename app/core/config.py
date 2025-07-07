import os
from pathlib import Path

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    MONGODB_URI = os.environ.get('MONGODB_URI') or 'mongodb://localhost:27017/backup_db'
    BACKUP_BASE_DIR = Path(os.environ.get('BACKUP_BASE_DIR', '/Users/ericmwirichia/Desktop/backups'))
    AUTH_TOKEN = os.environ.get('BACKUP_API_TOKEN', 'backup-secret-key-change-me')
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB
    
    # Device types allowed
    DEVICE_TYPES = ['laptop', 'mobile', 'server']
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
        'xls', 'xlsx', 'zip', 'tar', 'gz', 'mp3', 'mp4', 'mov', 
        'avi', 'mkv', 'sql', 'json', 'xml', 'csv', 'log', 'py', 'js'
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    MONGODB_URI = 'mongodb://localhost:27017/backup_test_db'
    BACKUP_BASE_DIR = Path('/tmp/test_backups')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
