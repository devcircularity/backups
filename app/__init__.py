# app/__init__.py
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
import os
import logging
from pathlib import Path

# Initialize extensions
limiter = Limiter(key_func=get_remote_address)

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
    app.config['BACKUP_BASE_DIR'] = Path(os.environ.get('BACKUP_BASE_DIR', '/mnt/backupdrive/backups'))
    app.config['MONGODB_URI'] = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/backup_db')
    app.config['AUTH_TOKEN'] = os.environ.get('BACKUP_API_TOKEN', 'backup-secret-key-change-me')
    
    # Initialize extensions
    limiter.init_app(app)
    
    # Initialize MongoDB
    try:
        client = MongoClient(app.config['MONGODB_URI'])
        app.db = client.get_database()
        # Test connection
        app.db.command('ping')
        print("MongoDB connection successful")
    except Exception as e:
        print(f"MongoDB connection failed: {e}")
        app.db = None
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    from app.routes.api import api_bp
    from app.routes.health import health_bp
    
    app.register_blueprint(health_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    # Initialize backup directory structure
    init_backup_structure(app.config['BACKUP_BASE_DIR'])
    
    return app

def setup_logging(app):
    """Setup application logging"""
    if not app.debug:
        log_dir = Path('/var/log')
        log_dir.mkdir(exist_ok=True)
        
        file_handler = logging.FileHandler('/var/log/backup-api.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Backup API startup')

def init_backup_structure(backup_dir):
    """Initialize the backup directory structure"""
    backup_dir.mkdir(exist_ok=True)
    
    device_types = ['laptop', 'mobile', 'server']
    for device_type in device_types:
        device_path = backup_dir / device_type
        device_path.mkdir(exist_ok=True)
    
    # Create example folders
    example_folders = [
        'laptop/mymac', 'laptop/dell',
        'mobile/eric-iphone', 'mobile/pixel-7',
        'server/aws-backups', 'server/db-dumps'
    ]
    
    for folder in example_folders:
        folder_path = backup_dir / folder
        folder_path.mkdir(parents=True, exist_ok=True)
