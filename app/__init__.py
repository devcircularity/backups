# app/__init__.py
from flask import Flask
from flask_cors import CORS
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
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
    app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
    backup_dir = Path(os.environ.get('BACKUP_BASE_DIR', './backups'))
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
        print("✅ MongoDB connection successful")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("API will continue without database functionality")
        app.db = None
    
    # Setup logging
    setup_logging(app)
    
    # Initialize backup directory structure and update config
    try:
        actual_backup_dir = init_backup_structure(backup_dir)
        app.config['BACKUP_BASE_DIR'] = actual_backup_dir
        print(f"✅ Backup directory ready: {actual_backup_dir}")
    except Exception as e:
        print(f"❌ Failed to initialize backup directory: {e}")
        raise
    
    # Register blueprints
    from app.routes.api import api_bp
    from app.routes.health import health_bp
    
    app.register_blueprint(health_bp)
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    return app

def setup_logging(app):
    """Setup application logging with fallback for permission issues"""
    # Try multiple log locations in order of preference
    log_paths = [
        '/var/log/backup-api.log',  # System log directory (Linux/Unix)
        os.path.expanduser('~/logs/backup-api.log'),  # User home directory
        './logs/backup-api.log',  # Local logs directory
        './backup-api.log'  # Current directory fallback
    ]
    
    log_file = None
    for log_path in log_paths:
        try:
            # Create directory if it doesn't exist
            log_dir = Path(log_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Test if we can write to this location
            test_handler = logging.FileHandler(log_path)
            test_handler.close()
            log_file = log_path
            print(f"Using log file: {log_file}")
            break
        except (PermissionError, OSError) as e:
            print(f"Cannot write to {log_path}: {e}")
            continue
    
    # Setup file logging if we found a writable location
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
    else:
        print("Warning: Could not set up file logging, using console only")
    
    # Always setup console logging
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    console_handler.setLevel(logging.INFO)
    app.logger.addHandler(console_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('Backup API startup')

def init_backup_structure(backup_dir):
    """Initialize the backup directory structure"""
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
        print(f"Backup directory initialized: {backup_dir}")
    except PermissionError:
        # Try alternative locations if default fails
        alternative_dirs = [
            Path.home() / 'backups',
            Path('./backups'),
            Path('/tmp/backups')
        ]
        
        for alt_dir in alternative_dirs:
            try:
                alt_dir.mkdir(parents=True, exist_ok=True)
                print(f"Using alternative backup directory: {alt_dir}")
                # Update the config to use the working directory
                return alt_dir
            except (PermissionError, OSError):
                continue
        
        raise RuntimeError("Could not create backup directory in any location")
    
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
    
    return backup_dir