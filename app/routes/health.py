# app/routes/health.py
from flask import Blueprint, jsonify, current_app
from datetime import datetime

health_bp = Blueprint('health', __name__)

@health_bp.route('/health')
def health_check():
    """Health check endpoint"""
    backup_dir_exists = current_app.config['BACKUP_BASE_DIR'].exists()
    
    # Check MongoDB connection
    mongodb_status = False
    if current_app.db is not None:
        try:
            current_app.db.command('ping')
            mongodb_status = True
        except Exception:
            pass
    
    return jsonify({
        'status': 'healthy' if backup_dir_exists and mongodb_status else 'degraded',
        'timestamp': datetime.utcnow().isoformat(),
        'backup_dir_exists': backup_dir_exists,
        'mongodb_connected': mongodb_status,
        'version': '1.0.0'
    })

@health_bp.route('/status')
def detailed_status():
    """Detailed system status"""
    from app.models.file_model import FileModel
    
    file_model = FileModel(current_app.db)
    
    # Get basic stats for each device type
    device_stats = {}
    for device in ['laptop', 'mobile', 'server']:
        device_stats[device] = file_model.get_device_stats(device)
    
    return jsonify({
        'timestamp': datetime.utcnow().isoformat(),
        'backup_directory': str(current_app.config['BACKUP_BASE_DIR']),
        'mongodb_connected': current_app.db is not None,
        'device_statistics': device_stats
    })