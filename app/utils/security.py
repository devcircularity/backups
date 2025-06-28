# app/utils/security.py
from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.utils import secure_filename
import re

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        provided_token = token.split(' ')[1]
        if provided_token != current_app.config['AUTH_TOKEN']:
            current_app.logger.warning(f"Invalid auth attempt from {request.remote_addr}")
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    return decorated_function

def sanitize_path(path_component):
    """Sanitize path components to prevent traversal attacks"""
    if not path_component or path_component in ['', '.', '..']:
        raise ValueError("Invalid path component")
    
    # Remove any path traversal attempts
    sanitized = secure_filename(path_component)
    if not sanitized or sanitized != path_component.replace('/', '_'):
        raise ValueError("Path contains invalid characters")
    
    return sanitized

def validate_device_type(device):
    """Validate device type against allowed types"""
    allowed_devices = ['laptop', 'mobile', 'server']
    if device not in allowed_devices:
        raise ValueError(f"Invalid device type. Must be one of: {allowed_devices}")
    return device

def allowed_file(filename):
    """Check if file extension is allowed"""
    if not filename or '.' not in filename:
        return False
    
    allowed_extensions = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
        'xls', 'xlsx', 'zip', 'tar', 'gz', 'mp3', 'mp4', 'mov', 
        'avi', 'mkv', 'sql', 'json', 'xml', 'csv', 'log'
    }
    
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions

def validate_filename(filename):
    """Validate filename for security"""
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    if not allowed_file(filename):
        raise ValueError("File type not allowed")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'\.\./', r'\.\.\\', r'^\/', r'^\\'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, filename):
            raise ValueError("Filename contains suspicious patterns")
    
    return sanitize_path(filename)