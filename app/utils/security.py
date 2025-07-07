# app/utils/security.py
from functools import wraps
from flask import request, jsonify, current_app
from werkzeug.utils import secure_filename
import re  # Import re at the top of the file
import os

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
        'avi', 'mkv', 'sql', 'json', 'xml', 'csv', 'log', 'py',
        'js', 'html', 'css', 'md', 'rtf', 'ppt', 'pptx'
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
        r'\.\./', r'\.\.\\', r'^\/', r'^\\', r'\x00'  # Path traversal and null bytes
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, filename):
            raise ValueError("Filename contains suspicious patterns")
    
    # Create a safe filename by replacing problematic characters
    # Keep original extension
    name, ext = os.path.splitext(filename)
    
    # Replace spaces and special characters with underscores, but keep basic characters
    # Note: re is already imported at the top, so no need to import again
    safe_name = re.sub(r'[^\w\-_\.]', '_', name)
    safe_filename = f"{safe_name}{ext}"
    
    return safe_filename

def get_file_size_limit():
    """Get maximum file size limit in bytes"""
    # Default to 100MB if not configured
    return current_app.config.get('MAX_CONTENT_LENGTH', 100 * 1024 * 1024)

def validate_file_size(file_size):
    """Validate file size against limits"""
    max_size = get_file_size_limit()
    if file_size > max_size:
        max_size_mb = max_size / (1024 * 1024)
        raise ValueError(f"File size exceeds maximum limit of {max_size_mb:.1f}MB")
    
    return True

def is_safe_path(basedir, path, follow_symlinks=True):
    """Check if a path is safe (within basedir)"""
    # Resolve the absolute path
    if follow_symlinks:
        return os.path.realpath(path).startswith(os.path.realpath(basedir))
    else:
        return os.path.abspath(path).startswith(os.path.abspath(basedir))

def generate_unique_filename(directory, filename):
    """Generate a unique filename if the file already exists"""
    base_path = os.path.join(directory, filename)
    
    if not os.path.exists(base_path):
        return filename
    
    name, ext = os.path.splitext(filename)
    counter = 1
    
    while True:
        new_filename = f"{name}_{counter}{ext}"
        new_path = os.path.join(directory, new_filename)
        
        if not os.path.exists(new_path):
            return new_filename
        
        counter += 1
        
        # Prevent infinite loop
        if counter > 9999:
            raise ValueError("Could not generate unique filename")

def clean_filename_for_storage(filename):
    """Clean filename for safe storage while preserving readability"""
    if not filename:
        return "untitled"
    
    # Get name and extension
    name, ext = os.path.splitext(filename)
    
    # Replace problematic characters but keep it readable
    # Keep alphanumeric, spaces, hyphens, underscores, periods
    clean_name = re.sub(r'[^\w\s\-_\.]', '', name)
    
    # Replace multiple spaces with single space
    clean_name = re.sub(r'\s+', ' ', clean_name).strip()
    
    # Replace spaces with underscores for filesystem compatibility
    clean_name = clean_name.replace(' ', '_')
    
    # Ensure it's not empty
    if not clean_name:
        clean_name = "file"
    
    # Ensure extension is clean
    if ext:
        clean_ext = re.sub(r'[^\w\.]', '', ext)
        if not clean_ext.startswith('.'):
            clean_ext = '.' + clean_ext
    else:
        clean_ext = ''
    
    return clean_name + clean_ext

def find_actual_filename(directory, requested_filename):
    """
    Find the actual filename on the filesystem that matches the requested filename.
    This handles cases where the filename might have been modified during upload.
    
    Args:
        directory: The directory to search in
        requested_filename: The filename being requested
        
    Returns:
        The actual filename if found, None otherwise
    """
    if not os.path.exists(directory):
        return None
    
    # First try exact match
    exact_path = os.path.join(directory, requested_filename)
    if os.path.exists(exact_path) and os.path.isfile(exact_path):
        return requested_filename
    
    # If exact match fails, try to find a cleaned version
    try:
        cleaned_requested = clean_filename_for_storage(requested_filename)
        cleaned_path = os.path.join(directory, cleaned_requested)
        if os.path.exists(cleaned_path) and os.path.isfile(cleaned_path):
            return cleaned_requested
    except:
        pass
    
    # If still not found, try case-insensitive search
    try:
        files_in_dir = os.listdir(directory)
        requested_lower = requested_filename.lower()
        
        for filename in files_in_dir:
            if filename.lower() == requested_lower:
                return filename
    except:
        pass
    
    # Last resort: try to find files with similar names (without special characters)
    try:
        # Remove special characters from requested filename for comparison
        requested_clean = re.sub(r'[^\w\-_\.]', '_', requested_filename)
        
        for filename in files_in_dir:
            filename_clean = re.sub(r'[^\w\-_\.]', '_', filename)
            if filename_clean == requested_clean:
                return filename
    except:
        pass
    
    return None