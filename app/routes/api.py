# app/routes/api.py
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.exceptions import RequestEntityTooLarge
from app.utils.security import sanitize_path, validate_device_type, validate_filename
from app.models.file_model import FileModel
from app.models.audit_model import AuditModel
from werkzeug.utils import secure_filename
from app import limiter
import os
from datetime import datetime
from pathlib import Path

api_bp = Blueprint('api', __name__)

def get_models():
    """Get model instances"""
    file_model = FileModel(current_app.db)
    audit_model = AuditModel(current_app.db)
    return file_model, audit_model

@api_bp.route('/devices')
def list_devices():
    """List available device types and their folders"""
    try:
        file_model, audit_model = get_models()
        
        devices = []
        for device_type in ['laptop', 'mobile', 'server']:
            device_path = current_app.config['BACKUP_BASE_DIR'] / device_type
            if device_path.exists():
                folders = [d.name for d in device_path.iterdir() if d.is_dir()]
                stats = file_model.get_device_stats(device_type)
                
                devices.append({
                    'type': device_type,
                    'folders': folders,
                    'folder_count': len(folders),
                    'total_files': stats.get('total_files', 0),
                    'total_size': stats.get('total_size', 0)
                })
        
        audit_model.log_action('list_devices', None, None, None, request.remote_addr)
        
        return jsonify({
            'devices': devices,
            'total_device_types': len(devices)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error listing devices: {str(e)}")
        return jsonify({'error': 'Failed to list devices'}), 500

@api_bp.route('/devices/<device>/folders')
def list_folders(device):
    """List folders for a specific device with nested folder support"""
    try:
        device = validate_device_type(device)
        file_model, audit_model = get_models()
        
        device_path = current_app.config['BACKUP_BASE_DIR'] / device
        
        if not device_path.exists():
            return jsonify({'error': f'Device type {device} not found'}), 404
        
        folders = []
        
        def get_folder_info(folder_path, relative_path=""):
            """Recursively get folder information"""
            folder_info = {
                'name': folder_path.name,
                'path': relative_path or folder_path.name,
                'full_path': str(folder_path.relative_to(device_path)),
                'is_nested': bool(relative_path),
                'file_count': 0,
                'total_size': 0,
                'subfolders': [],
                'has_files': False
            }
            
            try:
                # Count files and get subfolders
                for item in folder_path.iterdir():
                    if item.is_file() and not item.name.startswith('.'):
                        folder_info['file_count'] += 1
                        folder_info['total_size'] += item.stat().st_size
                        folder_info['has_files'] = True
                    elif item.is_dir():
                        subfolder_info = get_folder_info(
                            item, 
                            f"{relative_path}/{item.name}" if relative_path else item.name
                        )
                        folder_info['subfolders'].append(subfolder_info)
                        # Add subfolder stats to parent
                        folder_info['file_count'] += subfolder_info['file_count']
                        folder_info['total_size'] += subfolder_info['total_size']
                
                # Set last modified time
                try:
                    folder_info['last_modified'] = datetime.fromtimestamp(
                        folder_path.stat().st_mtime
                    ).isoformat()
                except:
                    folder_info['last_modified'] = None
                    
            except PermissionError:
                current_app.logger.warning(f"Permission denied accessing {folder_path}")
            
            return folder_info
        
        # Get all top-level folders
        for folder_path in device_path.iterdir():
            if folder_path.is_dir():
                folder_info = get_folder_info(folder_path)
                folders.append(folder_info)
        
        audit_model.log_action('list_folders', device, None, None, request.remote_addr)
        
        return jsonify({
            'device': device,
            'folders': folders,
            'total_folders': len(folders)
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error listing folders for {device}: {str(e)}")
        return jsonify({'error': 'Failed to list folders'}), 500

@api_bp.route('/devices/<device>/folders/<path:folder_path>')
def list_folder_contents(device, folder_path):
    """List contents of a specific folder (including nested paths)"""
    try:
        device = validate_device_type(device)
        file_model, audit_model = get_models()
        
        # Validate the folder path more carefully
        path_components = folder_path.split('/')
        sanitized_components = []
        
        for component in path_components:
            if not component or component in ['.', '..']:
                return jsonify({'error': 'Invalid folder path'}), 400
            # Use basic validation instead of secure_filename for paths
            if any(char in component for char in ['<', '>', ':', '"', '|', '?', '*']):
                return jsonify({'error': 'Invalid characters in folder path'}), 400
            sanitized_components.append(component)
        
        # Reconstruct the path
        clean_folder_path = '/'.join(sanitized_components)
        actual_folder_path = current_app.config['BACKUP_BASE_DIR'] / device / clean_folder_path
        
        if not actual_folder_path.exists() or not actual_folder_path.is_dir():
            return jsonify({'error': 'Folder not found'}), 404
        
        # Check if path is within allowed directory (security)
        try:
            actual_folder_path.resolve().relative_to(
                current_app.config['BACKUP_BASE_DIR'].resolve()
            )
        except ValueError:
            return jsonify({'error': 'Invalid folder path'}), 400
        
        contents = {
            'device': device,
            'folder_path': clean_folder_path,
            'folders': [],
            'files': [],
            'breadcrumb': clean_folder_path.split('/'),
            'parent_path': '/'.join(clean_folder_path.split('/')[:-1]) if '/' in clean_folder_path else None
        }
        
        # List directory contents
        try:
            for item in actual_folder_path.iterdir():
                if item.is_file() and not item.name.startswith('.'):
                    # Get file info from database if available
                    db_file = file_model.get_file_by_path(device, clean_folder_path, item.name)
                    
                    if db_file:
                        file_info = {
                            'filename': db_file['filename'],
                            'size': db_file['size'],
                            'mime_type': db_file.get('mime_type'),
                            'created_at': db_file['created_at'].isoformat(),
                            'modified_at': db_file['modified_at'].isoformat(),
                            'sha256': db_file.get('sha256'),
                            'tags': db_file.get('tags', []),
                            'version': db_file.get('version', 1)
                        }
                    else:
                        # File not in database, get basic info
                        stat = item.stat()
                        file_info = {
                            'filename': item.name,
                            'size': stat.st_size,
                            'mime_type': file_model.get_mime_type(item.name),
                            'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'sha256': None,
                            'tags': [],
                            'version': 1,
                            'in_database': False
                        }
                    
                    contents['files'].append(file_info)
                    
                elif item.is_dir():
                    # Get folder info
                    try:
                        stat = item.stat()
                        # Count files in subfolder
                        file_count = 0
                        total_size = 0
                        
                        for subitem in item.iterdir():
                            if subitem.is_file() and not subitem.name.startswith('.'):
                                file_count += 1
                                try:
                                    total_size += subitem.stat().st_size
                                except (OSError, PermissionError):
                                    pass  # Skip files we can't access
                        
                        folder_info = {
                            'name': item.name,
                            'path': f"{clean_folder_path}/{item.name}",
                            'file_count': file_count,
                            'total_size': total_size,
                            'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                        }
                        contents['folders'].append(folder_info)
                    except (OSError, PermissionError):
                        current_app.logger.warning(f"Cannot access folder: {item}")
                        continue
        
        except PermissionError:
            return jsonify({'error': 'Permission denied accessing folder'}), 403
        
        # Sort contents
        contents['folders'].sort(key=lambda x: x['name'])
        contents['files'].sort(key=lambda x: x['filename'])
        
        audit_model.log_action('list_folder_contents', device, clean_folder_path, None, request.remote_addr)
        
        return jsonify(contents)
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error listing folder contents {device}/{folder_path}: {str(e)}")
        return jsonify({'error': 'Failed to list folder contents'}), 500

@api_bp.route('/devices/<device>/folders/<path:folder_path>/files', methods=['POST'])
@limiter.limit("20 per minute")
def upload_file_nested(device, folder_path):
    """Upload a file to a nested folder path"""
    filename = None
    try:
        device = validate_device_type(device)
        file_model, audit_model = get_models()
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = validate_filename(file.filename)
        
        # Validate and clean the folder path
        path_components = folder_path.split('/')
        for component in path_components:
            if not component or component in ['.', '..']:
                return jsonify({'error': 'Invalid folder path'}), 400
            if any(char in component for char in ['<', '>', ':', '"', '|', '?', '*']):
                return jsonify({'error': 'Invalid characters in folder path'}), 400
        
        clean_folder_path = '/'.join(path_components)
        
        # Create nested folder structure if it doesn't exist
        actual_folder_path = current_app.config['BACKUP_BASE_DIR'] / device / clean_folder_path
        actual_folder_path.mkdir(parents=True, exist_ok=True)
        
        filepath = actual_folder_path / filename
        
        # Check if file already exists in database
        existing_file = file_model.get_file_by_path(device, clean_folder_path, filename)
        if existing_file:
            return jsonify({'error': 'File already exists'}), 409
        
        # Save file
        file.save(str(filepath))
        
        # Create database record
        metadata = {
            'client_ip': request.remote_addr,
            'source': 'api_upload',
            'tags': request.form.getlist('tags')
        }
        
        file_id = file_model.create_file_record(device, clean_folder_path, filename, filepath, metadata)
        
        # Get the created file record for response
        file_record = file_model.get_file_by_path(device, clean_folder_path, filename)
        
        audit_model.log_action('upload', device, clean_folder_path, filename, request.remote_addr, True, {
            'file_id': file_id,
            'file_size': file_record['size'],
            'nested_path': clean_folder_path
        })
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'file': {
                'filename': filename,
                'size': file_record['size'],
                'sha256': file_record['sha256'],
                'mime_type': file_record['mime_type'],
                'created_at': file_record['created_at'].isoformat(),
                'folder_path': clean_folder_path
            }
        }), 201
        
    except ValueError as e:
        filename_safe = filename if filename else 'unknown'
        if 'audit_model' in locals():
            audit_model.log_action('upload', device, folder_path, filename_safe, request.remote_addr, False, {'error': str(e)})
        return jsonify({'error': str(e)}), 400
    except RequestEntityTooLarge:
        return jsonify({'error': 'File too large'}), 413
    except Exception as e:
        filename_safe = filename if filename else 'unknown'
        if 'audit_model' in locals():
            audit_model.log_action('upload', device, folder_path, filename_safe, request.remote_addr, False, {'error': str(e)})
        return jsonify({'error': 'Upload failed'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files', methods=['POST'])
@limiter.limit("20 per minute")
def upload_file(device, folder):
    """Upload a file to specified device folder"""
    filename = None
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        file_model, audit_model = get_models()
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = validate_filename(file.filename)
        
        # Create folder structure if it doesn't exist
        folder_path = current_app.config['BACKUP_BASE_DIR'] / device / folder
        folder_path.mkdir(parents=True, exist_ok=True)
        
        filepath = folder_path / filename
        
        # Check if file already exists in database
        existing_file = file_model.get_file_by_path(device, folder, filename)
        if existing_file:
            return jsonify({'error': 'File already exists'}), 409
        
        # Save file
        file.save(str(filepath))
        
        # Create database record
        metadata = {
            'client_ip': request.remote_addr,
            'source': 'api_upload',
            'tags': request.form.getlist('tags')
        }
        
        file_id = file_model.create_file_record(device, folder, filename, filepath, metadata)
        
        # Get the created file record for response
        file_record = file_model.get_file_by_path(device, folder, filename)
        
        audit_model.log_action('upload', device, folder, filename, request.remote_addr, True, {
            'file_id': file_id,
            'file_size': file_record['size']
        })
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'file': {
                'filename': filename,
                'size': file_record['size'],
                'sha256': file_record['sha256'],
                'mime_type': file_record['mime_type'],
                'created_at': file_record['created_at'].isoformat()
            }
        }), 201
        
    except ValueError as e:
        filename_safe = filename if filename else 'unknown'
        if 'audit_model' in locals():
            audit_model.log_action('upload', device, folder, filename_safe, request.remote_addr, False, {'error': str(e)})
        return jsonify({'error': str(e)}), 400
    except RequestEntityTooLarge:
        return jsonify({'error': 'File too large'}), 413
    except Exception as e:
        filename_safe = filename if filename else 'unknown'
        if 'audit_model' in locals():
            audit_model.log_action('upload', device, folder, filename_safe, request.remote_addr, False, {'error': str(e)})
        return jsonify({'error': 'Upload failed'}), 500

@api_bp.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'server': 'local-file-server'
    })

@api_bp.route('/devices/<device>/folders/<path:folder_path>/files/<filename>', methods=['GET'])
def download_file_nested(device, folder_path, filename):
    """Download or view a file from nested folder path"""
    try:
        device = validate_device_type(device)
        
        # Validate and clean the folder path
        path_components = folder_path.split('/')
        sanitized_components = []
        
        for component in path_components:
            if not component or component.strip() == '':
                continue  # Skip empty components
            if component in ['.', '..']:
                return jsonify({'error': 'Invalid folder path'}), 400
            if any(char in component for char in ['<', '>', ':', '"', '|', '?', '*']):
                return jsonify({'error': 'Invalid characters in folder path'}), 400
            sanitized_components.append(component.strip())
        
        if not sanitized_components:
            return jsonify({'error': 'Invalid folder path'}), 400
        
        clean_folder_path = '/'.join(sanitized_components)
        
        # Define actual_folder_path before using it
        actual_folder_path = current_app.config['BACKUP_BASE_DIR'] / device / clean_folder_path
        
        # Check if folder exists
        if not actual_folder_path.exists() or not actual_folder_path.is_dir():
            return jsonify({'error': 'Folder not found'}), 404
        
        # Find the actual filename on disk
        from app.utils.security import find_actual_filename
        actual_filename = find_actual_filename(str(actual_folder_path), filename)
        
        if not actual_filename:
            return jsonify({'error': 'File not found'}), 404
        
        filepath = actual_folder_path / actual_filename
        
        # Security check - ensure file is within allowed directory
        try:
            filepath.resolve().relative_to(current_app.config['BACKUP_BASE_DIR'].resolve())
        except ValueError:
            return jsonify({'error': 'Invalid file path'}), 400
        
        # Serve the file
        return send_file(
            str(filepath),
            as_attachment=request.args.get('download', 'false').lower() == 'true',
            download_name=actual_filename
        )
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error serving file {device}/{folder_path}/{filename}: {str(e)}")
        return jsonify({'error': 'Failed to serve file'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files/<filename>', methods=['GET'])
def download_file_simple(device, folder, filename):
    """Download or view a file from simple folder path"""
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        
        # Find the actual filename on disk
        from app.utils.security import find_actual_filename
        folder_path = current_app.config['BACKUP_BASE_DIR'] / device / folder
        
        # Convert Path to string for find_actual_filename
        actual_filename = find_actual_filename(str(folder_path), filename)
        
        if not actual_filename:
            return jsonify({'error': 'File not found'}), 404
        
        filepath = folder_path / actual_filename
        
        # Security check
        try:
            filepath.resolve().relative_to(current_app.config['BACKUP_BASE_DIR'].resolve())
        except ValueError:
            return jsonify({'error': 'Invalid file path'}), 400
        
        # Serve the file
        return send_file(
            str(filepath),
            as_attachment=request.args.get('download', 'false').lower() == 'true',
            download_name=actual_filename
        )
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error serving file {device}/{folder}/{filename}: {str(e)}")
        return jsonify({'error': 'Failed to serve file'}), 500

# Error handlers
@api_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@api_bp.errorhandler(413)
def file_too_large(error):
    return jsonify({'error': 'File too large'}), 413

@api_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'retry_after': str(e.retry_after)}), 429