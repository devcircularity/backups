# app/routes/api.py
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.exceptions import RequestEntityTooLarge
from app.utils.security import require_auth, sanitize_path, validate_device_type, validate_filename
from app.models.file_model import FileModel
from app.models.audit_model import AuditModel
from app import limiter
import os
from pathlib import Path

api_bp = Blueprint('api', __name__)

def get_models():
    """Get model instances"""
    file_model = FileModel(current_app.db)
    audit_model = AuditModel(current_app.db)
    return file_model, audit_model

@api_bp.route('/devices')
@require_auth
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
@require_auth
def list_folders(device):
    """List folders for a specific device"""
    try:
        device = validate_device_type(device)
        file_model, audit_model = get_models()
        
        device_path = current_app.config['BACKUP_BASE_DIR'] / device
        
        if not device_path.exists():
            return jsonify({'error': f'Device type {device} not found'}), 404
        
        folders = []
        for folder_path in device_path.iterdir():
            if folder_path.is_dir():
                files = file_model.get_files_by_device(device, folder_path.name)
                total_size = sum(f.get('size', 0) for f in files)
                
                folders.append({
                    'name': folder_path.name,
                    'file_count': len(files),
                    'total_size': total_size,
                    'last_modified': max([f.get('modified_at') for f in files], default=None)
                })
        
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

@api_bp.route('/devices/<device>/folders/<folder>/files')
@require_auth
def list_files(device, folder):
    """List files in a specific device folder"""
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        file_model, audit_model = get_models()
        
        files = file_model.get_files_by_device(device, folder)
        
        # Convert MongoDB documents to JSON-serializable format
        file_list = []
        for file_doc in files:
            file_info = {
                'filename': file_doc['filename'],
                'size': file_doc['size'],
                'mime_type': file_doc.get('mime_type'),
                'created_at': file_doc['created_at'].isoformat(),
                'modified_at': file_doc['modified_at'].isoformat(),
                'sha256': file_doc.get('sha256'),
                'tags': file_doc.get('tags', []),
                'version': file_doc.get('version', 1)
            }
            file_list.append(file_info)
        
        audit_model.log_action('list_files', device, folder, None, request.remote_addr)
        
        return jsonify({
            'device': device,
            'folder': folder,
            'files': file_list,
            'total_files': len(file_list)
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error listing files in {device}/{folder}: {str(e)}")
        return jsonify({'error': 'Failed to list files'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def upload_file(device, folder):
    """Upload a file to specified device folder"""
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
            'tags': request.form.getlist('tags')  # Optional tags from form
        }
        
        file_id = file_model.create_file_record(device, folder, filename, filepath, metadata)
        
        # Get the created file record for response
        file_record = file_model.get_file_by_path(device, folder, filename)
        
        audit_model.log_action('upload', device, folder, filename, request.remote_addr, True, {
            'file_id': file_id,
            'file_size': file_record['size']
        })
        
        current_app.logger.info(f"File uploaded: {device}/{folder}/{filename}")
        
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
        audit_model.log_action('upload', device, folder, filename, request.remote_addr, False, {'error': str(e)})
        return jsonify({'error': str(e)}), 400
    except RequestEntityTooLarge:
        return jsonify({'error': 'File too large'}), 413
    except Exception as e:
        current_app.logger.error(f"Error uploading file: {str(e)}")
        audit_model.log_action('upload', device, folder, filename, request.remote_addr, False, {'error': str(e)})
        return jsonify({'error': 'Upload failed'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files/<filename>')
@require_auth
def download_file(device, folder, filename):
    """Download a specific file"""
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        filename = sanitize_path(filename)
        file_model, audit_model = get_models()
        
        # Check if file exists in database
        file_record = file_model.get_file_by_path(device, folder, filename)
        if not file_record:
            return jsonify({'error': 'File not found in database'}), 404
        
        filepath = Path(file_record['file_path'])
        
        if not filepath.exists():
            current_app.logger.warning(f"File exists in DB but not on disk: {filepath}")
            return jsonify({'error': 'File not found on disk'}), 404
        
        audit_model.log_action('download', device, folder, filename, request.remote_addr)
        
        return send_file(str(filepath), as_attachment=True)
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error downloading file {device}/{folder}/{filename}: {str(e)}")
        return jsonify({'error': 'Download failed'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files/<filename>', methods=['DELETE'])
@require_auth
def delete_file(device, folder, filename):
    """Delete a specific file"""
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        filename = sanitize_path(filename)
        file_model, audit_model = get_models()
        
        # Check if file exists in database
        file_record = file_model.get_file_by_path(device, folder, filename)
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        # Remove physical file
        filepath = Path(file_record['file_path'])
        if filepath.exists():
            filepath.unlink()
        
        # Mark as deleted in database (soft delete)
        file_model.mark_file_deleted(device, folder, filename)
        
        audit_model.log_action('delete', device, folder, filename, request.remote_addr)
        
        current_app.logger.info(f"File deleted: {device}/{folder}/{filename}")
        
        return jsonify({'message': 'File deleted successfully'})
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error deleting file {device}/{folder}/{filename}: {str(e)}")
        return jsonify({'error': 'Delete failed'}), 500

@api_bp.route('/devices/<device>/folders', methods=['POST'])
@require_auth
def create_folder(device):
    """Create a new folder"""
    try:
        device = validate_device_type(device)
        audit_model = get_models()[1]
        
        data = request.get_json()
        if not data or 'folder_name' not in data:
            return jsonify({'error': 'folder_name required in request body'}), 400
        
        folder = sanitize_path(data['folder_name'])
        
        folder_path = current_app.config['BACKUP_BASE_DIR'] / device / folder
        
        if folder_path.exists():
            return jsonify({'error': 'Folder already exists'}), 409
        
        folder_path.mkdir(parents=True, exist_ok=True)
        
        audit_model.log_action('create_folder', device, folder, '', request.remote_addr)
        
        current_app.logger.info(f"Folder created: {device}/{folder}")
        
        return jsonify({
            'message': 'Folder created successfully',
            'path': f"{device}/{folder}"
        }), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error creating folder {device}/{folder}: {str(e)}")
        return jsonify({'error': 'Failed to create folder'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files/<filename>/checksum')
@require_auth
def get_checksum(device, folder, filename):
    """Get file checksum for integrity verification"""
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        filename = sanitize_path(filename)
        file_model = get_models()[0]
        
        file_record = file_model.get_file_by_path(device, folder, filename)
        if not file_record:
            return jsonify({'error': 'File not found'}), 404
        
        algorithm = request.args.get('algorithm', 'sha256').lower()
        if algorithm not in ['md5', 'sha256']:
            return jsonify({'error': 'Invalid algorithm. Use md5 or sha256'}), 400
        
        checksum = file_record.get(algorithm)
        if not checksum:
            return jsonify({'error': f'{algorithm} checksum not available'}), 404
        
        return jsonify({
            'filename': filename,
            'algorithm': algorithm,
            'checksum': checksum,
            'size': file_record['size']
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error getting checksum: {str(e)}")
        return jsonify({'error': 'Checksum retrieval failed'}), 500

@api_bp.route('/devices/<device>/folders/<folder>/files/<filename>/verify', methods=['POST'])
@require_auth
def verify_file(device, folder, filename):
    """Verify file integrity against provided checksum"""
    try:
        device = validate_device_type(device)
        folder = sanitize_path(folder)
        filename = sanitize_path(filename)
        file_model = get_models()[0]
        
        data = request.get_json()
        if not data or 'checksum' not in data:
            return jsonify({'error': 'Checksum required in request body'}), 400
        
        expected_checksum = data['checksum']
        algorithm = data.get('algorithm', 'sha256').lower()
        
        if algorithm not in ['md5', 'sha256']:
            return jsonify({'error': 'Invalid algorithm. Use md5 or sha256'}), 400
        
        result = file_model.verify_file_integrity(device, folder, filename, expected_checksum, algorithm)
        
        return jsonify({
            'filename': filename,
            'algorithm': algorithm,
            'verification_result': result
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error verifying file: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500

@api_bp.route('/search')
@require_auth
def search_files():
    """Search files across all devices or specific device/folder"""
    try:
        query = request.args.get('q', '').strip()
        if not query:
            return jsonify({'error': 'Search query (q) is required'}), 400
        
        device = request.args.get('device')
        folder = request.args.get('folder')
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 results
        
        if device:
            device = validate_device_type(device)
        if folder:
            folder = sanitize_path(folder)
        
        file_model, audit_model = get_models()
        
        results = file_model.search_files(query, device, folder, limit)
        
        # Convert to JSON-serializable format
        search_results = []
        for file_doc in results:
            search_results.append({
                'device': file_doc['device'],
                'folder': file_doc['folder'],
                'filename': file_doc['filename'],
                'size': file_doc['size'],
                'mime_type': file_doc.get('mime_type'),
                'created_at': file_doc['created_at'].isoformat(),
                'tags': file_doc.get('tags', [])
            })
        
        audit_model.log_action('search', device, folder, None, request.remote_addr, True, {
            'query': query,
            'results_count': len(search_results)
        })
        
        return jsonify({
            'query': query,
            'results': search_results,
            'total_results': len(search_results),
            'search_filters': {
                'device': device,
                'folder': folder,
                'limit': limit
            }
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error searching files: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@api_bp.route('/audit/logs')
@require_auth
def get_audit_logs():
    """Get recent audit log entries"""
    try:
        limit = min(int(request.args.get('limit', 100)), 500)  # Max 500 entries
        device = request.args.get('device')
        action = request.args.get('action')
        
        if device:
            device = validate_device_type(device)
        
        audit_model = get_models()[1]
        logs = audit_model.get_recent_actions(limit, device, action)
        
        # Convert to JSON-serializable format
        log_entries = []
        for log in logs:
            log_entries.append({
                'timestamp': log['timestamp'].isoformat(),
                'action': log['action'],
                'device': log['device'],
                'folder': log['folder'],
                'filename': log['filename'],
                'client_ip': log['client_ip'],
                'success': log['success'],
                'details': log.get('details', {})
            })
        
        return jsonify({
            'logs': log_entries,
            'total_entries': len(log_entries),
            'filters': {
                'device': device,
                'action': action,
                'limit': limit
            }
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.error(f"Error retrieving audit logs: {str(e)}")
        return jsonify({'error': 'Failed to retrieve audit logs'}), 500

@api_bp.route('/stats')
@require_auth
def get_statistics():
    """Get comprehensive backup statistics"""
    try:
        file_model, audit_model = get_models()
        
        # Get device statistics
        device_stats = {}
        total_files = 0
        total_size = 0
        
        for device in ['laptop', 'mobile', 'server']:
            stats = file_model.get_device_stats(device)
            device_stats[device] = stats
            total_files += stats.get('total_files', 0)
            total_size += stats.get('total_size', 0)
        
        # Get recent activity stats (last 7 days)
        activity_stats = audit_model.get_action_stats(days=7)
        
        return jsonify({
            'overview': {
                'total_files': total_files,
                'total_size': total_size,
                'total_size_gb': round(total_size / (1024**3), 2)
            },
            'by_device': device_stats,
            'recent_activity': activity_stats,
            'generated_at': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error generating statistics: {str(e)}")
        return jsonify({'error': 'Failed to generate statistics'}), 500

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
