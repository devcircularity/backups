# app/models/file_model.py
from datetime import datetime
from bson import ObjectId
import hashlib
from pathlib import Path

class FileModel:
    def __init__(self, db):
        self.db = db
        self.collection = db.files if db is not None else None
    
    def create_file_record(self, device, folder, filename, filepath, metadata=None):
        """Create a new file record in MongoDB"""
        if self.collection is None:
            return None
            
        file_stats = Path(filepath).stat()
        
        file_record = {
            'device': device,
            'folder': folder,
            'filename': filename,
            'file_path': str(filepath),
            'size': file_stats.st_size,
            'sha256': self.calculate_file_hash(filepath),
            'md5': self.calculate_file_hash(filepath, 'md5'),
            'mime_type': self.get_mime_type(filename),
            'created_at': datetime.utcnow(),
            'modified_at': datetime.fromtimestamp(file_stats.st_mtime),
            'uploaded_by': metadata.get('client_ip') if metadata else None,
            'upload_source': metadata.get('source', 'api') if metadata else 'api',
            'tags': metadata.get('tags', []) if metadata else [],
            'is_deleted': False,
            'version': 1
        }
        
        result = self.collection.insert_one(file_record)
        return str(result.inserted_id)
    
    def get_file_by_path(self, device, folder, filename):
        """Get file record by device/folder/filename path"""
        if self.collection is None:
            return None
            
        return self.collection.find_one({
            'device': device,
            'folder': folder,
            'filename': filename,
            'is_deleted': False
        })
    
    def get_files_by_device(self, device, folder=None):
        """Get all files for a device, optionally filtered by folder"""
        if self.collection is None:
            return []
            
        query = {'device': device, 'is_deleted': False}
        if folder:
            query['folder'] = folder
            
        return list(self.collection.find(query).sort('created_at', -1))
    
    def update_file_metadata(self, device, folder, filename, updates):
        """Update file metadata"""
        if self.collection is None:
            return False
            
        result = self.collection.update_one(
            {'device': device, 'folder': folder, 'filename': filename, 'is_deleted': False},
            {'$set': {**updates, 'updated_at': datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    def mark_file_deleted(self, device, folder, filename):
        """Mark file as deleted (soft delete)"""
        if self.collection is None:
            return False
            
        result = self.collection.update_one(
            {'device': device, 'folder': folder, 'filename': filename, 'is_deleted': False},
            {'$set': {'is_deleted': True, 'deleted_at': datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    def get_device_stats(self, device):
        """Get statistics for a device"""
        if self.collection is None:
            return {'total_files': 0, 'total_size': 0}
            
        pipeline = [
            {'$match': {'device': device, 'is_deleted': False}},
            {'$group': {
                '_id': None,
                'total_files': {'$sum': 1},
                'total_size': {'$sum': '$size'},
                'folders': {'$addToSet': '$folder'}
            }}
        ]
        
        result = list(self.collection.aggregate(pipeline))
        if result:
            stats = result[0]
            stats['folder_count'] = len(stats.get('folders', []))
            del stats['_id']
            return stats
        
        return {'total_files': 0, 'total_size': 0, 'folder_count': 0}
    
    def search_files(self, query, device=None, folder=None, limit=50):
        """Search files by filename or metadata"""
        if self.collection is None:
            return []
            
        search_filter = {
            'is_deleted': False,
            '$or': [
                {'filename': {'$regex': query, '$options': 'i'}},
                {'tags': {'$regex': query, '$options': 'i'}}
            ]
        }
        
        if device:
            search_filter['device'] = device
        if folder:
            search_filter['folder'] = folder
            
        return list(self.collection.find(search_filter).limit(limit).sort('created_at', -1))
    
    def verify_file_integrity(self, device, folder, filename, expected_hash, algorithm='sha256'):
        """Verify file integrity against stored hash"""
        file_record = self.get_file_by_path(device, folder, filename)
        if not file_record:
            return {'exists': False}
            
        stored_hash = file_record.get(algorithm)
        if not stored_hash:
            return {'exists': True, 'hash_available': False}
            
        return {
            'exists': True,
            'hash_available': True,
            'valid': stored_hash == expected_hash,
            'stored_hash': stored_hash,
            'expected_hash': expected_hash
        }
    
    @staticmethod
    def calculate_file_hash(filepath, algorithm='sha256'):
        """Calculate file hash"""
        hash_algo = hashlib.new(algorithm)
        
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_algo.update(chunk)
            return hash_algo.hexdigest()
        except Exception:
            return None
    
    @staticmethod
    def get_mime_type(filename):
        """Get MIME type based on file extension"""
        ext = Path(filename).suffix.lower()
        mime_types = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.zip': 'application/zip',
            '.tar': 'application/x-tar',
            '.gz': 'application/gzip',
            '.mp3': 'audio/mpeg',
            '.mp4': 'video/mp4',
            '.mov': 'video/quicktime',
            '.avi': 'video/x-msvideo',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.csv': 'text/csv'
        }
        return mime_types.get(ext, 'application/octet-stream')