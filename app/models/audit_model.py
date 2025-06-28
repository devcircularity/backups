# app/models/audit_model.py
from datetime import datetime

class AuditModel:
    def __init__(self, db):
        self.db = db
        self.collection = db.audit_logs if db else None
    
    def log_action(self, action, device, folder, filename, client_ip, success=True, details=None):
        """Log an API action"""
        if not self.collection:
            return None
            
        log_entry = {
            'timestamp': datetime.utcnow(),
            'action': action,
            'device': device,
            'folder': folder,
            'filename': filename,
            'client_ip': client_ip,
            'success': success,
            'details': details or {},
            'session_id': None  # Can be added later for session tracking
        }
        
        result = self.collection.insert_one(log_entry)
        return str(result.inserted_id)
    
    def get_recent_actions(self, limit=100, device=None, action=None):
        """Get recent audit log entries"""
        if not self.collection:
            return []
            
        query = {}
        if device:
            query['device'] = device
        if action:
            query['action'] = action
            
        return list(self.collection.find(query).sort('timestamp', -1).limit(limit))
    
    def get_action_stats(self, device=None, days=7):
        """Get statistics for actions in the last N days"""
        if not self.collection:
            return {}
            
        from_date = datetime.utcnow() - datetime.timedelta(days=days)
        
        pipeline = [
            {'$match': {
                'timestamp': {'$gte': from_date},
                **({'device': device} if device else {})
            }},
            {'$group': {
                '_id': '$action',
                'count': {'$sum': 1},
                'success_count': {'$sum': {'$cond': ['$success', 1, 0]}},
                'failure_count': {'$sum': {'$cond': ['$success', 0, 1]}}
            }}
        ]
        
        results = list(self.collection.aggregate(pipeline))
        return {item['_id']: item for item in results}
