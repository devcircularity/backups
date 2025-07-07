import os
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Note: python-dotenv not installed. Using environment variables only.")

def check_permissions():
    """Check if we have necessary permissions"""
    backup_dir = os.environ.get('BACKUP_BASE_DIR', './backups')
    
    # Check if we can create the backup directory
    try:
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        print(f"✅ Backup directory accessible: {backup_dir}")
        return True
    except PermissionError:
        print(f"⚠️  Cannot access {backup_dir}, will use alternative location")
        return False

def main():
    print("🚀 Starting Eric's Backup Management API...")
    
    # Check permissions
    check_permissions()
    
    # Import and create app
    try:
        from app import create_app
        app = create_app()
    except Exception as e:
        print(f"❌ Failed to create Flask app: {e}")
        sys.exit(1)
    
    # Get configuration
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('PORT', 5001))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"📊 Configuration:")
    print(f"   - Host: {host}")
    print(f"   - Port: {port}")
    print(f"   - Debug: {debug_mode}")
    print(f"   - Backup directory: {app.config['BACKUP_BASE_DIR']}")
    print(f"   - MongoDB: {'Connected' if app.db is not None else 'Not connected'}")
    print(f"\n🌐 API will be available at: http://{host}:{port}")
    print(f"🔍 Health check: http://{host}:{port}/health")
    print(f"📚 API docs: http://{host}:{port}/api/v1/devices")
    
    if not debug_mode:
        print("\n⚠️  Running in production mode. Set FLASK_ENV=development for debug mode.")
    
    print("\n" + "="*50)
    
    try:
        app.run(host=host, port=port, debug=debug_mode)
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()