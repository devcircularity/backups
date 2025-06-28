import os
from app import create_app

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = create_app()

if __name__ == '__main__':
    # Development server
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"Starting Eric's Backup Management API on {host}:{port}")
    print(f"Debug mode: {debug_mode}")
    print(f"Backup directory: {app.config['BACKUP_BASE_DIR']}")
    
    app.run(host=host, port=port, debug=debug_mode)
