import sys
import os

# Add the current directory to sys.path to allow imports like 'app.db.session'
sys.path.append(os.getcwd())

try:
    from app.db.session import settings
    print(f"SUCCESS: Settings loaded.")
    print(f"DATABASE_URL={settings.DATABASE_URL}")
    print(f"MONGO_URL={settings.MONGO_URL}")
    print(f"BACKEND_CORS_ORIGINS={settings.BACKEND_CORS_ORIGINS}")
except Exception as e:
    print(f"FAILURE: {e}")
    sys.exit(1)
