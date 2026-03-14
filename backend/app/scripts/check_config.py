import sys # type: ignore
import os # type: ignore

# Add parent path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db.session import settings # type: ignore

print(f"--- Configuration Check ---")
print(f"DATABASE_URL: {settings.DATABASE_URL}")
print(f"MONGO_URL:    {settings.MONGO_URL}")
print(f"-------------------------")
