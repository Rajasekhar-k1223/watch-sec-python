import sys
import os

# Add parent path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db.session import settings

print(f"--- Configuration Check ---")
print(f"DATABASE_URL: {settings.DATABASE_URL}")
print(f"MONGO_URL:    {settings.MONGO_URL}")
print(f"-------------------------")
