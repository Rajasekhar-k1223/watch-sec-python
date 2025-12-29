from app.core.celery_app import celery_app
from pymongo import MongoClient
import os
from bson.objectid import ObjectId

# DB Config (Sync for Celery Worker)
# Ensure this matches your docker-compose or .env
MONGO_URL = os.getenv("MONGO_URL", "mongodb://mongo:taOtHmJnOLgnMorrtJpDZLmozClPXmOq@crossover.proxy.rlwy.net:30926")

def get_sync_db():
    client = MongoClient(MONGO_URL)
    return client["watchsec"]

@celery_app.task
def analyze_risk_background(log_id_str: str, title: str, process: str, url: str):
    """
    Background Task to analyze risk and update the MongoDB record.
    """
    print(f"[Celery] Analyzing Risk for Log: {log_id_str}")
    
    score = 0
    level = "Normal"
    
    # Text to scan
    text = (f"{title} {process} {url}").lower()
    
    # High Risk Keywords
    high_risk = ["terminal", "powershell", "cmd", "nmap", "wireshark", "tor browser", "metasploit"]
    if any(k in text for k in high_risk):
        score = 80
        level = "High"
    
    # Productivity Analysis
    unproductive = ["youtube", "facebook", "netflix", "instagram", "tiktok", "steam"]
    if any(k in text for k in unproductive):
        score = 10
        level = "Unproductive"

    # Update DB
    try:
        db = get_sync_db()
        collection = db["activity"]
        result = collection.update_one(
            {"_id": ObjectId(log_id_str)},
            {"$set": {"RiskScore": score, "RiskLevel": level}}
        )
        print(f"[Celery] Updated Log {log_id_str}: Score={score}, Level={level} (Matches: {result.modified_count})")
        return {"id": log_id_str, "score": score, "level": level}
    except Exception as e:
        print(f"[Celery] Error updating DB: {e}")
        raise e
