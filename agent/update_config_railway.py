import json
import os

CONFIG_PATH = "config.json"
NEW_URL = "https://watch-sec-python.up.railway.app"

if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, 'r') as f:
            data = json.load(f)
        
        print(f"Current Config: {data}")
        
        if data.get("BackendUrl") != NEW_URL:
            print(f"Updating BackendUrl to {NEW_URL}")
            data["BackendUrl"] = NEW_URL
            
            with open(CONFIG_PATH, 'w') as f:
                json.dump(data, f, indent=4)
            print("Update Complete.")
        else:
            print("BackendUrl already set correctly.")
            
    except Exception as e:
        print(f"Error reading/writing config: {e}")
