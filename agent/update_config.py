import json
import os

CONFIG_PATH = "config.json"
NEW_URL = "http://192.168.1.10:8000"

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
else:
    print("config.json not found. Creating from example...")
    # Optional: create from example if needed, but user usually has keys
    default_data = {
        "BackendUrl": NEW_URL,
        "TenantApiKey": "YOUR_KEY_HERE",
        "AgentId": "YOUR_ID_HERE"
    }
    with open(CONFIG_PATH, 'w') as f:
        json.dump(default_data, f, indent=4)
    print("Created new config.json")
