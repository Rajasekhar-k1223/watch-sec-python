import requests
import sys

API_URL = 'http://localhost:8000/api'
AGENT_ID = 'EC2AMAZ-KTMF3D1-CD84ED85-ADMINISTRATOR'

def get_token(username, password):
    res = requests.post(f"{API_URL}/auth/login", json={"username": username, "password": password})
    if res.ok:
        return res.json().get("token")
    else:
        print(f"Login failed: {res.text}")
        return None

def trigger_screenshot(token):
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.post(f"{API_URL}/commands/screenshot/{AGENT_ID}", headers=headers)
    if res.ok:
        print("Screenshot triggered successfully")
        print(res.json())
    else:
        print(f"Trigger failed: {res.text}")

if __name__ == "__main__":
    token = get_token("admin", "admin123")
    if token:
        trigger_screenshot(token)
