import requests
resp = requests.post("http://127.0.0.1:8000/api/events/report", json={"AgentId": "TEST-AGENT-1234", "Type": "Test", "Details": "Test", "Timestamp": "2026-05-21T03:40:00Z", "TenantApiKey": "test"})
print(resp.status_code, resp.text)
