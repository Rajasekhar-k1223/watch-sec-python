import asyncio
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)
res = client.get("/api/tenants")
print(res.status_code, res.text)
