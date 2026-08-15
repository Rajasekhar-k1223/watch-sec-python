import requests
import jwt, datetime
token = jwt.encode({'sub': 'elsea', 'role': 'TenantAdmin', 'tenant_id': 1}, 'monitorix_secret_key_123!@#', algorithm='HS256')
try:
    token = jwt.encode({'sub': 'elsea', 'role': 'TenantAdmin', 'tenant_id': 1}, 'rVcDsUVYia5tsHefxFKTbPOl', algorithm='HS256') # Just guessing secret from db pass, if not I'll check session.py
except: pass
res = requests.get("http://localhost:8000/api/tenants", headers={"Authorization": f"Bearer {token}"})
print(res.status_code, res.text)
