import re
path = "/app/app/api/downloads.py"
with open(path, "r") as f:
    content = f.read()

# Replace "async def download_public_agent(..."
original = "async def download_public_agent("
new = """
import traceback
async def download_public_agent(
"""
if "import traceback" not in content:
    content = content.replace(original, new)

# Find the end of the function and replace return
content = content.replace("    return Response(content=full_script, media_type=\"text/plain\")",
"""    except Exception as e:
        err = traceback.format_exc()
        print("ENDPOINT CRASHED:", err)
        with open("/tmp/500_error.txt", "w") as f:
            f.write(err)
        return Response(content=err, media_type="text/plain", status_code=500)
    return Response(content=full_script, media_type="text/plain")
""")

content = content.replace("    backend_url = _get_backend_url(request)",
"""    try:
        backend_url = _get_backend_url(request)""")

with open(path, "w") as f:
    f.write(content)
