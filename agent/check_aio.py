import aiohttp
import sys
print(f"Python: {sys.version}")
print(f"Aiohttp Version: {aiohttp.__version__}")
try:
    print(f"ClientWSTimeout: {aiohttp.ClientWSTimeout}")
except AttributeError:
    print("ClientWSTimeout NOT FOUND")
