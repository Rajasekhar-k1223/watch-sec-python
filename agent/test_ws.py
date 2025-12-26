try:
    import aiohttp
    print(f"aiohttp version: {aiohttp.__version__}")
    if hasattr(aiohttp, 'ClientWSTimeout'):
        print("ClientWSTimeout exists")
    else:
        print("ClientWSTimeout MISSING")
except Exception as e:
    print(e)
