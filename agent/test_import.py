try:
    import aiohttp
    print("aiohttp is importable")
except ImportError as e:
    print(f"ImportError: {e}")
