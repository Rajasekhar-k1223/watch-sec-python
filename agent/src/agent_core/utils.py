import gzip # type: ignore
import json # type: ignore
import base64 # type: ignore

def compress_payload(data: dict) -> dict:
    """
    Compress a dictionary payload using GZIP.
    Returns a dict with {'compressed': True, 'data': <base64_gzip_string>}
    """
    try:
        json_str = json.dumps(data)
        compressed_data = gzip.compress(json_str.encode('utf-8'))
        b64_encoded = base64.b64encode(compressed_data).decode('utf-8')
        
        return {
            'compressed': True,
            'data': b64_encoded
        }
    except Exception as e:
        print(f"Compression failed: {e}")
        return data  # Fallback to original data
