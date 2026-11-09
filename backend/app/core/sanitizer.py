"""
Monitorix Sensitive Data Logging Sanitizer
==========================================
100% Sovereign Monitorix Architecture. Zero external dependencies.

Prevents credential leakage into container stdout, system logs,
and exception handlers. Scrubs passwords, bearer tokens, API keys,
credit cards, and authorization headers.
"""

import re
import json
from typing import Any, Union

SENSITIVE_KEY_PATTERN = re.compile(
    r'(password|token|secret|authorization|key|access_token|refresh_token|api_key|raw_key|credit_card|ssn)',
    re.IGNORECASE
)

CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')

def mask_string(val: str) -> str:
    if not val or len(val) < 6:
        return "[REDACTED]"
    return val[:3] + "••••••••" + val[-2:]

def sanitize_dict_or_list(data: Any) -> Any:
    """Recursively sanitize dict or list data structure"""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_dict_or_list(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_dict_or_list(item) for item in data]
    elif isinstance(data, str):
        # Mask embedded CC or SSN
        masked = CREDIT_CARD_REGEX.sub("••••-••••-••••-••••", data)
        masked = SSN_REGEX.sub("•••-••-••••", masked)
        return masked
    return data

def sanitize_raw_body(body_bytes: bytes) -> str:
    """Safely decode and sanitize a raw HTTP request body for logging"""
    if not body_bytes:
        return "<empty>"
    try:
        decoded = body_bytes.decode('utf-8', errors='ignore')
        # Attempt JSON parse
        parsed = json.loads(decoded)
        sanitized = sanitize_dict_or_list(parsed)
        return json.dumps(sanitized)
    except Exception:
        # Fallback regex masking for non-JSON or form data
        s = body_bytes.decode('utf-8', errors='ignore')
        s = re.sub(r'("(?:password|token|secret|key)"\s*:\s*)"[^"]+"', r'\1"[REDACTED]"', s, flags=re.IGNORECASE)
        s = re.sub(r'((?:password|token|secret|key)=)[^&]+', r'\1[REDACTED]', s, flags=re.IGNORECASE)
        s = CREDIT_CARD_REGEX.sub("••••-••••-••••-••••", s)
        return s
