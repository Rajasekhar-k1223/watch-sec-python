import re
import os

class PrivacyRedactor:
    """
    Utility class for redacting sensitive information from logs and metadata.
    [v1.8.38] Stealth Protocol Edition
    """
    
    # Pre-compiled regex patterns for performance
    PATTERNS = {
        'ipv4': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'api_key': re.compile(r'(?i)(?:key|password|secret|token|auth)["\s:=]+([a-zA-Z0-9_\-\.]{12,})'),
        'windows_path': re.compile(r'\b[a-zA-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*\b'),
        'unix_path': re.compile(r'\b/(?:[^/\0 ]+/)*[^/\0 ]*\b')
    }

    @staticmethod
    def redact_text(text: str) -> str:
        """
        Redacts sensitive data from a given string.
        """
        if not text or not isinstance(text, str):
            return text
            
        redacted = text
        
        # 1. Redact Emails
        redacted = PrivacyRedactor.PATTERNS['email'].sub("[REDACTED_EMAIL]", redacted)
        
        # 2. Redact IP Addresses (Excluding localhost and common private ranges optionally?)
        # For now, redact all for maximum privacy.
        redacted = PrivacyRedactor.PATTERNS['ipv4'].sub("[REDACTED_IP]", redacted)
        
        # 3. Redact Sensitive Keys (keeping the label but hiding the value)
        def redact_key_match(match):
            full_match = match.group(0)
            secret_value = match.group(1)
            return full_match.replace(secret_value, "********")
            
        redacted = PrivacyRedactor.PATTERNS['api_key'].sub(redact_key_match, redacted)
        
        # 4. Redact User Paths (privacy)
        # We only redact paths that look like they contain a username (e.g. C:\Users\John\...)
        if "Users" in redacted or "/home/" in redacted:
            redacted = PrivacyRedactor.PATTERNS['windows_path'].sub("[REDACTED_PATH]", redacted)
            redacted = PrivacyRedactor.PATTERNS['unix_path'].sub("[REDACTED_PATH]", redacted)

        return redacted

    @staticmethod
    def redact_dict(data: dict) -> dict:
        """
        Recursively redacts sensitive data in a dictionary.
        """
        if not isinstance(data, dict):
            return data
            
        new_data = {}
        for k, v in data.items():
            if isinstance(v, str):
                new_data[k] = PrivacyRedactor.redact_text(v)
            elif isinstance(v, dict):
                new_data[k] = PrivacyRedactor.redact_dict(v)
            elif isinstance(v, list):
                new_data[k] = [PrivacyRedactor.redact_text(i) if isinstance(i, str) else i for i in v]
            else:
                new_data[k] = v
        return new_data
