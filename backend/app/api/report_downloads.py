"""
Secure Report Download Endpoint
================================
Files are stored ONCE on the Monitorix backend.
Emails contain a signed download link → users download directly from monitorix.co.in.
No file duplication. No SMTP attachment size limits.
"""

from fastapi import APIRouter, HTTPException # type: ignore
from fastapi.responses import FileResponse # type: ignore
import os # type: ignore
import hmac as hmac_lib # type: ignore
import hashlib # type: ignore
import time # type: ignore

router = APIRouter()


def _get_report_secret() -> str:
    secret = os.getenv("SECRET_KEY")
    if not secret:
        raise RuntimeError("[FATAL] SECRET_KEY environment variable is not set. Report signing key unavailable.")
    return secret


def generate_download_token(filename: str, expires_in_seconds: int = 7 * 24 * 3600) -> str:
    """Generate a signed token for secure file download (valid 7 days by default)."""
    secret = _get_report_secret()
    expiry = int(time.time()) + expires_in_seconds
    message = f"{filename}:{expiry}".encode()
    sig = hmac_lib.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"{expiry}:{sig}"


def verify_download_token(filename: str, token: str) -> bool:
    """Verify token is valid and not expired."""
    try:
        secret = _get_report_secret()
        expiry_str, sig = token.split(":", 1)
        expiry = int(expiry_str)
        if time.time() > expiry:
            return False  # Token expired
        message = f"{filename}:{expiry}".encode()
        expected_sig = hmac_lib.new(secret.encode(), message, hashlib.sha256).hexdigest()
        return hmac_lib.compare_digest(sig, expected_sig)
    except Exception:
        return False


def create_download_url(base_url: str, filename: str, expires_in_seconds: int = 7 * 24 * 3600) -> str:
    """Create a full signed download URL pointing to monitorix.co.in."""
    token = generate_download_token(filename, expires_in_seconds)
    return f"{base_url}/api/reports/download/{filename}?token={token}"


@router.get("/reports/download/{filename}")
async def download_report(filename: str, token: str):
    """
    Serve a report file if the token is valid.
    This endpoint is public (no login needed) but secured by a signed token.
    Token expires after 7 days.
    """
    # Security: Block path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Verify the signed token
    if not verify_download_token(filename, token):
        raise HTTPException(
            status_code=403,
            detail="Download link has expired or is invalid. Please request a new report."
        )

    # Serve the file
    report_path = f"/app/storage/reports/{filename}"
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report file not found on server")

    return FileResponse(
        path=report_path,
        filename=filename,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
