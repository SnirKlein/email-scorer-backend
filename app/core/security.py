import hmac
import hashlib
from fastapi import Request, HTTPException, Depends
from app.core.config import settings


async def verify_addon_signature(request: Request) -> None:
    """
    Verify the request comes from our Gmail Add-on using HMAC-SHA256.
    The Add-on signs the request body with the shared secret and sends
    the signature in the X-Addon-Signature header.
    """
    signature_header = request.headers.get("X-Addon-Signature")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header")

    body = await request.body()
    expected = hmac.new(
        settings.addon_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(f"sha256={expected}", signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")