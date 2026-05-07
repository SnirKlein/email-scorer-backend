import hmac
import hashlib
import json
from fastapi import Request, HTTPException

# Shared secret for HMAC signing.
SHARED_SECRET = "change-me-in-production"

async def verify_addon_signature(request: Request):
    header_sig = request.headers.get("X-Addon-Signature")
    if not header_sig:
        raise HTTPException(status_code=401, detail="Missing signature header")

    # Read the raw body and extract the stable fields
    raw_body = await request.body()
    try:
        payload = json.loads(raw_body)
        message_id = payload.get("message_id", "")
        date = payload.get("date", "")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Reconstruct the exact same stable string from the Apps Script
    stable_string_to_sign = f"{message_id}|{date}"

    # Calculate our own HMAC
    expected_hash = hmac.new(
        SHARED_SECRET.encode('utf-8'),
        stable_string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    received_hash = header_sig.replace("sha256=", "")

    if not hmac.compare_digest(expected_hash, received_hash):
        raise HTTPException(status_code=401, detail="Signature verification failed")