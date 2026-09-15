import os
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Protected App Key Server")

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

LICENSES = {}


class VerifyRequest(BaseModel):
    license_key: str
    app_id: str
    device_id: str


class CreateKeyRequest(BaseModel):
    days: int = 30
    max_devices: int = 1


@app.get("/")
def health():
    return {
        "ok": True,
        "service": "protected-app-key-server",
        "verify_endpoint": "/verify"
    }


@app.post("/verify")
def verify(body: VerifyRequest):
    license_data = LICENSES.get(body.license_key)

    if not license_data:
        raise HTTPException(
            status_code=403,
            detail="invalid_license"
        )

    if license_data["revoked"]:
        raise HTTPException(
            status_code=403,
            detail="license_revoked"
        )

    if datetime.now(timezone.utc) >= license_data["expires_at"]:
        raise HTTPException(
            status_code=403,
            detail="license_expired"
        )

    devices = license_data["devices"]

    if body.device_id not in devices:
        if len(devices) >= license_data["max_devices"]:
            raise HTTPException(
                status_code=403,
                detail="device_limit_reached"
            )

        devices.add(body.device_id)

    return {
        "ok": True,
        "expires_at": license_data["expires_at"].isoformat()
    }


@app.post("/admin/create-key")
def create_key(
    body: CreateKeyRequest,
    x_admin_secret: str | None = Header(default=None)
):
    if not ADMIN_SECRET:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_SECRET_not_configured"
        )

    if not secrets.compare_digest(
        x_admin_secret or "",
        ADMIN_SECRET
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorised"
        )

    if body.days <= 0:
        raise HTTPException(
            status_code=400,
            detail="invalid_days"
        )

    if body.max_devices <= 0:
        raise HTTPException(
            status_code=400,
            detail="invalid_max_devices"
        )

    raw = os.urandom(32)

    license_key = (
        "ENC-" +
        hashlib.sha256(raw).hexdigest()[:24].upper()
    )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(days=body.days)
    ).replace(microsecond=0)

    LICENSES[license_key] = {
        "expires_at": expires_at,
        "max_devices
