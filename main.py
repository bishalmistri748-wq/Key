import os
import hashlib
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Protected App Key Server")

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

# Temporary in-memory licenses
# Railway restart hone par ye reset ho jayenge.
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
    lic = LICENSES.get(body.license_key)

    if not lic:
        raise HTTPException(status_code=403, detail="invalid_license")

    if lic["revoked"]:
        raise HTTPException(status_code=403, detail="license_revoked")

    if datetime.now(timezone.utc) >= lic["expires_at"]:
        raise HTTPException(status_code=403, detail="license_expired")

    devices = lic["devices"]

    if body.device_id not in devices:
        if len(devices) >= lic["max_devices"]:
            raise HTTPException(
                status_code=403,
                detail="device_limit_reached"
            )
        devices.add(body.device_id)

    return {
        "ok": True,
        "expires_at": lic["expires_at"].isoformat()
    }


@app.post("/admin/create-key")
def create_key(
    body: CreateKeyRequest,
    x_admin_secret: str | None = None
):
    if not ADMIN_SECRET or x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorised")

    if body.days <= 0:
        raise HTTPException(status_code=400, detail="invalid_days")

    if body.max_devices <= 0:
        raise HTTPException(status_code=400, detail="invalid_max_devices")

    raw = os.urandom(18)
    key = "ENC-" + hashlib.sha256(raw).hexdigest()[:24].upper()

    expires = datetime.now(timezone.utc).replace(
        microsecond=0
    )

    from datetime import timedelta
    expires += timedelta(days=body.days)

    LICENSES[key] = {
        "expires_at": expires,
        "max_devices": body.max_devices,
        "devices": set(),
        "revoked": False
    }

    return {
        "ok": True,
        "license_key": key,
        "expires_at": expires.isoformat(),
        "max_devices": body.max_devices
    }


@app.post("/admin/revoke/{license_key}")
def revoke(
    license_key: str,
    x_admin_secret: str | None = None
):
    if not ADMIN_SECRET or x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="unauthorised")

    if license_key not in LICENSES:
        raise HTTPException(status_code=404, detail="license_not_found")

    LICENSES[license_key]["revoked"] = True

    return {
        "ok": True,
        "license_key": license_key,
        "revoked": True
    }
