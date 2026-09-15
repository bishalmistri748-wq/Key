import os, hmac, hashlib, secrets
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Protected App Key Server")

SERVER_SECRET = os.environ.get("SERVER_SECRET")
if not SERVER_SECRET:
    raise RuntimeError("SERVER_SECRET is not configured")

ALLOWED_CLIENTS = {
    x.strip() for x in os.environ.get("ALLOWED_CLIENTS", "").split(",") if x.strip()
}

class AuthRequest(BaseModel):
    client_id: str

@app.get("/")
def health():
    return {"ok": True, "service": "protected-app-key-server"}

@app.post("/authorise")
def authorise(body: AuthRequest, x_server_auth: str | None = Header(default=None)):
    expected = hashlib.sha256(SERVER_SECRET.encode()).hexdigest()
    if not hmac.compare_digest(x_server_auth or "", expected):
        raise HTTPException(status_code=401, detail="unauthorised")

    if ALLOWED_CLIENTS and body.client_id not in ALLOWED_CLIENTS:
        raise HTTPException(status_code=403, detail="client_not_authorised")

    return {
        "ok": True,
        "session_token": secrets.token_urlsafe(32),
        "expires_in": 300
    }
