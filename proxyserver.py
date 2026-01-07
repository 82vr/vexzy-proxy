import os
import time
from typing import Dict, Any, List, Tuple, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Vexzy Proxy", version="1.2.0")


OATHNET_API_KEY = os.getenv("OATHNET_API_KEY")
APP_LICENSE_KEYS = os.getenv("APP_LICENSE_KEYS", "")


OATHNET_BASE_URL = os.getenv("OATHNET_BASE_URL", "https://oathnet.org/api/service")


WINDOW_SECONDS = int(os.getenv("RL_WINDOW_SECONDS", "60"))
MAX_REQUESTS = int(os.getenv("RL_MAX_REQUESTS", "30"))

if not OATHNET_API_KEY:
    raise RuntimeError("Missing OATHNET_API_KEY environment variable.")

LICENSE_SET = {k.strip() for k in APP_LICENSE_KEYS.split(",") if k.strip()}
if not LICENSE_SET:
    raise RuntimeError("Missing APP_LICENSE_KEYS environment variable (must contain at least 1 license key).")

BLACKLIST_USERS = {u.strip().lower() for u in os.getenv("BLACKLIST_USERS", "").split(",") if u.strip()}
BLACKLIST_LICENSES = {k.strip() for k in os.getenv("BLACKLIST_LICENSES", "").split(",") if k.strip()}

_raw_pairs = [p.strip() for p in os.getenv("BLACKLIST_PAIRS", "").split(",") if p.strip()]
BLACKLIST_PAIRS = set()
for p in _raw_pairs:
    if ":" in p:
        lic, usr = p.split(":", 1)
        BLACKLIST_PAIRS.add((lic.strip(), usr.strip().lower()))


ALLOWLIST = {
    "/steam/",
    "/search/status/<uuid:search_id>/",
    "/search-stealer/",
    "/search-breach/",
    "/extract-subdomain/",
    "/ip-info/",
    "/holehe/",
    "/ghunt/",
    "/roblox-userinfo/",
    "/discord-to-roblox/",
    "/xbox/",
    "/mc-history/",
    "/discord-userinfo/",
    "/discord-username-history/",
}


_rate: Dict[Tuple[str, str], List[float]] = {}


def _check_auth(x_license: str, x_user: str) -> Tuple[str, str]:
    
    if not x_license or x_license not in LICENSE_SET:
        raise HTTPException(status_code=401, detail="Invalid or missing license")

    if x_license in BLACKLIST_LICENSES:
        raise HTTPException(status_code=403, detail="License is blacklisted")

    if not x_user:
        raise HTTPException(status_code=401, detail="Missing username")

    x_user = x_user.strip()

    if len(x_user) < 3 or len(x_user) > 24:
        raise HTTPException(status_code=401, detail="Username must be 3–24 characters")

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if any(c not in allowed for c in x_user):
        raise HTTPException(
            status_code=401,
            detail="Username contains invalid characters (use a-z A-Z 0-9 . _ -)",
        )

    if x_user.lower() in BLACKLIST_USERS:
        raise HTTPException(status_code=403, detail="User is blacklisted")

    if (x_license, x_user.lower()) in BLACKLIST_PAIRS:
        raise HTTPException(status_code=403, detail="User is blacklisted for this license")

    return x_license, x_user


def _rate_limit(license_key: str, user: str) -> None:
    now = time.time()
    key = (license_key, user.lower())
    timestamps = _rate.get(key, [])
    timestamps = [t for t in timestamps if (now - t) < WINDOW_SECONDS]
    if len(timestamps) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    timestamps.append(now)
    _rate[key] = timestamps


def _log_request(license_key: str, user: str, endpoint: str, client_ip: Optional[str]) -> None:
    print(f"[VEXZY] user={user} lic={license_key} ip={client_ip} endpoint={endpoint}")


@app.get("/")
def root():
    return {"ok": True, "service": "vexzy-proxy", "hint": "Use /health or /auth/verify or /api/oathnet"}


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/config")
def config_info():
    return {
        "ok": True,
        "base_url": OATHNET_BASE_URL,
        "allowlist_count": len(ALLOWLIST),
        "rate_limit": {"max_requests": MAX_REQUESTS, "window_seconds": WINDOW_SECONDS},
        "blacklists": {
            "users": len(BLACKLIST_USERS),
            "licenses": len(BLACKLIST_LICENSES),
            "pairs": len(BLACKLIST_PAIRS),
        },
    }


@app.post("/auth/verify")
def auth_verify(x_license: str = Header(default=""), x_user: str = Header(default="")):
    _check_auth(x_license, x_user)
    return {"ok": True, "user": x_user}


@app.post("/api/oathnet")
def oathnet_proxy(
    payload: Dict[str, Any],
    request: Request,
    x_license: str = Header(default=""),
    x_user: str = Header(default=""),
):
    lic, user = _check_auth(x_license, x_user)
    _rate_limit(lic, user)

    endpoint = payload.get("endpoint")
    params = payload.get("params", {}) or {}

    if not isinstance(endpoint, str) or not endpoint.startswith("/"):
        raise HTTPException(status_code=400, detail="endpoint must be a string starting with '/'")

    if endpoint not in ALLOWLIST:
        raise HTTPException(status_code=403, detail="Endpoint not allowed by proxy")

    if not isinstance(params, dict):
        raise HTTPException(status_code=400, detail="params must be an object/dict")

    client_ip = request.client.host if request.client else None
    _log_request(lic, user, endpoint, client_ip)

    url = f"{OATHNET_BASE_URL}{endpoint}"

    try:
        r = requests.get(
            url,
            headers={"x-api-key": OATHNET_API_KEY},
            params=params,
            timeout=30,
        )
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Upstream request failed")

    try:
        return JSONResponse(status_code=r.status_code, content=r.json())
    except ValueError:
        return JSONResponse(status_code=r.status_code, content={"raw": r.text})
