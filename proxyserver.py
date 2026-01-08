import os
import time
from typing import Dict, Any, List, Tuple, Optional
from collections import deque

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Vexzy Proxy", version="2.1.0")


OATHNET_API_KEY = os.getenv("OATHNET_API_KEY")
APP_LICENSE_KEYS = os.getenv("APP_LICENSE_KEYS", "")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
OATHNET_BASE_URL = os.getenv("OATHNET_BASE_URL", "https://oathnet.org/api/service")

WINDOW_SECONDS = int(os.getenv("RL_WINDOW_SECONDS", "60"))
MAX_REQUESTS = int(os.getenv("RL_MAX_REQUESTS", "30"))

if not OATHNET_API_KEY:
    raise RuntimeError("Missing OATHNET_API_KEY environment variable.")
if not ADMIN_API_KEY:
    raise RuntimeError("Missing ADMIN_API_KEY environment variable.")

STARTUP_LICENSES = {k.strip() for k in APP_LICENSE_KEYS.split(",") if k.strip()}
if not STARTUP_LICENSES:
    raise RuntimeError("Missing APP_LICENSE_KEYS environment variable (must contain at least 1 license key).")


ACTIVE_LICENSES = set(STARTUP_LICENSES)
BANNED_USERS = set()       
BANNED_LICENSES = set()   
BANNED_PAIRS = set()       


USAGE_LOG = deque(maxlen=500) 


ALLOWLIST = {
    "/steam/",
    "/roblox-userinfo/",
    "/ip-info/",
    "/holehe/",
   
}


_rate: Dict[Tuple[str, str], List[float]] = {}


def _require_admin(x_admin_key: str) -> None:
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized admin")


def _validate_username(username: str) -> str:
    u = (username or "").strip()
    if len(u) < 3 or len(u) > 24:
        raise HTTPException(status_code=401, detail="Username must be 3–24 characters")

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if any(c not in allowed for c in u):
        raise HTTPException(
            status_code=401,
            detail="Username contains invalid characters (use a-z A-Z 0-9 . _ -)",
        )
    return u


def _check_auth(x_license: str, x_user: str) -> Tuple[str, str]:
    if not x_license:
        raise HTTPException(status_code=401, detail="Missing license")
    if x_license not in ACTIVE_LICENSES:
        raise HTTPException(status_code=401, detail="Invalid or revoked license")
    if x_license in BANNED_LICENSES:
        raise HTTPException(status_code=403, detail="License is banned")

    user = _validate_username(x_user)
    user_l = user.lower()

    if user_l in BANNED_USERS:
        raise HTTPException(status_code=403, detail="User is banned")
    if (x_license, user_l) in BANNED_PAIRS:
        raise HTTPException(status_code=403, detail="User is banned for this license")

    return x_license, user


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
  
    return {"ok": True, "service": "vexzy-proxy"}


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
        "runtime": {
            "active_licenses": len(ACTIVE_LICENSES),
            "banned_users": len(BANNED_USERS),
            "banned_licenses": len(BANNED_LICENSES),
            "banned_pairs": len(BANNED_PAIRS),
            "usage_log_size": len(USAGE_LOG),
        },
    }


@app.post("/auth/verify")
def auth_verify(x_license: str = Header(default=""), x_user: str = Header(default="")):
    _check_auth(x_license, x_user)
    return {"ok": True, "user": x_user}



@app.get("/admin/status")
def admin_status(x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    return {
        "ok": True,
        "active_licenses_count": len(ACTIVE_LICENSES),
        "banned_users": sorted(list(BANNED_USERS))[:200],
        "banned_licenses": sorted(list(BANNED_LICENSES))[:200],
        "banned_pairs": [f"{lic}:{usr}" for (lic, usr) in list(BANNED_PAIRS)][:200],
    }


@app.get("/admin/licenses")
def admin_list_licenses(x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
  
    return {"ok": True, "active_licenses": sorted(list(ACTIVE_LICENSES))}


@app.get("/admin/usage")
def admin_usage(x_admin_key: str = Header(default=""), limit: int = 50):
    _require_admin(x_admin_key)
    limit = max(1, min(limit, 200))
    items = list(USAGE_LOG)[:limit]
    return {"ok": True, "items": items}


@app.post("/admin/add-license")
def admin_add_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    ACTIVE_LICENSES.add(k)
    return {"ok": True, "added_license": k}


@app.post("/admin/remove-license")
def admin_remove_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    ACTIVE_LICENSES.discard(k)
    
    to_remove = {(lic, usr) for (lic, usr) in BANNED_PAIRS if lic == k}
    for item in to_remove:
        BANNED_PAIRS.discard(item)
    return {"ok": True, "removed_license": k}


@app.post("/admin/ban-user")
def admin_ban_user(user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    u = _validate_username(user).lower()
    BANNED_USERS.add(u)
    return {"ok": True, "banned_user": u}


@app.post("/admin/unban-user")
def admin_unban_user(user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    u = (user or "").strip().lower()
    BANNED_USERS.discard(u)
    return {"ok": True, "unbanned_user": u}


@app.post("/admin/ban-license")
def admin_ban_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    BANNED_LICENSES.add(k)
    return {"ok": True, "banned_license": k}


@app.post("/admin/unban-license")
def admin_unban_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    BANNED_LICENSES.discard(k)
    return {"ok": True, "unbanned_license": k}


@app.post("/admin/ban-pair")
def admin_ban_pair(license_key: str, user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    u = _validate_username(user).lower()
    BANNED_PAIRS.add((k, u))
    return {"ok": True, "banned_pair": f"{k}:{u}"}


@app.post("/admin/unban-pair")
def admin_unban_pair(license_key: str, user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    u = (user or "").strip().lower()
    BANNED_PAIRS.discard((k, u))
    return {"ok": True, "unbanned_pair": f"{k}:{u}"}



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

   
    USAGE_LOG.appendleft({
        "ts": time.time(),
        "user": user,
        "license": lic,
        "ip": client_ip,
        "endpoint": endpoint
    })

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
