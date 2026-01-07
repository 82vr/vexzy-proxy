import os
import time
from typing import Dict, Any, List, Tuple

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="Vexzy Proxy", version="1.1.0")

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

   
    if not x_user or len(x_user) < 3 or len(x_user) > 24:
        raise HTTPException(status_code=401, detail="Invalid or missing user")

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if any(c not in allowed for c in x_user):
        raise HTTPException(status_code=401, detail="User contains invalid characters")

    return x_license, x_user


def _rate_limit(license_key: str, user: str) -> None:
    now = time.time()
    key = (license_key, user)
    timestamps = _rate.get(key, [])
    timestamps = [t for t in timestamps if (now - t) < WINDOW_SECONDS]
    if len(timestamps) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    timestamps.append(now)
    _rate[key] = timestamps


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/verify")
def auth_verify(x_license: str = Header(default=""), x_user: str = Header(default="")):
    
    _check_auth(x_license, x_user)
    return {"ok": True, "user": x_user}


@app.post("/api/oathnet")
def oathnet_proxy(
    payload: Dict[str, Any],
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
