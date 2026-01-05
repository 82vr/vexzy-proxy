# proxyserver.py
# A simple FastAPI proxy that keeps your OathNet API key server-side.
# Your tool calls THIS server, and this server calls OathNet.
#
# Install:
#   python -m pip install fastapi uvicorn requests
#
# Run (PowerShell, from this folder):
#   $env:OATHNET_API_KEY="YOUR_OATHNET_KEY"
#   $env:APP_LICENSE_KEYS="vexzy-lic-1,vexzy-lic-2"
#   python -m uvicorn proxyserver:app --host 0.0.0.0 --port 8080
#
# Test:
#   http://localhost:8080/health

import os
import time
from typing import Dict, Any, List

import requests
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="OathNet Proxy", version="1.0.0")



OATHNET_API_KEY = os.getenv("OATHNET_API_KEY")



APP_LICENSE_KEYS = os.getenv("APP_LICENSE_KEYS", "")


OATHNET_BASE_URL = os.getenv("OATHNET_BASE_URL", "https://oathnet.org/api/service")


WINDOW_SECONDS = int(os.getenv("RL_WINDOW_SECONDS", "60"))  # time window
MAX_REQUESTS = int(os.getenv("RL_MAX_REQUESTS", "30"))      # max requests per window per license

if not OATHNET_API_KEY:
    raise RuntimeError("Missing OATHNET_API_KEY environment variable.")

LICENSE_SET = {k.strip() for k in APP_LICENSE_KEYS.split(",") if k.strip()}
if not LICENSE_SET:
    # Safer to hard-fail than run open.
    raise RuntimeError("Missing APP_LICENSE_KEYS environment variable (must contain at least 1 license key).")

# ======================
# Endpoint allowlist
# ======================
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


# ======================
# In-memory rate tracking
# ======================
_rate: Dict[str, List[float]] = {}  # {license: [timestamps]}


def _check_license(x_license: str) -> str:
    if not x_license or x_license not in LICENSE_SET:
        raise HTTPException(status_code=401, detail="Invalid or missing license")
    return x_license


def _rate_limit(license_key: str) -> None:
    now = time.time()
    timestamps = _rate.get(license_key, [])
    timestamps = [t for t in timestamps if (now - t) < WINDOW_SECONDS]
    if len(timestamps) >= MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    timestamps.append(now)
    _rate[license_key] = timestamps


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/config")
def config_info():
    # Does NOT expose your OathNet key.
    return {
        "ok": True,
        "base_url": OATHNET_BASE_URL,
        "allowlist_count": len(ALLOWLIST),
        "rate_limit": {"max_requests": MAX_REQUESTS, "window_seconds": WINDOW_SECONDS},
    }


@app.post("/api/oathnet")
def oathnet_proxy(payload: Dict[str, Any], x_license: str = Header(default="")):
    # 1) Auth + rate limit
    lic = _check_license(x_license)
    _rate_limit(lic)

    # 2) Validate request
    endpoint = payload.get("endpoint")
    params = payload.get("params", {})

    if not isinstance(endpoint, str) or not endpoint.startswith("/"):
        raise HTTPException(status_code=400, detail="endpoint must be a string starting with '/'")

    if endpoint not in ALLOWLIST:
        raise HTTPException(status_code=403, detail="Endpoint not allowed by proxy")

    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise HTTPException(status_code=400, detail="params must be an object/dict")

    # 3) Forward request to OathNet
    url = f"{OATHNET_BASE_URL}{endpoint}"

    try:
        r = requests.get(
            url,
            headers={"x-api-key": OATHNET_API_KEY},
            params=params,
            timeout=20,
        )
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Upstream request failed")

    # 4) Return response
    try:
        return JSONResponse(status_code=r.status_code, content=r.json())
    except ValueError:
        # Not JSON
        return JSONResponse(status_code=r.status_code, content={"raw": r.text})
