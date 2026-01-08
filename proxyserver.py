import os
import time
from typing import Dict, Any, List, Tuple, Optional
from collections import deque

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Vexzy Proxy", version="3.0.0")

# ============================================================
# ENV
# ============================================================
OATHNET_API_KEY = os.getenv("OATHNET_API_KEY")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
OATHNET_BASE_URL = os.getenv("OATHNET_BASE_URL", "https://oathnet.org/api/service")

WINDOW_SECONDS = int(os.getenv("RL_WINDOW_SECONDS", "60"))
MAX_REQUESTS = int(os.getenv("RL_MAX_REQUESTS", "30"))

# Upstash Redis (REST)
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")

if not OATHNET_API_KEY:
    raise RuntimeError("Missing OATHNET_API_KEY environment variable.")
if not ADMIN_API_KEY:
    raise RuntimeError("Missing ADMIN_API_KEY environment variable.")
if not UPSTASH_REDIS_REST_URL or not UPSTASH_REDIS_REST_TOKEN:
    raise RuntimeError("Missing UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN env vars.")

# Optional: seed licenses into Redis on first run
SEED_LICENSES = {k.strip() for k in os.getenv("APP_LICENSE_KEYS", "").split(",") if k.strip()}

# ============================================================
# ALLOWLIST
# ============================================================
ALLOWLIST = {
    # ---- ADD YOUR ENDPOINTS BELOW THIS LINE ----
    "/steam/",
    # "/roblox-userinfo/",
    # "/ip-info/",
    # "/holehe/",
    # "/ghunt/",
    # ---- ADD YOUR ENDPOINTS ABOVE THIS LINE ----
}

# ============================================================
# KEYS (Redis sets)
# ============================================================
K_LICENSES = "vexzy:licenses"
K_BANNED_USERS = "vexzy:banned_users"
K_BANNED_LICENSES = "vexzy:banned_licenses"
K_BANNED_PAIRS = "vexzy:banned_pairs"  # store "license:user"

# ============================================================
# Runtime (in-memory only)
# ============================================================
USAGE_LOG = deque(maxlen=500)
_rate: Dict[Tuple[str, str], List[float]] = {}

def _redis_request(cmd: str, args: List[str]) -> Any:
    """
    Calls Upstash REST: POST /{cmd}/{arg1}/{arg2}...
    Returns decoded JSON (Upstash format).
    """
    url = UPSTASH_REDIS_REST_URL.rstrip("/") + f"/{cmd}"
    for a in args:
        url += "/" + requests.utils.quote(str(a), safe="")
    try:
        r = requests.post(
            url,
            headers={"Authorization": f"Bearer {UPSTASH_REDIS_REST_TOKEN}"},
            timeout=15
        )
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Redis persistence error: {e}")

def redis_sismember(key: str, member: str) -> bool:
    res = _redis_request("SISMEMBER", [key, member])
    # Upstash returns {"result": 0/1}
    return bool(res.get("result", 0))

def redis_sadd(key: str, member: str) -> None:
    _redis_request("SADD", [key, member])

def redis_srem(key: str, member: str) -> None:
    _redis_request("SREM", [key, member])

def redis_smembers(key: str) -> List[str]:
    res = _redis_request("SMEMBERS", [key])
    return res.get("result") or []

def _require_admin(x_admin_key: str) -> None:
    if x_admin_key != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized admin")

def _validate_username(username: str) -> str:
    u = (username or "").strip()
    if len(u) < 3 or len(u) > 24:
        raise HTTPException(status_code=401, detail="Username must be 3–24 characters")

    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    if any(c not in allowed for c in u):
        raise HTTPException(status_code=401, detail="Username contains invalid characters (use a-z A-Z 0-9 . _ -)")
    return u

def _auth_or_401(x_license: str, x_user: str) -> Tuple[str, str]:
    lic = (x_license or "").strip()
    if not lic:
        raise HTTPException(status_code=401, detail="Missing license")

    user = _validate_username(x_user)
    user_l = user.lower()

    # license active?
    if not redis_sismember(K_LICENSES, lic):
        raise HTTPException(status_code=401, detail="License is not active")

    # bans?
    if redis_sismember(K_BANNED_LICENSES, lic):
        raise HTTPException(status_code=401, detail="License is banned")

    if redis_sismember(K_BANNED_USERS, user_l):
        raise HTTPException(status_code=401, detail="User is banned")

    pair_key = f"{lic}:{user_l}"
    if redis_sismember(K_BANNED_PAIRS, pair_key):
        raise HTTPException(status_code=401, detail="User+license is banned")

    return lic, user

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

# ============================================================
# Seed licenses once (best-effort)
# ============================================================
@app.on_event("startup")
def seed_licenses():
    # If Redis already has licenses, do nothing.
    # If empty and you provided APP_LICENSE_KEYS, seed them.
    existing = redis_smembers(K_LICENSES)
    if existing:
        print(f"[SEED] Redis already has {len(existing)} license(s).")
        return
    if not SEED_LICENSES:
        print("[SEED] No seed licenses provided in APP_LICENSE_KEYS.")
        return
    for k in SEED_LICENSES:
        redis_sadd(K_LICENSES, k)
    print(f"[SEED] Seeded {len(SEED_LICENSES)} license(s) into Redis.")

# ============================================================
# Basic endpoints
# ============================================================
@app.get("/")
def root():
    return {"ok": True, "service": "vexzy-proxy"}

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/auth/verify")
def auth_verify(x_license: str = Header(default=""), x_user: str = Header(default="")):
    lic, user = _auth_or_401(x_license, x_user)
    return {"ok": True, "user": user, "license": lic}

# ============================================================
# Admin endpoints (persistent via Redis)
# ============================================================
@app.get("/admin/status")
def admin_status(x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    return {
        "ok": True,
        "licenses_count": len(redis_smembers(K_LICENSES)),
        "banned_users_count": len(redis_smembers(K_BANNED_USERS)),
        "banned_licenses_count": len(redis_smembers(K_BANNED_LICENSES)),
        "banned_pairs_count": len(redis_smembers(K_BANNED_PAIRS)),
    }

@app.get("/admin/licenses")
def admin_list_licenses(x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    return {"ok": True, "active_licenses": sorted(redis_smembers(K_LICENSES))}

@app.post("/admin/add-license")
def admin_add_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    redis_sadd(K_LICENSES, k)
    return {"ok": True, "added_license": k}

@app.post("/admin/remove-license")
def admin_remove_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    redis_srem(K_LICENSES, k)
    return {"ok": True, "removed_license": k}

@app.post("/admin/ban-user")
def admin_ban_user(user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    u = _validate_username(user).lower()
    redis_sadd(K_BANNED_USERS, u)
    return {"ok": True, "banned_user": u}

@app.post("/admin/unban-user")
def admin_unban_user(user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    u = (user or "").strip().lower()
    if u:
        redis_srem(K_BANNED_USERS, u)
    return {"ok": True, "unbanned_user": u}

@app.post("/admin/ban-license")
def admin_ban_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    redis_sadd(K_BANNED_LICENSES, k)
    return {"ok": True, "banned_license": k}

@app.post("/admin/unban-license")
def admin_unban_license(license_key: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if k:
        redis_srem(K_BANNED_LICENSES, k)
    return {"ok": True, "unbanned_license": k}

@app.post("/admin/ban-pair")
def admin_ban_pair(license_key: str, user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    if not k:
        raise HTTPException(status_code=400, detail="license_key is required")
    u = _validate_username(user).lower()
    redis_sadd(K_BANNED_PAIRS, f"{k}:{u}")
    return {"ok": True, "banned_pair": f"{k}:{u}"}

@app.post("/admin/unban-pair")
def admin_unban_pair(license_key: str, user: str, x_admin_key: str = Header(default="")):
    _require_admin(x_admin_key)
    k = (license_key or "").strip()
    u = (user or "").strip().lower()
    if k and u:
        redis_srem(K_BANNED_PAIRS, f"{k}:{u}")
    return {"ok": True, "unbanned_pair": f"{k}:{u}"}

@app.get("/admin/usage")
def admin_usage(x_admin_key: str = Header(default=""), limit: int = 50):
    _require_admin(x_admin_key)
    limit = max(1, min(limit, 200))
    items = list(USAGE_LOG)[:limit]
    return {"ok": True, "items": items}

# ============================================================
# Proxy endpoint
# ============================================================
@app.post("/api/oathnet")
def oathnet_proxy(
    payload: Dict[str, Any],
    request: Request,
    x_license: str = Header(default=""),
    x_user: str = Header(default=""),
):
    lic, user = _auth_or_401(x_license, x_user)
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
