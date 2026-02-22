# =============================
# UGANDA HEALTH ASSISTANT
# Runtime-SAFE (NO INDEXING BY DEFAULT)
# + Controlled indexing (ALLOW_INDEXING=1)
# + Multi-user auth
# + Conversation memory
# + Source attribution
# + CI/CD-friendly
# =============================

import os
import json
import time
import uuid
import hmac
import base64
import hashlib
import sqlite3
import threading
import traceback
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

# =============================
# CONFIG
# =============================
APP_TITLE = "Uganda Health Assistant"

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_ENABLED = bool(OPENAI_API_KEY)

ALLOW_INDEXING = os.environ.get("ALLOW_INDEXING", "0").strip() == "1"

APP_ADMIN_USER = os.environ.get("APP_USER", "admin")
APP_ADMIN_PASS = os.environ.get("APP_PASS", "secret123")

SESSION_COOKIE_NAME = "session"
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "86400"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "app.db"))

LOCAL_PDF_FOLDER = os.path.join(BASE_DIR, "pdfs")
CLOUD_PDF_FOLDER = "/app/pdfs"
PDF_FOLDER = LOCAL_PDF_FOLDER if os.name == "nt" else (
    CLOUD_PDF_FOLDER if os.path.exists(CLOUD_PDF_FOLDER) else LOCAL_PDF_FOLDER
)

PERSIST_DIR = os.path.join(BASE_DIR, "storage")
TOP_K = 30

# =============================
# OBSERVABILITY / EVAL CONFIG
# =============================
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "1").strip() == "1"
MODEL_NAME = os.environ.get("MODEL_NAME", "unknown").strip()
MODEL_VERSION = os.environ.get("MODEL_VERSION", "dev").strip()
SERVICE_VERSION = os.environ.get("SERVICE_VERSION", "0.1.0").strip()

# =============================
# NEW: SECURITY / OPS CONFIG
# =============================
# RBAC: allowed roles
ROLE_ADMIN = "admin"
ROLE_CLINICIAN = "clinician"
ROLE_USER = "user"

# Retention
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "90"))
CLEANUP_INTERVAL_HOURS = int(os.environ.get("CLEANUP_INTERVAL_HOURS", "24"))

# Rate limiting (simple token bucket-ish)
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "1").strip() == "1"
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "60"))  # requests per minute per key
RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "20"))  # allow short bursts

# External logging sink (best effort HTTP POST of JSON lines)
LOG_SINK_URL = os.environ.get("LOG_SINK_URL", "").strip()  # e.g., http(s) endpoint for ELK/Cloud
LOG_SINK_TIMEOUT_SEC = float(os.environ.get("LOG_SINK_TIMEOUT_SEC", "2.5"))

# Encryption at rest (application-layer encryption for selected text fields)
DATA_ENCRYPTION_KEY = os.environ.get("DATA_ENCRYPTION_KEY", "").strip()  # Fernet key recommended

# =============================
# APP STATE
# =============================
class AppState:
    ready: bool = False
    error: Optional[str] = None
    index = None

STATE = AppState()
LOCK = threading.Lock()

# =============================
# LOGGING
# =============================
def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def log_json(event: str, **fields):
    print(json.dumps({
        "ts": utc_now_iso(),
        "event": event,
        "app": "uganda-health-assistant",
        **fields
    }, ensure_ascii=False))

# =============================
# DATABASE
# =============================
def db_connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

DB_LOCK = threading.Lock()
DB_CONN = db_connect()

def db_exec(sql, params=()):
    with DB_LOCK:
        DB_CONN.execute(sql, params)
        DB_CONN.commit()

def db_query_one(sql, params=()):
    with DB_LOCK:
        return DB_CONN.execute(sql, params).fetchone()

def db_query_all(sql, params=()):
    with DB_LOCK:
        return DB_CONN.execute(sql, params).fetchall()

def init_db():
    db_exec("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        pass_hash TEXT,
        salt TEXT,
        role TEXT,
        active INTEGER,
        created_at TEXT
    );
    """)

    db_exec("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at TEXT,
        expires_at TEXT,
        ip TEXT,
        user_agent TEXT
    );
    """)

    db_exec("""
    CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY,
        session_token TEXT,
        role TEXT,
        content TEXT,
        ts TEXT
    );
    """)

# =============================
# EXTRA TABLES (AUDIT, METRICS, ERRORS)
# =============================
def init_db_extras():
    db_exec("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY,
        request_id TEXT,
        ts TEXT,
        user_id INTEGER,
        username TEXT,
        action TEXT,
        path TEXT,
        method TEXT,
        ip TEXT,
        user_agent TEXT,
        status_code INTEGER,
        details_json TEXT
    );
    """)

    db_exec("""
    CREATE TABLE IF NOT EXISTS query_metrics (
        id INTEGER PRIMARY KEY,
        request_id TEXT UNIQUE,
        ts TEXT,
        session_token TEXT,
        user_id INTEGER,
        username TEXT,
        question TEXT,
        question_len INTEGER,
        top_k INTEGER,
        min_score REAL,
        retrieved_count INTEGER,
        relevant_count INTEGER,
        top_score REAL,
        total_latency_ms INTEGER,
        retrieve_latency_ms INTEGER,
        synth_latency_ms INTEGER,
        model_name TEXT,
        model_version TEXT,
        service_version TEXT,
        prompt_hash TEXT,
        answer_len INTEGER,
        status TEXT
    );
    """)

    db_exec("""
    CREATE TABLE IF NOT EXISTS retrieval_logs (
        id INTEGER PRIMARY KEY,
        request_id TEXT,
        rank INTEGER,
        score REAL,
        document TEXT,
        page TEXT,
        excerpt_hash TEXT
    );
    """)

    db_exec("""
    CREATE TABLE IF NOT EXISTS error_logs (
        id INTEGER PRIMARY KEY,
        request_id TEXT,
        ts TEXT,
        user_id INTEGER,
        username TEXT,
        path TEXT,
        method TEXT,
        ip TEXT,
        user_agent TEXT,
        error_type TEXT,
        error_message TEXT,
        traceback TEXT
    );
    """)

# Wrap init_db without editing its original body
_init_db_original = init_db
def init_db():
    _init_db_original()
    init_db_extras()

# =============================
# AUTH
# =============================
def pbkdf2(password, salt):
    return base64.b64encode(
        hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    ).decode()

def create_user(username, password, role="user"):
    salt = os.urandom(16)
    db_exec(
        "INSERT INTO users (username, pass_hash, salt, role, active, created_at) VALUES (?,?,?,?,?,?)",
        (username, pbkdf2(password, salt), base64.b64encode(salt).decode(), role, 1, utc_now_iso())
    )

def verify_user(username, password):
    r = db_query_one("SELECT * FROM users WHERE username=?", (username,))
    if not r or not r["active"]:
        return None
    salt = base64.b64decode(r["salt"])
    if not hmac.compare_digest(r["pass_hash"], pbkdf2(password, salt)):
        return None
    return dict(r)

# =============================
# SESSION HELPERS
# =============================
def create_session(user_id: int, ip: str, user_agent: str) -> str:
    token = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires = now.timestamp() + SESSION_TTL_SECONDS
    expires_at = datetime.fromtimestamp(expires, tz=timezone.utc).isoformat()
    db_exec(
        "INSERT INTO sessions (token, user_id, created_at, expires_at, ip, user_agent) VALUES (?,?,?,?,?,?)",
        (token, user_id, utc_now_iso(), expires_at, ip, user_agent)
    )
    return token

def get_session(token: str):
    if not token:
        return None
    r = db_query_one("SELECT * FROM sessions WHERE token=?", (token,))
    if not r:
        return None
    try:
        exp = datetime.fromisoformat(r["expires_at"])
    except Exception:
        return None
    if datetime.now(timezone.utc) > exp:
        db_exec("DELETE FROM sessions WHERE token=?", (token,))
        return None
    return dict(r)

def delete_session(token: str):
    if token:
        db_exec("DELETE FROM sessions WHERE token=?", (token,))

def get_user_by_id(user_id: int):
    r = db_query_one("SELECT * FROM users WHERE id=?", (user_id,))
    return dict(r) if r else None

# =============================
# CONVERSATION MEMORY
# =============================
def save_turn(session_token: str, role: str, content: str):
    db_exec(
        "INSERT INTO conversations (session_token, role, content, ts) VALUES (?,?,?,?)",
        (session_token, role, content, utc_now_iso())
    )

def load_recent_history(session_token: str, limit: int = 6) -> str:
    rows = db_query_all(
        "SELECT role, content FROM conversations WHERE session_token=? ORDER BY id DESC LIMIT ?",
        (session_token, limit)
    )
    rows = list(reversed(rows))
    return "\n".join([f"{r['role'].capitalize()}: {r['content']}" for r in rows])

# =============================
# INDEX
# =============================
def load_index_only():
    from llama_index.core import StorageContext, load_index_from_storage
    storage = StorageContext.from_defaults(persist_dir=PERSIST_DIR)
    return load_index_from_storage(storage)

def build_index_from_pdfs():
    from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
    docs = SimpleDirectoryReader(PDF_FOLDER).load_data()
    index = VectorStoreIndex.from_documents(docs)
    index.storage_context.persist(persist_dir=PERSIST_DIR)
    log_json("index_built", docs=len(docs))
    return index

# =============================
# OBSERVABILITY HELPERS
# =============================
def sha256_text(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()

def request_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

def request_ua(request: Request) -> str:
    return request.headers.get("user-agent", "")[:500]

# =============================
# NEW: EXTERNAL LOG SINK (best effort)
# =============================
def _sink_send(payload: dict):
    if not LOG_SINK_URL:
        return
    try:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            LOG_SINK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=LOG_SINK_TIMEOUT_SEC) as _:
            pass
    except Exception:
        # never crash app due to sink failures
        return

_log_json_original = log_json
def log_json(event: str, **fields):
    payload = {
        "ts": utc_now_iso(),
        "event": event,
        "app": "uganda-health-assistant",
        **fields
    }
    _log_json_original(event, **fields)
    if LOG_SINK_URL:
        threading.Thread(target=_sink_send, args=(payload,), daemon=True).start()

# =============================
# NEW: ENCRYPTION (application-layer, optional)
# =============================
_FERNET = None
_ENCRYPTION_ENABLED = False
try:
    if DATA_ENCRYPTION_KEY:
        from cryptography.fernet import Fernet  # type: ignore
        _FERNET = Fernet(DATA_ENCRYPTION_KEY.encode("utf-8") if len(DATA_ENCRYPTION_KEY) < 60 else DATA_ENCRYPTION_KEY)
        _ENCRYPTION_ENABLED = True
except Exception:
    _FERNET = None
    _ENCRYPTION_ENABLED = False

def maybe_encrypt(s: str) -> str:
    if not _ENCRYPTION_ENABLED or not _FERNET:
        return s
    try:
        token = _FERNET.encrypt((s or "").encode("utf-8"))
        return "enc:" + token.decode("utf-8")
    except Exception:
        return s

def maybe_decrypt(s: str) -> str:
    if not s:
        return s
    if not _ENCRYPTION_ENABLED or not _FERNET:
        return s
    if not s.startswith("enc:"):
        return s
    try:
        token = s[4:].encode("utf-8")
        out = _FERNET.decrypt(token)
        return out.decode("utf-8", errors="ignore")
    except Exception:
        return s

# Wrap conversation functions to encrypt/decrypt without changing calling logic
_save_turn_original = save_turn
_load_recent_history_original = load_recent_history

def save_turn(session_token: str, role: str, content: str):
    _save_turn_original(session_token, role, maybe_encrypt(content))

def load_recent_history(session_token: str, limit: int = 6) -> str:
    rows = db_query_all(
        "SELECT role, content FROM conversations WHERE session_token=? ORDER BY id DESC LIMIT ?",
        (session_token, limit)
    )
    rows = list(reversed(rows))
    return "\n".join([f"{r['role'].capitalize()}: {maybe_decrypt(r['content'])}" for r in rows])

# =============================
# AUDIT / ERROR / METRICS
# =============================
def audit_log(
    *,
    request_id: str,
    user: Optional[dict],
    action: str,
    request: Request,
    status_code: int,
    details: Optional[dict] = None
):
    try:
        payload = {
            "request_id": request_id,
            "ts": utc_now_iso(),
            "user_id": (user or {}).get("id"),
            "username": (user or {}).get("username"),
            "action": action,
            "path": request.url.path,
            "method": request.method,
            "ip": request_ip(request),
            "user_agent": request_ua(request),
            "status_code": int(status_code),
            "details": details or {}
        }
        db_exec(
            "INSERT INTO audit_logs (request_id, ts, user_id, username, action, path, method, ip, user_agent, status_code, details_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                request_id,
                payload["ts"],
                payload["user_id"],
                payload["username"],
                payload["action"],
                payload["path"],
                payload["method"],
                payload["ip"],
                payload["user_agent"],
                payload["status_code"],
                json.dumps(payload["details"], ensure_ascii=False),
            ),
        )
        log_json("audit", **payload)
    except Exception as e:
        log_json("audit_log_failed", error=str(e))

def error_log(
    *,
    request_id: str,
    user: Optional[dict],
    request: Request,
    exc: Exception
):
    try:
        payload = {
            "request_id": request_id,
            "ts": utc_now_iso(),
            "user_id": (user or {}).get("id"),
            "username": (user or {}).get("username"),
            "path": request.url.path,
            "method": request.method,
            "ip": request_ip(request),
            "user_agent": request_ua(request),
            "error_type": type(exc).__name__,
            "error_message": str(exc)[:1000],
        }
        tb = traceback.format_exc()[:8000]
        db_exec(
            "INSERT INTO error_logs (request_id, ts, user_id, username, path, method, ip, user_agent, error_type, error_message, traceback) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                payload["request_id"],
                payload["ts"],
                payload["user_id"],
                payload["username"],
                payload["path"],
                payload["method"],
                payload["ip"],
                payload["user_agent"],
                payload["error_type"],
                payload["error_message"],
                tb,
            ),
        )
        log_json("error", **payload, traceback=tb)
    except Exception as e:
        log_json("error_log_failed", error=str(e))

def metrics_init(
    *,
    request_id: str,
    session_token: str,
    user: Optional[dict],
    question: str,
    top_k: int,
    min_score: float,
    request: Request
):
    try:
        db_exec(
            """
            INSERT OR IGNORE INTO query_metrics
            (request_id, ts, session_token, user_id, username, question, question_len, top_k, min_score,
             retrieved_count, relevant_count, top_score, total_latency_ms, retrieve_latency_ms, synth_latency_ms,
             model_name, model_version, service_version, prompt_hash, answer_len, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                request_id,
                utc_now_iso(),
                session_token,
                (user or {}).get("id"),
                (user or {}).get("username"),
                question,
                len(question or ""),
                int(top_k),
                float(min_score),
                0,
                0,
                None,
                0,
                0,
                0,
                MODEL_NAME,
                MODEL_VERSION,
                SERVICE_VERSION,
                None,
                0,
                "started",
            ),
        )
    except Exception as e:
        log_json("metrics_init_failed", error=str(e))

def metrics_update(
    *,
    request_id: str,
    retrieved_count: Optional[int] = None,
    relevant_count: Optional[int] = None,
    top_score: Optional[float] = None,
    total_latency_ms: Optional[int] = None,
    retrieve_latency_ms: Optional[int] = None,
    synth_latency_ms: Optional[int] = None,
    prompt_hash: Optional[str] = None,
    answer_len: Optional[int] = None,
    status: Optional[str] = None,
):
    fields = []
    params = []
    if retrieved_count is not None:
        fields.append("retrieved_count=?")
        params.append(int(retrieved_count))
    if relevant_count is not None:
        fields.append("relevant_count=?")
        params.append(int(relevant_count))
    if top_score is not None:
        fields.append("top_score=?")
        params.append(float(top_score))
    if total_latency_ms is not None:
        fields.append("total_latency_ms=?")
        params.append(int(total_latency_ms))
    if retrieve_latency_ms is not None:
        fields.append("retrieve_latency_ms=?")
        params.append(int(retrieve_latency_ms))
    if synth_latency_ms is not None:
        fields.append("synth_latency_ms=?")
        params.append(int(synth_latency_ms))
    if prompt_hash is not None:
        fields.append("prompt_hash=?")
        params.append(prompt_hash)
    if answer_len is not None:
        fields.append("answer_len=?")
        params.append(int(answer_len))
    if status is not None:
        fields.append("status=?")
        params.append(status)

    if not fields:
        return

    try:
        sql = "UPDATE query_metrics SET " + ", ".join(fields) + " WHERE request_id=?"
        params.append(request_id)
        db_exec(sql, tuple(params))
    except Exception as e:
        log_json("metrics_update_failed", error=str(e))

def retrieval_log_nodes(request_id: str, relevant_nodes: list):
    try:
        for i, n in enumerate(relevant_nodes[:20], start=1):
            meta = n.metadata if isinstance(n.metadata, dict) else {}
            doc = meta.get("file_name") or meta.get("source") or "unknown"
            page = meta.get("page_label") or meta.get("page")
            excerpt = ""
            try:
                excerpt = getattr(n, "text", "") or getattr(getattr(n, "node", None), "text", "") or ""
            except Exception:
                excerpt = ""
            db_exec(
                "INSERT INTO retrieval_logs (request_id, rank, score, document, page, excerpt_hash) VALUES (?,?,?,?,?,?)",
                (
                    request_id,
                    int(i),
                    float(n.score) if n.score is not None else None,
                    str(doc)[:300],
                    str(page)[:50] if page is not None else None,
                    sha256_text(excerpt) if excerpt else None,
                ),
            )
    except Exception as e:
        log_json("retrieval_log_failed", error=str(e))

# =============================
# NEW: RBAC HELPERS
# =============================
def require_role(user: Optional[dict], allowed_roles: List[str]) -> bool:
    if not user:
        return False
    role = (user.get("role") or "").strip().lower()
    return role in [r.lower() for r in allowed_roles]

# =============================
# NEW: RATE LIMITER
# =============================
_RL_LOCK = threading.Lock()
_RL_STATE: Dict[str, Dict[str, Any]] = {}
# state per key: {"tokens": float, "last": float}
def rate_limit_check(key: str) -> bool:
    if not RATE_LIMIT_ENABLED:
        return True
    now = time.time()
    refill_per_sec = RATE_LIMIT_RPM / 60.0
    capacity = max(1, RATE_LIMIT_BURST)

    with _RL_LOCK:
        st = _RL_STATE.get(key)
        if not st:
            st = {"tokens": float(capacity), "last": now}
            _RL_STATE[key] = st
        # refill
        elapsed = now - float(st["last"])
        st["last"] = now
        st["tokens"] = min(float(capacity), float(st["tokens"]) + elapsed * refill_per_sec)
        # consume
        if float(st["tokens"]) >= 1.0:
            st["tokens"] = float(st["tokens"]) - 1.0
            return True
        return False

def rate_limit_key(request: Request, user: Optional[dict]) -> str:
    # prefer user-based, fallback to IP
    if user and user.get("id") is not None:
        return f"user:{user['id']}"
    return f"ip:{request_ip(request)}"

# =============================
# NEW: DATA RETENTION / CLEANUP
# =============================
def retention_cleanup_once():
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
        cutoff_iso = cutoff.isoformat()

        # conversations
        db_exec("DELETE FROM conversations WHERE ts < ?", (cutoff_iso,))
        # audit_logs
        db_exec("DELETE FROM audit_logs WHERE ts < ?", (cutoff_iso,))
        # query_metrics
        db_exec("DELETE FROM query_metrics WHERE ts < ?", (cutoff_iso,))
        # retrieval_logs: joinless; delete by request_id not possible directly by time
        # simple strategy: keep retrieval_logs for request_ids still present
        db_exec("""
            DELETE FROM retrieval_logs
            WHERE request_id NOT IN (SELECT request_id FROM query_metrics)
        """)
        # errors
        db_exec("DELETE FROM error_logs WHERE ts < ?", (cutoff_iso,))

        log_json("retention_cleanup_done", retention_days=RETENTION_DAYS, cutoff=cutoff_iso)
    except Exception as e:
        log_json("retention_cleanup_failed", error=str(e))

def retention_cleanup_loop():
    while True:
        time.sleep(max(60, CLEANUP_INTERVAL_HOURS * 3600))
        retention_cleanup_once()

# =============================
# FASTAPI
# =============================
app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <html>
      <head><title>Uganda Health Assistant</title></head>
      <body style="font-family: Arial; padding: 40px;">
        <h2>Uganda Health Assistant</h2>
        <p>Service is running.</p>
        <ul>
          <li><a href="/docs">API docs</a></li>
          <li><a href="/healthz">Health check</a></li>
          <li><a href="/readyz">Readiness</a></li>
          <li><a href="/admin/monitor">Monitoring dashboard</a></li>
        </ul>
      </body>
    </html>
    """

class AskBody(BaseModel):
    question: str = Field(..., min_length=1)

# =============================
# AUTH ENDPOINTS
# =============================
class LoginBody(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

@app.post("/auth/login")
def login(body: LoginBody, request: Request, response: Response):
    rid = uuid.uuid4().hex
    user = verify_user(body.username, body.password)
    if not user:
        audit_log(
            request_id=rid,
            user=None,
            action="login_failed",
            request=request,
            status_code=401,
            details={"username": body.username},
        )
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})

    token = create_session(user["id"], request_ip(request), request_ua(request))
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  # set True behind HTTPS
        max_age=SESSION_TTL_SECONDS,
    )
    audit_log(
        request_id=rid,
        user=user,
        action="login_success",
        request=request,
        status_code=200,
        details={},
    )
    return {"ok": True, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}

@app.post("/auth/logout")
def logout(request: Request, response: Response):
    rid = uuid.uuid4().hex
    token = request.cookies.get(SESSION_COOKIE_NAME)
    sess = get_session(token) if token else None
    user = get_user_by_id(sess["user_id"]) if sess else None
    delete_session(token)
    response.delete_cookie(SESSION_COOKIE_NAME)
    audit_log(
        request_id=rid,
        user=user,
        action="logout",
        request=request,
        status_code=200,
        details={},
    )
    return {"ok": True}

@app.get("/auth/me")
def me(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    sess = get_session(token) if token else None
    if not sess:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    user = get_user_by_id(sess["user_id"])
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    return {"user": {"id": user["id"], "username": user["username"], "role": user["role"]}}

# =============================
# NEW: ADMIN USER MANAGEMENT (RBAC)
# =============================
class CreateUserBody(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=6)
    role: str = Field(..., min_length=1)

@app.post("/admin/users")
def admin_create_user(body: CreateUserBody, request: Request):
    rid = getattr(request.state, "request_id", uuid.uuid4().hex)
    user = getattr(request.state, "user", None)
    if not require_role(user, [ROLE_ADMIN]):
        audit_log(request_id=rid, user=user, action="rbac_denied", request=request, status_code=403, details={"endpoint": "/admin/users"})
        return JSONResponse(status_code=403, content={"detail": "Admin only"})

    role = body.role.strip().lower()
    if role not in [ROLE_ADMIN, ROLE_CLINICIAN, ROLE_USER]:
        return JSONResponse(status_code=400, content={"detail": "Invalid role. Use admin|clinician|user"})

    try:
        create_user(body.username, body.password, role)
        audit_log(request_id=rid, user=user, action="admin_create_user", request=request, status_code=200, details={"created": body.username, "role": role})
        return {"ok": True, "created": {"username": body.username, "role": role}}
    except Exception as e:
        error_log(request_id=rid, user=user, request=request, exc=e)
        return JSONResponse(status_code=400, content={"detail": "Could not create user (maybe username exists)."})

# =============================
# AUTH ENFORCEMENT + ERROR TRACKING + RATE LIMITING MIDDLEWARE
# =============================
@app.middleware("http")
async def auth_and_observability_middleware(request: Request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex
    request.state.request_id = rid

    token = request.cookies.get(SESSION_COOKIE_NAME)
    sess = get_session(token) if token else None
    user = get_user_by_id(sess["user_id"]) if sess else None
    request.state.user = user
    request.state.session_token = token or ""

    # Protect key endpoints
    protected_paths = ("/api/ask", "/api/eval/export", "/admin/monitor", "/admin/users")
    if REQUIRE_AUTH and request.url.path in protected_paths:
        if not user:
            audit_log(
                request_id=rid,
                user=None,
                action="auth_blocked",
                request=request,
                status_code=401,
                details={"path": request.url.path},
            )
            return JSONResponse(status_code=401, content={"detail": "Authentication required. Login at /auth/login"})

    # RBAC gates:
    # - /api/ask => clinician, admin, user
    # - /api/eval/export and /admin/* => admin only
    if request.url.path == "/api/ask":
        if user and not require_role(user, [ROLE_ADMIN, ROLE_CLINICIAN, ROLE_USER]):
            audit_log(request_id=rid, user=user, action="rbac_denied", request=request, status_code=403, details={"path": request.url.path})
            return JSONResponse(status_code=403, content={"detail": "Insufficient role"})
    if request.url.path in ("/api/eval/export", "/admin/monitor", "/admin/users"):
        if user and not require_role(user, [ROLE_ADMIN]):
            audit_log(request_id=rid, user=user, action="rbac_denied", request=request, status_code=403, details={"path": request.url.path})
            return JSONResponse(status_code=403, content={"detail": "Admin only"})

    # Rate limiting only for /api/ask
    if request.url.path == "/api/ask":
        k = rate_limit_key(request, user)
        if not rate_limit_check(k):
            audit_log(request_id=rid, user=user, action="rate_limited", request=request, status_code=429, details={"key": k})
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Slow down."})

    start = time.perf_counter()
    try:
        response = await call_next(request)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        audit_log(
            request_id=rid,
            user=user,
            action="request",
            request=request,
            status_code=getattr(response, "status_code", 200),
            details={"latency_ms": elapsed_ms},
        )
        response.headers["x-request-id"] = rid
        return response
    except Exception as e:
        error_log(request_id=rid, user=user, request=request, exc=e)
        audit_log(
            request_id=rid,
            user=user,
            action="request_error",
            request=request,
            status_code=500,
            details={"error": str(e)},
        )
        raise

from llama_index.core.prompts import PromptTemplate
from llama_index.core.response_synthesizers import get_response_synthesizer

QA_PROMPT = PromptTemplate(
"""
You are a Public Health Specialist supporting clinical and programmatic decision-making in Uganda.

Use ONLY the guideline excerpts provided below to answer the question.
Do NOT use external knowledge, prior training knowledge, assumptions, or general medical reasoning.

Conversation so far:
---------------------
{chat_history}
---------------------

Guideline excerpts:
---------------------
{context_str}
---------------------

Current question:
{query_str}

Instructions:
- Base your answer ONLY on the guideline excerpts.
- If the excerpts do NOT contain sufficient information to answer the question directly and explicitly, respond ONLY with this exact line and nothing else:
I do not know based on the provided guideline excerpts.
- Do NOT infer, extrapolate, generalize, or assume beyond the text.
- Do NOT partially answer.
- Maintain HIV as the primary condition ONLY if explicitly referenced in the excerpts.

- If you did NOT respond with the exact "I do not know..." line, then:
  - Provide the answer first.
  - Then on a NEW LINE, add exactly ONE follow-up question in this exact format:
Copy-paste this question to get a response: <your single question here>
-If you did respond with "I do not know......." line, then:
    -Do not continue with, Copy-paste this question to get a response: <your single question here>

"""
)

@app.post("/api/ask")
def ask(body: AskBody, request: Request):

    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
    session_token_for_metrics = request.cookies.get(SESSION_COOKIE_NAME) or "anonymous"
    user_for_metrics = getattr(request.state, "user", None)
    total_t0 = time.perf_counter()

    metrics_init(
        request_id=request_id,
        session_token=session_token_for_metrics,
        user=user_for_metrics,
        question=body.question,
        top_k=TOP_K,
        min_score=0.35,
        request=request
    )

    if not STATE.ready or not STATE.index:
        metrics_update(
            request_id=request_id,
            status="not_ready",
            total_latency_ms=int((time.perf_counter() - total_t0) * 1000)
        )
        return JSONResponse(status_code=503, content={"detail": "Not ready"})

    session_token = request.cookies.get(SESSION_COOKIE_NAME) or "anonymous"

    save_turn(session_token, "user", body.question)
    chat_history = load_recent_history(session_token, limit=4)

    retriever = STATE.index.as_retriever(similarity_top_k=TOP_K)

    retrieve_t0 = time.perf_counter()
    contextual_query = chat_history + "\nCurrent question: " + body.question
    nodes = retriever.retrieve(contextual_query)
    retrieve_ms = int((time.perf_counter() - retrieve_t0) * 1000)

    metrics_update(
        request_id=request_id,
        retrieved_count=len(nodes or []),
        retrieve_latency_ms=retrieve_ms
    )

    if not nodes:
        metrics_update(
            request_id=request_id,
            relevant_count=0,
            top_score=None,
            status="no_retrieval",
            total_latency_ms=int((time.perf_counter() - total_t0) * 1000),
            answer_len=len("I do not know.")
        )
        return {"answer": "I do not know.", "sources": []}

    MIN_SCORE = 0.35
    relevant_nodes = [n for n in nodes if (n.score or 0) >= MIN_SCORE]

    # Compute top_score once
    top_score = None
    try:
        scores = [float(n.score) for n in relevant_nodes if n.score is not None]
        top_score = max(scores) if scores else None
    except Exception:
        top_score = None

    # =============================
    # HARD SCOPE / RELEVANCE GATE
    # =============================
    STRICT_TOP_SCORE = 0.60
    MIN_RELEVANT_NODES = 2

    if (not relevant_nodes) or (top_score is None) or (top_score < STRICT_TOP_SCORE) or (len(relevant_nodes) < MIN_RELEVANT_NODES):
        metrics_update(
            request_id=request_id,
            relevant_count=len(relevant_nodes or []),
            top_score=top_score,
            status="below_threshold",
            total_latency_ms=int((time.perf_counter() - total_t0) * 1000),
            answer_len=len("I do not know. The available Ministry of Health guidelines do not address this question.")
        )
        return {
            "answer": "I do not know. The available Ministry of Health guidelines do not address this question.",
            "sources": []
        }

    # Now safe to log retrieval + continue
    metrics_update(
        request_id=request_id,
        relevant_count=len(relevant_nodes or []),
        top_score=top_score
    )
    retrieval_log_nodes(request_id, relevant_nodes or [])

    synth = get_response_synthesizer(
        response_mode="compact",
        text_qa_template=QA_PROMPT.partial_format(chat_history=chat_history)
    )

    prompt_hash = sha256_text(str(QA_PROMPT) + "\n" + (chat_history or ""))
    metrics_update(request_id=request_id, prompt_hash=prompt_hash)

    synth_t0 = time.perf_counter()
    response = synth.synthesize(
        query=body.question,
        nodes=relevant_nodes
    )
    synth_ms = int((time.perf_counter() - synth_t0) * 1000)

    answer_text = str(response)
    save_turn(session_token, "assistant", answer_text)

    total_ms = int((time.perf_counter() - total_t0) * 1000)
    metrics_update(
        request_id=request_id,
        synth_latency_ms=synth_ms,
        total_latency_ms=total_ms,
        answer_len=len(answer_text or ""),
        status="ok"
    )

    # ===== Clean source builder (NO PAGE NUMBERS) =====
    sources = []
    for n in relevant_nodes[:5]:
        meta = n.metadata if isinstance(n.metadata, dict) else {}
        sources.append({
            "document": meta.get("file_name") or meta.get("source") or "unknown",
            "score": round(float(n.score), 3) if n.score is not None else None
        })

    return {
        "answer": answer_text,
        "sources": sources
    }


@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/readyz")
def readyz():
    return {"ready": STATE.ready, "error": STATE.error}

# =============================
# EVALUATION EXPORT ENDPOINT (admin-only via middleware)
# =============================
@app.get("/api/eval/export")
def eval_export(request: Request):
    rows = db_query_all("""
        SELECT
            qm.request_id, qm.ts, qm.username, qm.session_token,
            qm.question_len, qm.top_k, qm.min_score,
            qm.retrieved_count, qm.relevant_count, qm.top_score,
            qm.retrieve_latency_ms, qm.synth_latency_ms, qm.total_latency_ms,
            qm.model_name, qm.model_version, qm.service_version,
            qm.prompt_hash, qm.answer_len, qm.status
        FROM query_metrics qm
        ORDER BY qm.id DESC
        LIMIT 5000
    """)

    header = [
        "request_id","ts","username","session_token",
        "question_len","top_k","min_score",
        "retrieved_count","relevant_count","top_score",
        "retrieve_latency_ms","synth_latency_ms","total_latency_ms",
        "model_name","model_version","service_version",
        "prompt_hash","answer_len","status"
    ]

    def csv_escape(v):
        s = "" if v is None else str(v)
        if any(ch in s for ch in [",", "\n", "\r", '"']):
            s = '"' + s.replace('"', '""') + '"'
        return s

    lines = [",".join(header)]
    for r in rows:
        lines.append(",".join([csv_escape(r[h]) for h in header]))

    content = "\n".join(lines)
    return PlainTextResponse(content, media_type="text/csv")

# =============================
# NEW: MONITORING DASHBOARD (admin-only via middleware)
# =============================
@app.get("/admin/monitor", response_class=HTMLResponse)
def monitor(request: Request):
    # quick summary: last 24h activity + recent errors + latency snapshots
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    q_total = db_query_one("SELECT COUNT(1) AS c FROM query_metrics WHERE ts >= ?", (since,))
    q_ok = db_query_one("SELECT COUNT(1) AS c FROM query_metrics WHERE ts >= ? AND status='ok'", (since,))
    q_fail = db_query_one("SELECT COUNT(1) AS c FROM query_metrics WHERE ts >= ? AND status!='ok'", (since,))

    # last 200 latencies to estimate p50/p95 quickly
    lats = db_query_all("""
        SELECT total_latency_ms FROM query_metrics
        WHERE ts >= ? AND total_latency_ms > 0
        ORDER BY id DESC LIMIT 200
    """, (since,))
    lat_vals = [int(r["total_latency_ms"]) for r in lats if r["total_latency_ms"] is not None]
    lat_vals_sorted = sorted(lat_vals)

    def pct(vals, p):
        if not vals:
            return None
        idx = int(round((p/100.0) * (len(vals)-1)))
        return vals[max(0, min(idx, len(vals)-1))]

    p50 = pct(lat_vals_sorted, 50)
    p95 = pct(lat_vals_sorted, 95)

    errors = db_query_all("""
        SELECT ts, username, path, error_type, error_message
        FROM error_logs
        ORDER BY id DESC
        LIMIT 20
    """)

    html_errors = ""
    for e in errors:
        html_errors += f"<tr><td>{e['ts']}</td><td>{e['username'] or ''}</td><td>{e['path']}</td><td>{e['error_type']}</td><td>{(e['error_message'] or '')}</td></tr>"

    enc_status = "ENABLED" if _ENCRYPTION_ENABLED else "DISABLED"
    sink_status = "ENABLED" if LOG_SINK_URL else "DISABLED"

    return f"""
    <html>
      <head><title>Monitoring</title></head>
      <body style="font-family: Arial; padding: 30px;">
        <h2>Monitoring Dashboard</h2>

        <h3>Service</h3>
        <ul>
          <li><b>Service Version:</b> {SERVICE_VERSION}</li>
          <li><b>Model:</b> {MODEL_NAME} ({MODEL_VERSION})</li>
          <li><b>Ready:</b> {STATE.ready}</li>
          <li><b>Encryption:</b> {enc_status}</li>
          <li><b>External Log Sink:</b> {sink_status}</li>
          <li><b>Retention Days:</b> {RETENTION_DAYS}</li>
          <li><b>Rate limit:</b> {"ON" if RATE_LIMIT_ENABLED else "OFF"} ({RATE_LIMIT_RPM} rpm, burst {RATE_LIMIT_BURST})</li>
        </ul>

        <h3>Last 24 hours</h3>
        <ul>
          <li><b>Total queries:</b> {q_total['c'] if q_total else 0}</li>
          <li><b>OK:</b> {q_ok['c'] if q_ok else 0}</li>
          <li><b>Non-OK:</b> {q_fail['c'] if q_fail else 0}</li>
          <li><b>Latency p50/p95 (ms):</b> {p50 if p50 is not None else "n/a"} / {p95 if p95 is not None else "n/a"}</li>
        </ul>

        <h3>Recent errors (latest 20)</h3>
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse; width: 100%;">
          <tr>
            <th>Time</th><th>User</th><th>Path</th><th>Type</th><th>Message</th>
          </tr>
          {html_errors}
        </table>

        <p style="margin-top: 20px;">
          <a href="/docs">API docs</a> | <a href="/">Home</a>
        </p>
      </body>
    </html>
    """

# =============================
# STARTUP
# =============================
@app.on_event("startup")
def startup():
    try:
        init_db()
        if not db_query_one("SELECT 1 FROM users LIMIT 1"):
            create_user(APP_ADMIN_USER, APP_ADMIN_PASS, "admin")
            log_json("bootstrap_admin")

        # Ensure there is at least one clinician role user in some environments (optional)
        # (No auto-create here; admin can create clinicians via /admin/users)

        if os.path.isdir(PERSIST_DIR) and os.listdir(PERSIST_DIR):
            STATE.index = load_index_only()
        else:
            if not ALLOW_INDEXING:
                raise RuntimeError("Index missing. Set ALLOW_INDEXING=1 to rebuild.")
            STATE.index = build_index_from_pdfs()

        STATE.ready = True
        log_json("startup_ready")

        log_json(
            "service_version",
            service_version=SERVICE_VERSION,
            model_name=MODEL_NAME,
            model_version=MODEL_VERSION,
            require_auth=REQUIRE_AUTH,
            retention_days=RETENTION_DAYS,
            rate_limit_enabled=RATE_LIMIT_ENABLED,
            rate_limit_rpm=RATE_LIMIT_RPM,
            encryption_enabled=_ENCRYPTION_ENABLED,
            log_sink_enabled=bool(LOG_SINK_URL)
        )

        # Run retention cleanup once on startup, then schedule.
        retention_cleanup_once()
        threading.Thread(target=retention_cleanup_loop, daemon=True).start()

    except Exception as e:
        STATE.error = str(e)
        log_json("startup_error", error=str(e))


# =============================
# UI ROUTES (Pilot Professional Interface)
# =============================

@app.get("/ui/login", response_class=HTMLResponse)
def ui_login():
    return """
    <html>
    <head>
        <title>Login - Uganda Health Assistant</title>
        <style>
            body { font-family: Arial; background:#f5f7fa; display:flex; justify-content:center; align-items:center; height:100vh; }
            .box { background:white; padding:40px; border-radius:8px; width:350px; box-shadow:0 4px 10px rgba(0,0,0,0.1); }
            input { width:100%; padding:10px; margin:8px 0; }
            button { width:100%; padding:10px; background:#007bff; color:white; border:none; cursor:pointer; }
            button:hover { background:#0056b3; }
        </style>
    </head>
    <body>
        <div class="box">
            <h2>Login</h2>
            <input id="username" placeholder="Username"/>
            <input id="password" type="password" placeholder="Password"/>
            <button onclick="login()">Login</button>
            <p id="msg" style="color:red;"></p>
        </div>

        <script>
        async function login() {
            const res = await fetch('/auth/login', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value
                })
            });
            if (res.ok) {
                window.location = '/ui/chat';
            } else {
                document.getElementById('msg').innerText = "Invalid credentials";
            }
        }
        </script>
    </body>
    </html>
    """

@app.get("/ui/chat", response_class=HTMLResponse)
def ui_chat():
    return """
    <html>
    <head>
        <title>Uganda Health Assistant</title>
        <style>
            body { font-family: Arial; margin:0; background:#f0f2f5; }
            header { background:#007bff; color:white; padding:15px; display:flex; justify-content:space-between; }
            #chat { padding:20px; max-width:900px; margin:auto; }
            .msg { margin-bottom:15px; padding:12px; border-radius:6px; }
            .user { background:#d9edf7; }
            .assistant { background:white; border:1px solid #ddd; }
            textarea { width:100%; height:80px; padding:10px; }
            button { padding:10px 15px; margin-top:10px; margin-right:5px; }
            .sources { font-size:12px; color:#555; margin-top:8px; }
        </style>
    </head>
    <body>
        <header>
            <div><b>Uganda Health Assistant</b></div>
            <div>
                <a href="/ui/admin" style="color:white; margin-right:15px;">Admin</a>
                <a href="#" onclick="logout()" style="color:white;">Logout</a>

<script>
async function logout() {
    await fetch('/auth/logout', { method: 'POST' });
    window.location = '/ui/login';
}
</script>
            </div>
        </header>

        <div id="chat"></div>

        <div style="max-width:900px; margin:auto; padding:20px;">
            <textarea id="question" placeholder="Ask a clinical question..."></textarea>
            <br/>
            <button onclick="ask()">Ask</button>
            <button onclick="clearChat()">Clear</button>
        </div>

        <script>
        async function ask() {
            const q = document.getElementById('question').value;
            if (!q) return;

            addMessage("You", q, "user");

            document.getElementById('question').value = "";

            const res = await fetch('/api/ask', {
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({question:q})
            });

            if (!res.ok) {
                addMessage("System", "Error processing request.", "assistant");
                return;
            }

            const data = await res.json();
            let sourcesHtml = "";
            if (data.sources && data.sources.length > 0) {
                sourcesHtml = "<div class='sources'><b>Sources:</b><ul>";
                data.sources.forEach(s=>{
                    sourcesHtml += `<li>${s.document} [score ${s.score}]</li>`;
                });
                sourcesHtml += "</ul></div>";
            }

            addMessage("Assistant", data.answer + sourcesHtml, "assistant");
        }

        function addMessage(sender, text, cls) {
            const div = document.createElement('div');
            div.className = 'msg ' + cls;
            div.innerHTML = "<b>" + sender + ":</b><br/>" + text;
            document.getElementById('chat').appendChild(div);
            window.scrollTo(0,document.body.scrollHeight);
        }

        async function clearChat() {
            await fetch('/ui/clear', {method:'POST'});
            document.getElementById('chat').innerHTML = "";
        }
        </script>
    </body>
    </html>
    """

@app.post("/ui/clear")
def ui_clear(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        db_exec("DELETE FROM conversations WHERE session_token=?", (token,))
    return {"ok": True}


@app.get("/ui/admin", response_class=HTMLResponse)
def ui_admin(request: Request):
    user = getattr(request.state, "user", None)

    if not user or not require_role(user, [ROLE_ADMIN]):
        return HTMLResponse(
            "<h3>403 - Admin access required</h3>",
            status_code=403
        )

    return """
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: Arial; padding:30px; }
            input { padding:8px; margin:5px; }
            button { padding:8px 12px; }
        </style>
    </head>
    <body>
        <h2>Admin Panel</h2>

        <h3>Create User</h3>
        <input id="new_user" placeholder="Username"/>
        <input id="new_pass" type="password" placeholder="Password"/>
        <input id="new_role" placeholder="Role (admin|clinician|user)"/>
        <button onclick="createUser()">Create</button>
        <p id="admin_msg"></p>

        <h3>Evaluation Export</h3>
        <a href="/api/eval/export" target="_blank">Download CSV</a>

        <h3>Monitoring</h3>
        <a href="/admin/monitor" target="_blank">Open Dashboard</a>

        <br/><br/>
        <a href="/ui/chat">Back to Chat</a>

        <script>
        async function createUser() {
            const res = await fetch('/admin/users', {
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({
                    username:document.getElementById('new_user').value,
                    password:document.getElementById('new_pass').value,
                    role:document.getElementById('new_role').value
                })
            });

            if (res.ok) {
                document.getElementById('admin_msg').innerText = "User created.";
            } else {
                document.getElementById('admin_msg').innerText = "Failed.";
            }
        }
        </script>
    </body>
    </html>
    """


# =============================
# MAIN
# =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8080)))