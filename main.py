# =============================
# UGANDA HEALTH ASSISTANT
# Runtime-SAFE (NO INDEXING BY DEFAULT)
# + Controlled indexing (ALLOW_INDEXING=1)
# + Multi-user auth
# + Audit logging
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
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

# =============================
# CONFIG
# =============================
APP_TITLE = "Uganda Health Assistant"

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_ENABLED = bool(OPENAI_API_KEY)

if not OPENAI_ENABLED:
    print("⚠️ OPENAI_API_KEY is NOT set – app will run in READ-ONLY mode")

# 🔑 INDEXING CONTROL (NEW)
ALLOW_INDEXING = os.environ.get("ALLOW_INDEXING", "0").strip() == "1"

APP_ADMIN_USER = os.environ.get("APP_USER", "admin")
APP_ADMIN_PASS = os.environ.get("APP_PASS", "secret123")

SESSION_COOKIE_NAME = "session"
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "86400"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "app.db"))

LOCAL_PDF_FOLDER = os.path.join(BASE_DIR, "pdfs")
CLOUD_PDF_FOLDER = "/app/pdfs"
PDF_FOLDER = LOCAL_PDF_FOLDER if os.name == "nt" else (CLOUD_PDF_FOLDER if os.path.exists(CLOUD_PDF_FOLDER) else LOCAL_PDF_FOLDER)

PERSIST_DIR = os.path.join(BASE_DIR, "storage")
TOP_K = 8

APP_VERSION = os.environ.get("APP_VERSION", "dev")
GIT_SHA = os.environ.get("GIT_SHA", "unknown")

# =============================
# APP STATE
# =============================
class AppState:
    ready: bool = False
    error: Optional[str] = None
    index = None

STATE = AppState()
LOCK = threading.Lock()
CHAT_STORE: Dict[str, List[Dict[str, Any]]] = {}

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
        "version": APP_VERSION,
        "git_sha": GIT_SHA,
        **fields
    }, ensure_ascii=False))

# =============================
# DATABASE
# =============================
def db_connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
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
    db_exec("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        pass_hash TEXT,
        salt TEXT,
        role TEXT,
        active INTEGER,
        created_at TEXT
    );""")

    db_exec("""CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        created_at TEXT,
        expires_at TEXT,
        ip TEXT,
        user_agent TEXT
    );""")

    db_exec("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY,
        ts TEXT,
        username TEXT,
        action TEXT,
        path TEXT,
        ip TEXT,
        user_agent TEXT,
        detail TEXT
    );""")

# =============================
# PASSWORDS
# =============================
def pbkdf2(password, salt):
    return base64.b64encode(
        hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    ).decode()

def create_user(username, password, role="user"):
    salt = os.urandom(16)
    db_exec(
        "INSERT INTO users VALUES (NULL,?,?,?,?,?,?)",
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
# AUDIT
# =============================
def audit_log(username, action, path, request, detail=None):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    db_exec(
        "INSERT INTO audit_log VALUES (NULL,?,?,?,?,?,?,?)",
        (utc_now_iso(), username, action, path, ip, ua, json.dumps(detail) if detail else None)
    )

# =============================
# INDEX (LOAD ONLY)
# =============================
def load_index_only():
    from llama_index.core import StorageContext, load_index_from_storage, Settings
    from llama_index.llms.openai import OpenAI
    from llama_index.embeddings.openai import OpenAIEmbedding
    from llama_index.core.prompts import PromptTemplate

    if not os.path.isdir(PERSIST_DIR) or not os.listdir(PERSIST_DIR):
        raise RuntimeError("Index storage missing")

    Settings.llm = OpenAI(api_key=OPENAI_API_KEY, model="gpt-4o-mini")
    Settings.embed_model = OpenAIEmbedding(api_key=OPENAI_API_KEY)

    storage = StorageContext.from_defaults(persist_dir=PERSIST_DIR)
    index = load_index_from_storage(storage)

    return index, PromptTemplate("{context_str}\n\n{query_str}"), PromptTemplate("{context_str}\n\n{query_str}")

# =============================
# INDEX (BUILD – CONTROLLED)
# =============================
def build_index_from_pdfs():
    from llama_index.core import VectorStoreIndex, SimpleDirectoryReader, Settings
    from llama_index.llms.openai import OpenAI
    from llama_index.embeddings.openai import OpenAIEmbedding

    if not OPENAI_ENABLED:
        raise RuntimeError("OPENAI_API_KEY missing")

    if not os.path.isdir(PDF_FOLDER):
        raise RuntimeError("PDF folder not found")

    Settings.llm = OpenAI(api_key=OPENAI_API_KEY, model="gpt-4o-mini")
    Settings.embed_model = OpenAIEmbedding(api_key=OPENAI_API_KEY)

    docs = SimpleDirectoryReader(PDF_FOLDER).load_data()
    index = VectorStoreIndex.from_documents(docs)
    index.storage_context.persist(persist_dir=PERSIST_DIR)

    log_json("index_built", docs=len(docs))
    return load_index_only()

# =============================
# FASTAPI
# =============================
app = FastAPI()

@app.on_event("startup")
def startup():
    try:
        init_db()

        if not db_query_one("SELECT 1 FROM users LIMIT 1"):
            create_user(APP_ADMIN_USER, APP_ADMIN_PASS, "admin")
            log_json("bootstrap_admin")

        if os.path.isdir(PERSIST_DIR) and os.listdir(PERSIST_DIR):
            idx = load_index_only()
            log_json("index_loaded")
        else:
            if not ALLOW_INDEXING:
                raise RuntimeError("Index missing. Set ALLOW_INDEXING=1 to rebuild.")
            idx = build_index_from_pdfs()

        STATE.index = idx
        STATE.ready = True
        log_json("startup_ready")

    except Exception as e:
        STATE.error = str(e)
        log_json("startup_error", error=str(e))

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/readyz")
def readyz():
    return {"ready": STATE.ready, "error": STATE.error}

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8080)))