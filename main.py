# =============================
# UGANDA HEALTH ASSISTANT
# Runtime-SAFE (NO INDEXING POSSIBLE)
# + Multi-user auth
# + Audit logging (who/when/what)
# + CI/CD-friendly health endpoints + env config
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

# Admin bootstrap user (created on first run if DB empty)
# IMPORTANT: change these in production via env vars.
APP_ADMIN_USER = os.environ.get("APP_USER", "admin")
APP_ADMIN_PASS = os.environ.get("APP_PASS", "secret123")

# Session security
SESSION_COOKIE_NAME = "session"
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "86400"))  # 24h default
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0").strip() == "1"        # set to 1 behind HTTPS
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")                # Lax/Strict/None

# Database
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "app.db"))

# PDFs / Storage
LOCAL_PDF_FOLDER = os.path.join(BASE_DIR, "pdfs")
CLOUD_PDF_FOLDER = "/app/pdfs"

if os.name == "nt":
    PDF_FOLDER = LOCAL_PDF_FOLDER
else:
    PDF_FOLDER = CLOUD_PDF_FOLDER if os.path.exists(CLOUD_PDF_FOLDER) else LOCAL_PDF_FOLDER

PERSIST_DIR = os.path.join(BASE_DIR, "storage")

TOP_K = 8

# CI/CD (optional build metadata)
APP_VERSION = os.environ.get("APP_VERSION", "dev")
GIT_SHA = os.environ.get("GIT_SHA", "unknown")

print("PDF FOLDER:", PDF_FOLDER)
print("STORAGE DIR:", PERSIST_DIR)
print("DB PATH:", DB_PATH)
print("APP VERSION:", APP_VERSION, "GIT SHA:", GIT_SHA)

# =============================
# APP STATE
# =============================
class AppState:
    ready: bool = False
    error: Optional[str] = None
    index = None

STATE = AppState()
LOCK = threading.Lock()

# In-memory chat history (per session token)
# Structure: { session_token: [ {"role": "user"/"assistant", "content": "...", "sources": [...]}, ... ] }
CHAT_STORE: Dict[str, List[Dict[str, Any]]] = {}

# =============================
# LOGGING (CI/CD FRIENDLY)
# =============================
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def log_json(event: str, **fields):
    payload = {
        "ts": utc_now_iso(),
        "event": event,
        "app": "uganda-health-assistant",
        "version": APP_VERSION,
        "git_sha": GIT_SHA,
        **fields
    }
    print(json.dumps(payload, ensure_ascii=False))

# =============================
# DATABASE
# =============================
def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Improve concurrency a bit
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

DB_LOCK = threading.Lock()
DB_CONN = db_connect()

def db_exec(sql: str, params: Tuple = ()) -> None:
    with DB_LOCK:
        DB_CONN.execute(sql, params)
        DB_CONN.commit()

def db_query_one(sql: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
    with DB_LOCK:
        cur = DB_CONN.execute(sql, params)
        row = cur.fetchone()
        return row

def db_query_all(sql: str, params: Tuple = ()) -> List[sqlite3.Row]:
    with DB_LOCK:
        cur = DB_CONN.execute(sql, params)
        rows = cur.fetchall()
        return rows

def init_db():
    # Users: role = admin|user, active 0/1
    db_exec("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pass_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    """)

    # Sessions: token stored server-side
    db_exec("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    # Audit log
    db_exec("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        username TEXT,
        action TEXT NOT NULL,
        path TEXT,
        ip TEXT,
        user_agent TEXT,
        detail TEXT
    );
    """)

    # Indexes (simple)
    db_exec("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);")
    db_exec("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username);")

def pbkdf2_hash_password(password: str, salt_bytes: bytes, iterations: int = 200_000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return base64.b64encode(dk).decode("utf-8")

def create_user(username: str, password: str, role: str = "user", active: int = 1) -> None:
    username = username.strip()
    if not username:
        raise ValueError("username is empty")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")

    salt = os.urandom(16)
    pass_hash = pbkdf2_hash_password(password, salt)
    db_exec(
        "INSERT INTO users (username, pass_hash, salt, role, active, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, pass_hash, base64.b64encode(salt).decode("utf-8"), role, int(active), utc_now_iso())
    )

def verify_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    row = db_query_one("SELECT * FROM users WHERE username = ?", (username,))
    if not row:
        return None
    if int(row["active"]) != 1:
        return None

    salt = base64.b64decode(row["salt"])
    expected = row["pass_hash"]
    got = pbkdf2_hash_password(password, salt)

    # constant time compare
    if not hmac.compare_digest(expected, got):
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "active": int(row["active"])
    }

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    row = db_query_one("SELECT id, username, role, active FROM users WHERE id = ?", (user_id,))
    if not row:
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"], "active": int(row["active"])}

def audit_log(username: Optional[str], action: str, path: str, request: Request, detail: Optional[Dict[str, Any]] = None):
    ip = (request.client.host if request.client else None)
    ua = request.headers.get("user-agent")
    detail_str = json.dumps(detail, ensure_ascii=False) if detail is not None else None
    db_exec(
        "INSERT INTO audit_log (ts, username, action, path, ip, user_agent, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (utc_now_iso(), username, action, path, ip, ua, detail_str)
    )
    log_json("audit", username=username, action=action, path=path, ip=ip)

def new_session(user_id: int, request: Request) -> str:
    token = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    exp = now.timestamp() + SESSION_TTL_SECONDS
    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
    created_at = now.isoformat()

    ip = (request.client.host if request.client else None)
    ua = request.headers.get("user-agent")

    db_exec(
        "INSERT INTO sessions (token, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
        (token, user_id, created_at, expires_at, ip, ua)
    )
    return token

def delete_session(token: str):
    db_exec("DELETE FROM sessions WHERE token = ?", (token,))

def get_session_user(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    row = db_query_one("SELECT token, user_id, expires_at FROM sessions WHERE token = ?", (token,))
    if not row:
        return None
    expires_at = row["expires_at"]
    try:
        exp_ts = datetime.fromisoformat(expires_at).timestamp()
    except Exception:
        # if expires parsing fails, invalidate session
        delete_session(token)
        return None

    if time.time() > exp_ts:
        delete_session(token)
        return None

    user = get_user_by_id(int(row["user_id"]))
    if not user or user["active"] != 1:
        delete_session(token)
        return None
    return user

# =============================
# LOGIN HTML (UNCHANGED)
# =============================
LOGIN_HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Login - Uganda Health Assistant</title>
<style>
body {
  font-family: Arial, sans-serif;
  background: #0b1e3d;
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
}
form {
  background: #142850;
  padding: 30px;
  border-radius: 8px;
  width: 320px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.35);
}
h2 { text-align: center; margin: 0 0 10px 0; }
input {
  width: 100%;
  padding: 10px;
  margin-top: 10px;
  border-radius: 8px;
  border: 1px solid rgba(255,255,255,0.2);
  outline: none;
}
button {
  margin-top: 15px;
  width: 100%;
  padding: 10px;
  background: #00a8ff;
  border: none;
  color: white;
  font-size: 16px;
  cursor: pointer;
  border-radius: 10px;
}
button:active { transform: scale(0.99); }
</style>
</head>
<body>
<form method="post" action="/login">
  <h2>Uganda Health Assistant</h2>
  <input name="username" placeholder="Username" required />
  <input name="password" type="password" placeholder="Password" required />
  <button type="submit">Login</button>
</form>
</body>
</html>
"""

# =============================
# MAIN UI (TABLE SUPPORT + SAFE RENDERER)
# =============================
INDEX_HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Uganda Health Assistant</title>
<style>
:root{
  --bg: #0b1220;
  --panel: #0f1a33;
  --header: #142850;
  --card: #0f1a33;
  --text: #e9eef8;
  --muted: rgba(233,238,248,0.75);
  --accent: #00a8ff;
  --border: rgba(255,255,255,0.08);
}

* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  font-family: Arial, sans-serif;
  background: linear-gradient(180deg, #0b1220 0%, #070c16 100%);
  color: var(--text);
}

.app { height: 100%; display: flex; flex-direction: column; }

header {
  background: linear-gradient(90deg, var(--header), #0d1d3a);
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  border-bottom: 1px solid var(--border);
}

header .title { font-size: 16px; font-weight: 700; line-height: 1.2; }
header .subtitle { font-size: 12px; color: var(--muted); margin-top: 2px; }

.header-left { display: flex; flex-direction: column; min-width: 0; }
.header-actions { display: flex; gap: 8px; align-items: center; }

.btn {
  border: 1px solid var(--border);
  background: rgba(255,255,255,0.06);
  color: var(--text);
  padding: 8px 10px;
  border-radius: 12px;
  font-size: 13px;
  cursor: pointer;
  text-decoration: none;
}
.btn.primary { background: var(--accent); border-color: rgba(0,0,0,0); color: #08111f; font-weight: 700; }
.btn:active { transform: scale(0.99); }

main { flex: 1; display: flex; justify-content: center; overflow: hidden; }

.container {
  width: 100%;
  max-width: 900px;
  height: 100%;
  display: flex;
  flex-direction: column;
  padding: 12px;
  gap: 10px;
}

.statusbar {
  font-size: 12px;
  color: var(--muted);
  padding: 8px 10px;
  border: 1px solid var(--border);
  border-radius: 14px;
  background: rgba(255,255,255,0.04);
}

.chatbox {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: 18px;
  background: rgba(255,255,255,0.03);
}

.msg { display: flex; margin: 10px 0; }
.msg.user { justify-content: flex-end; }
.msg.assistant { justify-content: flex-start; }

.bubble {
  max-width: 92%;
  padding: 10px 12px;
  border-radius: 16px;
  border: 1px solid var(--border);
  white-space: pre-wrap;
  word-wrap: break-word;
  line-height: 1.35;
  font-size: 14px;
}
.msg.user .bubble { background: rgba(0,168,255,0.14); }
.msg.assistant .bubble { background: rgba(255,255,255,0.05); }

/* Table rendering */
.md-table-wrap {
  overflow-x: auto;
  margin-top: 8px;
  border: 1px solid rgba(255,255,255,0.10);
  border-radius: 12px;
}
.md-table {
  width: 100%;
  border-collapse: collapse;
  min-width: 520px;
}
.md-table th, .md-table td {
  border: 1px solid rgba(255,255,255,0.10);
  padding: 8px 10px;
  vertical-align: top;
  text-align: left;
}
.md-table th { background: rgba(0,0,0,0.18); font-weight: 700; }

.sources {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px dashed rgba(255,255,255,0.18);
  font-size: 12px;
  color: var(--muted);
}
.sources .src { display: block; margin-top: 4px; }

.composer {
  display: flex;
  gap: 10px;
  align-items: center;
  padding: 10px;
  border: 1px solid var(--border);
  border-radius: 18px;
  background: rgba(255,255,255,0.04);
}
.composer input {
  flex: 1;
  padding: 12px;
  border-radius: 14px;
  border: 1px solid var(--border);
  background: rgba(0,0,0,0.2);
  color: var(--text);
  outline: none;
  font-size: 14px;
}
.composer input::placeholder { color: rgba(233,238,248,0.55); }

.smallhint { font-size: 12px; color: rgba(233,238,248,0.55); padding: 0 4px; }

@media (min-width: 768px) {
  header .title { font-size: 18px; }
  .bubble { font-size: 15px; max-width: 75%; }
}
</style>
</head>
<body>
<div class="app">
  <header>
    <div class="header-left">
      <div class="title">Uganda Health Assistant</div>
      <div class="subtitle" id="subtitle">Guideline assistant (RAG)</div>
    </div>
    <div class="header-actions">
      <button class="btn" onclick="clearChat()">Clear</button>
      <a class="btn" href="/logout">Logout</a>
    </div>
  </header>

  <main>
    <div class="container">
      <div class="statusbar" id="statusbar">Checking status…</div>
      <div class="chatbox" id="chatbox"></div>

      <div class="composer">
        <input id="q" placeholder="Type your question…" autocomplete="off" />
        <button class="btn primary" onclick="ask()">Ask</button>
      </div>
      <div class="smallhint">Tip: press Enter to send.</div>
    </div>
  </main>
</div>

<script>
function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, function(m) {
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]);
  });
}

function scrollToBottom() {
  const box = document.getElementById("chatbox");
  box.scrollTop = box.scrollHeight;
}

function parseMarkdownTable(lines) {
  if (!lines || lines.length < 2) return null;
  const trim = (x) => (x || "").trim();
  const splitRow = (row) => {
    let r = trim(row);
    if (!r.startsWith("|")) return null;
    r = r.replace(/^\\|/, "").replace(/\\|$/, "");
    return r.split("|").map(c => trim(c));
  };

  const header = splitRow(lines[0]);
  const sep = splitRow(lines[1]);
  if (!header || !sep) return null;

  const looksLikeSep = sep.every(c => /^:?-{3,}:?$/.test(c) || c === "---" || c === "--");
  if (!looksLikeSep) return null;

  const rows = [];
  for (let i = 2; i < lines.length; i++) {
    const r = splitRow(lines[i]);
    if (!r) return null;
    rows.push(r);
  }
  return { header, rows };
}

function renderAnswerWithTables(bubble, text) {
  const raw = (text || "").replace(/\\r/g, "");
  const lines = raw.split("\\n");

  let i = 0;

  const appendTextBlock = (blockLines) => {
    if (!blockLines.length) return;
    const div = document.createElement("div");
    div.innerHTML = escapeHtml(blockLines.join("\\n"));
    bubble.appendChild(div);
  };

  while (i < lines.length) {
    let block = [];
    while (i < lines.length && lines[i].trim() !== "") {
      block.push(lines[i]);
      i++;
    }
    while (i < lines.length && lines[i].trim() === "") {
      i++;
      if (bubble.lastChild) {
        const spacer = document.createElement("div");
        spacer.style.height = "8px";
        bubble.appendChild(spacer);
      }
    }
    if (!block.length) continue;

    const maybeTable = parseMarkdownTable(block);
    if (!maybeTable) {
      appendTextBlock(block);
      continue;
    }

    const wrap = document.createElement("div");
    wrap.className = "md-table-wrap";

    const table = document.createElement("table");
    table.className = "md-table";

    const thead = document.createElement("thead");
    const trh = document.createElement("tr");
    maybeTable.header.forEach(h => {
      const th = document.createElement("th");
      th.textContent = h;
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    maybeTable.rows.forEach(r => {
      const tr = document.createElement("tr");
      r.forEach(cell => {
        const td = document.createElement("td");
        td.textContent = cell;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    wrap.appendChild(table);
    bubble.appendChild(wrap);
  }
}

function addMessage(role, text, sources) {
  const box = document.getElementById("chatbox");
  const msg = document.createElement("div");
  msg.className = "msg " + (role === "user" ? "user" : "assistant");

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  if (role === "assistant") {
    renderAnswerWithTables(bubble, text);
  } else {
    bubble.innerHTML = escapeHtml(text);
  }

  if (role === "assistant" && sources && sources.length) {
    const sdiv = document.createElement("div");
    sdiv.className = "sources";
    sdiv.innerHTML = "<b>Sources</b>";
    sources.forEach(s => {
      const line = document.createElement("span");
      line.className = "src";
      line.textContent = "• " + s;
      sdiv.appendChild(line);
    });
    bubble.appendChild(sdiv);
  }

  msg.appendChild(bubble);
  box.appendChild(msg);
  scrollToBottom();
}

async function loadStatus() {
  try {
    const r = await fetch("/api/status");
    const d = await r.json();
    const bar = document.getElementById("statusbar");

    if (d.ready) {
      bar.textContent = "✅ Ready (" + (d.user || "unknown") + ")";
    } else {
      bar.textContent = "⚠️ Not ready: " + (d.error || "Unknown");
    }

    if (!d.openai_enabled) {
      bar.textContent = "⚠️ OPENAI_API_KEY missing (cannot answer questions).";
    }
  } catch (e) {
    document.getElementById("statusbar").textContent = "⚠️ Status error: " + e;
  }
}

async function loadHistory() {
  try {
    const r = await fetch("/api/history");
    if (!r.ok) return;
    const d = await r.json();
    const box = document.getElementById("chatbox");
    box.innerHTML = "";

    (d.history || []).forEach(turn => {
      if (turn.role === "user") addMessage("user", turn.content || "", null);
      if (turn.role === "assistant") addMessage("assistant", turn.content || "", turn.sources || []);
    });
    scrollToBottom();
  } catch (e) {}
}

async function ask() {
  const input = document.getElementById("q");
  const q = (input.value || "").trim();
  if (!q) return;

  input.value = "";
  addMessage("user", q, null);

  try {
    const r = await fetch("/api/ask", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({question: q})
    });

    const d = await r.json();

    if (!r.ok) {
      addMessage("assistant", d.detail || "Error", []);
      return;
    }

    addMessage("assistant", d.answer || "I do not know.", d.sources || []);
  } catch (e) {
    addMessage("assistant", "Network error: " + e, []);
  }
}

async function clearChat() {
  try {
    const r = await fetch("/api/clear", { method: "POST" });
    if (r.ok) {
      const box = document.getElementById("chatbox");
      box.innerHTML = "";
      scrollToBottom();
    }
  } catch (e) {}
}

document.getElementById("q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    ask();
  }
});

loadStatus();
loadHistory();
</script>
</body>
</html>
"""

# =============================
# FASTAPI
# =============================
app = FastAPI()

class AskBody(BaseModel):
    question: str

class CreateUserBody(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=8)
    role: str = Field("user")  # 'user' or 'admin'

class ResetPasswordBody(BaseModel):
    password: str = Field(..., min_length=8)

# =============================
# AUTH HELPERS
# =============================
def session_token(request: Request) -> str:
    return request.cookies.get(SESSION_COOKIE_NAME) or ""

def current_user(request: Request) -> Optional[Dict[str, Any]]:
    token = session_token(request)
    return get_session_user(token)

def is_logged(request: Request) -> bool:
    return current_user(request) is not None

def require_user(request: Request) -> Optional[Dict[str, Any]]:
    user = current_user(request)
    if not user:
        return None
    return user

def require_admin(request: Request) -> Optional[Dict[str, Any]]:
    user = current_user(request)
    if not user:
        return None
    if user.get("role") != "admin":
        return None
    return user

# =============================
# TABLE INTENT DETECTOR
# =============================
def wants_table(question: str) -> bool:
    q = (question or "").strip().lower()
    if not q:
        return False
    triggers = [
        "table", "tabulate", "in a table", "as a table", "table format",
        "put in a table", "render a table", "show as table", "show in table",
        "summarize in a table", "format as table"
    ]
    return any(t in q for t in triggers)

# =============================
# SOURCE FORMATTER (NO PAGE NUMBERS)
# =============================
def format_sources(retrieved) -> List[str]:
    out: List[str] = []
    seen = set()

    for r in retrieved:
        node = getattr(r, "node", None)
        if not node:
            continue
        meta = node.metadata or {}
        source_file = meta.get("source_file") or meta.get("file_name") or meta.get("filename") or meta.get("source")
        if source_file:
            key = str(source_file)
            if key in seen:
                continue
            seen.add(key)
            out.append(f"{source_file}")
    return out

# =============================
# CHAT HISTORY
# =============================
def append_history(skey: str, role: str, content: str, sources: Optional[List[str]] = None):
    with LOCK:
        if skey not in CHAT_STORE:
            CHAT_STORE[skey] = []
        entry = {"role": role, "content": content}
        if sources is not None:
            entry["sources"] = sources
        CHAT_STORE[skey].append(entry)
        if len(CHAT_STORE[skey]) > 60:
            CHAT_STORE[skey] = CHAT_STORE[skey][-60:]

# =============================
# LOAD-ONLY INDEX
# =============================
def load_index_only():
    if not OPENAI_ENABLED:
        raise RuntimeError("OPENAI_API_KEY is missing")

    from llama_index.core import StorageContext, load_index_from_storage, Settings
    from llama_index.core.prompts import PromptTemplate
    from llama_index.llms.openai import OpenAI
    from llama_index.embeddings.openai import OpenAIEmbedding

    COMPREHENSIVE_PROMPT = PromptTemplate(
        """You are a clinical guideline assistant.

Rules (must follow):
- Use ONLY the provided context. Do not use outside knowledge.
- If the context does not contain the answer, say exactly: I do not know.
- Be comprehensive and practical: include key criteria, steps, thresholds, and exceptions IF they are present in the context.
- Structure your answer with short headings and numbered steps when helpful.
- Do not invent missing cutoffs, doses, eligibility rules, timelines, or contraindications.

Context:
{context_str}

Question: {query_str}

Answer:"""
    )

    TABLE_PROMPT = PromptTemplate(
        """You are a clinical guideline assistant.

Rules (must follow):
- Use ONLY the provided context. Do not use outside knowledge.
- If the context does not contain the answer, say exactly: I do not know.
- The user asked for a TABLE.
- Output MUST be a markdown table using pipe syntax (| col | col |).
- Include only rows/columns supported by the context.
- If you need to add a short note, put it AFTER the table as plain text.

Context:
{context_str}

Question: {query_str}

Answer (markdown table):"""
    )

    Settings.llm = OpenAI(api_key=OPENAI_API_KEY, model="gpt-4o-mini")
    Settings.embed_model = OpenAIEmbedding(api_key=OPENAI_API_KEY, model="text-embedding-3-small")

    if not os.path.isdir(PERSIST_DIR) or not os.listdir(PERSIST_DIR):
        raise RuntimeError("Index storage missing or empty")

    storage = StorageContext.from_defaults(persist_dir=PERSIST_DIR)
    index = load_index_from_storage(storage)

    return index, COMPREHENSIVE_PROMPT, TABLE_PROMPT

# =============================
# STARTUP
# =============================
@app.on_event("startup")
def startup():
    try:
        init_db()

        # Bootstrap admin if no users exist
        row = db_query_one("SELECT COUNT(*) AS n FROM users", ())
        n = int(row["n"]) if row else 0
        if n == 0:
            create_user(APP_ADMIN_USER, APP_ADMIN_PASS, role="admin", active=1)
            log_json("bootstrap_admin_created", username=APP_ADMIN_USER)

        idx, prompt, table_prompt = load_index_only()
        STATE.index = (idx, prompt, table_prompt)
        STATE.ready = True
        log_json("startup_ready")
    except Exception as e:
        STATE.error = str(e)
        log_json("startup_error", error=str(e))

# =============================
# MIDDLEWARE (OPTIONAL AUDIT OF ALL REQUESTS)
# =============================
@app.middleware("http")
async def request_audit_middleware(request: Request, call_next):
    # We keep this light: only log request completion with status.
    # High-detail actions (login/ask/admin ops) are explicitly audited below.
    start = time.time()
    resp = await call_next(request)
    dur_ms = int((time.time() - start) * 1000)

    user = current_user(request)
    log_json(
        "http",
        path=str(request.url.path),
        method=request.method,
        status=getattr(resp, "status_code", None),
        ms=dur_ms,
        user=(user["username"] if user else None),
    )
    return resp

# =============================
# ROUTES
# =============================
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not is_logged(request):
        return HTMLResponse(LOGIN_HTML)
    return HTMLResponse(INDEX_HTML)

# CI/CD health checks
@app.get("/healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION, "git_sha": GIT_SHA}

@app.get("/readyz")
def readyz():
    return {"ready": STATE.ready, "error": STATE.error, "openai_enabled": OPENAI_ENABLED}

@app.get("/api/status")
def status(request: Request):
    user = current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    return {
        "ready": STATE.ready,
        "error": STATE.error,
        "openai_enabled": OPENAI_ENABLED,
        "user": user["username"],
        "role": user["role"],
        "version": APP_VERSION,
        "git_sha": GIT_SHA
    }

@app.get("/api/history")
def history(request: Request):
    user = require_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    skey = session_token(request)
    with LOCK:
        hist = CHAT_STORE.get(skey, [])
    return {"history": hist}

@app.post("/api/clear")
def clear(request: Request):
    user = require_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    skey = session_token(request)
    with LOCK:
        CHAT_STORE[skey] = []
    audit_log(user["username"], "clear_chat", "/api/clear", request, detail=None)
    return {"ok": True}

# =============================
# LOGIN / LOGOUT (MULTI-USER)
# =============================
@app.post("/login")
async def login(request: Request):
    form = await request.form()
    username = (form.get("username") or "").strip()
    password = (form.get("password") or "")

    user = verify_user(username, password)
    if not user:
        audit_log(username or None, "login_failed", "/login", request, detail={"reason": "invalid_credentials"})
        return HTMLResponse(LOGIN_HTML, status_code=401)

    token = new_session(user["id"], request)
    audit_log(user["username"], "login_success", "/login", request, detail={"role": user["role"]})

    r = RedirectResponse("/", status_code=302)
    r.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE
    )
    return r

@app.get("/logout")
def logout(request: Request):
    token = session_token(request)
    user = current_user(request)
    if token:
        delete_session(token)

    if user:
        audit_log(user["username"], "logout", "/logout", request, detail=None)

    r = RedirectResponse("/", status_code=302)
    r.delete_cookie(SESSION_COOKIE_NAME)
    return r

# =============================
# ADMIN: USER MANAGEMENT
# =============================
@app.get("/api/users")
def list_users(request: Request):
    admin = require_admin(request)
    if not admin:
        return JSONResponse(status_code=403, content={"detail": "Admin only"})

    rows = db_query_all("SELECT username, role, active, created_at FROM users ORDER BY created_at DESC", ())
    out = []
    for r in rows:
        out.append({
            "username": r["username"],
            "role": r["role"],
            "active": int(r["active"]),
            "created_at": r["created_at"]
        })

    audit_log(admin["username"], "list_users", "/api/users", request, detail={"count": len(out)})
    return {"users": out}

@app.post("/api/users")
def admin_create_user(request: Request, body: CreateUserBody):
    admin = require_admin(request)
    if not admin:
        return JSONResponse(status_code=403, content={"detail": "Admin only"})

    role = (body.role or "user").strip().lower()
    if role not in ("user", "admin"):
        return JSONResponse(status_code=400, content={"detail": "role must be 'user' or 'admin'"})

    try:
        create_user(body.username, body.password, role=role, active=1)
    except Exception as e:
        return JSONResponse(status_code=400, content={"detail": f"Could not create user: {e}"})

    audit_log(admin["username"], "create_user", "/api/users", request, detail={"created_username": body.username, "role": role})
    return {"ok": True, "created": body.username, "role": role}

@app.post("/api/users/{username}/reset_password")
def admin_reset_password(request: Request, username: str, body: ResetPasswordBody):
    admin = require_admin(request)
    if not admin:
        return JSONResponse(status_code=403, content={"detail": "Admin only"})

    username = (username or "").strip()
    row = db_query_one("SELECT id, salt FROM users WHERE username = ?", (username,))
    if not row:
        return JSONResponse(status_code=404, content={"detail": "User not found"})

    salt = os.urandom(16)
    pass_hash = pbkdf2_hash_password(body.password, salt)
    db_exec("UPDATE users SET pass_hash = ?, salt = ? WHERE username = ?",
            (pass_hash, base64.b64encode(salt).decode("utf-8"), username))

    audit_log(admin["username"], "reset_password", f"/api/users/{username}/reset_password", request, detail={"target": username})
    return {"ok": True, "reset": username}

@app.post("/api/users/{username}/deactivate")
def admin_deactivate_user(request: Request, username: str):
    admin = require_admin(request)
    if not admin:
        return JSONResponse(status_code=403, content={"detail": "Admin only"})

    username = (username or "").strip()
    if username == admin["username"]:
        return JSONResponse(status_code=400, content={"detail": "You cannot deactivate yourself"})

    row = db_query_one("SELECT username FROM users WHERE username = ?", (username,))
    if not row:
        return JSONResponse(status_code=404, content={"detail": "User not found"})

    db_exec("UPDATE users SET active = 0 WHERE username = ?", (username,))
    # invalidate any sessions for that user
    db_exec("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))

    audit_log(admin["username"], "deactivate_user", f"/api/users/{username}/deactivate", request, detail={"target": username})
    return {"ok": True, "deactivated": username}

@app.get("/api/audit")
def admin_audit(request: Request, limit: int = 50):
    admin = require_admin(request)
    if not admin:
        return JSONResponse(status_code=403, content={"detail": "Admin only"})

    limit = max(1, min(int(limit), 500))
    rows = db_query_all(
        "SELECT ts, username, action, path, ip, user_agent, detail FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    out = []
    for r in rows:
        out.append({
            "ts": r["ts"],
            "username": r["username"],
            "action": r["action"],
            "path": r["path"],
            "ip": r["ip"],
            "user_agent": r["user_agent"],
            "detail": r["detail"]
        })

    audit_log(admin["username"], "view_audit", "/api/audit", request, detail={"limit": limit})
    return {"audit": out}

# =============================
# CORE: ASK (RAG) + AUDIT
# =============================
@app.post("/api/ask")
def ask(request: Request, body: AskBody):
    user = require_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

    if not OPENAI_ENABLED:
        audit_log(user["username"], "ask_blocked_no_key", "/api/ask", request, detail=None)
        return JSONResponse(status_code=503, content={"detail": "OPENAI_API_KEY not configured"})

    if STATE.error:
        audit_log(user["username"], "ask_blocked_state_error", "/api/ask", request, detail={"error": STATE.error})
        return JSONResponse(status_code=500, content={"detail": STATE.error})

    if not STATE.ready or not STATE.index:
        audit_log(user["username"], "ask_blocked_not_ready", "/api/ask", request, detail=None)
        return JSONResponse(status_code=503, content={"detail": "Index not ready"})

    q = (body.question or "").strip()
    if not q:
        return JSONResponse(status_code=400, content={"detail": "Question is empty"})

    skey = session_token(request)
    append_history(skey, "user", q)

    idx, comprehensive_prompt, table_prompt = STATE.index

    retriever = idx.as_retriever(similarity_top_k=TOP_K)
    retrieved = retriever.retrieve(q)
    sources = format_sources(retrieved)

    if not retrieved:
        answer = "I do not know."
        append_history(skey, "assistant", answer, [])
        audit_log(user["username"], "ask_no_retrieval", "/api/ask", request, detail={"question": q})
        return {"answer": answer, "sources": []}

    chosen_prompt = table_prompt if wants_table(q) else comprehensive_prompt
    qe = idx.as_query_engine(text_qa_template=chosen_prompt)
    answer = str(qe.query(q)).strip() or "I do not know."

    append_history(skey, "assistant", answer, sources)

    # Audit: who asked what + basic metadata (don’t store full context)
    audit_log(
        user["username"],
        "ask",
        "/api/ask",
        request,
        detail={
            "question": q,
            "table_requested": wants_table(q),
            "sources_count": len(sources)
        }
    )

    return {"answer": answer, "sources": sources}

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8080)))