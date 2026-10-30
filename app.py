from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from flask import (
    Flask, abort, flash, redirect, render_template_string, request,
    session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=1_000_000,
)

DB_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "dm_assistant.sqlite3")))
GRAPH_VERSION = os.getenv("GRAPH_API_VERSION", "v26.0")
IG_USER_ID = os.getenv("IG_USER_ID", "").strip()
ACCESS_TOKEN = os.getenv("IG_ACCESS_TOKEN", "").strip()
APP_SECRET = os.getenv("META_APP_SECRET", "").strip()
VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "").strip()
DASH_USER = os.getenv("DASHBOARD_USERNAME", "owner")
DASH_HASH = os.getenv("DASHBOARD_PASSWORD_HASH", "").strip()
BUSINESS_NAME = os.getenv("BUSINESS_NAME", "our page")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ig_message_id TEXT UNIQUE,
                sender_id TEXT NOT NULL,
                sender_name TEXT,
                message_text TEXT NOT NULL,
                received_at TEXT NOT NULL,
                suggested_reply TEXT NOT NULL,
                approved_reply TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                sent_message_id TEXT,
                error TEXT
            )
        """)


def draft_reply(message: str) -> str:
    """Small local intent-based bilingual reply suggester; human approval is required."""
    text = (message or "").strip().lower()
    if not text:
        return "Thanks for reaching out! / संपर्क करने के लिए धन्यवाद!"

    rules = [
        (("price", "cost", "rate", "कितना", "कीमत", "दाम", "रेट"),
         f"Thanks for your interest in {BUSINESS_NAME}! Please tell us which item or service you're asking about, and we'll share the details. / {BUSINESS_NAME} में रुचि दिखाने के लिए धन्यवाद! कृपया बताएं कि आप किस प्रोडक्ट या सर्विस के बारे में पूछ रहे हैं।"),
        (("order", "delivery", "track", "shipping", "ऑर्डर", "डिलीवरी", "पार्सल"),
         "Thanks for your message! Please share your order reference (not any password or OTP), and we'll check the status. / मैसेज के लिए धन्यवाद! कृपया अपना ऑर्डर रेफरेंस भेजें, हम स्टेटस चेक करने में मदद करेंगे।"),
        (("hello", "hi", "hey", "नमस्ते", "हाय", "हेलो"),
         f"Hi! Thanks for messaging {BUSINESS_NAME}. How can we help you today? / नमस्ते! {BUSINESS_NAME} को मैसेज करने के लिए धन्यवाद। हम आपकी कैसे मदद कर सकते हैं?"),
        (("collab", "collaboration", "sponsor", "partnership", "collab", "सहयोग"),
         "Thanks for considering a collaboration! Please share a short overview and your preferred contact details. / कोलैबोरेशन के लिए संपर्क करने का धन्यवाद! कृपया अपना छोटा-सा परिचय और संपर्क जानकारी साझा करें।"),
        (("thanks", "thank you", "धन्यवाद", "शुक्रिया"),
         "You're welcome! Happy to help. / आपका स्वागत है! मदद करके खुशी हुई।"),
        (("location", "address", "where", "कहाँ", "पता", "लोकेशन"),
         "Thanks for asking! Please tell us which location or service area you mean. / पूछने के लिए धन्यवाद! कृपया बताएं कि आप किस लोकेशन या सर्विस एरिया के बारे में पूछ रहे हैं।"),
    ]
    for keywords, reply in rules:
        if any(word in text for word in keywords):
            return reply

    excerpt = message.strip().replace("\n", " ")
    if len(excerpt) > 160:
        excerpt = excerpt[:157] + "..."
    return (
        f"Thanks for reaching out! We received your message: “{excerpt}”. "
        "Could you share a little more detail so we can help? / "
        "मैसेज करने के लिए धन्यवाद! कृपया थोड़ा और विवरण साझा करें ताकि हम आपकी मदद कर सकें।"
    )


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def check_csrf() -> None:
    supplied = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        abort(400, "Invalid form token. Refresh the page and try again.")


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


def verify_meta_signature(raw_body: bytes, signature_header: str | None) -> bool:
    if not APP_SECRET:
        return False
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def extract_events(payload: dict[str, Any]):
    for entry in payload.get("entry", []) or []:
        for event in entry.get("messaging", []) or []:
            message = event.get("message") or {}
            sender_id = (event.get("sender") or {}).get("id")
            text = message.get("text")
            mid = message.get("mid")
            if sender_id and text and not message.get("is_echo"):
                yield str(sender_id), str(text), str(mid or ""), None


def save_incoming(sender_id: str, text: str, mid: str) -> None:
    suggestion = draft_reply(text)
    with db() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO messages
            (ig_message_id, sender_id, message_text, received_at, suggested_reply, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
        """, (mid or None, sender_id, text[:5000], now_iso(), suggestion))


def send_instagram_message(recipient_id: str, text: str) -> dict[str, Any]:
    if not (IG_USER_ID and ACCESS_TOKEN):
        raise RuntimeError("Set IG_USER_ID and IG_ACCESS_TOKEN in .env first.")
    if not text.strip():
        raise ValueError("Reply cannot be empty.")
    url = f"https://graph.instagram.com/{GRAPH_VERSION}/{IG_USER_ID}/messages"
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {ACCESS_TOKEN}"},
        json={"recipient": {"id": recipient_id}, "message": {"text": text}},
        timeout=20,
    )
    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text[:500]}
    if not response.ok:
        raise RuntimeError(f"Instagram API error {response.status_code}: {body}")
    return body


LOGIN_HTML = """
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · DM Assistant</title><style>
body{font:16px system-ui;background:#f3f4f6;margin:0;display:grid;min-height:100vh;place-items:center}
main{background:white;padding:28px;border-radius:16px;width:min(360px,88vw);box-shadow:0 8px 32px #0001}
input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:10px;border:1px solid #ccc;border-radius:9px;font:inherit}
button{background:#222;color:white;cursor:pointer}small{color:#555}
</style></head><body><main><h2>Instagram DM Assistant</h2><p>Owner sign-in</p>
<form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<input name="username" autocomplete="username" placeholder="Username" required>
<input name="password" type="password" autocomplete="current-password" placeholder="Password" required>
<button>Sign in</button></form><p><small>Local approval dashboard. Never enter your Instagram password here.</small></p>
{% for m in get_flashed_messages() %}<p>{{m}}</p>{% endfor %}</main></body></html>
"""

DASH_HTML = """
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Instagram DM Assistant</title><style>
*{box-sizing:border-box}body{font:15px system-ui;background:#f5f6f8;color:#171717;margin:0}
header{background:#171717;color:white;padding:18px 4vw;display:flex;justify-content:space-between;align-items:center}
main{max-width:980px;margin:24px auto;padding:0 16px}.card{background:white;border:1px solid #e5e7eb;border-radius:14px;padding:18px;margin:14px 0}
.meta{color:#666;font-size:13px}.msg{white-space:pre-wrap;background:#f7f7f8;padding:12px;border-radius:9px;margin:10px 0}
textarea{width:100%;min-height:100px;padding:12px;border:1px solid #bbb;border-radius:9px;font:inherit}
button,.linkbtn{border:0;border-radius:8px;padding:10px 14px;background:#171717;color:white;cursor:pointer;font:inherit;text-decoration:none}
.secondary{background:#e8e8eb;color:#111}.danger{background:#9b1c1c}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}.flash{background:#fff6d9;padding:10px;border-radius:8px}
.status{font-weight:600}.empty{padding:28px;text-align:center;color:#666}
</style></head><body>
<header><strong>Instagram DM Assistant</strong><form method="post" action="{{url_for('logout')}}">
<input type="hidden" name="_csrf" value="{{csrf_token()}}"><button class="secondary">Sign out</button></form></header>
<main>
<p>New messages are stored as drafts. Nothing is sent until you edit (if needed) and approve it.</p>
{% for m in get_flashed_messages() %}<p class="flash">{{m}}</p>{% endfor %}
{% if not configured %}<p class="flash">API sending is not configured yet. Add IG_USER_ID and IG_ACCESS_TOKEN to .env. Webhook reception also needs META_APP_SECRET and META_VERIFY_TOKEN.</p>{% endif %}
<h2>Pending messages ({{pending|length}})</h2>
{% for item in pending %}
<section class="card">
<div class="meta">Received {{item['received_at']}} · Sender ID {{item['sender_id']}}</div>
<h3>Incoming message</h3><div class="msg">{{item['message_text']}}</div>
<form method="post" action="{{url_for('approve', message_id=item['id'])}}">
<input type="hidden" name="_csrf" value="{{csrf_token()}}">
<label for="reply{{item['id']}}"><strong>Suggested reply — review and edit before sending</strong></label>
<textarea id="reply{{item['id']}}" name="reply" required>{{item['suggested_reply']}}</textarea>
<div class="row"><button {% if not configured %}disabled title="Configure API credentials first"{% endif %}>Approve &amp; send</button></form>
<form method="post" action="{{url_for('dismiss', message_id=item['id'])}}">
<input type="hidden" name="_csrf" value="{{csrf_token()}}"><button class="secondary">Dismiss</button></form></div>
</section>
{% else %}<div class="card empty">No pending messages yet. Send a DM to your professional account to test the webhook.</div>{% endfor %}
<h2>Recent activity</h2>
{% for item in recent %}
<section class="card"><div class="meta">{{item['received_at']}} · {{item['status']}}</div>
<div class="msg">{{item['message_text']}}</div>
{% if item['approved_reply'] %}<strong>Approved reply</strong><div class="msg">{{item['approved_reply']}}</div>{% endif %}
{% if item['error'] %}<p class="flash">{{item['error']}}</p>{% endif %}</section>
{% else %}<p class="meta">No activity yet.</p>{% endfor %}
</main></body></html>
"""


@app.get("/login")
def login():
    return render_template_string(LOGIN_HTML)


@app.post("/login")
def login_post():
    supplied_csrf = request.form.get("_csrf", "")
    if not session.get("_csrf") or not hmac.compare_digest(supplied_csrf, session["_csrf"]):
        abort(400)
    if not DASH_HASH:
        flash("Set DASHBOARD_PASSWORD_HASH in .env before signing in.")
        return redirect(url_for("login"))
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if hmac.compare_digest(username, DASH_USER) and check_password_hash(DASH_HASH, password):
        session.clear()
        session["logged_in"] = True
        session["_csrf"] = secrets.token_urlsafe(32)
        return redirect(request.args.get("next") or url_for("dashboard"))
    flash("Incorrect username or password.")
    return redirect(url_for("login"))


@app.post("/logout")
@login_required
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@login_required
def dashboard():
    with db() as conn:
        pending = conn.execute(
            "SELECT * FROM messages WHERE status='pending' ORDER BY id DESC LIMIT 100"
        ).fetchall()
        recent = conn.execute(
            "SELECT * FROM messages WHERE status!='pending' ORDER BY id DESC LIMIT 30"
        ).fetchall()
    configured = bool(IG_USER_ID and ACCESS_TOKEN)
    return render_template_string(DASH_HTML, pending=pending, recent=recent, configured=configured)


@app.post("/approve/<int:message_id>")
@login_required
def approve(message_id: int):
    check_csrf()
    reply = request.form.get("reply", "").strip()
    if not reply or len(reply) > 1000:
        flash("Reply must contain 1–1000 characters.")
        return redirect(url_for("dashboard"))
    with db() as conn:
        item = conn.execute(
            "SELECT * FROM messages WHERE id=? AND status='pending'", (message_id,)
        ).fetchone()
    if not item:
        flash("Message is no longer pending.")
        return redirect(url_for("dashboard"))
    try:
        result = send_instagram_message(item["sender_id"], reply)
        sent_id = result.get("message_id") or result.get("id")
        with db() as conn:
            conn.execute("""
                UPDATE messages SET status='sent', approved_reply=?, sent_message_id=?, error=NULL
                WHERE id=? AND status='pending'
            """, (reply, sent_id, message_id))
        flash("Reply sent successfully.")
    except Exception as exc:
        with db() as conn:
            conn.execute(
                "UPDATE messages SET error=? WHERE id=?",
                (str(exc)[:1000], message_id),
            )
        flash(f"Could not send reply: {exc}")
    return redirect(url_for("dashboard"))


@app.post("/dismiss/<int:message_id>")
@login_required
def dismiss(message_id: int):
    check_csrf()
    with db() as conn:
        conn.execute(
            "UPDATE messages SET status='dismissed' WHERE id=? AND status='pending'",
            (message_id,),
        )
    flash("Message dismissed.")
    return redirect(url_for("dashboard"))


@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")
    if mode == "subscribe" and VERIFY_TOKEN and hmac.compare_digest(token, VERIFY_TOKEN):
        return challenge, 200
    return "Verification failed", 403


@app.post("/webhook")
def webhook_receive():
    raw = request.get_data(cache=False)
    if not verify_meta_signature(raw, request.headers.get("X-Hub-Signature-256")):
        abort(403)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        abort(400)
    if payload.get("object") not in {"instagram", "page"}:
        return "Ignored", 200
    for sender_id, message_text, message_id, _ in extract_events(payload):
        save_incoming(sender_id, message_text, message_id)
    return "EVENT_RECEIVED", 200


@app.get("/health")
def health():
    return {"ok": True, "time": now_iso()}, 200


if __name__ == "__main__":
    init_db()
    if not DASH_HASH:
        print("WARNING: Set DASHBOARD_PASSWORD_HASH in .env before exposing this app.")
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
