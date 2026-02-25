#!/usr/bin/env python3
"""
WeChat Webhook Receiver
=======================

Event-driven architecture — zero polling.

Message receive path:
  wxsend.dll (Wine hook) → writes JSON line to Z:\\tmp\\wechat_incoming.jsonl
                         = /tmp/wechat_incoming.jsonl on Linux
  inotify watcher       → fires instantly on file modification
  _inotify_watcher()    → parses new lines, dispatches to session workers

Message send path:
  wechat_frida_send.py <wxid> <message>   (PRIMARY — no fallback)

HTTP webhook endpoint (port defined by WEBHOOK_PORT) kept for any future
direct-POST capable DLL.

Configuration via environment variables — see .env.example.
"""

import ctypes
import json
import logging
import os
import queue
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
import shutil
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, request, jsonify

# ── Config (from environment) ─────────────────────────────────────────────────

WEBHOOK_HOST = os.environ.get("WEBHOOK_HOST", "0.0.0.0")
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "19089"))
WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", "/webhook/message")

WXSEND_URL = os.environ.get("WXSEND_URL", "http://127.0.0.1:19088")

# OpenClaw / AI gateway integration (optional — set to route messages to an AI agent)
GATEWAY_URL = os.environ.get("GATEWAY_URL", "")
GATEWAY_TOKEN = os.environ.get("GATEWAY_TOKEN", "")
SESSION_PREFIX = os.environ.get("SESSION_PREFIX", "agent:main:wechat:")
SESSIONS_SEND_TIMEOUT = int(os.environ.get("SESSIONS_SEND_TIMEOUT", "60"))
HTTP_POST_TIMEOUT = SESSIONS_SEND_TIMEOUT + 10

# Your WeChat ID — messages from yourself are ignored
SELF_WXID = os.environ.get("SELF_WXID", "")

# Bot mention trigger for group chats (e.g. "@YourBotName")
BOT_MENTION = os.environ.get("BOT_MENTION", "@bot")

SEND_SCRIPT = os.environ.get(
    "SEND_SCRIPT",
    os.path.join(os.path.dirname(__file__), "wechat_frida_send.py"),
)
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/wechat_webhook.log")

# inotify shared file (written by wxsend.dll via Z: drive)
INCOMING_FILE = os.environ.get("INCOMING_FILE", "/tmp/wechat_incoming.jsonl")

# Media handling
MEDIA_TEMP_DIR = os.environ.get("MEDIA_TEMP_DIR", "/tmp/wechat_media")

# MicroMsg.db path for contact name resolution
# Typically: <WINEPREFIX>/drive_c/users/<USER>/Documents/WeChat Files/<wxid>/Msg/MicroMsg.db
MICRO_DB = os.environ.get("MICRO_DB", "")

# pywxdump offsets for WeChatWin.dll
VERSION_OFFSETS = {
    "3.9.2.23": [0x2ffd590, 0x2ffd930, 0x2ffd500, 0x252e178, 0x2ffd90c],
    "3.9.2.26": [0x2fffa30, 0x2fffe30, 0x2fff900, 0x252e178, 0x2fffe0c],
}
WECHAT_VERSION = os.environ.get("WECHAT_VERSION", "3.9.2.23")
KEY_SIZE = 32
PAGE_SIZE = 4096
KDF_ITER = 64000
SQLITE_HDR = b"SQLite format 3\x00"

# DLL injection
INJECT_EXE = os.environ.get(
    "INJECT_EXE",
    os.path.join(os.path.dirname(__file__), "bin", "inject2.exe"),
)
WINEPREFIX = os.environ.get("WINEPREFIX", os.path.expanduser("~/.wine"))

# AI model to use for WeChat sessions (optional)
WECHAT_MODEL = os.environ.get("WECHAT_MODEL", "")

# ── Flask App ────────────────────────────────────────────────────────────────

app = Flask(__name__)

# ── Logging ──────────────────────────────────────────────────────────────────

def _setup_logging() -> logging.Logger:
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    logger = logging.getLogger("wechat_webhook")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    try:
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(logging.Formatter(fmt, datefmt))
        logger.addHandler(fh)
    except Exception as e:
        print(f"Warning: Could not write to {LOG_FILE}: {e}", file=sys.stderr)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter(fmt, datefmt))
    logger.addHandler(sh)

    return logger

log = _setup_logging()

# ── Signal Handling ──────────────────────────────────────────────────────────

_running = True

def _handle_signal(signum, frame):
    global _running
    log.info(f"Received signal {signum} — shutting down cleanly.")
    _running = False

signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)

# ── Contact Cache ────────────────────────────────────────────────────────────

_contact_cache: dict[str, str] = {}
_cache_loaded_at: float = 0.0
CACHE_TTL = 300

def _find_wechat_pid() -> int | None:
    result = subprocess.run(["pgrep", "-f", "WeChat.exe"], capture_output=True, text=True)
    for pid in result.stdout.strip().split("\n"):
        pid = pid.strip()
        if not pid:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().decode("utf-8", errors="ignore")
            if (
                "WeChat.exe" in cmdline
                and "WeChatAppEx" not in cmdline
                and "WeChatPlayer" not in cmdline
                and "WechatUtility" not in cmdline
                and "WeChatOCR" not in cmdline
            ):
                return int(pid)
        except Exception:
            continue
    return None

def _find_wechatwin_base(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if "WeChatWin.dll" in line:
                    parts = line.split()
                    if len(parts) > 2 and parts[2] == "00000000":
                        return int(line.split("-")[0], 16)
    except Exception:
        pass
    return None

def _extract_key(pid: int, dll_base: int, version: str = WECHAT_VERSION) -> bytes | None:
    import struct
    offsets = VERSION_OFFSETS.get(version)
    if not offsets:
        return None
    key_ptr_addr = dll_base + offsets[4]
    try:
        with open(f"/proc/{pid}/mem", "rb") as mem:
            mem.seek(key_ptr_addr)
            ptr_bytes = mem.read(4)
            key_ptr = struct.unpack("<I", ptr_bytes)[0]
            if key_ptr < 0x10000:
                return None
            mem.seek(key_ptr)
            return mem.read(KEY_SIZE)
    except Exception as e:
        log.warning(f"Key extraction failed: {e}")
        return None

def _decrypt_db(key_bytes: bytes, db_path: str, out_path: str) -> bool:
    import hashlib
    try:
        from Crypto.Cipher import AES
    except ImportError:
        log.warning("pycryptodome not installed — cannot decrypt MicroMsg.db")
        return False

    try:
        with open(db_path, "rb") as f:
            data = f.read()
        if len(data) < PAGE_SIZE:
            return False
        salt = data[:16]
        enc_key = hashlib.pbkdf2_hmac("sha1", key_bytes, salt, KDF_ITER, KEY_SIZE)
        with open(out_path, "wb") as out:
            out.write(SQLITE_HDR)
            for i in range(0, len(data), PAGE_SIZE):
                page = data[i : i + PAGE_SIZE] if i > 0 else data[16 : i + PAGE_SIZE]
                if len(page) < 48:
                    break
                iv = page[-48:-32]
                encrypted = page[:-48]
                tail = page[-48:]
                decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(encrypted)
                out.write(decrypted)
                out.write(tail)
        return True
    except Exception as e:
        log.warning(f"DB decryption error: {e}")
        return False

def _build_contact_cache() -> dict[str, str]:
    contacts: dict[str, str] = {}
    if not MICRO_DB:
        log.warning("MICRO_DB not set — contact cache unavailable")
        return contacts
    pid = _find_wechat_pid()
    if not pid:
        log.warning("WeChat.exe not found — contact cache unavailable")
        return contacts
    dll_base = _find_wechatwin_base(pid)
    if not dll_base:
        log.warning("WeChatWin.dll not found — contact cache unavailable")
        return contacts
    key = _extract_key(pid, dll_base)
    if not key:
        log.warning("Could not extract SQLCipher key — contact cache unavailable")
        return contacts
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        if not _decrypt_db(key, MICRO_DB, tmp.name):
            log.warning("MicroMsg.db decryption failed — contact cache unavailable")
            return contacts
        import sqlite3
        conn = sqlite3.connect(tmp.name)
        try:
            cur = conn.execute("SELECT UserName, NickName, Remark FROM Contact")
            for username, nickname, remark in cur:
                display = (remark or "").strip() or (nickname or "").strip() or username
                contacts[username] = display
            log.info(f"Contact cache loaded: {len(contacts)} entries")
        finally:
            conn.close()
    except Exception as e:
        log.warning(f"Contact cache build error: {e}")
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
    return contacts

def get_display_name(wxid: str) -> str:
    return _contact_cache.get(wxid, wxid)

def refresh_contacts_if_needed():
    global _contact_cache, _cache_loaded_at
    now = time.time()
    if now - _cache_loaded_at >= CACHE_TTL:
        log.info("Refreshing contact cache…")
        new_cache = _build_contact_cache()
        if new_cache:
            _contact_cache = new_cache
        _cache_loaded_at = now

# ── Media Handling ────────────────────────────────────────────────────────────

def _ensure_media_dir():
    os.makedirs(MEDIA_TEMP_DIR, exist_ok=True)

# ── Session Routing ───────────────────────────────────────────────────────────

_model_set_sessions: set = set()

def _ensure_session_model(session_key: str):
    """Set model override for new sessions (if WECHAT_MODEL and GATEWAY_URL are set)."""
    if not WECHAT_MODEL or not GATEWAY_URL:
        return
    if session_key in _model_set_sessions:
        return
    try:
        payload = {
            "tool": "session_status",
            "args": {"sessionKey": session_key, "model": WECHAT_MODEL},
            "sessionKey": session_key,
        }
        headers = {
            "Authorization": f"Bearer {GATEWAY_TOKEN}",
            "Content-Type": "application/json",
        }
        requests.post(GATEWAY_URL, json=payload, headers=headers, timeout=10)
        _model_set_sessions.add(session_key)
        log.info(f"Set model {WECHAT_MODEL} for {session_key}")
    except Exception as e:
        log.warning(f"Failed to set model for {session_key}: {e}")

def route_to_session(session_key: str, message: str) -> str | None:
    """Route message to AI gateway session. Returns reply text or None."""
    if not GATEWAY_URL or not GATEWAY_TOKEN:
        log.warning("GATEWAY_URL/GATEWAY_TOKEN not set — cannot route to session")
        return None
    _ensure_session_model(session_key)
    payload = {
        "tool": "sessions_send",
        "args": {
            "sessionKey": session_key,
            "message": message,
            "timeoutSeconds": SESSIONS_SEND_TIMEOUT,
        },
        "sessionKey": session_key,
    }
    headers = {
        "Authorization": f"Bearer {GATEWAY_TOKEN}",
        "Content-Type": "application/json",
    }
    try:
        r = requests.post(
            GATEWAY_URL,
            json=payload,
            headers=headers,
            timeout=HTTP_POST_TIMEOUT,
        )
        data = r.json()
        if not data.get("ok"):
            log.warning(f"sessions_send failed: {data.get('error')}")
            return None
        details = data.get("result", {}).get("details", {})
        status = details.get("status")
        reply = details.get("reply", "").strip()
        log.debug(f"sessions_send response: status={status}, reply_len={len(reply)}")
        if status == "ok" and reply:
            log.info(f"Got reply from {session_key}: {reply[:100]}…")
            return reply
        else:
            log.warning(f"sessions_send status={status}, reply_empty={not reply} for {session_key}")
            return None
    except Exception as e:
        log.warning(f"route_to_session error: {e}")
        return None

def send_wechat_reply(target_wxid: str, reply: str):
    """Send reply via wechat_frida_send.py — PRIMARY sender."""
    try:
        result = subprocess.run(
            [sys.executable, SEND_SCRIPT, target_wxid, reply],
            timeout=15,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            log.info(f"Reply sent to {target_wxid}: {reply[:80]}")
        else:
            log.warning(
                f"wechat_frida_send.py exited {result.returncode}: {result.stderr.strip()}"
            )
    except Exception as e:
        log.warning(f"Failed to send WeChat reply to {target_wxid}: {e}")

# ── Per-Session Worker Threads ────────────────────────────────────────────────

_worker_queues: dict[str, queue.Queue] = {}
_worker_lock = threading.Lock()
_SENTINEL = object()

def _session_worker(session_key: str, q: queue.Queue):
    log.info(f"[worker] started for {session_key}")
    while True:
        try:
            item = q.get(timeout=120)
        except queue.Empty:
            with _worker_lock:
                _worker_queues.pop(session_key, None)
            log.info(f"[worker] idle timeout — exiting for {session_key}")
            return
        if item is _SENTINEL:
            with _worker_lock:
                _worker_queues.pop(session_key, None)
            log.info(f"[worker] shutdown signal — exiting for {session_key}")
            return
        msg = item
        try:
            _process_message_blocking(msg, session_key)
        except Exception as e:
            log.error(f"[worker] unhandled error for {session_key}: {e}")
        finally:
            q.task_done()
        if not _running:
            with _worker_lock:
                _worker_queues.pop(session_key, None)
            return

def _get_or_create_worker(session_key: str) -> queue.Queue:
    with _worker_lock:
        if session_key not in _worker_queues:
            q: queue.Queue = queue.Queue()
            _worker_queues[session_key] = q
            t = threading.Thread(
                target=_session_worker,
                args=(session_key, q),
                daemon=True,
                name=f"wechat-{session_key[-20:]}",
            )
            t.start()
        return _worker_queues[session_key]

def _dispatch_message(msg: dict, session_key: str):
    q = _get_or_create_worker(session_key)
    q.put(msg)

def _shutdown_workers():
    with _worker_lock:
        keys = list(_worker_queues.keys())
    for key in keys:
        with _worker_lock:
            q = _worker_queues.get(key)
        if q:
            q.put(_SENTINEL)

# ── Message Processing ────────────────────────────────────────────────────────

def _process_message_blocking(msg: dict, session_key: str):
    from_user = msg.get("fromUser", "")
    from_group = msg.get("fromGroup", "")
    is_group = from_group.endswith("@chatroom")
    content = msg.get("content", "").strip()
    msg_type = msg.get("msgType", 1)

    display_name = get_display_name(from_user)

    if msg_type == 3:
        content = "[Image received]"
    elif msg_type == 34:
        content = "[Audio received]"
    elif msg_type == 43:
        content = "[Video received]"
    elif msg_type == 49:
        content = "[Document received]"

    if is_group:
        text = (
            f"WeChat group message from {display_name} (wxid: {from_user}) "
            f"in group {from_group}: {content}"
        )
        reply_target = from_group
    else:
        text = f"WeChat message from {display_name} (wxid: {from_user}): {content}"
        reply_target = from_user

    if len(text) > 1200:
        text = text[:1197] + "..."

    log.info(f"Routing to session {session_key}")
    reply = route_to_session(session_key, text)

    if reply and reply.strip() not in ("NO_REPLY", "HEARTBEAT_OK"):
        send_wechat_reply(reply_target, reply)
    else:
        log.info(f"Session {session_key} returned no reply — skipping send")

def _preprocess_message(msg: dict) -> str | None:
    from_user = msg.get("fromUser", "")
    content = msg.get("content", "").strip()
    from_group = msg.get("fromGroup", "")
    is_group = from_group.endswith("@chatroom")

    if SELF_WXID and from_user == SELF_WXID:
        return None
    if not content:
        return None

    if is_group:
        mention_triggers = [BOT_MENTION]
        if SELF_WXID:
            mention_triggers.append(SELF_WXID)
        if not any(t in content for t in mention_triggers):
            return None
        session_key = f"{SESSION_PREFIX}{from_group}"
    else:
        session_key = f"{SESSION_PREFIX}{from_user}"

    return session_key

# ── inotify Watcher (event-driven, zero polling) ──────────────────────────────

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_IN_MODIFY = 0x00000002
_IN_CLOSE_WRITE = 0x00000008

def _inotify_watcher():
    """
    Watch INCOMING_FILE for writes using inotify.
    When the DLL appends a line, this fires immediately.
    No polling — pure event-driven.
    """
    Path(INCOMING_FILE).touch(exist_ok=True)

    ifd = _libc.inotify_init()
    if ifd < 0:
        log.error(f"inotify_init failed: errno={ctypes.get_errno()}")
        return

    wd = _libc.inotify_add_watch(
        ifd,
        INCOMING_FILE.encode(),
        _IN_MODIFY | _IN_CLOSE_WRITE,
    )
    if wd < 0:
        log.error(f"inotify_add_watch failed: errno={ctypes.get_errno()}")
        os.close(ifd)
        return

    log.info(f"inotify watcher active on {INCOMING_FILE}")

    file_pos = 0

    while _running:
        rlist, _, _ = select.select([ifd], [], [], 1.0)
        if not rlist:
            continue

        try:
            os.read(ifd, 4096)
        except OSError:
            break

        try:
            with open(INCOMING_FILE, "r", encoding="utf-8", errors="replace") as f:
                f.seek(file_pos)
                new_lines = f.readlines()
                file_pos = f.tell()
        except Exception as e:
            log.warning(f"inotify: error reading {INCOMING_FILE}: {e}")
            continue

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                log.warning(f"inotify: invalid JSON: {e} — line: {line[:80]}")
                continue

            session_key = _preprocess_message(msg)
            if session_key:
                log.info(f"inotify: message from {msg.get('fromUser','?')} → {session_key}")
                _dispatch_message(msg, session_key)
            else:
                log.debug(f"inotify: message skipped (preprocess): {line[:80]}")

    os.close(ifd)
    log.info("inotify watcher exited")

# ── HTTP Webhook Endpoint ─────────────────────────────────────────────────────

@app.route(WEBHOOK_PATH, methods=["POST"])
def webhook_message():
    try:
        data = request.get_json(force=True)
    except Exception as e:
        log.warning(f"Failed to parse JSON: {e}")
        return jsonify({"error": "invalid json"}), 400

    session_key = _preprocess_message(data)
    if session_key is None:
        log.debug(f"Message skipped (preprocessor): {data}")
        return jsonify({"status": "skipped"}), 200

    log.info(f"HTTP webhook received message for {session_key}")
    _dispatch_message(data, session_key)
    return jsonify({"status": "queued"}), 202

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": int(time.time())}), 200

# ── DLL Auto-Injection ────────────────────────────────────────────────────────

def _ensure_dll_injected():
    """Inject wxsend.dll if not already running (checks port 19088)."""
    log.info(f"Checking if wxsend.dll is reachable at {WXSEND_URL}…")
    try:
        r = requests.get(f"{WXSEND_URL}/status", timeout=3)
        r.json()
        log.info("wxsend.dll already running.")
        return True
    except Exception:
        pass

    log.info("wxsend.dll not reachable — running DLL injection…")
    env = os.environ.copy()
    env["WINEPREFIX"] = WINEPREFIX
    env.setdefault("DISPLAY", ":99")
    try:
        subprocess.Popen(
            ["wine", INJECT_EXE],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        log.warning(f"Failed to launch inject2.exe: {e}")
        return False

    log.info("Waiting up to 10s for wxsend.dll to respond on port 19088…")
    deadline = time.time() + 10
    while time.time() < deadline:
        time.sleep(1)
        try:
            r = requests.get(f"{WXSEND_URL}/status", timeout=2)
            r.json()
            log.info("wxsend.dll now reachable after injection.")
            return True
        except Exception:
            pass

    log.warning("wxsend.dll did not respond within 10s — proceeding anyway.")
    return False

# ── Polling Fallback ──────────────────────────────────────────────────────────

def _poll_dll_messages():
    """Fallback: poll wxsend.dll HTTP API for new messages."""
    last_ts = int(time.time()) - 60
    poll_interval = 0.5
    while True:
        try:
            resp = requests.get(f"{WXSEND_URL}/messages?since={last_ts}", timeout=5)
            data = resp.json()
            msgs = data.get("messages", [])
            if msgs:
                log.info(f"Polled {len(msgs)} message(s)")
            for msg in msgs:
                if SELF_WXID and msg.get("fromUser") == SELF_WXID:
                    continue
                ts = msg.get("timestamp", 0)
                if ts >= last_ts:
                    last_ts = ts + 1
                wxid = msg.get("fromUser", "")
                if not wxid:
                    continue
                session_key = f"{SESSION_PREFIX}{wxid}"
                _process_message_blocking(msg, session_key)
        except Exception as e:
            log.warning(f"Poll error: {e}")
        time.sleep(poll_interval)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info("WeChat Webhook Receiver starting (event-driven, zero polling)")
    log.info(f"  Incoming file: {INCOMING_FILE}")
    log.info(f"  HTTP webhook:  http://{WEBHOOK_HOST}:{WEBHOOK_PORT}{WEBHOOK_PATH}")
    log.info(f"  Health:        http://{WEBHOOK_HOST}:{WEBHOOK_PORT}/health")
    log.info(f"  Send script:   {SEND_SCRIPT}")
    log.info(f"  Gateway:       {GATEWAY_URL or '(not configured)'}")
    log.info(f"  Session pfx:   {SESSION_PREFIX}")
    log.info("=" * 60)

    log.info("Loading contact cache…")
    refresh_contacts_if_needed()

    _ensure_dll_injected()

    try:
        inotify_t = threading.Thread(
            target=_inotify_watcher,
            daemon=True,
            name="inotify-watcher",
        )
        inotify_t.start()
        log.info("inotify watcher thread started")
    except Exception as e:
        log.warning(f"inotify watcher failed to start: {e}")

    poll_t = threading.Thread(
        target=_poll_dll_messages,
        daemon=True,
        name="poll-dll",
    )
    poll_t.start()
    log.info("DLL polling thread started")

    try:
        app.run(
            host=WEBHOOK_HOST,
            port=WEBHOOK_PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        pass
    finally:
        log.info("Shutting down…")
        _shutdown_workers()
        log.info("Webhook receiver stopped.")

if __name__ == "__main__":
    main()
