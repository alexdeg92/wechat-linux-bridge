#!/usr/bin/env python3
"""
wechat_frida_send.py - Send WeChat messages via injected wxsend.dll HTTP hook

Usage: python3 wechat_frida_send.py <wxid> <message>
       python3 wechat_frida_send.py <wxid> -f /path/to/image.jpg

## Architecture
This script does NOT use Frida's Python API to attach to WeChat (which fails for
Wine processes with "connection is closed"). Instead it uses a compiled Win32 DLL
(wxsend.dll) injected into the live WeChat.exe process, which exposes an HTTP
server on 127.0.0.1:19088 (configurable via WXSEND_PORT env var).

## Injection Method
- inject2.exe (Win32 DLL injector) is run under Wine to call LoadLibraryA
  on the target process
- Wine process enumeration: `wine tasklist` shows WeChat.exe as Wine PID
- inject2.exe takes <wine_pid> <dll_path> (dll_path uses Z: for Linux filesystem)

## Offsets (WeChatWin.dll v3.9.2.23 — from wxhelper project):
  WX_SEND_TEXT:           0xce6c80   (SendTextMsg function)
  WX_SEND_MESSAGE_MGR:   0x768140   (GetSendMessageMgr — called for side effects)
  WX_FREE_CHAT_MSG:      0x756960   (FreeChatMsg — called after send)
  WX_RECV_MSG_HOOK:      0xd19a0b   (receive hook insertion point)

## WeChatWin.dll:
  Architecture: PE32 (32-bit), running under Wine WoW64

## HTTP API (port 19088):
  GET  /status              → {"hwnd":N,"hooked":1,"msgCount":N}
  GET  /messages?since=TS   → {"messages":[...], "count":N}
  POST /                    → {"wxid":"...","msg":"..."} → {"code":N,"result":"OK"}

## Note on return code:
  The 'code' field in POST response is EAX after POPAD (restored original EAX
  value, not SendTextMsg's return value). Non-zero code with result:OK means
  the send executed on WeChat's UI thread without crashing.

Configuration via environment variables — see .env.example.
"""

import sys
import json
import os
import subprocess
import time
import urllib.request
import urllib.error
import mimetypes
from pathlib import Path

# ── Config ───────────────────────────────────────────────────────────────────
WXSEND_PORT = int(os.environ.get("WXSEND_PORT", "19088"))
WXSEND_URL = os.environ.get("WXSEND_URL", f"http://127.0.0.1:{WXSEND_PORT}")

# Path to inject2.exe (defaults to bin/ next to this script)
_script_dir = os.path.dirname(os.path.abspath(__file__))
INJECT_EXE = os.environ.get(
    "INJECT_EXE",
    os.path.join(_script_dir, "bin", "inject2.exe"),
)
# Path to wxsend.dll (defaults to bin/ next to this script)
WXSEND_DLL = os.environ.get(
    "WXSEND_DLL",
    os.path.join(_script_dir, "bin", "wxsend.dll"),
)
# Wine DLL path uses Z: which maps to Linux root filesystem
WXSEND_DLL_WINE = "Z:" + WXSEND_DLL

WINEPREFIX = os.environ.get("WINEPREFIX", os.path.expanduser("~/.wine"))
DISPLAY = os.environ.get("DISPLAY", ":99")

INJECT_TIMEOUT = 10  # seconds to wait for HTTP server after injection


# ── Helpers ──────────────────────────────────────────────────────────────────

def check_server() -> dict | None:
    """Return /status dict if wxsend.dll HTTP server is up, else None."""
    try:
        with urllib.request.urlopen(f"{WXSEND_URL}/status", timeout=2) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def get_wechat_wine_pid() -> int | None:
    """Find WeChat.exe Wine PID via `wine tasklist`."""
    try:
        env = {**os.environ, "WINEPREFIX": WINEPREFIX, "DISPLAY": DISPLAY}
        result = subprocess.run(
            ["wine", "tasklist"],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.splitlines():
            if line.startswith("WeChat.exe"):
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1])
    except Exception as e:
        print(f"[-] get_wechat_wine_pid failed: {e}", file=sys.stderr)
    return None


def inject_dll() -> bool:
    """Inject wxsend.dll into WeChat.exe via inject2.exe under Wine."""
    wine_pid = get_wechat_wine_pid()
    if wine_pid is None:
        print("[-] WeChat.exe not found in Wine process list", file=sys.stderr)
        return False

    print(f"[*] Injecting wxsend.dll into WeChat.exe (Wine PID {wine_pid})...")
    env = {**os.environ, "WINEPREFIX": WINEPREFIX, "DISPLAY": DISPLAY}

    result = subprocess.run(
        ["wine", INJECT_EXE, str(wine_pid), WXSEND_DLL_WINE],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    output = result.stdout.strip()
    if "DLL loaded at:" in output or "0x" in output.lower():
        print(f"[+] Injection result: {output}")
        return True
    else:
        print(f"[-] Injection may have failed: stdout={output!r} stderr={result.stderr.strip()!r}")
        return False


def ensure_server() -> bool:
    """Make sure the wxsend.dll HTTP server is up, injecting if needed."""
    status = check_server()
    if status:
        if not status.get("hooked"):
            print(f"[-] wxsend.dll loaded but hook not active: {status}", file=sys.stderr)
            return False
        print(f"[+] wxsend.dll already active: {status}")
        return True

    print("[*] wxsend.dll not loaded — injecting now...")
    if not inject_dll():
        return False

    # Wait for HTTP server to start (DLL spawns a thread with Sleep(2000))
    deadline = time.time() + INJECT_TIMEOUT
    while time.time() < deadline:
        time.sleep(0.5)
        status = check_server()
        if status:
            if status.get("hooked"):
                print(f"[+] wxsend.dll now active: {status}")
                return True

    print("[-] Timed out waiting for wxsend.dll HTTP server", file=sys.stderr)
    return False


def send_message(wxid: str, msg: str) -> bool:
    """POST a send-message request. Returns True if request succeeded."""
    payload = json.dumps({"wxid": wxid, "msg": msg}, ensure_ascii=False).encode("utf-8")
    payload = payload.replace(b"\\n", b"\n")
    req = urllib.request.Request(
        f"{WXSEND_URL}/api/?type=2",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            code = result.get("code", 0)
            res = result.get("result", "?")
            print(f"[+] Send result: code={code} result={res!r}")
            # Note: 'code' is EAX after POPAD (not SendTextMsg return value).
            # Any non-crash response with result:OK is a successful send.
            return res == "OK"
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP error: {e.code} {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Send failed: {e}", file=sys.stderr)
        return False


def send_file(wxid: str, file_path: str) -> bool:
    """
    Send a file (image, document, video, audio) to a contact.

    Supports:
    - Images (jpg, png, gif, bmp, webp)
    - Documents (pdf, doc, docx, xls, xlsx)
    - Audio (mp3, wav, m4a, aac)
    - Video (mp4, mov, avi, mkv)

    Returns True if request succeeded.
    """
    path = Path(file_path)
    if not path.exists():
        print(f"[-] File not found: {file_path}", file=sys.stderr)
        return False

    if not path.is_file():
        print(f"[-] Not a file: {file_path}", file=sys.stderr)
        return False

    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    media_type = _classify_media_type(mime_type)

    print(f"[*] Sending {media_type} to {wxid!r}: {path.name!r}")
    print(f"[*] MIME type: {mime_type}")

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print(f"[-] Failed to read file: {e}", file=sys.stderr)
        return False

    boundary = "----WeChat" + str(int(time.time() * 1000))
    body = bytearray()

    body += f'--{boundary}\r\n'.encode()
    body += b'Content-Disposition: form-data; name="wxid"\r\n\r\n'
    body += wxid.encode("utf-8")
    body += b'\r\n'

    body += f'--{boundary}\r\n'.encode()
    body += b'Content-Disposition: form-data; name="type"\r\n\r\n'
    body += media_type.encode("utf-8")
    body += b'\r\n'

    body += f'--{boundary}\r\n'.encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode()
    body += f'Content-Type: {mime_type}\r\n\r\n'.encode()
    body += file_data
    body += b'\r\n'
    body += f'--{boundary}--\r\n'.encode()

    req = urllib.request.Request(
        f"{WXSEND_URL}/file",
        data=bytes(body),
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            code = result.get("code", 0)
            res = result.get("result", "?")
            print(f"[+] Send result: code={code} result={res!r}")
            return res == "OK"
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP error: {e.code} {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Send failed: {e}", file=sys.stderr)
        return False


def _classify_media_type(mime_type: str) -> str:
    """Classify file as image, document, audio, or video based on MIME type."""
    mime_lower = mime_type.lower()

    if mime_lower.startswith("image/"):
        return "image"
    elif mime_lower.startswith("audio/") or mime_lower in ("application/x-m4a", "application/x-aac"):
        return "audio"
    elif mime_lower.startswith("video/"):
        return "video"
    else:
        return "document"


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Send text or file messages to WeChat contacts via wxsend.dll"
    )
    parser.add_argument("wxid", help="Target WeChat ID (wxid_xxx or group@chatroom)")
    parser.add_argument("message", nargs="?", default=None, help="Text message to send")
    parser.add_argument("-f", "--file", help="File to send (image, document, audio, or video)")
    parser.add_argument("-m", "--message", dest="msg_arg", help="Text message (alternative to positional)")

    args = parser.parse_args()

    wxid = args.wxid
    message = args.message or args.msg_arg
    file_path = args.file

    if not message and not file_path:
        parser.print_help()
        print("\nError: Must specify either a message or --file", file=sys.stderr)
        sys.exit(1)

    if not ensure_server():
        print("[-] Cannot connect to wxsend.dll — aborting", file=sys.stderr)
        sys.exit(2)

    if message:
        print(f"[*] Sending text to {wxid!r}: {message!r}")
        if not send_message(wxid, message):
            print(f"[-] Message send failed", file=sys.stderr)
            sys.exit(3)

    if file_path:
        if not send_file(wxid, file_path):
            print(f"[-] File send failed", file=sys.stderr)
            sys.exit(4)

    print(f"[+] All items sent successfully")
    sys.exit(0)


if __name__ == "__main__":
    main()
