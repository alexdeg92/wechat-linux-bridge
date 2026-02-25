# wechat-linux-bridge

Run WeChat desktop (Windows version) on Linux via Wine with full message send/receive automation through DLL injection.

No Frida required. No ADB. No virtual machine. Just Wine + a small injected Win32 DLL.

---

## What It Is

This project lets you **send and receive WeChat messages programmatically on Linux** by:

1. Running WeChat Windows desktop app inside Wine
2. Injecting a custom Win32 DLL (`wxsend.dll`) into the WeChat process
3. The DLL hooks WeChat's internal send/receive functions directly
4. A Python receiver (`wechat_webhook_receiver.py`) dispatches incoming messages and can route them to any handler — including an AI agent

**Tested with:** WeChat 3.9.2.23 on Wine 8.x / 9.x (Linux x86_64)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Wine process (WeChat.exe)                          │
│                                                     │
│  WeChatWin.dll                                      │
│    ↕ hook (JMP patch)                               │
│  wxsend.dll (injected)                              │
│    ├── HTTP server :19088  ←── wechat_frida_send.py │
│    └── inotify file write  ──→ wechat_webhook_      │
│         /tmp/wechat_incoming.jsonl    receiver.py   │
└─────────────────────────────────────────────────────┘
```

**Receive path (inotify, zero-polling):**
- `wxsend.dll` appends JSON lines to `/tmp/wechat_incoming.jsonl` (via Wine's `Z:\tmp\`)
- Python uses `inotify` to watch the file — fires instantly on any write
- Messages are dispatched to per-sender worker threads

**Send path:**
- `wechat_frida_send.py <wxid> <message>` POSTs to the DLL's HTTP server on `:19088`
- The DLL calls WeChat's `SendTextMsg` on the UI thread via `SendMessage(WM_WXSEND, ...)`

---

## Prerequisites

- Linux x86_64
- Wine (wine32 + wine64) installed
- Python 3.11+
- `xdotool` (for auto-clicking login dialogs)
- `Xvfb` (virtual framebuffer — or a real X display)
- `curl` (for startup verification)
- WeChat Windows installer (v3.9.2.23 recommended — offsets are version-specific)

---

## Setup

### 1. Install WeChat in Wine

```bash
export WINEPREFIX=~/.wechat-wine
WINEARCH=win32 wineboot --init
wine WeChatSetup.exe   # install WeChat
```

### 2. Clone this repo

```bash
git clone https://github.com/youruser/wechat-linux-bridge
cd wechat-linux-bridge
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env with your paths and settings
```

Key variables:
| Variable | Description |
|---|---|
| `WINEPREFIX` | Path to Wine prefix where WeChat is installed |
| `WECHAT_EXE_PATH` | Full path to `WeChat.exe` inside the Wine prefix |
| `SELF_WXID` | Your own WeChat ID (to filter self-messages) |
| `INJECT_EXE` | Path to `inject2.exe` |
| `WXSEND_DLL` | Path to `wxsend.dll` |

### 4. Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Start WeChat with DLL injection

```bash
source .env
bash start-wechat.sh
```

This will:
- Start Xvfb if needed
- Launch WeChat under Wine
- Inject `wxsend.dll` into the WeChat process
- Verify the hook is live on port 19088

### 6. Start the webhook receiver

```bash
source venv/bin/activate
python3 wechat_webhook_receiver.py
```

---

## Sending Messages

```bash
# Text message
python3 wechat_frida_send.py wxid_xxxxxxxxxxxxxxxx "Hello from Linux!"

# With explicit flag
python3 wechat_frida_send.py wxid_xxxxxxxxxxxxxxxx -m "Hello!"

# File/image
python3 wechat_frida_send.py wxid_xxxxxxxxxxxxxxxx -f /path/to/image.jpg

# Group chat
python3 wechat_frida_send.py 12345678901@chatroom "Hello group!"
```

---

## Receiving Messages

By default, incoming messages are logged. To route them to a custom handler, edit `_process_message_blocking()` in `wechat_webhook_receiver.py`.

To integrate with an AI gateway (e.g. OpenClaw), set:
```
GATEWAY_URL=http://your-gateway/tools/invoke
GATEWAY_TOKEN=your_token
```

Messages will be routed to `sessions_send` with key `agent:main:wechat:<wxid>`.

---

## Compiling `wxsend.dll` from Source

The prebuilt DLL is in `bin/wxsend.dll`. To rebuild:

**Requirements:**
- MinGW-w64 cross-compiler (`i686-w64-mingw32-g++`)
- Windows SDK headers (via MinGW)

```bash
i686-w64-mingw32-g++ \
  -shared \
  -o bin/wxsend.dll \
  src/wxsend.cpp \
  -lws2_32 \
  -luser32 \
  -static-libgcc \
  -static-libstdc++ \
  -O2 \
  -s
```

> **Note:** The function offsets in `wxsend.cpp` are specific to **WeChatWin.dll v3.9.2.23**.
> If you use a different version, you must find the correct offsets using a disassembler
> (IDA, Ghidra, x64dbg). Refer to the [wxhelper](https://github.com/ttttupup/wxhelper) project
> for offset tables.

---

## DLL Offsets (WeChatWin.dll v3.9.2.23)

| Symbol | Offset | Description |
|--------|--------|-------------|
| `WX_SEND_TEXT_OFFSET` | `0xce6c80` | `SendTextMsg` function |
| `WX_SEND_MESSAGE_MGR_OFFSET` | `0x768140` | `GetSendMessageMgr` |
| `WX_FREE_CHAT_MSG_OFFSET` | `0x756960` | `FreeChatMsg` |
| `WX_RECV_MSG_HOOK_OFFSET` | `0xd19a0b` | Receive hook insertion point |

---

## How inject2.exe Works

`inject2.exe` is a standard Win32 DLL injector:
1. Opens the target process with `OpenProcess(PROCESS_ALL_ACCESS, ...)`
2. Allocates memory in the target with `VirtualAllocEx`
3. Writes the DLL path to the allocated memory
4. Creates a remote thread pointing to `LoadLibraryA`

It's run under Wine: `wine inject2.exe <wine_pid> <Z:\path\to\wxsend.dll>`

Wine's process IDs visible to `tasklist` are **Wine-internal PIDs** (usually small numbers like 32, 56), not Linux PIDs.

---

## Known Issues

- **Version sensitivity:** Offsets are hardcoded for v3.9.2.23. Other WeChat versions will crash or silently fail.
- **Wine process enumeration:** `wine tasklist` can be slow (~3–5s). Plan accordingly.
- **Hook stability:** The receive hook patches 5 bytes at the hook site with a JMP. If WeChat updates or reloads `WeChatWin.dll`, the hook will be lost until re-injection.
- **32-bit Wine:** WeChat.exe is a 32-bit PE binary. You need `wine32` support (`WINEARCH=win32`).
- **Auto-login:** If WeChat shows a QR code or "Open WeChat" dialog on launch, you may need to handle it once manually. After initial login, WeChat typically stays logged in via the Wine profile's saved credentials.
- **inotify on `/tmp`:** The DLL writes to `Z:\tmp\wechat_incoming.jsonl` = `/tmp/wechat_incoming.jsonl`. Make sure `/tmp` is a real filesystem (not tmpfs restrictions) and the file is writable.

---

## File Structure

```
wechat-linux-bridge/
├── bin/
│   ├── wxsend.dll          # Prebuilt Win32 hook DLL (injected into WeChat)
│   └── inject2.exe         # Win32 DLL injector (run via wine)
├── src/
│   └── wxsend.cpp          # DLL source code
├── wechat_webhook_receiver.py  # Python receiver (inotify + HTTP webhook)
├── wechat_frida_send.py        # Python sender (HTTP → DLL)
├── start-wechat.sh             # Startup script
├── requirements.txt
├── .env.example
├── .gitignore
└── LICENSE
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Credits

- DLL hooking approach inspired by the [wxhelper](https://github.com/ttttupup/wxhelper) project
- SQLCipher key extraction technique from [pywxdump](https://github.com/xaoyaoo/PyWxDump)
