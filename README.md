# WeChat Linux Bridge 🐧💬

Run WeChat desktop on Linux via Wine with automated message sending and receiving through DLL injection.

## What is this?

This project lets you run WeChat on a headless Linux server and programmatically send/receive messages. It works by:

1. Running WeChat.exe inside Wine on a virtual display (Xvfb)
2. Injecting a custom DLL (`wxsend.dll`) that hooks WeChat's internal send/receive functions
3. Exposing an HTTP API (port 19088) for sending messages and reading incoming ones
4. Running a Python webhook receiver that routes messages to your application

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Wine Environment                    │
│                                                        │
│  WeChat.exe ──► wxsend.dll (injected)                 │
│                    │                                   │
│                    ├── HTTP Server :19088              │
│                    │     GET /status                   │
│                    │     GET /messages?since=TS         │
│                    │     POST /api/?type=2 (send)       │
│                    │                                   │
│                    └── File write (inotify)            │
│                         /tmp/wechat_incoming.jsonl     │
└──────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌──────────────────────┐
│  wechat_frida_  │    │ wechat_webhook_      │
│  send.py        │    │ receiver.py          │
│  (send msgs)    │    │ (receive + route)    │
│                 │    │                      │
│  CLI tool for   │    │ inotify watcher +    │
│  sending text   │    │ HTTP webhook +       │
│  and files      │    │ polling fallback     │
└─────────────────┘    └──────────────────────┘
                              │
                              ▼
                       Your Application
                       (AI bot, custom handler, etc.)
```

## Prerequisites

- **Linux** (tested on Ubuntu 22.04/24.04)
- **Wine** (stable, 32-bit): `apt install wine32`
- **Xvfb** (virtual display): `apt install xvfb`
- **Python 3.10+** with pip
- **Cross-compiler** (for DLL compilation): `apt install g++-mingw-w64-i686`
- **WeChat** Windows installer (v3.9.2.23 tested)

## Quick Start

### 1. Install WeChat in Wine

```bash
export WINEPREFIX=~/.wechat-wine
WINEARCH=win32 winecfg  # Initialize 32-bit prefix
wine WeChat_Setup.exe    # Install WeChat
```

### 2. Set up virtual display

```bash
Xvfb :99 -screen 0 1024x768x24 &
export DISPLAY=:99
```

### 3. Start WeChat

```bash
cp .env.example .env
# Edit .env with your paths
bash start-wechat.sh
```

### 4. Scan QR code to log in

```bash
# Take a screenshot to see the QR code
scrot /tmp/wechat_qr.png
# View it on your local machine and scan with WeChat mobile app
```

> **Tip:** Enable auto-login in WeChat settings so you don't need to scan QR after restarts.

### 5. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 6. Send a test message

```bash
python3 wechat_frida_send.py <target_wxid> "Hello from Linux!"
```

### 7. Start the webhook receiver

```bash
python3 wechat_webhook_receiver.py
```

## Compiling the DLL

If you need to recompile `wxsend.dll`:

```bash
i686-w64-mingw32-g++ -shared -o bin/wxsend.dll src/wxsend.cpp \
  -lwsock32 -lws2_32 -static-libgcc -static-libstdc++
```

## Configuration

All configuration is via environment variables. See `.env.example` for the full list.

Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WINEPREFIX` | `~/.wine` | Wine prefix where WeChat is installed |
| `WXSEND_URL` | `http://127.0.0.1:19088` | DLL HTTP server URL |
| `WEBHOOK_PORT` | `19089` | Webhook receiver listen port |
| `SELF_WXID` | _(required)_ | Your WeChat ID (to filter own messages) |
| `GATEWAY_URL` | _(optional)_ | AI gateway URL for message routing |
| `GATEWAY_TOKEN` | _(optional)_ | AI gateway auth token |
| `WECHAT_MODEL` | _(optional)_ | AI model for WeChat sessions |

## HTTP API (DLL)

Once injected, the DLL exposes:

- `GET /status` — `{"hwnd": N, "hooked": 1, "msgCount": N}`
- `GET /messages?since=TIMESTAMP` — Get messages since Unix timestamp
- `POST /api/?type=2` — Send text: `{"wxid": "...", "msg": "..."}`

### Send return codes

The `code` field in send responses is the restored EAX register value (not a return code). A response with `result: "OK"` means the send executed successfully regardless of the code value.

## Systemd Service

```bash
sudo cp wechat-webhook.service /etc/systemd/system/
sudo cp wechat.slice /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wechat-webhook.service
```

The `wechat.slice` limits CPU (80%) and RAM (6GB) to prevent WeChat from consuming all resources.

## Supported WeChat Versions

| Version | Status | Notes |
|---------|--------|-------|
| 3.9.2.23 | ✅ Tested | Recommended |
| 3.9.2.26 | ⚠️ Offsets included | Untested |

For other versions, you'll need to find the correct offsets for `SendTextMsg`, `GetSendMessageMgr`, `FreeChatMsg`, and the receive hook in `WeChatWin.dll`.

## Known Issues

- **Wine networking:** The DLL's built-in webhook push (`PostMessageToWebhook`) may not work under Wine's Winsock. The polling fallback handles this automatically.
- **Send requires active GUI:** `SendTextMsg` uses `SendMessageW` to the WeChat window proc. If the GUI isn't rendering (black screen), sends may silently fail.
- **Multiple DLL injections:** Re-injecting the DLL while a previous instance is loaded will fail to bind the HTTP port. Restart WeChat for a clean injection.
- **WeChat updates:** Any WeChat update will likely change DLL offsets, breaking the hooks. Pin your WeChat version.

## Troubleshooting

**DLL not responding on port 19088:**
- Check if WeChat.exe is running: `pgrep -fa WeChat.exe`
- Re-inject: `wine bin/inject2.exe <wine_pid> Z:\\path\\to\\wxsend.dll`
- Check for port conflicts: `ss -tlnp | grep 19088`

**Messages received but replies not sending:**
- Check DLL status: `curl http://127.0.0.1:19088/status`
- If `hooked: 0`, the hook didn't attach — re-inject
- If `code: 0` on send, WeChat's internal state may be broken — restart WeChat

**WeChat shows black screen:**
- Ensure only ONE Xvfb instance on your display: `pgrep -fa Xvfb`
- Kill duplicates and restart: `pkill Xvfb && Xvfb :99 -screen 0 1024x768x24 &`

## Credits

- DLL injection technique inspired by [wxhelper](https://github.com/ttttupup/wxhelper)
- Offset research from the WeChat reverse engineering community

## License

MIT — see [LICENSE](LICENSE)

## ⚠️ Disclaimer

This project is for educational and personal use only. Automated messaging may violate WeChat's Terms of Service. Use at your own risk.
