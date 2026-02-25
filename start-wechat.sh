#!/bin/bash
# start-wechat.sh — Launch WeChat under Wine with DLL injection
#
# Required environment variables (set in .env or export before running):
#   WINEPREFIX       — path to your Wine prefix (e.g. ~/.wechat-wine)
#   WECHAT_EXE_PATH  — full path to WeChat.exe inside the Wine prefix
#   WXSEND_DLL       — path to wxsend.dll (Linux filesystem path, Z: not needed here)
#   INJECT_EXE       — path to inject2.exe (Linux filesystem path)
#
# Optional:
#   DISPLAY          — X display to use (default: :99)
#   WECHAT_SLICE     — systemd slice for resource limits (default: none)

set -e

: "${WINEPREFIX:?WINEPREFIX must be set (e.g. ~/.wechat-wine)}"
: "${WECHAT_EXE_PATH:?WECHAT_EXE_PATH must be set (e.g. ~/.wechat-wine/drive_c/.../WeChat.exe)}"
: "${WXSEND_DLL:?WXSEND_DLL must be set (path to wxsend.dll)}"
: "${INJECT_EXE:?INJECT_EXE must be set (path to inject2.exe)}"

export WINEPREFIX
export DISPLAY="${DISPLAY:-:99}"

# Start Xvfb if not running
pgrep Xvfb || Xvfb "$DISPLAY" -screen 0 1024x768x24 &
sleep 2

# Start WeChat if not running
if ! pgrep -f WeChat.exe > /dev/null; then
    echo "[*] Starting WeChat..."
    if [ -n "${WECHAT_SLICE:-}" ]; then
        systemd-run --slice="$WECHAT_SLICE" --scope wine "$WECHAT_EXE_PATH" &
    else
        wine "$WECHAT_EXE_PATH" &
    fi
    sleep 10

    # Auto-click "Open WeChat" button if needed (login confirmation screen)
    # Adjust coordinates to match your screen resolution
    xdotool mousemove 512 480 click 1
    sleep 5
else
    echo "[*] WeChat already running"
fi

# Convert Linux DLL path to Wine Z: drive path
WXSEND_DLL_WINE="Z:${WXSEND_DLL}"

# Get WeChat.exe Wine PID
WINE_PID=$(wine tasklist 2>/dev/null | grep -i "WeChat.exe" | head -1 | awk '{print $2}')
if [ -z "$WINE_PID" ]; then
    echo "[-] Could not find WeChat.exe Wine PID"
    exit 1
fi

echo "[*] Injecting wxsend.dll into WeChat.exe (Wine PID $WINE_PID)..."
wine "$INJECT_EXE" "$WINE_PID" "$WXSEND_DLL_WINE"
sleep 3

# Verify hook is active
echo "[*] Checking wxsend.dll status..."
STATUS=$(curl -s --max-time 3 http://127.0.0.1:19088/status 2>/dev/null || true)
if echo "$STATUS" | grep -q '"hooked":1'; then
    echo "[+] WeChat hook LIVE: $STATUS"
else
    echo "[-] wxsend.dll not responding on port 19088 — injection may have failed"
    echo "    Status: $STATUS"
    exit 1
fi
