#include <winsock2.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <ctime>

#define WX_SEND_TEXT_OFFSET       0xce6c80
#define WX_SEND_MESSAGE_MGR_OFFSET 0x768140
#define WX_FREE_CHAT_MSG_OFFSET   0x756960
#define WX_RECV_MSG_HOOK_OFFSET   0xd19a0b
#define WX_RECV_MSG_HOOK_NEXT_OFFSET 0x756960
#define WM_WXSEND (WM_USER + 0x1234)

#define MAX_MESSAGES 500

struct WeChatString {
    wchar_t *ptr;
    unsigned long length;
    unsigned long max_length;
    unsigned long c_ptr;
    unsigned long c_len;
};

struct SendRequest {
    wchar_t wxid[256];
    wchar_t msg[4096];
    int result;
};

// Message storage
struct StoredMessage {
    char fromUser[256];
    char fromGroup[256]; 
    char content[8192];
    int msgType;
    int isSendMsg;
    unsigned long timestamp;
    unsigned long long msgId;
};

static StoredMessage g_messages[MAX_MESSAGES];
static int g_msgCount = 0;
static int g_msgIndex = 0;  // circular buffer index
static CRITICAL_SECTION g_msgLock;

// Hook state
static HWND g_wechatHwnd = NULL;
static WNDPROC g_origWndProc = NULL;
static unsigned long g_wechatBase = 0;
static char g_origRecvCode[5] = {0};
static unsigned long g_recvJmpBack = 0;
static unsigned long g_recvNextAddr = 0;

// WString read helper
static void ReadWString(unsigned long addr, unsigned long offset, char* out, int maxLen) {
    { // no SEH in gcc
        wchar_t* ptr = *(wchar_t**)(addr + offset);
        unsigned long len = *(unsigned long*)(addr + offset + 4);
        if (ptr && len > 0 && len < 10000) {
            WideCharToMultiByte(CP_UTF8, 0, ptr, len, out, maxLen - 1, NULL, NULL);
        }
    } if(0) { // SEH fallback
        out[0] = 0;
    }
}

// Webhook POST structure - passed to thread
struct WebhookPayload {
    char json[16384];
};

// Write message JSON to shared file (Linux reads via inotify)
// Z:\tmp maps to /tmp on the Linux host
static void WriteMessageToFile(const char* json) {
    HANDLE hFile = CreateFileA(
        "Z:\\tmp\\wechat_incoming.jsonl",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD written;
    WriteFile(hFile, json, (DWORD)strlen(json), &written, NULL);
    WriteFile(hFile, "\n", 1, &written, NULL);
    CloseHandle(hFile);
}

// Thread function to POST message to webhook (non-blocking)
static DWORD WINAPI WebhookPostThread(LPVOID param) {
    WebhookPayload* payload = (WebhookPayload*)param;

    // PRIMARY: Write to shared file — Linux inotify picks this up instantly
    WriteMessageToFile(payload->json);
    
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        free(payload);
        WSACleanup();
        return 1;
    }
    
    // Set socket to non-blocking mode
    unsigned long iMode = 1;
    ioctlsocket(sock, FIONBIO, &iMode);
    
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(19089);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    // Attempt connection (non-blocking, will likely return WSAEWOULDBLOCK)
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            closesocket(sock);
            free(payload);
            WSACleanup();
            return 1;
        }
    }
    
    // Wait for connection to complete using select
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    
    struct timeval timeout = {};
    timeout.tv_sec = 2;  // 2 second timeout
    timeout.tv_usec = 0;
    
    if (select((int)sock + 1, NULL, &writeSet, NULL, &timeout) <= 0) {
        closesocket(sock);
        free(payload);
        WSACleanup();
        return 1;
    }
    
    // Build HTTP POST request
    char request[32768];
    int jsonLen = strlen(payload->json);
    sprintf(request,
        "POST /webhook/message HTTP/1.1\r\n"
        "Host: 127.0.0.1:19089\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        jsonLen, payload->json);
    
    // Send HTTP request
    int reqLen = strlen(request);
    int sent = 0;
    while (sent < reqLen) {
        int n = send(sock, request + sent, reqLen - sent, 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                Sleep(10);
                continue;
            }
            break;
        }
        sent += n;
    }
    
    // Wait a bit for response (non-blocking read)
    Sleep(100);
    
    char response[1024];
    recv(sock, response, sizeof(response) - 1, 0);
    
    closesocket(sock);
    free(payload);
    WSACleanup();
    return 0;
}

// Build JSON and POST to webhook in separate thread
static void PostMessageToWebhook(StoredMessage* msg) {
    WebhookPayload* payload = (WebhookPayload*)malloc(sizeof(WebhookPayload));
    if (!payload) return;
    
    memset(payload, 0, sizeof(WebhookPayload));
    
    // Build JSON payload - escape special characters
    int pos = sprintf(payload->json, "{\"fromUser\":\"");
    
    // Escape fromUser
    for (int i = 0; msg->fromUser[i] && pos < 16350; i++) {
        char c = msg->fromUser[i];
        if (c == '"') { payload->json[pos++] = '\\'; payload->json[pos++] = '"'; }
        else if (c == '\\') { payload->json[pos++] = '\\'; payload->json[pos++] = '\\'; }
        else if (c == '\n') { payload->json[pos++] = '\\'; payload->json[pos++] = 'n'; }
        else if (c == '\r') { payload->json[pos++] = '\\'; payload->json[pos++] = 'r'; }
        else if ((unsigned char)c >= 0x20) payload->json[pos++] = c;
    }
    
    // fromGroup
    pos += sprintf(payload->json + pos, "\",\"fromGroup\":\"");
    for (int i = 0; msg->fromGroup[i] && pos < 16350; i++) {
        char c = msg->fromGroup[i];
        if (c == '"') { payload->json[pos++] = '\\'; payload->json[pos++] = '"'; }
        else if (c == '\\') { payload->json[pos++] = '\\'; payload->json[pos++] = '\\'; }
        else if (c == '\n') { payload->json[pos++] = '\\'; payload->json[pos++] = 'n'; }
        else if (c == '\r') { payload->json[pos++] = '\\'; payload->json[pos++] = 'r'; }
        else if ((unsigned char)c >= 0x20) payload->json[pos++] = c;
    }
    
    // content (largest field)
    pos += sprintf(payload->json + pos, "\",\"content\":\"");
    for (int i = 0; msg->content[i] && pos < 16200; i++) {
        char c = msg->content[i];
        if (c == '"') { payload->json[pos++] = '\\'; payload->json[pos++] = '"'; }
        else if (c == '\\') { payload->json[pos++] = '\\'; payload->json[pos++] = '\\'; }
        else if (c == '\n') { payload->json[pos++] = '\\'; payload->json[pos++] = 'n'; }
        else if (c == '\r') { payload->json[pos++] = '\\'; payload->json[pos++] = 'r'; }
        else if ((unsigned char)c >= 0x20) payload->json[pos++] = c;
    }
    
    // msgType, timestamp, msgId
    pos += sprintf(payload->json + pos,
        "\",\"msgType\":%d,\"timestamp\":%lu,\"msgId\":%llu}",
        msg->msgType, msg->timestamp, msg->msgId);
    
    // Spawn thread to send (detached, cleans up after itself)
    CreateThread(NULL, 0, WebhookPostThread, payload, 0, NULL);
}

// Called when a message is received
void __cdecl OnRecvMsg(unsigned long msg_addr) {
    EnterCriticalSection(&g_msgLock);
    
    StoredMessage* msg = &g_messages[g_msgIndex % MAX_MESSAGES];
    memset(msg, 0, sizeof(StoredMessage));
    
    { // no SEH in gcc
        msg->msgId = *(unsigned long long*)(msg_addr + 0x30);
        msg->msgType = *(int*)(msg_addr + 0x38);
        msg->isSendMsg = *(int*)(msg_addr + 0x3C);
        msg->timestamp = *(unsigned long*)(msg_addr + 0x44);
        
        ReadWString(msg_addr, 0x48, msg->fromGroup, sizeof(msg->fromGroup));
        
        unsigned long fromUserLen = *(unsigned long*)(msg_addr + 0x178);
        if (fromUserLen > 0) {
            ReadWString(msg_addr, 0x174, msg->fromUser, sizeof(msg->fromUser));
        } else {
            strncpy(msg->fromUser, msg->fromGroup, sizeof(msg->fromUser) - 1);
        }
        
        unsigned long contentLen = *(unsigned long*)(msg_addr + 0x74);
        if (contentLen > 0) {
            ReadWString(msg_addr, 0x70, msg->content, sizeof(msg->content));
        }
    } if(0) { // SEH fallback
        // ignore read errors
    }
    
    g_msgIndex++;
    if (g_msgCount < MAX_MESSAGES) g_msgCount++;
    
    // Post message to webhook in separate thread (non-blocking)
    PostMessageToWebhook(msg);
    
    LeaveCriticalSection(&g_msgLock);
}

// Naked hook function - same as wxhelper
__attribute__((naked)) void handle_sync_msg() {
    __asm__ __volatile__ (
        "pushal\n"
        "pushfl\n"
        "pushl %%ecx\n"
        "call __Z9OnRecvMsgm\n"
        "addl $4, %%esp\n"
        "popfl\n"
        "popal\n"
        "call *%0\n"
        "jmp *%1\n"
        :
        : "m" (g_recvNextAddr), "m" (g_recvJmpBack)
    );
}

static void HookRecvMsg() {
    g_wechatBase = (unsigned long)GetModuleHandleA("WeChatWin.dll");
    if (!g_wechatBase) return;
    
    unsigned long hookAddr = g_wechatBase + WX_RECV_MSG_HOOK_OFFSET;
    g_recvNextAddr = g_wechatBase + WX_RECV_MSG_HOOK_NEXT_OFFSET;
    g_recvJmpBack = hookAddr + 5;
    
    // Save original 5 bytes
    memcpy(g_origRecvCode, (void*)hookAddr, 5);
    
    // Write JMP to our hook
    DWORD oldProtect;
    VirtualProtect((void*)hookAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    unsigned char jmp[5];
    jmp[0] = 0xE9;  // JMP rel32
    unsigned long rel = (unsigned long)handle_sync_msg - hookAddr - 5;
    memcpy(&jmp[1], &rel, 4);
    memcpy((void*)hookAddr, jmp, 5);
    
    VirtualProtect((void*)hookAddr, 5, oldProtect, &oldProtect);
}

// SendText implementation (same as before)
static int DoSendText(const wchar_t* wxid, const wchar_t* msg) {
    unsigned long base = (unsigned long)GetModuleHandleA("WeChatWin.dll");
    if (!base) return -1;
    
    WeChatString to_user = {(wchar_t*)wxid, (unsigned long)wcslen(wxid), (unsigned long)wcslen(wxid)*2, 0, 0};
    WeChatString text_msg = {(wchar_t*)msg, (unsigned long)wcslen(msg), (unsigned long)wcslen(msg)*2, 0, 0};
    wchar_t **msg_pptr = &text_msg.ptr;
    char chat_msg[0x2D8];
    memset(chat_msg, 0, sizeof(chat_msg));
    
    unsigned long getMgrAddr = base + WX_SEND_MESSAGE_MGR_OFFSET;
    unsigned long sendAddr = base + WX_SEND_TEXT_OFFSET;
    unsigned long freeAddr = base + WX_FREE_CHAT_MSG_OFFSET;
    
    unsigned char* sc = (unsigned char*)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!sc) return -2;
    
    int i = 0;
    sc[i++] = 0x60;
    sc[i++] = 0xE8; unsigned long rel = getMgrAddr - ((unsigned long)&sc[i] + 4); memcpy(&sc[i], &rel, 4); i += 4;
    sc[i++] = 0x6A; sc[i++] = 0x00;
    sc[i++] = 0x6A; sc[i++] = 0x00;
    sc[i++] = 0x6A; sc[i++] = 0x00;
    sc[i++] = 0x6A; sc[i++] = 0x01;
    sc[i++] = 0x6A; sc[i++] = 0x00;
    sc[i++] = 0xB8; unsigned long val = (unsigned long)msg_pptr; memcpy(&sc[i], &val, 4); i += 4;
    sc[i++] = 0x50;
    sc[i++] = 0xBA; val = (unsigned long)&to_user; memcpy(&sc[i], &val, 4); i += 4;
    sc[i++] = 0xB9; val = (unsigned long)chat_msg; memcpy(&sc[i], &val, 4); i += 4;
    sc[i++] = 0xE8; rel = sendAddr - ((unsigned long)&sc[i] + 4); memcpy(&sc[i], &rel, 4); i += 4;
    sc[i++] = 0x83; sc[i++] = 0xC4; sc[i++] = 0x18;
    sc[i++] = 0xB9; val = (unsigned long)chat_msg; memcpy(&sc[i], &val, 4); i += 4;
    sc[i++] = 0xE8; rel = freeAddr - ((unsigned long)&sc[i] + 4); memcpy(&sc[i], &rel, 4); i += 4;
    sc[i++] = 0x61;
    sc[i++] = 0xC3;
    
    typedef int (*Fn)(void);
    int result = ((Fn)sc)();
    VirtualFree(sc, 0, MEM_RELEASE);
    return result;
}

static LRESULT CALLBACK HookWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_WXSEND) {
        SendRequest* req = (SendRequest*)lParam;
        req->result = DoSendText(req->wxid, req->msg);
        return 0;
    }
    return CallWindowProcW(g_origWndProc, hwnd, msg, wParam, lParam);
}

static BOOL CALLBACK FindWnd(HWND hwnd, LPARAM) {
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId()) {
        g_wechatHwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI HttpThread(LPVOID) {
    Sleep(2000);
    
    InitializeCriticalSection(&g_msgLock);
    
    // Hook recv messages
    HookRecvMsg();
    
    // Find window and hook WndProc for send
    EnumWindows(FindWnd, 0);
    if (g_wechatHwnd)
        g_origWndProc = (WNDPROC)SetWindowLongPtrW(g_wechatHwnd, GWLP_WNDPROC, (LONG_PTR)HookWndProc);
    
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {}; addr.sin_family = AF_INET; addr.sin_port = htons(19088); addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int opt = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    bind(srv, (struct sockaddr*)&addr, sizeof(addr)); listen(srv, 5);
    
    while(1) {
        SOCKET client = accept(srv, NULL, NULL);
        if (client == INVALID_SOCKET) continue;
        char buf[8192] = {}; recv(client, buf, sizeof(buf)-1, 0);
        
        // GET /status
        if (strstr(buf, "GET /status")) {
            char resp[256]; sprintf(resp, "HTTP/1.1 200 OK\r\n\r\n{\"hwnd\":%lu,\"hooked\":%d,\"msgCount\":%d}", 
                (unsigned long)g_wechatHwnd, g_origWndProc?1:0, g_msgCount);
            send(client, resp, strlen(resp), 0); closesocket(client); continue;
        }
        
        // GET /messages?since=TIMESTAMP
        if (strstr(buf, "GET /messages")) {
            char* sinceStr = strstr(buf, "since=");
            unsigned long since = sinceStr ? strtoul(sinceStr + 6, NULL, 10) : 0;
            
            EnterCriticalSection(&g_msgLock);
            
            // Build JSON array
            char* resp_buf = (char*)malloc(1024 * 1024); // 1MB
            int pos = sprintf(resp_buf, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"messages\":[");
            
            int count = 0;
            int start = (g_msgCount < MAX_MESSAGES) ? 0 : (g_msgIndex % MAX_MESSAGES);
            for (int n = 0; n < g_msgCount && count < 200; n++) {
                StoredMessage* m = &g_messages[(start + n) % MAX_MESSAGES];
                if (m->timestamp < since) continue;
                if (m->isSendMsg) continue; // skip our own sends
                
                if (count > 0) pos += sprintf(resp_buf + pos, ",");
                pos += sprintf(resp_buf + pos, 
                    "{\"fromUser\":\"%s\",\"fromGroup\":\"%s\",\"content\":\"",
                    m->fromUser, m->fromGroup);
                // Escape content for JSON
                for (int c = 0; m->content[c] && pos < 900000; c++) {
                    char ch = m->content[c];
                    if (ch == '"') { resp_buf[pos++] = '\\'; resp_buf[pos++] = '"'; }
                    else if (ch == '\\') { resp_buf[pos++] = '\\'; resp_buf[pos++] = '\\'; }
                    else if (ch == '\n') { resp_buf[pos++] = '\\'; resp_buf[pos++] = 'n'; }
                    else if (ch == '\r') { resp_buf[pos++] = '\\'; resp_buf[pos++] = 'r'; }
                    else if ((unsigned char)ch >= 0x20) resp_buf[pos++] = ch;
                }
                pos += sprintf(resp_buf + pos, 
                    "\",\"msgType\":%d,\"timestamp\":%lu,\"msgId\":%llu}",
                    m->msgType, m->timestamp, m->msgId);
                count++;
            }
            
            pos += sprintf(resp_buf + pos, "],\"count\":%d}", count);
            
            LeaveCriticalSection(&g_msgLock);
            
            send(client, resp_buf, pos, 0);
            free(resp_buf);
            closesocket(client);
            continue;
        }
        
        // POST - send message
        char* body = strstr(buf, "\r\n\r\n");
        if (!body) { closesocket(client); continue; }
        body += 4;
        
        char wxid_buf[256]={}; char msg_buf[4096]={}; char* p;
        if ((p = strstr(body, "\"wxid\""))) { p = strchr(p+6,'"')+1; char* e = strchr(p,'"'); if(e){size_t n=e-p;if(n>255)n=255;memcpy(wxid_buf,p,n);} }
        if ((p = strstr(body, "\"msg\""))) { p = strchr(p+5,'"')+1; char* e = strchr(p,'"'); if(e){size_t n=e-p;if(n>4095)n=4095;memcpy(msg_buf,p,n);} }
        
        char resp[512];
        if (wxid_buf[0] && msg_buf[0]) {
            SendRequest req = {};
            MultiByteToWideChar(CP_UTF8, 0, wxid_buf, -1, req.wxid, 256);
            MultiByteToWideChar(CP_UTF8, 0, msg_buf, -1, req.msg, 4096);
            if (g_wechatHwnd && g_origWndProc) {
                SendMessageW(g_wechatHwnd, WM_WXSEND, 0, (LPARAM)&req);
                sprintf(resp, "HTTP/1.1 200 OK\r\n\r\n{\"code\":%d,\"result\":\"OK\"}", req.result);
            } else {
                sprintf(resp, "HTTP/1.1 200 OK\r\n\r\n{\"code\":0,\"result\":\"no window\"}");
            }
        } else {
            sprintf(resp, "HTTP/1.1 400 Bad Request\r\n\r\n{\"code\":0,\"result\":\"bad\"}");
        }
        send(client, resp, strlen(resp), 0); closesocket(client);
    }
}

extern "C" BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) { DisableThreadLibraryCalls(h); CreateThread(NULL,0,HttpThread,NULL,0,NULL); }
    return TRUE;
}
