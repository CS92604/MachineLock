// MachineCodeTool.cpp - shows the machine code and copies it, customer sends it to the owner
// reads 4 hw ids and hashes them, nothing leaves the pc
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <bcrypt.h>
#include <winioctl.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ---- fingerprint start ----
// same block in both cpp files, keep in sync or the codes wont match licenses

// 4 ids: guid, bios uuid, board sn, disk sn
// h1 = 8 bytes, goes in the license. h2 = 16 bytes, stays secret. zeros = couldnt read it
struct Mach { unsigned char h1[4][8]; unsigned char h2[4][16]; };

static bool Sha256(const void* p, ULONG n, unsigned char out[32]) {
    return BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)p, n, out, 32) >= 0;
}

static std::string B64(const BYTE* p, DWORD n) {
    const DWORD f = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
    DWORD c = 0;
    CryptBinaryToStringA(p, n, f, NULL, &c);
    std::string s(c, 0);
    CryptBinaryToStringA(p, n, f, &s[0], &c);
    s.resize(c);
    return s;
}

static std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

// junk values from cheap boards ("To Be Filled By O.E.M." etc)
static bool Placeholder(const std::string& s) {
    if (s.empty() || s.find_first_not_of(s[0]) == std::string::npos) return true;
    std::string l = s;
    for (auto& c : l) c = (char)tolower((unsigned char)c);
    static const char* bad[] = { "to be filled by o.e.m.", "default string", "none", "not specified", "system serial number",
                                 "base board serial number", "not applicable", "n/a", "unknown", "123456789" };
    for (auto b : bad) if (l == b) return true;
    return false;
}

static void Slot(const std::string& raw, unsigned char* h1, unsigned char* h2) {
    memset(h1, 0, 8);
    memset(h2, 0, 16);
    std::string s = Trim(raw);
    unsigned char h[32];
    if (!Placeholder(s) && Sha256(s.data(), (ULONG)s.size(), h)) { memcpy(h1, h, 8); memcpy(h2, h + 8, 16); }
}

static std::string MachineGuid() {
    char buf[128];
    DWORD n = sizeof buf;
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, NULL, buf, &n) != ERROR_SUCCESS) return "";
    return buf;
}

// smbios table, want system uuid + board serial
static void Smbios(std::string& uuid, std::string& board) {
    UINT n = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (n < 8) return;
    std::vector<BYTE> b(n);
    if (GetSystemFirmwareTable('RSMB', 0, b.data(), n) != n) return;
    DWORD len;
    memcpy(&len, &b[4], 4);
    BYTE* p = &b[8];
    BYTE* end = p + std::min<DWORD>(len, n - 8);
    while (p + 4 <= end && p[0] != 127) {            // 127 = end
        BYTE* str = p + p[1];                        // strings follow the fixed part
        if (str + 2 > end) break;
        BYTE* q = str;                               // ends at double NUL
        while (q + 1 < end && (q[0] || q[1])) q++;
        if (q + 1 >= end) break;
        auto S = [&](int idx) -> std::string {       // 1 based
            BYTE* s = str;
            for (int i = 1; i < idx && s <= q; i++) s += strlen((char*)s) + 1;
            return (idx > 0 && s < q) ? std::string((char*)s) : std::string();
        };
        if (p[0] == 1 && p[1] >= 0x19) {             // type 1 sysinfo, uuid at +8
            char hex[33];
            for (int i = 0; i < 16; i++) snprintf(hex + i * 2, 3, "%02x", p[8 + i]);
            uuid = hex;
        } else if (p[0] == 2 && p[1] >= 8) {         // type 2 baseboard, serial idx at +7
            board = S(p[7]);
        }
        p = q + 2;
    }
}

// disk sn, "" if it wont say. 0 access is enough, no admin
static std::string SerialOf(const std::string& path) {
    HANDLE h = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return "";
    STORAGE_PROPERTY_QUERY q = {};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    BYTE buf[1024] = {};
    DWORD got = 0;
    std::string r;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf, sizeof buf - 1, &got, NULL)) {
        auto* d = (STORAGE_DEVICE_DESCRIPTOR*)buf;
        if (d->SerialNumberOffset && d->SerialNumberOffset < got) r = (char*)buf + d->SerialNumberOffset;
    }
    CloseHandle(h);
    return Trim(r);
}

// windows disk first (drive0 isnt always it), else first drive with a sn
static std::string DiskSerial() {
    char win[MAX_PATH];
    if (GetWindowsDirectoryA(win, MAX_PATH) >= 2 && win[1] == ':') {
        std::string s = SerialOf(std::string("\\\\.\\") + win[0] + ":");
        if (!Placeholder(s)) return s;
    }
    for (int i = 0; i < 16; i++) {
        std::string s = SerialOf("\\\\.\\PhysicalDrive" + std::to_string(i));
        if (!Placeholder(s)) return s;
    }
    return "";
}

static void Fingerprint(Mach& m) {
    std::string uuid, board;
    Smbios(uuid, board);
    const std::string id[4] = { MachineGuid(), uuid, board, DiskSerial() };
    for (int i = 0; i < 4; i++) Slot(id[i], m.h1[i], m.h2[i]);
}

// needs a real window as owner, NULL fails
static bool CopyText(HWND owner, const std::string& s) {
    bool ok = false;
    for (int i = 0; i < 5; i++) {
        if (OpenClipboard(owner)) {                  // might be busy, retry
            EmptyClipboard();
            if (HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, s.size() + 1)) {
                memcpy(GlobalLock(g), s.c_str(), s.size() + 1);
                GlobalUnlock(g);
                if (SetClipboardData(CF_TEXT, g)) ok = true; else GlobalFree(g);
            }
            CloseClipboard();
            if (ok) break;
        }
        Sleep(100);
    }
    return ok;
}
// ---- fingerprint end ----

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    Mach m;
    Fingerprint(m);
    const std::string code = B64((const BYTE*)&m, sizeof m);

    static const char* names[4] = { "Windows ID", "firmware UUID", "motherboard serial", "disk serial" };
    static const unsigned char zero[8] = {};
    std::string found;
    int n = 0;
    for (int i = 0; i < 4; i++)
        if (memcmp(m.h1[i], zero, 8)) found += (n++ ? ", " : "") + std::string(names[i]);

    // hidden window, clipboard needs an owner
    HWND owner = CreateWindowExA(0, "STATIC", "", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    const bool copied = CopyText(owner, code);

    // 32 chars/line for the box, clipboard gets 1 line
    std::string shown;
    for (size_t i = 0; i < code.size(); i += 32) shown += code.substr(i, 32) + "\n";

    std::string msg = "Your machine code:\n\n" + shown + "\n" +
        (copied ? "It's on your clipboard now. Paste it into a message to the app owner.\n"
                : "Couldn't get to the clipboard. Close this and run it again.\n") +
        "\nIDs read: " + std::to_string(n) + " of 4" + (n ? " (" + found + ")" : "") + "\n" +
        (n < 3 ? "This PC hides some of its IDs, so a license will be tied to it less tightly.\n" : "") +
        "\nThe code is only hashes of those IDs, no names, files or anything personal, and nothing is sent anywhere. "
        "Only give it to the app owner.";
    MessageBoxA(NULL, msg.c_str(), "Machine code", MB_OK | MB_ICONINFORMATION);
    return 0;
}
