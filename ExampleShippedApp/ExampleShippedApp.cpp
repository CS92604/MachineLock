// ExampleShippedApp.cpp - calculator behind a license key
// how it works: README. short version in LicenseOk()
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <bcrypt.h>
#include <winioctl.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")
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

// public keys from PrivateOwnerApp (primary, spare). demo ones, swap in yours
// no updates later so both go in the first build
static const unsigned char kPub[][64] = {
    {0x10,0xc0,0x8a,0x31,0x7d,0x8d,0xa9,0x7a,0xff,0xc2,0x57,0xc6,0xb3,0x63,0x10,0xad,0xc6,0x67,0xdd,0x73,0x36,0xbd,0x4a,0x19,0xd9,0xbb,0xb5,0x1e,0x89,0xf1,0x9c,0x03,0x06,0xa4,0x6c,0x5a,0x80,0xc5,0x13,0xf8,0xb8,0x3a,0x28,0xcf,0x9e,0xed,0xf4,0x97,0x30,0x73,0x4e,0xba,0xc3,0x64,0xf8,0x9c,0xf1,0x80,0x17,0x94,0x8c,0xbd,0x00,0x05},
    {0xea,0xe8,0xd8,0x5d,0xcd,0x17,0x27,0xb2,0xee,0x35,0x71,0x8e,0xf4,0x0a,0x91,0xbb,0xe6,0xaa,0x90,0x90,0xdf,0x4c,0x80,0xc9,0xa4,0xb6,0xcf,0xaa,0x10,0x44,0xd0,0xdb,0xba,0x05,0x96,0x74,0x3b,0x78,0xd8,0xb5,0x15,0x58,0x97,0x51,0x2a,0x3c,0x5a,0x42,0x59,0xfa,0x89,0x6b,0xac,0x2e,0xab,0x34,0x23,0x58,0x8e,0xef,0x05,0x23,0x0d,0xdb},
};
static const BYTE kTag[8] = { 'C', 'A', 'L', 'C', 0, 0, 0, 0 };   // same as Tag in the .cs

static unsigned char gK[16];   // app key, only set after a good check

static bool Verify(const BYTE* msg, ULONG n, const BYTE* sig, const BYTE* xy) {
    BCRYPT_ALG_HANDLE a;
    if (BCryptOpenAlgorithmProvider(&a, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) < 0) return false;
    BYTE blob[72];
    BCRYPT_ECCKEY_BLOB* h = (BCRYPT_ECCKEY_BLOB*)blob;
    h->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    h->cbKey = 32;
    memcpy(blob + 8, xy, 64);
    BCRYPT_KEY_HANDLE k;
    bool ok = false;
    if (BCryptImportKeyPair(a, NULL, BCRYPT_ECCPUBLIC_BLOB, &k, blob, sizeof blob, 0) >= 0) {
        unsigned char d[32];
        ok = Sha256(msg, n, d) && BCryptVerifySignature(k, NULL, d, 32, (PUCHAR)sig, 64, 0) >= 0;
        BCryptDestroyKey(k);
    }
    BCryptCloseAlgorithmProvider(a, 0);
    return ok;
}

static bool UnB64(const std::string& in, std::vector<BYTE>& out) {
    std::string t;   // pasted keys have spaces/newlines, strip
    for (char ch : in) if (!isspace((unsigned char)ch)) t += ch;
    DWORD n = 0;
    if (!CryptStringToBinaryA(t.c_str(), 0, CRYPT_STRING_BASE64, NULL, &n, NULL, NULL)) return false;
    out.resize(n);
    if (!CryptStringToBinaryA(t.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &n, NULL, NULL)) return false;
    out.resize(n);
    return true;
}

// newest time seen, registry + file so wiping one doesnt reset it
static const char* kSub = "Software\\ExampleShippedApp";

static std::string SeenDir() {
    char a[MAX_PATH];
    return GetEnvironmentVariableA("APPDATA", a, MAX_PATH) ? std::string(a) + "\\ExampleShippedApp" : "";
}

static unsigned long long SeenGet() {
    unsigned long long a = 0, b = 0;
    DWORD n = 8;
    RegGetValueA(HKEY_CURRENT_USER, kSub, "Seen", RRF_RT_REG_QWORD, NULL, &a, &n);
    std::string d = SeenDir();
    if (!d.empty())
        if (FILE* f = fopen((d + "\\seen.dat").c_str(), "rb")) { if (fread(&b, 8, 1, f) != 1) b = 0; fclose(f); }
    return std::max(a, b);
}

static void SeenSet(unsigned long long v) {
    RegSetKeyValueA(HKEY_CURRENT_USER, kSub, "Seen", REG_QWORD, &v, 8);
    std::string d = SeenDir();
    if (d.empty()) return;
    CreateDirectoryA(d.c_str(), NULL);
    if (FILE* f = fopen((d + "\\seen.dat").c_str(), "wb")) { fwrite(&v, 8, 1, f); fclose(f); }
}

static bool NotExpired(unsigned long long exp) {
    if (!exp) return true;   // 0 = never
    unsigned long long now = (unsigned long long)time(NULL), seen = SeenGet();
    if (now >= exp || now + 3600 < seen) return false;   // expired or clock set back
    if (now > seen + 60) SeenSet(now);
    return true;
}

// layout: 0 expiry | 8 tag | 16 id hashes | 48 wrapped keys | 112 key chk | 120 sig
// gK set on success, zeroed on fail
static bool LicenseOk(const std::string& text) {
    memset(gK, 0, sizeof gK);
    std::vector<BYTE> r;
    if (!UnB64(text, r) || r.size() != 184) return false;
    const BYTE* d = r.data();
    bool signedOk = false;
    for (const auto& pk : kPub) if (Verify(d, 120, d + 120, pk)) { signedOk = true; break; }
    if (!signedOk || memcmp(d + 8, kTag, 8)) return false;   // sig first, dont trust the rest before that

    Mach m;
    Fingerprint(m);
    static const BYTE zero[8] = {};
    int have = 0, hits = 0;
    bool gotK = false;
    BYTE K[16];
    for (int i = 0; i < 4; i++) {
        const BYTE* h1 = d + 16 + i * 8;
        if (!memcmp(h1, zero, 8)) continue;   // id wasnt readable when key was made
        have++;
        if (memcmp(h1, m.h1[i], 8)) continue;
        hits++;
        BYTE c[16], hk[32];
        for (int j = 0; j < 16; j++) c[j] = d[48 + i * 16 + j] ^ m.h2[i][j];
        if (!gotK && Sha256(c, 16, hk) && !memcmp(hk, d + 112, 8)) { memcpy(K, c, 16); gotK = true; }
    }
    unsigned long long exp;
    memcpy(&exp, d, 8);
    if (have == 0)   // test key: no pc binding, must expire, no app key
        return exp != 0 && NotExpired(exp);
    if (hits < std::min(have, 3) || !gotK) return false;
    if (!NotExpired(exp)) return false;
    memcpy(gK, K, 16);
    return true;
}

static std::string Here(const char* name) {
    char p[MAX_PATH];
    GetModuleFileNameA(NULL, p, MAX_PATH);
    std::string s = p;
    return s.substr(0, s.find_last_of('\\') + 1) + name;
}

static std::string Slurp(const std::string& path) {
    std::string s;
    if (FILE* f = fopen(path.c_str(), "rb")) {
        char b[512];
        size_t n;
        while (s.size() < 4096 && (n = fread(b, 1, sizeof b, f)) > 0) s.append(b, n);
        fclose(f);
    }
    return s;
}

// next to the exe, or %APPDATA%\ExampleShippedApp if exe dir is read only
static bool LicenseFound() {
    if (LicenseOk(Slurp(Here("license.key")))) return true;
    std::string d = SeenDir();
    return !d.empty() && LicenseOk(Slurp(d + "\\license.key"));
}

static void SaveLicense(const char* text) {
    if (FILE* f = fopen(Here("license.key").c_str(), "wb")) { fwrite(text, 1, strlen(text), f); fclose(f); return; }
    std::string d = SeenDir();
    if (d.empty()) return;
    CreateDirectoryA(d.c_str(), NULL);
    if (FILE* f = fopen((d + "\\license.key").c_str(), "wb")) { fwrite(text, 1, strlen(text), f); fclose(f); }
}

// the calculator, + - * / and brackets
struct P { const char* s; bool bad; };
static double Expr(P& p);
static double Atom(P& p) {
    if (*p.s == '(') {
        p.s++;
        double v = Expr(p);
        if (*p.s == ')') p.s++; else p.bad = true;
        return v;
    }
    if (*p.s == '-') { p.s++; return -Atom(p); }
    char* e;
    double v = strtod(p.s, &e);
    if (e == p.s) p.bad = true;
    p.s = e;
    return v;
}
static double Term(P& p) {
    double v = Atom(p);
    while (*p.s == '*' || *p.s == '/') { char o = *p.s++; double r = Atom(p); v = o == '*' ? v * r : v / r; }
    return v;
}
static double Expr(P& p) {
    double v = Term(p);
    while (*p.s == '+' || *p.s == '-') { char o = *p.s++; double r = Term(p); v = o == '+' ? v + r : v - r; }
    return v;
}

enum { ID_CODE = 100, ID_COPY, ID_KEY, ID_IMPORT, ID_ACT, ID_DISP, ID_BTN = 200 };
static HWND gWnd;
static HFONT gUi, gBig;
static std::vector<HWND> gLic, gCalc;   // license screen / calc controls
static std::string gCode, gExpr;
static const char* kBtn[20] = { "C", "(", ")", "/", "7", "8", "9", "*", "4", "5", "6", "-",
                                "1", "2", "3", "+", "0", ".", "<", "=" };
static bool gOk;

static HWND Mk(HWND p, const char* cls, const char* txt, DWORD st, int x, int y, int w, int h, int id,
               std::vector<HWND>& grp, HFONT f) {
    HWND c = CreateWindowA(cls, txt, WS_CHILD | WS_VISIBLE | st, x, y, w, h, p, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessageA(c, WM_SETFONT, (WPARAM)f, TRUE);
    grp.push_back(c);
    return c;
}

static void ShowPanel() {
    for (HWND c : gLic) ShowWindow(c, gOk ? SW_HIDE : SW_SHOW);
    for (HWND c : gCalc) ShowWindow(c, gOk ? SW_SHOW : SW_HIDE);
}

static void BuildCalc(HWND hw) {
    for (HWND c : gCalc) DestroyWindow(c);
    gCalc.clear();
    gExpr.clear();
    Mk(hw, "STATIC", "0", SS_RIGHT | SS_CENTERIMAGE | WS_BORDER, 12, 12, 316, 44, ID_DISP, gCalc, gBig);
    for (int i = 0; i < 20; i++)
        Mk(hw, "BUTTON", kBtn[i], BS_PUSHBUTTON, 12 + (i % 4) * 80, 68 + (i / 4) * 52, 76, 48, ID_BTN + i, gCalc, gBig);
    SetTimer(hw, 1, 60000, NULL);   // recheck every min so an expired key locks while open
}

static void SetDisp(const std::string& s) { SetWindowTextA(GetDlgItem(gWnd, ID_DISP), s.c_str()); }

static void Press(const std::string& k) {
    if (k == "C") gExpr.clear();
    else if (k == "<") { if (!gExpr.empty()) gExpr.pop_back(); }
    else if (k == "=") {
        if (gExpr.empty()) return;
        P p{ gExpr.c_str(), false };
        double v = Expr(p);
        if (p.bad || *p.s || !std::isfinite(v)) { gExpr.clear(); SetDisp("Error"); return; }
        char b[64];
        snprintf(b, sizeof b, "%.10g", v);
        gExpr = b;
    } else if (gExpr.size() < 40) gExpr += k;
    SetDisp(gExpr.empty() ? "0" : gExpr);
}

static void Activate(HWND hw) {
    char buf[4096];
    GetWindowTextA(GetDlgItem(hw, ID_KEY), buf, sizeof buf);
    if (!LicenseOk(buf)) return;   // bad key: say nothing
    SaveLicense(buf);
    gOk = true;
    BuildCalc(hw);
    ShowPanel();
}

static LRESULT CALLBACK WndProc(HWND hw, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        gWnd = hw;
        gUi = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        gBig = CreateFontA(-24, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
        const DWORD ed = WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL;
        Mk(hw, "STATIC", "This copy is not activated. Send this machine code to the app owner:", 0, 12, 12, 316, 30, 0, gLic, gUi);
        Mk(hw, "EDIT", gCode.c_str(), ed | ES_READONLY, 12, 46, 316, 58, ID_CODE, gLic, gUi);
        Mk(hw, "BUTTON", "Copy code", BS_PUSHBUTTON, 12, 110, 100, 26, ID_COPY, gLic, gUi);
        Mk(hw, "STATIC", "Paste your license key, or import license.key:", 0, 12, 150, 316, 18, 0, gLic, gUi);
        Mk(hw, "EDIT", "", ed, 12, 172, 316, 58, ID_KEY, gLic, gUi);
        Mk(hw, "BUTTON", "Import file...", BS_PUSHBUTTON, 12, 238, 100, 26, ID_IMPORT, gLic, gUi);
        Mk(hw, "BUTTON", "Activate", BS_PUSHBUTTON, 228, 238, 100, 26, ID_ACT, gLic, gUi);
        if (gOk) BuildCalc(hw);
        ShowPanel();
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == ID_COPY) CopyText(hw, gCode);
        else if (id == ID_IMPORT) {
            OPENFILENAMEA o = { sizeof o };
            char f[MAX_PATH] = "";
            o.hwndOwner = hw;
            o.lpstrFilter = "Key files\0*.key\0All files\0*.*\0";
            o.lpstrFile = f;
            o.nMaxFile = MAX_PATH;
            o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameA(&o)) SetWindowTextA(GetDlgItem(hw, ID_KEY), Slurp(f).c_str());
        }
        else if (id == ID_ACT) Activate(hw);
        else if (id >= ID_BTN && id < ID_BTN + 20) Press(kBtn[id - ID_BTN]);
        return 0;
    }
    case WM_TIMER:
        if (gOk && !LicenseFound()) { gOk = false; KillTimer(hw, 1); ShowPanel(); }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hw, m, wp, lp);
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE, LPSTR, int show) {
    Mach mc;
    Fingerprint(mc);
    gCode = B64((const BYTE*)&mc, sizeof mc);
    gOk = LicenseFound();

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "ExampleShippedApp";
    RegisterClassA(&wc);

    const DWORD st = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT r = { 0, 0, 340, 340 };
    AdjustWindowRect(&r, st, FALSE);
    HWND w = CreateWindowA(wc.lpszClassName, "Calculator", st, CW_USEDEFAULT, CW_USEDEFAULT,
                           r.right - r.left, r.bottom - r.top, NULL, NULL, hi, NULL);
    ShowWindow(w, show);
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    return 0;
}
