// ============================================================================
// Fightcade FBNeo GGPO Proxy DLL (Zero-Crash Stack-Based bDraw Branch Tracer)
// ============================================================================
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define PROXY_BUILD_TIMESTAMP __DATE__ " " __TIME__

// 自行定義 OPENFILENAME 結構以相容精簡版 TCC 編譯環境
typedef struct tagOFNA {
   DWORD         lStructSize;
   HWND          hwndOwner;
   HINSTANCE     hInstance;
   LPCSTR        lpstrFilter;
   LPSTR         lpstrCustomFilter;
   DWORD         nMaxCustFilter;
   DWORD         nFilterIndex;
   LPSTR         lpstrFile;
   DWORD         nMaxFile;
   LPSTR         lpstrFileTitle;
   DWORD         nMaxFileTitle;
   LPCSTR        lpstrInitialDir;
   LPCSTR        lpstrTitle;
   DWORD         Flags;
   WORD          nFileOffset;
   WORD          nFileExtension;
   LPCSTR        lpstrDefExt;
   LPARAM        lCustData;
   void*         lpfnHook;
   LPCSTR        lpTemplateName;
   void*         pvReserved;
   DWORD         dwReserved;
   DWORD         FlagsEx;
} OPENFILENAMEA, *LPOPENFILENAMEA;

typedef struct tagOFNW {
   DWORD         lStructSize;
   HWND          hwndOwner;
   HINSTANCE     hInstance;
   LPCWSTR       lpstrFilter;
   LPWSTR        lpstrCustomFilter;
   DWORD         nMaxCustFilter;
   DWORD         nFilterIndex;
   LPWSTR        lpstrFile;
   DWORD         nMaxFile;
   LPWSTR        lpstrFileTitle;
   DWORD         nMaxFileTitle;
   LPCWSTR       lpstrInitialDir;
   LPCWSTR       lpstrTitle;
   DWORD         Flags;
   WORD          nFileOffset;
   WORD          nFileExtension;
   LPCWSTR       lpstrDefExt;
   LPARAM        lCustData;
   void*         lpfnHook;
   LPCWSTR       lpTemplateName;
   void*         pvReserved;
   DWORD         dwReserved;
   DWORD         FlagsEx;
} OPENFILENAMEW, *LPOPENFILENAMEW;

// ============================================================================
// 1. 代理身分識別簽名與版本標籤 (供外部啟動器進行冪等性防呆檢查，切勿移除)
// ============================================================================
__declspec(dllexport) const char* GGPONET_PROXY_SIGNATURE = "ARGON_REWIND_PROXY_V1";
__declspec(dllexport) const char* GGPONET_PROXY_VERSION   = "v1.1.0";

// 動態計算檔案 SHA-256 (零靜態依賴，安全相容 TCC)
static void CalcFileSHA256(const char* filePath, char* outHex, size_t outHexLen) {
    outHex[0] = '\0';
    HMODULE hAdv = LoadLibraryA("advapi32.dll");
    if (!hAdv) return;
    typedef uintptr_t HCRYPTPROV_T;
    typedef uintptr_t HCRYPTHASH_T;
    typedef BOOL (WINAPI *pfn_CryptAcquireContextA)(HCRYPTPROV_T*, LPCSTR, LPCSTR, DWORD, DWORD);
    typedef BOOL (WINAPI *pfn_CryptCreateHash)(HCRYPTPROV_T, unsigned int, uintptr_t, DWORD, HCRYPTHASH_T*);
    typedef BOOL (WINAPI *pfn_CryptHashData)(HCRYPTHASH_T, const BYTE*, DWORD, DWORD);
    typedef BOOL (WINAPI *pfn_CryptGetHashParam)(HCRYPTHASH_T, DWORD, BYTE*, DWORD*, DWORD);
    typedef BOOL (WINAPI *pfn_CryptDestroyHash)(HCRYPTHASH_T);
    typedef BOOL (WINAPI *pfn_CryptReleaseContext)(HCRYPTPROV_T, DWORD);

    pfn_CryptAcquireContextA pAcquire = (pfn_CryptAcquireContextA)GetProcAddress(hAdv, "CryptAcquireContextA");
    pfn_CryptCreateHash pCreate = (pfn_CryptCreateHash)GetProcAddress(hAdv, "CryptCreateHash");
    pfn_CryptHashData pData = (pfn_CryptHashData)GetProcAddress(hAdv, "CryptHashData");
    pfn_CryptGetHashParam pParam = (pfn_CryptGetHashParam)GetProcAddress(hAdv, "CryptGetHashParam");
    pfn_CryptDestroyHash pDestroy = (pfn_CryptDestroyHash)GetProcAddress(hAdv, "CryptDestroyHash");
    pfn_CryptReleaseContext pRelease = (pfn_CryptReleaseContext)GetProcAddress(hAdv, "CryptReleaseContext");

    if (pAcquire && pCreate && pData && pParam && pDestroy && pRelease) {
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            HCRYPTPROV_T hProv = 0;
            if (pAcquire(&hProv, NULL, NULL, 24 /* PROV_RSA_AES */, 0xF0000000 /* CRYPT_VERIFYCONTEXT */)) {
                HCRYPTHASH_T hHash = 0;
                if (pCreate(hProv, 0x0000800c /* CALG_SHA_256 */, 0, 0, &hHash)) {
                    BYTE buf[2048];
                    DWORD cb = 0;
                    while (ReadFile(hFile, buf, sizeof(buf), &cb, NULL) && cb > 0) {
                        pData(hHash, buf, cb, 0);
                    }
                    BYTE rgbHash[32];
                    DWORD cbHash = 32;
                    if (pParam(hHash, 2 /* HP_HASHVAL */, rgbHash, &cbHash, 0)) {
                        for (DWORD i = 0; i < cbHash && (i * 2 + 1) < outHexLen; i++) {
                            sprintf(outHex + (i * 2), "%02x", rgbHash[i]);
                        }
                    }
                    pDestroy(hHash);
                }
                pRelease(hProv, 0);
            }
            CloseHandle(hFile);
        }
    }
    FreeLibrary(hAdv);
}

// 全域狀態控制與環境變數退避鎖
static BOOL g_bRewindModeActive = FALSE;
static volatile BOOL g_bLuaMounted = FALSE;
static char g_module_dir[MAX_PATH] = {0};
static uintptr_t g_exe_base = 0;
static void DetectExeBase() {
    if (!g_exe_base) {
        g_exe_base = (uintptr_t)GetModuleHandleA(NULL);
    }
}

// 將宿主二進位絕對虛擬位址 (VA, 預設基底 0x00400000) 轉換為當前進程真實指針 (支援 ASLR 與非 ASLR)
static inline void* GetHostPtrByVa(uintptr_t va) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return (void*)va;
    return (void*)(g_exe_base + (va - 0x00400000));
}


// ============================================================================
// 夥伴任務：主程式版本白名單防禦與可寫邊界檢查
// ============================================================================
#define KNOWN_EXE_TIMEDATESTAMP 0x668BA427
#define KNOWN_EXE_SIZEOFIMAGE   0x0714B000

static int g_exe_whitelist_matched = 0;
static int g_counter_writeback_enabled = 0; // 乾淨模式：絕不倒撥牆上計數器，杜絕 0xc0000409 與音畫不同步！

static void ValidateExeWhitelist() {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)g_exe_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(g_exe_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD stamp = nt->FileHeader.TimeDateStamp;
    DWORD sizeOfImg = nt->OptionalHeader.SizeOfImage;

    if (stamp == KNOWN_EXE_TIMEDATESTAMP && sizeOfImg == KNOWN_EXE_SIZEOFIMAGE) {
        g_exe_whitelist_matched = 1;
    } else {
        g_exe_whitelist_matched = 0;
    }
}

static int CheckMemoryWritable(const void* addr, size_t sz) {
    if (!addr || sz == 0) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_READONLY))) {
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// proxy_ggpo.c：分離「串流汲取完畢 (g_bStreamDrained)」與「播放頭撞尾定格 (g_bStreamEndedFreeze)」
// ============================================================================
static volatile BOOL g_bStreamDrained     = FALSE; // 一旦為 TRUE 終生為 TRUE (代表總長已釘死在 g_record_frame)
static volatile BOOL g_bStreamEndedFreeze = FALSE; // 當前播放頭是否正停在最後一幀定格
static volatile BOOL g_bManualPaused      = FALSE; // 手動暫停旗標 (凍結播放頭不自增)
static BOOL g_bReachedEOF                 = FALSE; // 兼容標記 (同 g_bStreamDrained)
static void NotifyLuaReachedEOF(void);

static HWND g_hAutoLuaWnd = NULL;
static WNDPROC g_OrigMainWndProc = NULL;
static volatile BOOL g_bUserRequestedClose = FALSE;

// 1. 幽靈視窗三合一封印術：讓 Lua Script 對話框 100% 物理隱形，且免疫內部 SW_SHOW 重繪！
static void MakeWindowPermanentlyInvisible(HWND hLuaDlg) {
    if (!hLuaDlg) return;
    LONG_PTR exStyle = GetWindowLongPtrA(hLuaDlg, GWL_EXSTYLE);
    exStyle |= (WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
    exStyle &= ~WS_EX_APPWINDOW;
    SetWindowLongPtrA(hLuaDlg, GWL_EXSTYLE, exStyle);

    // Alpha = 0 (完全透明空氣，DWM 層級 100% 隱形)
    typedef BOOL (WINAPI *pfn_SetLayeredWindowAttributes)(HWND, COLORREF, BYTE, DWORD);
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32) {
        pfn_SetLayeredWindowAttributes pSetLayered = (pfn_SetLayeredWindowAttributes)GetProcAddress(hUser32, "SetLayeredWindowAttributes");
        if (pSetLayered) {
            pSetLayered(hLuaDlg, 0, 0, 0x00000002 /* LWA_ALPHA */);
        }
    }

    // 座標流放螢幕外十萬八千里遠 (-32000, -32000) 並隱藏
    SetWindowPos(hLuaDlg, HWND_BOTTOM, -32000, -32000, 0, 0, 
                 SWP_NOACTIVATE | SWP_NOSIZE | SWP_HIDEWINDOW);
    ShowWindow(hLuaDlg, SW_HIDE);
}

// 2. 攔截 FBNeo 主視窗訊息迴圈 (防止 GGPO 播完或斷流偷關視窗，轉為定格狀態)
static LRESULT CALLBACK RewindMainWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_SYSCOMMAND && (wParam & 0xFFF0) == SC_CLOSE) {
        g_bUserRequestedClose = TRUE;
    }
    if (uMsg == WM_CLOSE || uMsg == WM_DESTROY) {
        if (!g_bUserRequestedClose) {
            // 抓到了！這是 Replay 結束或斷流觸發的自動關閉，當場吃掉！
            g_bStreamDrained = TRUE;
            g_bStreamEndedFreeze = TRUE;
            g_bReachedEOF = TRUE;
            NotifyLuaReachedEOF();
            return 0; // 直接吃掉訊息，主程式絕不關閉！
        }
    }
    return CallWindowProcA(g_OrigMainWndProc, hwnd, uMsg, wParam, lParam);
}

static void AttachMainWindowCloseGuard(HWND hMainWnd) {
    if (hMainWnd && !g_OrigMainWndProc) {
        g_OrigMainWndProc = (WNDPROC)SetWindowLongPtrA(hMainWnd, GWLP_WNDPROC, (LONG_PTR)RewindMainWndProc);
    }
}

// ============================================================================
// proxy_ggpo.c：宿主三變數死而復生鎖 (Triple-Lock Session Keep-Alive)
// 基於真實二進位反組譯指令 (RVA 0x00049C08 / 0x0020925B)：
// 1. RVA 0x01D21600: bGGPOActive (宿主每幀檢查，若為 0 則跳過同步輸入，必須鎖定為 1！)
// 2. RVA 0x01D21604: bGGPOFinished (重播結束標記，必須鎖定為 0！)
// 3. RVA 0x01C56734: pGGPOSession (宿主真正的會話指標，必須鎖定為 g_saved_ggpo！)
// ============================================================================
static void* g_saved_ggpo = NULL;
static int   g_host_session_ptrs_verified = 0;

static void EnforceHostGGPOSessionAlive(void) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    volatile uint32_t* p_bGGPOActive   = (volatile uint32_t*)(g_exe_base + 0x01D21600);
    volatile uint32_t* p_bGGPOFinished = (volatile uint32_t*)(g_exe_base + 0x01D21604);
    volatile void**    p_pGGPOSession  = (volatile void**)(g_exe_base + 0x01C56734);

    if (!g_host_session_ptrs_verified) {
        if (CheckMemoryWritable((const void*)p_bGGPOActive, 4) &&
            CheckMemoryWritable((const void*)p_bGGPOFinished, 4) &&
            CheckMemoryWritable((const void*)p_pGGPOSession, sizeof(void*))) {
            g_host_session_ptrs_verified = 1;
        } else {
            return;
        }
    }

    // 自動快取 session 指標
    if (!g_saved_ggpo && *p_pGGPOSession) {
        g_saved_ggpo = (void*)*p_pGGPOSession;
    }

    // 1. 永遠鎖定活動旗標為 1，確保宿主的 jz 永遠不跳，每幀必定調用同步輸入！
    {
        if (*p_bGGPOActive != 1) {
            *p_bGGPOActive = 1;
            static char s_lp[MAX_PATH];
            if (!s_lp[0]) snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);
            FILE* fp = fopen(s_lp, "a");
            if (fp) {
                fprintf(fp, "[TRIPLE_LOCK] 偵測到宿主 bGGPOActive (RVA 0x01D21600) 被清空，已瞬間強制寫回 1！\n");
                fclose(fp);
            }
        }
    }

    // 2. 永遠鎖定結束旗標為 0，確保宿主絕不判定重播已死！
    {
        if (*p_bGGPOFinished != 0) {
            *p_bGGPOFinished = 0;
            static char s_lp[MAX_PATH];
            if (!s_lp[0]) snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);
            FILE* fp = fopen(s_lp, "a");
            if (fp) {
                fprintf(fp, "[TRIPLE_LOCK] 偵測到宿主 bGGPOFinished (RVA 0x01D21604) 被設為 1，已瞬間強制清零！\n");
                fclose(fp);
            }
        }
    }

    // 3. 永遠鎖定 session 指標，確保會話永生！
    if (g_saved_ggpo) {
        if (*p_pGGPOSession == NULL) {
            *p_pGGPOSession = g_saved_ggpo;
            static char s_lp[MAX_PATH];
            if (!s_lp[0]) snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);
            FILE* fp = fopen(s_lp, "a");
            if (fp) {
                fprintf(fp, "[TRIPLE_LOCK] 偵測到宿主 pGGPOSession (RVA 0x01C56734) 被置 NULL，已瞬間寫回 %p！\n", g_saved_ggpo);
                fclose(fp);
            }
        }
    }
}

// ============================================================================
// 2. 主執行緒同步自動掛載 Lua 腳本 (直接設定 Edit 控制項路徑，免 IAT Hook，免跨執行緒競爭)
// ============================================================================
static void PerformMainThreadAutoMount() {
    if (g_bLuaMounted) return;
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    static char s_lp[MAX_PATH];
    if (!s_lp[0]) snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);

    // 1. 呼叫 FBNeo 內建的 FBALuaOpenWindow 函式 (RVA 0x0004D560)
    typedef void (*pfn_LuaOpenWindow)(void);
    pfn_LuaOpenWindow LuaOpenWindow = (pfn_LuaOpenWindow)(g_exe_base + 0x0004D560);
    if (LuaOpenWindow && !IsBadCodePtr((FARPROC)LuaOpenWindow)) {
        LuaOpenWindow();
    }

    // 2. 從 FBNeo 全域變數讀取 Lua 對話框 HWND (RVA 0x01D1DF54)
    HWND* ppLuaWnd = (HWND*)(g_exe_base + 0x01D1DF54);
    HWND hLuaDlg = (ppLuaWnd && !IsBadReadPtr(ppLuaWnd, sizeof(HWND))) ? *ppLuaWnd : NULL;
    if (!hLuaDlg || !IsWindow(hLuaDlg)) {
        hLuaDlg = FindWindowA(NULL, "Lua Script");
    }

    if (hLuaDlg && IsWindow(hLuaDlg)) {
        // 先在建立瞬間直接施加幽靈視窗封印術！
        MakeWindowPermanentlyInvisible(hLuaDlg);

        // 3. 取得腳本路徑並直接設定給 Edit 控制項 (IDC_LUAPATH = 20368 / 0x4F90)
        char szScriptPath[MAX_PATH] = {0};
        snprintf(szScriptPath, sizeof(szScriptPath), "%sscripts\\rewind_core.lua", g_module_dir);
        SetDlgItemTextA(hLuaDlg, 20368, szScriptPath);

        // 4. 觸發 Run 按鈕 (IDC_LUARUN = 20366)
        SendMessageA(hLuaDlg, WM_COMMAND, MAKEWPARAM(20366, BN_CLICKED), 0);

        // 5. 再次施加幽靈封印術，徹底化為空氣
        MakeWindowPermanentlyInvisible(hLuaDlg);
        g_hAutoLuaWnd = hLuaDlg;
        g_bLuaMounted = TRUE;

        // 將焦點還給遊戲主畫面，並掛上防關窗金牌守護！
        HWND* ppScrnWnd = (HWND*)(g_exe_base + 0x01D1DEC0);
        HWND hScrn = (ppScrnWnd && !IsBadReadPtr(ppScrnWnd, sizeof(HWND))) ? *ppScrnWnd : NULL;
        if (hScrn && IsWindow(hScrn)) {
            AttachMainWindowCloseGuard(hScrn);
            SetForegroundWindow(hScrn);
            SetFocus(hScrn);
        }

        FILE* fp = fopen(s_lp, "a");
        if (fp) {
            fprintf(fp, "\n=== [MAIN_THREAD AUTOMOUNT SUCCESS] rewind_core.lua 已在主執行緒順利掛載並啟動！(HWND=0x%p) ===\n\n", (void*)hLuaDlg);
            fclose(fp);
        }
    } else {
        FILE* fp = fopen(s_lp, "a");
        if (fp) {
            fprintf(fp, "\n=== [MAIN_THREAD AUTOMOUNT FAILED] 無法取得 LuaScript 對話框控制代碼！ ===\n\n");
            fclose(fp);
        }
    }
}

#define MAX_REPLAY_FRAMES 540000
#define INPUT_SIZE_MAX 32

// 模組路徑暫存
static char g_real_dll_path[MAX_PATH] = {0};

// 全域歷史緩衝區
static BYTE g_input_history[MAX_REPLAY_FRAMES][INPUT_SIZE_MAX];
static int  g_input_lens[MAX_REPLAY_FRAMES];
static int  g_record_frame = 0;
static int  g_play_frame = 0;
static int  g_frame_replayed = 0;
static int  g_is_rewound = 0;

static void NotifyLuaReachedEOF() {
    char ipc_path[MAX_PATH] = {0};
    snprintf(ipc_path, sizeof(ipc_path), "%sscripts\\ipc_state.txt", g_module_dir);
    FILE* fp = fopen(ipc_path, "w");
    if (fp) {
        fprintf(fp, "%d %d 1 3 %d\n", g_play_frame, g_record_frame, g_record_frame);
        fclose(fp);
    }
}

// 夥伴指導：端到端每幀畫面 Hash (全幅 320x224 步幅 64 取樣)
static uint32_t g_fb_live_hashes[MAX_REPLAY_FRAMES];
static int      g_fb_live_recorded[MAX_REPLAY_FRAMES];
static int      g_match_count_300 = 0;
static int      g_mismatch_count_300 = 0;
static int      g_check_window_frames = 0;

// 夥伴指導：管線事件順序環狀緩衝區
#define EVENT_RING_SIZE 32
static struct {
    char tag[8];
    uint32_t cur;
    int inf;
} g_event_ring[EVENT_RING_SIZE];
static int g_event_idx = 0;

static uintptr_t g_exe_base;
static uintptr_t g_my_dll_base = 0;
static HMODULE hReal = NULL;
static void DetectExeBase();

// ----------------------------------------------------------------------------
// 夥伴任務 4：每幀加 1 的 DWORD 計數器普查系統 (Counter Census)
// ----------------------------------------------------------------------------
#define MAX_COUNTER_CANDS 60000

typedef struct {
    uintptr_t addr;
    uint32_t val1; // 第 1 幀之值
    uint32_t val2; // 第 2 幀之值
    uint32_t val3; // 第 3 幀之值
} CounterCandidate;

static CounterCandidate* g_counter_candidates = NULL;
static int g_counter_total_cands = 0;
static int g_counter_step = 0;
static int g_counter_start_frame = 0;
static int g_counter_done_k15 = 0;

static uint32_t GetModuleSize(HMODULE hMod) {
    if (!hMod) return 0;
    uintptr_t base = (uintptr_t)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

static void IdentifyOwner(uintptr_t addr, char* out_buf, size_t buf_sz) {
    HMODULE hExe = GetModuleHandleA(NULL);
    uint32_t exe_sz = GetModuleSize(hExe);
    if (hExe && addr >= (uintptr_t)hExe && addr < (uintptr_t)hExe + exe_sz) {
        snprintf(out_buf, buf_sz, "EXE (fcadefbneo.exe, RVA=0x%08X)", (unsigned int)(addr - (uintptr_t)hExe));
        return;
    }
    if (g_my_dll_base) {
        uint32_t my_sz = GetModuleSize((HMODULE)g_my_dll_base);
        if (addr >= g_my_dll_base && addr < g_my_dll_base + my_sz) {
            snprintf(out_buf, buf_sz, "PROXY_DLL (ggponet.dll, RVA=0x%08X)", (unsigned int)(addr - g_my_dll_base));
            return;
        }
    }
    HMODULE hR = hReal ? hReal : GetModuleHandleA("ggponet_real.dll");
    if (hR) {
        uint32_t r_sz = GetModuleSize(hR);
        if (addr >= (uintptr_t)hR && addr < (uintptr_t)hR + r_sz) {
            snprintf(out_buf, buf_sz, "REAL_DLL (ggponet_real.dll, RVA=0x%08X)", (unsigned int)(addr - (uintptr_t)hR));
            return;
        }
    }
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((const void*)addr, &mbi, sizeof(mbi)) && mbi.AllocationBase) {
        char modName[MAX_PATH] = {0};
        if (GetModuleFileNameA((HMODULE)mbi.AllocationBase, modName, sizeof(modName))) {
            char* p = strrchr(modName, '\\');
            snprintf(out_buf, buf_sz, "OTHER_MOD (%s)", p ? (p + 1) : modName);
            return;
        }
    }
    snprintf(out_buf, buf_sz, "UNKNOWN_REGION");
}

static void RunCensusStep(int live_frame) {
#ifndef ENABLE_LEGACY_DIAGNOSTICS
    (void)live_frame;
    return;
#else
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    if (g_counter_step == 0) {
        if (live_frame == 400) {
            if (!g_counter_candidates) {
                g_counter_candidates = (CounterCandidate*)malloc(sizeof(CounterCandidate) * MAX_COUNTER_CANDS);
            }
            if (!g_counter_candidates) return;
            g_counter_total_cands = 0;
            g_counter_start_frame = live_frame;

            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)g_exe_base;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(g_exe_base + dos->e_lfanew);
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
            for (int s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                if (sec[s].Characteristics & IMAGE_SCN_MEM_WRITE) {
                    uintptr_t start = g_exe_base + sec[s].VirtualAddress;
                    uintptr_t end = start + sec[s].Misc.VirtualSize;
                    for (uintptr_t p = start; p < end - 4; p += 4) {
                        if (!IsBadReadPtr((const void*)p, 4)) {
                            uint32_t val = *(uint32_t*)p;
                            int diff = (int)val - live_frame;
                            if (diff >= -100 && diff <= 100) {
                                if (g_counter_total_cands < MAX_COUNTER_CANDS) {
                                    g_counter_candidates[g_counter_total_cands].addr = p;
                                    g_counter_candidates[g_counter_total_cands].val1 = val;
                                    g_counter_total_cands++;
                                }
                            }
                        }
                    }
                }
            }
            g_counter_step = 1;
            char s_log_path[MAX_PATH];
            snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
            FILE* fp = fopen(s_log_path, "a");
            if (fp) {
                fprintf(fp, "[COUNTER_CENSUS] 幀 400 啟動！初篩候選數量: %d\n", g_counter_total_cands);
                fclose(fp);
            }
        }
    } else if (g_counter_step == 1 && live_frame == g_counter_start_frame + 1) {
        int new_cnt = 0;
        for (int i = 0; i < g_counter_total_cands; i++) {
            uintptr_t p = g_counter_candidates[i].addr;
            if (!IsBadReadPtr((const void*)p, 4)) {
                uint32_t val = *(uint32_t*)p;
                if (val == g_counter_candidates[i].val1 + 1) {
                    g_counter_candidates[new_cnt].addr = p;
                    g_counter_candidates[new_cnt].val1 = g_counter_candidates[i].val1;
                    g_counter_candidates[new_cnt].val2 = val;
                    new_cnt++;
                }
            }
        }
        g_counter_total_cands = new_cnt;
        g_counter_step = 2;
    } else if (g_counter_step == 2 && live_frame == g_counter_start_frame + 2) {
        int new_cnt = 0;
        for (int i = 0; i < g_counter_total_cands; i++) {
            uintptr_t p = g_counter_candidates[i].addr;
            if (!IsBadReadPtr((const void*)p, 4)) {
                uint32_t val = *(uint32_t*)p;
                if (val == g_counter_candidates[i].val2 + 1) {
                    g_counter_candidates[new_cnt].addr = p;
                    g_counter_candidates[new_cnt].val1 = g_counter_candidates[i].val1;
                    g_counter_candidates[new_cnt].val2 = g_counter_candidates[i].val2;
                    g_counter_candidates[new_cnt].val3 = val;
                    new_cnt++;
                }
            }
        }
        g_counter_total_cands = new_cnt;
        g_counter_step = 3;
    }
#endif
}

static void CheckCensusAtK15(int k_step) {
#ifndef ENABLE_LEGACY_DIAGNOSTICS
    (void)k_step;
    return;
#else
    if (g_counter_step != 3 || g_counter_done_k15 || k_step != 15) return;
    g_counter_done_k15 = 1;

    char out_path[MAX_PATH];
    snprintf(out_path, sizeof(out_path), "%sscripts\\counter_census.txt", g_module_dir);
    FILE* fp = fopen(out_path, "w");
    if (!fp) return;

    fprintf(fp, "========================================================================================\n");
    fprintf(fp, " 每幀加 1 的 DWORD 計數器普查報告 (在重播 k=15 時採樣)\n");
    fprintf(fp, " 普查基準: LIVE 連續 3 幀 (%d, %d, %d) 剛好每幀遞增 1\n",
        g_counter_start_frame, g_counter_start_frame + 1, g_counter_start_frame + 2);
    fprintf(fp, " 總候選數量: %d\n", g_counter_total_cands);
    fprintf(fp, "========================================================================================\n");
    fprintf(fp, "%-10s | %-10s | %-10s | %-10s | %-12s | %-32s\n",
        "位址", "LIVE_f1", "LIVE_f3", "重播k=15值", "是否吻合914/915", "擁有者 (模組與RVA)");
    fprintf(fp, "----------------------------------------------------------------------------------------\n");

    int match_count = 0;
    for (int i = 0; i < g_counter_total_cands; i++) {
        uintptr_t p = g_counter_candidates[i].addr;
        uint32_t cur_val = 0;
        if (!IsBadReadPtr((const void*)p, 4)) {
            cur_val = *(uint32_t*)p;
        }
        char owner[128] = {0};
        IdentifyOwner(p, owner, sizeof(owner));

        int is_wallclock = (cur_val == 914 || cur_val == 915 || cur_val == 913 || cur_val == 916);
        if (is_wallclock) match_count++;

        fprintf(fp, "0x%08X | %-10u | %-10u | %-10u | %-12s | %s\n",
            (unsigned int)p, g_counter_candidates[i].val1, g_counter_candidates[i].val3,
            cur_val, is_wallclock ? "** MATCH **" : "no", owner);
    }

    fprintf(fp, "========================================================================================\n");
    fprintf(fp, " 吻合 914/915 牆上時間候選計數器總數: %d\n", match_count);
    fprintf(fp, "========================================================================================\n");
    fclose(fp);
#endif
}

static int g_pcur_verified = 0;
static void LogEvent(const char* tag, int inf) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;
    volatile uint32_t* p_cur = (volatile uint32_t*)(g_exe_base + 0x02D21B24);
    if (!g_pcur_verified) {
        if (p_cur && !IsBadReadPtr((const void*)p_cur, 4)) g_pcur_verified = 1;
        else return;
    }
    uint32_t c_val = *p_cur;
    int idx = g_event_idx % EVENT_RING_SIZE;
    strncpy(g_event_ring[idx].tag, tag, 7);
    g_event_ring[idx].tag[7] = '\0';
    g_event_ring[idx].cur = c_val;
    g_event_ring[idx].inf = inf;
    g_event_idx++;
}

// 上一次輸入紀錄
static BYTE g_last_rec_input[INPUT_SIZE_MAX];
static int  g_has_last_rec = 0;
static BYTE g_last_play_input[INPUT_SIZE_MAX];
static int  g_has_last_play = 0;

// 統計計數器
static int g_seq = 0;
static int g_real_sync_calls = 0;
static int g_real_adv_calls = 0;

// 主線程 ID
static DWORD g_main_tid = 0;

// 真實 DLL 模組與函式指標
typedef int (__cdecl *fn_sync_input)(void* session, void* values, int size, int* disconnect_flags);
typedef int (__cdecl *fn_adv_frame)(void* session);
typedef void (__cdecl *fn_lua_pushinteger)(void* L, ptrdiff_t n);
typedef ptrdiff_t (__cdecl *fn_lua_tointeger)(void* L, int idx);
typedef void (__cdecl *fn_lua_pushboolean)(void* L, int b);
typedef int (__cdecl *fn_lua_gettop)(void* L);

static fn_sync_input        p_real_sync_input = NULL;
static fn_adv_frame         p_real_adv_frame = NULL;

static void* p_real_ggpo_start_session = NULL;
static void* p_real_ggpo_start_synctest = NULL;
static void* p_real_ggpo_start_replay = NULL;
static void* p_real_ggpo_start_streaming = NULL;
static void* p_real_ggpo_set_frame_delay = NULL;
static void* p_real_ggpo_idle = NULL;
static void* p_real_ggpo_get_stats = NULL;
static void* p_real_ggpo_close_session = NULL;
static void* p_real_ggpo_log = NULL;
static void* p_real_ggpo_logv = NULL;
static void* p_real_ggpo_client_connect = NULL;
static void* p_real_ggpo_client_chat = NULL;
static void* p_real_ggpo_client_set_game_event = NULL;

static fn_lua_pushinteger   p_lua_pushinteger = NULL;
static fn_lua_tointeger     p_lua_tointeger = NULL;
static fn_lua_pushboolean   p_lua_pushboolean = NULL;
static fn_lua_gettop        p_lua_gettop = NULL;


// ----------------------------------------------------------------------------
// 延遲初始化真實 DLL
// ----------------------------------------------------------------------------
static void InitRealDll() {
    if (!hReal) {
        if (g_real_dll_path[0]) {
            hReal = LoadLibraryA(g_real_dll_path);
        }
        if (!hReal) {
            hReal = LoadLibraryA("ggponet_real.dll");
        }
        if (!hReal) {
            hReal = LoadLibraryA("emulator\\fbneo\\ggponet_real.dll");
        }
        if (hReal) {
            p_real_ggpo_start_session          = (void*)GetProcAddress(hReal, "ggpo_start_session");
            p_real_ggpo_start_synctest          = (void*)GetProcAddress(hReal, "ggpo_start_synctest");
            p_real_ggpo_start_replay           = (void*)GetProcAddress(hReal, "ggpo_start_replay");
            p_real_ggpo_start_streaming        = (void*)GetProcAddress(hReal, "ggpo_start_streaming");
            p_real_ggpo_set_frame_delay        = (void*)GetProcAddress(hReal, "ggpo_set_frame_delay");
            p_real_ggpo_idle                   = (void*)GetProcAddress(hReal, "ggpo_idle");
            p_real_ggpo_get_stats              = (void*)GetProcAddress(hReal, "ggpo_get_stats");
            p_real_ggpo_close_session          = (void*)GetProcAddress(hReal, "ggpo_close_session");
            p_real_ggpo_log                    = (void*)GetProcAddress(hReal, "ggpo_log");
            p_real_ggpo_logv                   = (void*)GetProcAddress(hReal, "ggpo_logv");
            p_real_ggpo_client_connect         = (void*)GetProcAddress(hReal, "ggpo_client_connect");
            p_real_ggpo_client_chat            = (void*)GetProcAddress(hReal, "ggpo_client_chat");
            p_real_ggpo_client_set_game_event  = (void*)GetProcAddress(hReal, "ggpo_client_set_game_event");

            p_real_sync_input                  = (fn_sync_input)GetProcAddress(hReal, "ggpo_synchronize_input");
            p_real_adv_frame                   = (fn_adv_frame)GetProcAddress(hReal, "ggpo_advance_frame");
        }
    }
    if (!p_lua_pushinteger) {
        HMODULE hLua = GetModuleHandleA("lua51.dll");
        if (!hLua) hLua = LoadLibraryA("lua51.dll");
        if (!hLua) hLua = LoadLibraryA("emulator\\fbneo\\lua51.dll");
        if (hLua) {
            p_lua_pushinteger = (fn_lua_pushinteger)GetProcAddress(hLua, "lua_pushinteger");
            p_lua_tointeger   = (fn_lua_tointeger)GetProcAddress(hLua, "lua_tointeger");
            p_lua_pushboolean = (fn_lua_pushboolean)GetProcAddress(hLua, "lua_pushboolean");
            p_lua_gettop      = (fn_lua_gettop)GetProcAddress(hLua, "lua_gettop");
        }
    }
}

// ----------------------------------------------------------------------------
// 13 個原生函式 Naked JMP 轉發
// ----------------------------------------------------------------------------
#define MAKE_NAKED_FORWARD(name) \
    __declspec(dllexport) void name() { \
        if (!hReal) InitRealDll(); \
        __asm__("leave\n\t" \
                "jmp *p_real_" #name); \
    }

// ============================================================================
// 夥伴 Argon 規範：GGPO 事件結構與回呼免死金牌 (鐵閘 1)
// ============================================================================
#define GGPO_EVENTCODE_CONNECTED_TO_PEER       1000
#define GGPO_EVENTCODE_SYNCHRONIZING_WITH_PEER 1001
#define GGPO_EVENTCODE_SYNCHRONIZED_WITH_PEER  1002
#define GGPO_EVENTCODE_RUNNING                 1003
#define GGPO_EVENTCODE_DISCONNECTED_FROM_PEER  1004
#define GGPO_EVENTCODE_TIMESYNC                1005
#define GGPO_EVENTCODE_CONNECTION_INTERRUPTED  1006
#define GGPO_EVENTCODE_CONNECTION_RESUMED      1007

typedef struct {
   int code;
   union {
      struct { int player; } connected;
      struct { int player; int count; int total; } synchronizing;
      struct { int player; } synchronized;
      struct { int player; } disconnected;
      struct { int frames_ahead; } timesync;
      struct { int player; int disconnect_timeout; } connection_interrupted;
      struct { int player; } connection_resumed;
   } u;
} GGPOEvent;

typedef struct {
   int  (__cdecl *begin_game)(const char *game);
   int  (__cdecl *save_game_state)(unsigned char **buffer, int *len, int *checksum, int frame);
   int  (__cdecl *load_game_state)(unsigned char *buffer, int len);
   int  (__cdecl *log_game_state)(char *filename, unsigned char *buffer, int len);
   void (__cdecl *free_buffer)(void *buffer);
   int  (__cdecl *advance_frame)(int flags);
   void (__cdecl *on_event)(GGPOEvent *info);
} GGPOSessionCallbacks;

static void (__cdecl *g_orig_on_event)(GGPOEvent* info) = NULL;
static GGPOSessionCallbacks g_proxy_cb;

static void __cdecl ProxyOnEvent(GGPOEvent* info) {
    if (!info) return;

    // 當真實 GGPO 發出斷線 (1004) 或連接中斷 (1006) 事件時，當場吞噬保護！
    if (info->code == GGPO_EVENTCODE_DISCONNECTED_FROM_PEER ||
        info->code == GGPO_EVENTCODE_CONNECTION_INTERRUPTED) {
        
        static char s_lp[MAX_PATH] = {0};
        if (!s_lp[0]) snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_lp, "a");
        if (fp) {
            fprintf(fp, "[PROXY_ON_EVENT] 成功攔截並吞噬 GGPO 斷線事件！code=%d player=%d，FBNeo GGPO 會話受到金牌保護！\n",
                info->code, info->u.disconnected.player);
            fclose(fp);
        }
        return; // 絕不通知 FBNeo，保證 FBNeo 永遠深信 GGPO 會話活躍，持續每幀同步輸入！
    }

    if (g_orig_on_event) {
        g_orig_on_event(info);
    }
}

static GGPOSessionCallbacks* WrapCallbacks(GGPOSessionCallbacks* cb) {
    if (!cb) return NULL;
    g_proxy_cb = *cb;
    g_orig_on_event = cb->on_event;
    g_proxy_cb.on_event = ProxyOnEvent;
    return &g_proxy_cb;
}

__declspec(dllexport) int __cdecl ggpo_start_session(void** session, GGPOSessionCallbacks* cb, const char* game, int num_players, int input_size, unsigned short localport) {
    if (!hReal) InitRealDll();
    typedef int (__cdecl *fn_ses)(void**, GGPOSessionCallbacks*, const char*, int, int, unsigned short);
    fn_ses p = (fn_ses)p_real_ggpo_start_session;
    if (p) return p(session, WrapCallbacks(cb), game, num_players, input_size, localport);
    return 0;
}

__declspec(dllexport) int __cdecl ggpo_start_synctest(void** session, GGPOSessionCallbacks* cb, const char* game, int num_players, int input_size, int frames) {
    if (!hReal) InitRealDll();
    typedef int (__cdecl *fn_st)(void**, GGPOSessionCallbacks*, const char*, int, int, int);
    fn_st p = (fn_st)p_real_ggpo_start_synctest;
    if (p) return p(session, WrapCallbacks(cb), game, num_players, input_size, frames);
    return 0;
}

__declspec(dllexport) int __cdecl ggpo_start_replay(void** session, GGPOSessionCallbacks* cb, const char* game, int num_players, int input_size) {
    if (!hReal) InitRealDll();
    typedef int (__cdecl *fn_sr)(void**, GGPOSessionCallbacks*, const char*, int, int);
    fn_sr p = (fn_sr)p_real_ggpo_start_replay;
    if (p) return p(session, WrapCallbacks(cb), game, num_players, input_size);
    return 0;
}

__declspec(dllexport) int __cdecl ggpo_start_streaming(void** session, GGPOSessionCallbacks* cb, const char* game, int num_players, int input_size, const char* filename) {
    if (!hReal) InitRealDll();
    typedef int (__cdecl *fn_ss)(void**, GGPOSessionCallbacks*, const char*, int, int, const char*);
    fn_ss p = (fn_ss)p_real_ggpo_start_streaming;
    if (p) return p(session, WrapCallbacks(cb), game, num_players, input_size, filename);
    return 0;
}

MAKE_NAKED_FORWARD(ggpo_set_frame_delay)

typedef USHORT (WINAPI *fn_CaptureStackBackTrace)(ULONG, ULONG, PVOID*, PULONG);
static fn_CaptureStackBackTrace p_CaptureStackBackTrace = NULL;

__declspec(dllexport) int __cdecl ggpo_close_session(void* session) {
    if (!g_exe_base) DetectExeBase();
    if (!p_CaptureStackBackTrace) {
        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        if (hK32) p_CaptureStackBackTrace = (fn_CaptureStackBackTrace)GetProcAddress(hK32, "RtlCaptureStackBackTrace");
    }
    void* callers[8] = {0};
    USHORT nFrames = p_CaptureStackBackTrace ? p_CaptureStackBackTrace(1, 8, callers, NULL) : 0;

    static char s_lp[MAX_PATH];
    if (!s_lp[0]) snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);
    FILE* fp = fopen(s_lp, "a");
    if (fp) {
        fprintf(fp, "\n=== [GGPO_CLOSE_SESSION BLACKBOX] session=%p | nFrames=%d ===\n", session, (int)nFrames);
        for (int i = 0; i < nFrames; i++) {
            uintptr_t addr = (uintptr_t)callers[i];
            uintptr_t rva = (addr >= g_exe_base && addr < g_exe_base + 0x01000000) ? (addr - g_exe_base) : 0;
            fprintf(fp, "  -> Frame[%d]: 0x%08X (RVA: 0x%08X)\n", i, (unsigned int)addr, (unsigned int)rva);
        }
        fprintf(fp, "=========================================================\n\n");
        fclose(fp);
    }

    if (session && !g_saved_ggpo) g_saved_ggpo = session;
    EnforceHostGGPOSessionAlive();

    if (g_bRewindModeActive && !g_bUserRequestedClose) {
        return 0; // GGPO_OK: 絕不真正關閉，保持會話活耀！
    }
    if (!hReal) InitRealDll();
    if (p_real_ggpo_close_session) {
        typedef int (__cdecl *fn_cs)(void*);
        return ((fn_cs)p_real_ggpo_close_session)(session);
    }
    return 0;
}
MAKE_NAKED_FORWARD(ggpo_log)
MAKE_NAKED_FORWARD(ggpo_logv)
MAKE_NAKED_FORWARD(ggpo_client_connect)
MAKE_NAKED_FORWARD(ggpo_client_chat)
static int g_last_real_ret = 0x00000101;
static int g_stream_starving = 0;
static DWORD g_last_valid_sync_tick = 0;
__declspec(dllexport) int __cdecl ggpo_idle(void* ggpo, int timeout) {
    // 當正在看歷史回放或串流已到底時，不再呼叫官方 idle，防止觸發內部幽靈回滾覆蓋 Lua 快照！
    if (g_bStreamDrained || (g_is_rewound && g_play_frame < g_record_frame - 1)) {
        return 0;
    }
    if (!hReal) InitRealDll();
    if (p_real_ggpo_idle) {
        typedef int (__cdecl *fn_idle)(void*, int);
        return ((fn_idle)p_real_ggpo_idle)(ggpo, timeout);
    }
    return 0;
}

MAKE_NAKED_FORWARD(ggpo_get_stats)

// ----------------------------------------------------------------------------
// 唯讀呼叫棧分支判定器 (Zero-Crash Stack Tracer)
// ----------------------------------------------------------------------------
static void DetectRunFrameBranch(int is_rewind) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    if (!p_CaptureStackBackTrace) {
        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        if (hK32) p_CaptureStackBackTrace = (fn_CaptureStackBackTrace)GetProcAddress(hK32, "RtlCaptureStackBackTrace");
    }
    if (!p_CaptureStackBackTrace) return;

    void* frames[8];
    USHORT n = p_CaptureStackBackTrace(1, 8, frames, NULL);
    if (n < 4) return;

    // frames[0]: proxy_ggpo
    // frames[1]: RVA 0x0002A9EC (sync wrapper)
    // frames[2]: RVA 0x000499F8 (RunFrame internal)
    // frames[3]: RunFrame caller return address!!
    uintptr_t caller_addr = (uintptr_t)frames[3];
    uintptr_t caller_rva = (caller_addr >= g_exe_base && caller_addr < g_exe_base + 0x01000000) ? (caller_addr - g_exe_base) : 0;

    const char* branch_desc = "UNKNOWN";
    int deduced_bDraw = -1;

    if (caller_rva == 0x00049E48) {
        branch_desc = "CASE_A (Catchup loop edi, cmp [0x02056434])";
        deduced_bDraw = 0; // 若 0x02056434 為 0 則為 0
    } else if (caller_rva == 0x00049E6B) {
        branch_desc = "CASE_B (Skip-draw catchup loop esi, HARDCODED bDraw=0 !!)";
        deduced_bDraw = 0; // 寫死為 0
    } else if (caller_rva == 0x00049E7F) {
        branch_desc = "CASE_C (Normal frame, bDraw=1 !!)";
        deduced_bDraw = 1;
    }

    static int s_logged_live = 0;
    static int s_logged_rew = 0;
    if ((!is_rewind && s_logged_live < 5) || (is_rewind && s_logged_rew < 10)) {
        if (!is_rewind) s_logged_live++; else s_logged_rew++;

        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[RUNFRAME_BRANCH %s] Caller_RVA=0x%08X | bDraw=%d | %s | play=%d rec=%d\n",
                is_rewind ? "REWIND" : "LIVE", (unsigned int)caller_rva, deduced_bDraw, branch_desc, g_play_frame, g_record_frame);
            fclose(fp);
        }
    }
}

// ----------------------------------------------------------------------------
// 三大計數器增量度量 (cur, emulated, rendered)
// ----------------------------------------------------------------------------
static void MeasureRunFrameCounters(int is_rewind) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    volatile uint32_t* p_cur = (volatile uint32_t*)(g_exe_base + 0x02D21B24);
    volatile uint32_t* p_emu = (volatile uint32_t*)(g_exe_base + 0x02D21B2C);
    volatile uint32_t* p_ren = (volatile uint32_t*)(g_exe_base + 0x06D8B340);

    if (IsBadReadPtr((const void*)p_cur, 4) ||
        IsBadReadPtr((const void*)p_emu, 4) ||
        IsBadReadPtr((const void*)p_ren, 4)) {
        return;
    }

    static DWORD s_last_time = 0;
    static uint32_t s_last_cur = 0, s_last_emu = 0, s_last_ren = 0;
    DWORD now = GetTickCount();

    if (s_last_time == 0) {
        s_last_time = now;
        s_last_cur = *p_cur;
        s_last_emu = *p_emu;
        s_last_ren = *p_ren;
        return;
    }

    if (now - s_last_time >= 1000) {
        uint32_t c_val = *p_cur, e_val = *p_emu, r_val = *p_ren;
        uint32_t c_delta = c_val - s_last_cur;
        uint32_t e_delta = e_val - s_last_emu;
        uint32_t r_delta = r_val - s_last_ren;

        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[RF_COUNTERS %s] cur_delta=%u | emu_delta=%u | ren_delta=%u | (cur=%u, emu=%u, ren=%u)\n",
                is_rewind ? "REWIND" : "LIVE", c_delta, e_delta, r_delta, c_val, e_val, r_val);
            fclose(fp);
        }
        s_last_time = now;
        s_last_cur = c_val;
        s_last_emu = e_val;
        s_last_ren = r_val;
    }
}

// ----------------------------------------------------------------------------
// 影像緩衝區 Checksum 校驗 (無死角指針診斷與 256KB 全畫面步幅像素 Hash)
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 實體 24-bit BMP 畫面導出函式 (RGB565 -> BGR24 標準 Windows BMP)
// ----------------------------------------------------------------------------
static void SaveBufferToBmp24(const char* filepath, const uint8_t* src, int w, int h) {
    if (!src || !filepath) return;
    FILE* fp = fopen(filepath, "wb");
    if (!fp) return;

    int row_padded = (w * 3 + 3) & (~3);
    uint32_t image_sz = row_padded * h;
    uint32_t file_sz = 54 + image_sz;

    #pragma pack(push, 1)
    struct {
        uint16_t bfType;
        uint32_t bfSize;
        uint16_t bfReserved1;
        uint16_t bfReserved2;
        uint32_t bfOffBits;
    } bfh = {0x4D42, file_sz, 0, 0, 54};

    struct {
        uint32_t biSize;
        int32_t  biWidth;
        int32_t  biHeight;
        uint16_t biPlanes;
        uint16_t biBitCount;
        uint32_t biCompression;
        uint32_t biSizeImage;
        int32_t  biXPelsPerMeter;
        int32_t  biYPelsPerMeter;
        uint32_t biClrUsed;
        uint32_t biClrImportant;
    } bih = {40, w, h, 1, 24, 0, image_sz, 2835, 2835, 0, 0};
    #pragma pack(pop)

    fwrite(&bfh, 14, 1, fp);
    fwrite(&bih, 40, 1, fp);

    uint8_t* row_buf = (uint8_t*)malloc(row_padded);
    if (row_buf) {
        // BMP 由下到上 (bottom-up) 寫入
        for (int y = h - 1; y >= 0; y--) {
            memset(row_buf, 0, row_padded);
            const uint16_t* src_row = (const uint16_t*)(src + y * w * 2);
            for (int x = 0; x < w; x++) {
                uint16_t p = src_row[x];
                // RGB565 -> BGR24
                uint8_t r = ((p >> 11) & 0x1F) << 3;
                uint8_t g = ((p >> 5) & 0x3F) << 2;
                uint8_t b = (p & 0x1F) << 3;
                row_buf[x * 3 + 0] = b;
                row_buf[x * 3 + 1] = g;
                row_buf[x * 3 + 2] = r;
            }
            fwrite(row_buf, row_padded, 1, fp);
        }
        free(row_buf);
    }
    fclose(fp);
}

// ----------------------------------------------------------------------------
// 影像緩衝區 Checksum 校驗 (整幀無抽樣 FNV-1a 全量像素 Hash 與 BMP 對照輸出)
// ----------------------------------------------------------------------------
static uint32_t s_seen_rep_hashes[256];
static int      s_distinct_rep_count = 0;

static void CheckFrameBufferChecksum(int is_rewind, const char* tag) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    uintptr_t* pp_draw = (uintptr_t*)(g_exe_base + 0x02D21B40);
    uintptr_t* pp_vid = (uintptr_t*)(g_exe_base + 0x02D72BB8);
    uintptr_t val_draw = (pp_draw && !IsBadReadPtr(pp_draw, 4)) ? *pp_draw : 0;
    uintptr_t val_vid = (pp_vid && !IsBadReadPtr(pp_vid, 4)) ? *pp_vid : 0;

    uint8_t* target_buf = (uint8_t*)(val_draw ? val_draw : val_vid);

    int buf_valid = 0;
    size_t safe_len = 0;
    DWORD mem_prot = 0, mem_state = 0;
    if (target_buf) {
        uint8_t* p = target_buf;
        while (safe_len < 143360) {
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            if (VirtualQuery((const void*)p, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) break;
            mem_prot = mbi.Protect;
            mem_state = mbi.State;
            size_t p_end = (size_t)mbi.BaseAddress + mbi.RegionSize;
            if (p_end <= (size_t)p) break;
            safe_len += (p_end - (size_t)p);
            p = (uint8_t*)p_end;
        }
        if (safe_len >= 1024) buf_valid = 1;
        if (safe_len > 143360) safe_len = 143360;
    }

    // 夥伴指導：整幀無抽樣全量 FNV-1a 雜湊 (320x224x2 = 143,360 位元組)
    uint32_t sum = 2166136261u;
    if (buf_valid && safe_len >= 1024) {
        // 避開頂部 Lua HUD 疊加區域 (跳過前 8KB ~ 16 行掃描線)
        size_t start_off = (safe_len > 16384) ? 8192 : 0;
        for (size_t i = start_off; i < safe_len; i++) {
            sum ^= target_buf[i];
            sum *= 16777619u;
        }
    }

    // 夥伴指導：在 f=720, 750, 780, 840 時分別輸出實體 BMP 供肉眼檢驗與二進位比對
    int f_idx = is_rewind ? (g_play_frame - 1) : (g_record_frame - 1);
    if (buf_valid && safe_len >= 143360) {
        if (f_idx == 720 || f_idx == 750 || f_idx == 780 || f_idx == 840) {
            char bmp_path[MAX_PATH];
            snprintf(bmp_path, sizeof(bmp_path), "%sscripts\\%s_f%d.bmp",
                g_module_dir, is_rewind ? "replay" : "live", f_idx);
            SaveBufferToBmp24(bmp_path, target_buf, 320, 224);
        }
    }

    // 夥伴指導：端到端每幀畫面 Hash 比對 (至少追蹤 300 幀)
    if (buf_valid && tag && (strcmp(tag, "ADV") == 0 || strcmp(tag, "SYNC") == 0)) {
        if (!is_rewind) {
            // LIVE 狀態：記錄剛步進完畢之幀的畫面 Hash
            if (f_idx >= 0 && f_idx < MAX_REPLAY_FRAMES) {
                g_fb_live_hashes[f_idx] = sum;
                g_fb_live_recorded[f_idx] = 1;
            }
        } else {
            // REWIND 狀態：比對同一個輸入幀的畫面 Hash
            if (f_idx >= 0 && f_idx < MAX_REPLAY_FRAMES && g_fb_live_recorded[f_idx]) {
                uint32_t live_h = g_fb_live_hashes[f_idx];
                uint32_t live_prev = (f_idx > 0 && g_fb_live_recorded[f_idx - 1]) ? g_fb_live_hashes[f_idx - 1] : 0;
                uint32_t live_next = (f_idx + 1 < MAX_REPLAY_FRAMES && g_fb_live_recorded[f_idx + 1]) ? g_fb_live_hashes[f_idx + 1] : 0;

                int m_curr = (sum == live_h);
                int m_prev = (live_prev && sum == live_prev);
                int m_next = (live_next && sum == live_next);

                // 統計相異雜湊值數量
                if (g_check_window_frames < 180) {
                    int already_seen = 0;
                    for (int s = 0; s < s_distinct_rep_count; s++) {
                        if (s_seen_rep_hashes[s] == sum) { already_seen = 1; break; }
                    }
                    if (!already_seen && s_distinct_rep_count < 250) {
                        s_seen_rep_hashes[s_distinct_rep_count++] = sum;
                    }
                }

                if (g_check_window_frames < 300) {
                    g_check_window_frames++;
                    if (m_curr) {
                        g_match_count_300++;
                    } else {
                        g_mismatch_count_300++;
                    }

                    // 夥伴指導 1：前 180 幀輸出完整序列、毫秒時間戳記與 ±1 偏移檢驗
                    if (g_check_window_frames <= 180) {
                        static char s_log_path[MAX_PATH] = {0};
                        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
                        FILE* fp = fopen(s_log_path, "a");
                        if (fp) {
                            char szTime[32] = {0};
                            SYSTEMTIME st;
                            GetLocalTime(&st);
                            snprintf(szTime, sizeof(szTime), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                            fprintf(fp, "[%s] [FRAME_CORR #%03d f=%d] rep=0x%08X | live(k)=0x%08X (m=%d) | live(k-1)=0x%08X (m=%d) | live(k+1)=0x%08X (m=%d)\n",
                                szTime, g_check_window_frames, f_idx, sum, live_h, m_curr, live_prev, m_prev, live_next, m_next);
                            if (g_check_window_frames == 180) {
                                fprintf(fp, "\n[%s] ========== [FRAME_CORR 180-FRAME SUMMARY] ========== \n", szTime);
                                fprintf(fp, "  總比對幀數: 180 幀 (f=%d .. f=%d)\n", f_idx - 179, f_idx);
                                fprintf(fp, "  完全吻合 (m=1): %d 幀\n", g_match_count_300);
                                fprintf(fp, "  分歧幀數 (m=0): %d 幀 (包含前 5 幀雙緩衝管線覆蓋延遲)\n", g_mismatch_count_300);
                                fprintf(fp, "  吻合率: %.2f%%\n", (g_match_count_300 / 180.0) * 100.0);
                                fprintf(fp, "  相異畫面雜湊總數 (Distinct Hashes): %d / 180 (證明畫面非靜態)\n", s_distinct_rep_count);
                                fprintf(fp, "  緩衝區取樣位址: 0x%p (val_draw=0x%p, val_vid=0x%p, safe_len=%u)\n",
                                    (void*)target_buf, (void*)val_draw, (void*)val_vid, (unsigned int)safe_len);
                                fprintf(fp, "==========================================================\n\n");
                            }
                            fclose(fp);
                        }
                    } else if (g_check_window_frames % 50 == 0 || g_check_window_frames == 300) {
                        static char s_log_path[MAX_PATH] = {0};
                        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
                        FILE* fp = fopen(s_log_path, "a");
                        if (fp) {
                            fprintf(fp, "[PIXEL_VERIFY f=%d (進度 %d/300)] live=0x%08X rep=0x%08X | 吻合=%d 分歧=%d\n",
                                f_idx, g_check_window_frames, live_h, sum, g_match_count_300, g_mismatch_count_300);
                            fclose(fp);
                        }
                    }
                }
            }
        }
    }

    static uint32_t s_last_sum = 0;
    static int s_changed_cnt = 0;
    static int s_total_frames = 0;
    static DWORD s_last_chk_time = 0;

    if (buf_valid && sum != s_last_sum) {
        s_changed_cnt++;
        s_last_sum = sum;
    }
    s_total_frames++;

    DWORD now = GetTickCount();
    if (s_last_chk_time == 0) s_last_chk_time = now;
    if (now - s_last_chk_time >= 1000) {
        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[FB_DIAG %s %s] pDraw=0x%08X pVid=0x%08X | valid=%d safe=%u prot=0x%X chg=%d/%d\n",
                is_rewind ? "REWIND" : "LIVE", tag, (unsigned int)val_draw, (unsigned int)val_vid,
                buf_valid, (unsigned int)safe_len, (unsigned int)mem_prot, s_changed_cnt, s_total_frames);
            fclose(fp);
        }
        s_changed_cnt = 0;
        s_total_frames = 0;
        s_last_chk_time = now;
    }
}

// ----------------------------------------------------------------------------
// 夥伴指定 4 大關鍵旗標診斷 ([0x3173C40], [0x02121690], [0x0212168C], [0x021215F8])
// ----------------------------------------------------------------------------
static void LogGatekeeperVariables(int is_rewind) {
    if (!g_exe_base) return;
    volatile uint32_t* p_v1 = (volatile uint32_t*)(g_exe_base + 0x02D73C40);
    volatile uint32_t* p_v2 = (volatile uint32_t*)(g_exe_base + 0x01D21688);
    volatile uint8_t*  p_v3 = (volatile uint8_t*)(g_exe_base + 0x02D6F79A);
    volatile uint8_t*  p_v4 = (volatile uint8_t*)(g_exe_base + 0x02D6F6CA);
    volatile uint32_t* p_v5 = (volatile uint32_t*)(g_exe_base + 0x02D72BF0);

    // 夥伴特別指定的 4 大旗標
    volatile uint32_t* p_f1690 = (volatile uint32_t*)(g_exe_base + 0x01D21690);
    volatile uint32_t* p_f168c = (volatile uint32_t*)(g_exe_base + 0x01D2168C); // 快照狀態旗標
    volatile uint32_t* p_f15f8 = (volatile uint32_t*)(g_exe_base + 0x01D215F8);

    if (IsBadReadPtr((const void*)p_v1, 4) ||
        IsBadReadPtr((const void*)p_v2, 4) ||
        IsBadReadPtr((const void*)p_v3, 1) ||
        IsBadReadPtr((const void*)p_v4, 1) ||
        IsBadReadPtr((const void*)p_v5, 4) ||
        IsBadReadPtr((const void*)p_f1690, 4) ||
        IsBadReadPtr((const void*)p_f168c, 4) ||
        IsBadReadPtr((const void*)p_f15f8, 4)) {
        return;
    }

    uint32_t v1 = *p_v1;
    uint32_t v2 = *p_v2;
    uint8_t  v3 = *p_v3;
    uint8_t  v4 = *p_v4;
    uint32_t v5 = *p_v5;

    uint32_t f1690 = *p_f1690;
    uint32_t f168c = *p_f168c;
    uint32_t f15f8 = *p_f15f8;

    static DWORD s_last_time = 0;
    DWORD now = GetTickCount();
    if (s_last_time == 0 || now - s_last_time >= 1000) {
        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[GATES %s] V1_skip=%u | V2_rst=%u | V3_sync=%u | V4_okay=%u | V5_plug=%u\n",
                is_rewind ? "REWIND" : "LIVE", v1, v2, v3, v4, v5);
            fprintf(fp, "[PARTNER_FLAGS %s] f_3173C40=%u | f_2121690=%u | f_212168C=%u | f_21215F8=%u\n",
                is_rewind ? "REWIND" : "LIVE", v1, f1690, f168c, f15f8);
            fclose(fp);
        }
        s_last_time = now;
    }
}

// ----------------------------------------------------------------------------
// 視訊翻頁索引監控 (檢驗 VidFrame 內部是否成功執行至翻頁點)
// ----------------------------------------------------------------------------
static void LogFlipIndex(int is_rewind) {
    if (!g_exe_base) return;
    volatile uint32_t* p_flip = (volatile uint32_t*)(g_exe_base + 0x02D72BF8);
    if (IsBadReadPtr((const void*)p_flip, 4)) return;

    static uint32_t s_last_val = 0xFFFFFFFF;
    static int s_flip_cnt = 0;
    static DWORD s_last_time = 0;

    uint32_t cur_val = *p_flip;
    if (cur_val != s_last_val) {
        s_flip_cnt++;
        s_last_val = cur_val;
    }

    DWORD now = GetTickCount();
    if (s_last_time == 0) s_last_time = now;
    if (now - s_last_time >= 1000) {
        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[FLIP_INDEX %s] cur_idx=%u | flips_per_sec=%d\n",
                is_rewind ? "REWIND" : "LIVE", cur_val, s_flip_cnt);
            fclose(fp);
        }
        s_flip_cnt = 0;
        s_last_time = now;
    }
}

// 夥伴指導 3：第二條輸入路徑與 values 緩衝區雙向探測
static void* g_last_values_ptr = NULL;
static uint8_t g_last_live_input[16] = {0};
static int g_last_live_input_len = 0;
static int g_rewind_first_sync_done = 0;
static int g_rewind_sync_count = 0;
// 【診斷模式保留說明】：
// 預設為 0 (出貨安全模式)，絕不主動侵入或覆寫進程 Heap 記憶體，防止 0xc0000374 Heap Corruption。
// 若未來需要進行記憶體鏡像寫入實驗，可經由 lua_set_continuous_purify(1) 開啟。
static int g_continuous_purify_enabled = 0;

static void PurifyAllMirrorsFrameByFrame(int play_f);

// ----------------------------------------------------------------------------
// 夥伴指導：記憶體輸入副本普查 (Input Copy Census in Process Memory)
// ----------------------------------------------------------------------------
#define MAX_CENSUS_CANDIDATES 1024

static uintptr_t g_census_candidates[MAX_CENSUS_CANDIDATES];
static int       g_census_cand_count = 0;
static uint8_t   g_census_target_pattern[16] = {0};
static int       g_census_pattern_len = 0;
static size_t    g_my_dll_size = 0x400000;

static void RunInputCensus_BeforeLoad(const uint8_t* pattern, int pattern_len) {
#ifndef ENABLE_LEGACY_DIAGNOSTICS
    (void)pattern;
    (void)pattern_len;
    g_census_cand_count = 0;
    return;
#else
    g_census_cand_count = 0;
    if (!pattern || pattern_len < 6) return;
    if (pattern_len > 16) pattern_len = 16;
    memcpy(g_census_target_pattern, pattern, pattern_len);
    g_census_pattern_len = pattern_len;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t min_addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t max_addr = (uintptr_t)si.lpMaximumApplicationAddress;

    uintptr_t p = min_addr;
    while (p < max_addr && g_census_cand_count < MAX_CENSUS_CANDIDATES) {
        MEMORY_BASIC_INFORMATION mbi;
        memset(&mbi, 0, sizeof(mbi));
        if (VirtualQuery((void*)p, &mbi, sizeof(mbi)) != sizeof(mbi)) break;

        uintptr_t reg_base = (uintptr_t)mbi.BaseAddress;
        size_t reg_size = mbi.RegionSize;
        uintptr_t reg_end = reg_base + reg_size;

        int is_writable = (mbi.State == MEM_COMMIT) &&
                          !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
                          (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

        int in_proxy_dll = (g_my_dll_base && reg_base >= g_my_dll_base && reg_base < g_my_dll_base + g_my_dll_size);
        int is_neogeo_68k = (reg_base >= 0x00100000 && reg_base < 0x00110000);

        if (is_writable && !in_proxy_dll && !is_neogeo_68k && reg_size >= (size_t)pattern_len) {
            const uint8_t* buf = (const uint8_t*)reg_base;
            size_t limit = reg_size - pattern_len;
            for (size_t i = 0; i <= limit; i += 2) {
                if (memcmp(buf + i, pattern, pattern_len) == 0) {
                    g_census_candidates[g_census_cand_count++] = reg_base + i;
                    if (g_census_cand_count >= MAX_CENSUS_CANDIDATES) break;
                }
            }
        }

        if (reg_end <= p) break;
        p = reg_end;
    }
#endif
}

// ----------------------------------------------------------------------------
// 夥伴指導 3：候選分組定義與 152 位元組結構體傾印
// ----------------------------------------------------------------------------
static const uintptr_t s_group_A_offsets[] = {
    0x15AEC18, 0x15AECB0, 0x15AED48, 0x15AEDE0,
    0x15AEE78, 0x15AEF10, 0x15AEFA8, 0x15AF040
};
#define NUM_GROUP_A (sizeof(s_group_A_offsets) / sizeof(s_group_A_offsets[0]))

static const uintptr_t s_group_B_offsets[] = {
    0x15B8BE8, 0x15B8C80, 0x15B8D18, 0x15B8DB0,
    0x15B8E48, 0x15B8EE0, 0x15B8F78
};
#define NUM_GROUP_B (sizeof(s_group_B_offsets) / sizeof(s_group_B_offsets[0]))

static const uintptr_t s_group_CD_offsets[] = {
    0x18067E0, 0x1806878, 0x1806910,
    0x1809E98, 0x1809F30, 0x1809FC8
};
#define NUM_GROUP_CD (sizeof(s_group_CD_offsets) / sizeof(s_group_CD_offsets[0]))

static int g_bisection_target_group = -1; // -1: 全改寫; 0: Baseline; 1: Group A; 2: Group B; 3: Group CD; 4: Values; 5: Heap

__declspec(dllexport) int lua_set_bisection_group(void* L) {
    if (p_lua_tointeger && L) {
        g_bisection_target_group = (int)p_lua_tointeger(L, 1);
        return 0;
    }
    return 0;
}

static void DumpAllGroupsRingDiff(int slot);

static void QueryPointerMemoryType(uintptr_t ptr, char* out_buf, size_t buf_sz) {
    MEMORY_BASIC_INFORMATION mbi;
    memset(&mbi, 0, sizeof(mbi));
    if (VirtualQuery((const void*)ptr, &mbi, sizeof(mbi))) {
        const char* type_str = "MEM_UNKNOWN";
        if (mbi.Type == MEM_IMAGE) type_str = "MEM_IMAGE (代碼/模組段)";
        else if (mbi.Type == MEM_MAPPED) type_str = "MEM_MAPPED (映射視窗)";
        else if (mbi.Type == MEM_PRIVATE) type_str = "MEM_PRIVATE (堆積/私有)";

        const char* prot_str = "UNKNOWN";
        if (mbi.Protect & PAGE_EXECUTE_READ) prot_str = "EXECUTE_READ";
        else if (mbi.Protect & PAGE_EXECUTE_READWRITE) prot_str = "EXECUTE_READWRITE";
        else if (mbi.Protect & PAGE_READONLY) prot_str = "READONLY";
        else if (mbi.Protect & PAGE_READWRITE) prot_str = "READWRITE";

        char mod_name[MAX_PATH] = "NoModule";
        if (mbi.AllocationBase) {
            HMODULE hMod = (HMODULE)mbi.AllocationBase;
            GetModuleFileNameA(hMod, mod_name, sizeof(mod_name));
            char* p_slash = strrchr(mod_name, '\\');
            if (p_slash) memmove(mod_name, p_slash + 1, strlen(p_slash + 1) + 1);
        }
        snprintf(out_buf, buf_sz, "0x%08X -> %s | %s | Mod: %s", (unsigned int)ptr, type_str, prot_str, mod_name);
    } else {
        snprintf(out_buf, buf_sz, "0x%08X -> (VirtualQuery Failed)", (unsigned int)ptr);
    }
}

static void Dump152ByteStructure(uintptr_t addr, const char* label) {
    static char s_log_path[MAX_PATH] = {0};
    if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
    FILE* fp = fopen(s_log_path, "a");
    if (!fp) return;

    fprintf(fp, "\n========== [STRUCTURE 152-BYTE DUMP: %s at 0x%08X] ==========\n", label, (unsigned int)addr);
    if (!IsBadReadPtr((const void*)addr, 152)) {
        const uint8_t* p = (const uint8_t*)addr;
        for (int row = 0; row < 152; row += 16) {
            fprintf(fp, "+%02X: ", row);
            int n = (row + 16 <= 152) ? 16 : (152 - row);
            for (int col = 0; col < n; col++) fprintf(fp, "%02X ", p[row + col]);
            for (int col = n; col < 16; col++) fprintf(fp, "   ");
            fprintf(fp, " | ");
            for (int col = 0; col < n; col++) {
                uint8_t c = p[row + col];
                fprintf(fp, "%c", (c >= 32 && c <= 126) ? c : '.');
            }
            fprintf(fp, "\n");
        }

        // 夥伴指導：使用 VirtualQuery 嚴格檢驗指標欄位屬性
        fprintf(fp, "\n--- [指標欄位 VirtualQuery 嚴格屬性核驗] ---\n");
        int ptr_offsets[] = { 0x18, 0x28, 0x2C, 0x38, 0x64, 0x68, 0x7C, 0x80, 0x84, 0x88, 0x8C, 0x90, 0x94 };
        for (size_t i = 0; i < sizeof(ptr_offsets)/sizeof(ptr_offsets[0]); i++) {
            int off = ptr_offsets[i];
            uintptr_t val = *(uintptr_t*)(addr + off);
            char info[256] = {0};
            QueryPointerMemoryType(val, info, sizeof(info));
            fprintf(fp, "  [+0x%02X] %s\n", off, info);
        }
    } else {
        fprintf(fp, "(Invalid Read Pointer)\n");
    }
    fprintf(fp, "====================================================================\n\n");
    fclose(fp);
}

static int RunInputCensus_AfterLoad(int target_frame) {
#ifndef ENABLE_LEGACY_DIAGNOSTICS
    (void)target_frame;
    return 0;
#else
    if (g_census_cand_count == 0 || g_census_pattern_len < 6) return 0;

    static char s_log_path[MAX_PATH] = {0};
    if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
    FILE* fp = fopen(s_log_path, "a");

    uint8_t target_prev_input[16] = {0};
    int has_prev = 0;
    if (target_frame > 0 && target_frame - 1 < g_record_frame) {
        int prev_f = target_frame - 1;
        int len = g_input_lens[prev_f];
        if (len <= 0) len = 9;
        if (len > 16) len = 16;
        memcpy(target_prev_input, g_input_history[prev_f], len);
        has_prev = 1;
    }

    if (g_exe_base) {
        Dump152ByteStructure(g_exe_base + s_group_A_offsets[0], "Group A #1 (P1 Input Record)");
    }

    const char* mode_names[] = {
        "Mode 0: Baseline (無淨化對照組)",
        "Mode 1: No-op Control (空操作：寫入目前值測副作用)",
        "Mode 2: Full Set (全集合：A+B+CD+Values+Heap 全淨化)",
        "Mode 3: Leave-one-out (全集 - A)",
        "Mode 4: Leave-one-out (全集 - B)",
        "Mode 5: Leave-one-out (全集 - C&D)",
        "Mode 6: Leave-one-out (全集 - Heap)",
        "Mode 7: Leave-one-out (全集 - Values)",
        "Mode 8: Combo (C&D + Heap 雙集合)"
    };
    int mode_idx = g_bisection_target_group;
    const char* cur_mode_str = (mode_idx >= 0 && mode_idx <= 8) ? mode_names[mode_idx] : "預設全淨化";

    if (fp) {
        fprintf(fp, "\n========== [EXPERIMENT REPORT (target_f=%d)] ==========\n", target_frame);
        fprintf(fp, "當前測試模式: 【%s】\n", cur_mode_str);
        fprintf(fp, "倒帶前瞬時輸入 L: ");
        for (int i = 0; i < g_census_pattern_len; i++) fprintf(fp, "%02X ", g_census_target_pattern[i]);
        fprintf(fp, "\n目標前一幀 H[T-1]: ");
        for (int i = 0; i < g_census_pattern_len; i++) fprintf(fp, "%02X ", target_prev_input[i]);
        fprintf(fp, "\n普查命中位址數: %d\n", g_census_cand_count);
    }

    int unrecovered_cnt = 0;
    int purified_cnt = 0;
    int is_noop = (g_bisection_target_group == 1);

    for (int i = 0; i < g_census_cand_count; i++) {
        uintptr_t addr = g_census_candidates[i];
        if (!IsBadReadPtr((const void*)addr, g_census_pattern_len)) {
            if (memcmp((const void*)addr, g_census_target_pattern, g_census_pattern_len) == 0) {
                unrecovered_cnt++;

                // 判斷該位址所屬分組 (1: A, 2: B, 3: CD, 4: Values, 5: Heap)
                int addr_group = 5;
                if (g_exe_base) {
                    for (size_t a = 0; a < NUM_GROUP_A; a++) {
                        if (addr == g_exe_base + s_group_A_offsets[a]) { addr_group = 1; break; }
                    }
                    if (addr_group == 5) {
                        for (size_t b = 0; b < NUM_GROUP_B; b++) {
                            if (addr == g_exe_base + s_group_B_offsets[b]) { addr_group = 2; break; }
                        }
                    }
                    if (addr_group == 5) {
                        for (size_t c = 0; c < NUM_GROUP_CD; c++) {
                            if (addr == g_exe_base + s_group_CD_offsets[c]) { addr_group = 3; break; }
                        }
                    }
                    if (addr_group == 5 && addr == g_exe_base + 0x3D94528) {
                        addr_group = 4;
                    }
                }

                // 夥伴指導：Leave-one-out 矩陣篩選
                int should_purify = 0;
                switch (g_bisection_target_group) {
                    case 0: should_purify = 0; break;                           // Baseline
                    case 1: should_purify = 1; break;                           // No-op Control
                    case 2: should_purify = 1; break;                           // Full set
                    case 3: should_purify = (addr_group != 1); break;           // 全集 - A
                    case 4: should_purify = (addr_group != 2); break;           // 全集 - B
                    case 5: should_purify = (addr_group != 3); break;           // 全集 - CD
                    case 6: should_purify = (addr_group != 5); break;           // 全集 - Heap
                    case 7: should_purify = (addr_group != 4); break;           // 全集 - Values
                    case 8: should_purify = (addr_group == 3 || addr_group == 5); break; // CD + Heap
                    default: should_purify = 1; break;                          // 預設全淨化
                }

                if (should_purify) {
                    DWORD old_protect;
                    if (VirtualProtect((void*)addr, g_census_pattern_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
                        if (is_noop) {
                            // 空操作：讀出並原樣寫回目前值 (位元不變，純測保護屬性切換副作用)
                            uint8_t cur_val[16] = {0};
                            memcpy(cur_val, (void*)addr, g_census_pattern_len);
                            memcpy((void*)addr, cur_val, g_census_pattern_len);
                        } else {
                            memcpy((void*)addr, target_prev_input, g_census_pattern_len);
                        }
                        VirtualProtect((void*)addr, g_census_pattern_len, old_protect, &old_protect);
                        purified_cnt++;
                    }
                }
            }
        }
    }

    if (fp) {
        fprintf(fp, "普查未還原數: %d / %d | 執行處理數: %d (No-op=%d)\n",
            unrecovered_cnt, g_census_cand_count, purified_cnt, is_noop);
        fprintf(fp, "=========================================================\n\n");
        fclose(fp);
    }
    return purified_cnt;
#endif
}

// ----------------------------------------------------------------------------
static int  g_last_active_frame = 0;
static int  g_idle_streak = 0;
static BYTE g_last_input_sample[INPUT_SIZE_MAX] = {0};

static int IsEmptyOrSameInput(const BYTE* buf, int sz) {
    if (!buf || sz <= 0) return 1;
    int all_zero = 1;
    for (int i = 0; i < sz; i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) return 1;
    if (memcmp(buf, g_last_input_sample, sz) == 0) return 1;
    return 0;
}

// 核心攔截 1：ggpo_synchronize_input (影子模式：永遠原樣轉發，事後用歷史覆寫)
// ----------------------------------------------------------------------------
// 影子模式：永遠原樣轉發真實 GGPO，僅在倒帶時將 values 替換為歷史輸入，保障狀態機 100% 安定
static int g_takeover_enabled = 0;
static int g_skip_real_advance = 0;
static int g_last_real_adv_ret = 0;
static int g_zero_ret_streak = 0;
static int g_takeover_sync_count = 0;
static DWORD g_last_lua_state_tick = 0;
// 600 FPS 高解析度定速巡航計時器 (完美復刻官方 → 鍵 10x 速度，防止 Turbo 跑太快吃進假空白幀)
static LARGE_INTEGER g_qpcFreq      = {0};
static LARGE_INTEGER g_targetQpc    = {0};

static void EnforceSafe600FpsSpeedLimit(void* ggpo) {
    if (g_qpcFreq.QuadPart == 0) {
        QueryPerformanceFrequency(&g_qpcFreq);
        QueryPerformanceCounter(&g_targetQpc);
    }

    static int s_speed_tick = 0;
    s_speed_tick++;

    // 不在 RunFrame 內部呼叫 p_real_ggpo_idle (會破壞輸入相位)，水位補充由外部 ggpo_idle 負責
    (void)ggpo;

    // 每推進 10 幀 (目標耗時 16.666ms = 600 FPS)：
    // 採用 QPC 絕對目標時間戳補償法，徹底避開 Windows 15.625ms Sleep 時間片陷阱！
    // 若在舊 CPU (如 i7-4770) 上因 Savestate 單批耗時超過 16.6ms，後續批次自動無延遲全速追趕！
    if (s_speed_tick % 10 == 0) {
        LONGLONG batchTicks = (g_qpcFreq.QuadPart * 10) / 600;
        g_targetQpc.QuadPart += batchTicks;

        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);

        if (now.QuadPart < g_targetQpc.QuadPart) {
            double aheadMs = (double)(g_targetQpc.QuadPart - now.QuadPart) * 1000.0 / (double)g_qpcFreq.QuadPart;
            if (aheadMs >= 16.0) {
                Sleep(1);
                QueryPerformanceCounter(&now);
            }
            while (now.QuadPart < g_targetQpc.QuadPart) {
                SwitchToThread();
                QueryPerformanceCounter(&now);
            }
        } else {
            // 若落後超過 2 個批次 (例如正常 60 FPS 播放或暫停期間)，將目標時間軸平滑對齊至當前時間 - 1個批次補償額度
            if (now.QuadPart - g_targetQpc.QuadPart > batchTicks * 2) {
                g_targetQpc.QuadPart = now.QuadPart - batchTicks;
            }
        }
    }
}

__declspec(dllexport) int __cdecl ggpo_synchronize_input(void* session, void* values, int size, int* disconnect_flags) {
    if (session && !g_saved_ggpo) g_saved_ggpo = session;
    EnforceHostGGPOSessionAlive();
    if (!hReal) InitRealDll();
    if (!g_bRewindModeActive) {
        if (p_real_sync_input) return p_real_sync_input(session, values, size, disconnect_flags);
        return 0;
    }

    // 主執行緒精準自動掛載：第 30 幀遊戲渲染管線完全就緒時瞬間掛載 (若視窗尚未就緒則每 30 幀自動重試)
    static int s_syncFrameCount = 0;
    if (g_bRewindModeActive && !g_bLuaMounted) {
        s_syncFrameCount++;
        if (s_syncFrameCount >= 30 && (s_syncFrameCount % 30 == 0)) {
            PerformMainThreadAutoMount();
        }
    }

    int total_sz = size * 2; // 雙玩家輸入緩衝區 (P1 + P2 通道)
    int n = (total_sz > 0 && total_sz <= INPUT_SIZE_MAX) ? total_sz : ((size > 0 && size <= INPUT_SIZE_MAX) ? size : 18);
    int ret = 0x00000101;
    g_seq++;

    // 【零成本視窗隱形守護】：僅在視窗意外變為可見時才呼叫 Win32 API 封印，徹底消除每幀 ShowWindow/SetWindowPos 的 DWM 核心態開銷！
    if (g_hAutoLuaWnd && IsWindowVisible(g_hAutoLuaWnd)) {
        MakeWindowPermanentlyInvisible(g_hAutoLuaWnd);
    }

    // 啟動 600 FPS 定速巡航保護，杜絕 Turbo 狂飆導致的音畫與中斷 Desync
    EnforceSafe600FpsSpeedLimit(session);

    int is_rew = (g_bStreamDrained || (g_is_rewound && g_play_frame < g_record_frame)) ? 1 : 0;

    // ========================================================================
    // 分支 A：歷史回放或已見底狀態 (g_bStreamDrained || g_play_frame < g_record_frame)
    // 關鍵鐵律：
    // 1. 絕不呼叫 p_real_sync_input，防止消耗真實串流緩衝區造成缺幀 Desync！
    // 2. 恆回傳 0x00000101 (低位 AL=1 代表輸入就緒)，確保 fcadefbneo.exe 每幀必驅動 68000 CPU 與 Lua 回呼！
    // ========================================================================
    if (is_rew) {
        ret = 0x00000101;
        g_stream_starving = 0;
        g_skip_real_advance = 1;
        if (CheckMemoryWritable(disconnect_flags, sizeof(int))) *disconnect_flags = 0;

        int play_f = g_play_frame;
        if (play_f < 0) play_f = 0;
        if (g_record_frame > 0 && play_f >= g_record_frame) {
            play_f = g_record_frame - 1;
        }

        if (values && play_f >= 0 && play_f < MAX_REPLAY_FRAMES) {
            int len = g_input_lens[play_f];
            if (len <= 0 || len > n) len = n;
            memcpy(values, g_input_history[play_f], len);
        }

        if (g_continuous_purify_enabled) {
            PurifyAllMirrorsFrameByFrame(play_f);
        }

        if (g_bManualPaused) {
            // 手動暫停中：播放頭絕對凍結於當前幀，絕不自增！
            g_is_rewound = 1;
        } else if (g_bStreamDrained && g_play_frame >= g_record_frame - 1) {
            g_play_frame = (g_record_frame > 0) ? (g_record_frame - 1) : 0;
            g_is_rewound = 1;
        } else {
            g_play_frame++;
            if (!g_bStreamDrained && g_record_frame > 0 && g_play_frame >= g_record_frame) {
                g_play_frame = g_record_frame;
                g_is_rewound = 0;
            } else {
                g_is_rewound = 1;
            }
        }
        g_frame_replayed = 1;
    }
    // ========================================================================
    // 分支 B：LIVE 真實串流開荒記錄 (!g_bStreamDrained && g_play_frame >= g_record_frame)
    // ========================================================================
    else if (p_real_sync_input) {
        ret = p_real_sync_input(session, values, size, disconnect_flags);

        g_real_sync_calls++;
        int is_disc = (disconnect_flags && CheckMemoryWritable(disconnect_flags, sizeof(int)) && *disconnect_flags != 0);
        if (disconnect_flags && CheckMemoryWritable(disconnect_flags, sizeof(int))) {
            *disconnect_flags = 0; // 絕不允許任何斷線標記洩漏給 FBNeo 原生宿主！
        }

        if ((ret & 0x01) != 0) {
            // 成功取得真實新幀輸入！
            g_stream_starving = 0;
            g_last_valid_sync_tick = GetTickCount();
            g_zero_ret_streak = 0;
            g_last_real_ret = ret;
            g_skip_real_advance = 0;
            g_frame_replayed = 0;

            if (values && n > 0) {
                if (IsEmptyOrSameInput((const BYTE*)values, n)) {
                    g_idle_streak++;
                } else {
                    g_idle_streak = 0;
                    g_last_active_frame = g_record_frame;
                    memcpy(g_last_input_sample, values, n);
                }

                if (n <= INPUT_SIZE_MAX) {
                    memcpy(g_last_live_input, values, n);
                    g_last_live_input_len = n;
                }
                if (g_record_frame < MAX_REPLAY_FRAMES) {
                    memcpy(g_input_history[g_record_frame], values, n);
                    g_input_lens[g_record_frame] = n;
                    g_record_frame++;
                    RunCensusStep(g_record_frame);
                }
            }
            g_is_rewound = 0;
            g_play_frame = g_record_frame;

            // 若官方發出斷線旗標或連續 3600 幀無輸入且已過 1000 幀，判定完賽 (不截斷已錄製幀)
            if ((is_disc || g_idle_streak >= 3600) && g_record_frame > 1000) {
                g_bStreamDrained     = TRUE;
                g_bStreamEndedFreeze = FALSE;
                g_bReachedEOF        = TRUE;
                g_is_rewound         = 1;

                g_play_frame = (g_record_frame > 0) ? (g_record_frame - 1) : 0;
                NotifyLuaReachedEOF();
                ret = 0x00000101;
                if (CheckMemoryWritable(disconnect_flags, sizeof(int))) *disconnect_flags = 0;

                static char s_eof_log[MAX_PATH] = {0};
                if (!s_eof_log[0]) snprintf(s_eof_log, sizeof(s_eof_log), "%sproxy_key.log", g_module_dir);
                FILE* fpe = fopen(s_eof_log, "a");
                if (fpe) {
                    fprintf(fpe, "\n=== [TRUE_EOF_LOCKED] 觸發真·EOF 剎車 (Idle/Disc)！idle_streak=%d | 最終定格 rec=%d play=%d ===\n\n",
                        g_idle_streak, g_record_frame, g_play_frame);
                    fclose(fpe);
                }
            }
        } else {
            // 佇列暫時無輸入：原樣回傳 0，讓宿主原生跳過該次 BurnDrvFrame 並回主迴圈 ggpo_idle 收包
            g_zero_ret_streak++;
            g_skip_real_advance = 1;
            g_stream_starving = 1;

            DWORD starve_ms = GetTickCount() - g_last_valid_sync_tick;
            int eof_timeout = (g_idle_streak >= 180 && starve_ms >= 5000) || starve_ms >= 10000;

            if (g_record_frame > 1000 && eof_timeout) {
                g_bStreamDrained     = TRUE;
                g_bStreamEndedFreeze = FALSE;
                g_bReachedEOF        = TRUE;
                g_is_rewound         = 1;
                g_frame_replayed     = 1;
                is_rew               = 1;

                g_play_frame = (g_record_frame > 0) ? (g_record_frame - 1) : 0;

                if (values && g_play_frame >= 0 && g_play_frame < MAX_REPLAY_FRAMES) {
                    int len = g_input_lens[g_play_frame];
                    if (len <= 0 || len > n) len = n;
                    memcpy(values, g_input_history[g_play_frame], len);
                }

                NotifyLuaReachedEOF();
                ret = 0x00000101;
                if (CheckMemoryWritable(disconnect_flags, sizeof(int))) *disconnect_flags = 0;

                static char s_eof_log[MAX_PATH] = {0};
                if (!s_eof_log[0]) snprintf(s_eof_log, sizeof(s_eof_log), "%sproxy_key.log", g_module_dir);
                FILE* fpe = fopen(s_eof_log, "a");
                if (fpe) {
                    fprintf(fpe, "\n=== [TRUE_EOF_LOCKED] 串流抽乾觸發真·EOF 剎車 (starve=%lums)！zero_streak=%d | 最終定格 rec=%d play=%d ===\n\n",
                        (unsigned long)starve_ms, g_zero_ret_streak, g_record_frame, g_play_frame);
                    fclose(fpe);
                }
            }
        }
    }

    // 每秒記錄真實 sync 回傳值
    static DWORD s_last_sync_log = 0;
    DWORD now = GetTickCount();
    if (now - s_last_sync_log >= 1000) {
        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[SYNC_RET %s] ret=%d (eax=0x%08X) | play=%d rec=%d is_rew=%d drained=%d\n",
                is_rew ? "REWIND" : "LIVE", ret, (unsigned int)ret, g_play_frame, g_record_frame, is_rew, (int)g_bStreamDrained);
            fclose(fp);
        }
        s_last_sync_log = now;
    }

    // C 端進度狀態保底輸出：若 Lua 尚未掛載或超過 500ms 未更新，由 C 端每 15 幀主動寫入 ipc_state.txt
    if ((g_play_frame % 15 == 0) && (GetTickCount() - g_last_lua_state_tick > 500)) {
        char st_path[MAX_PATH] = {0};
        snprintf(st_path, sizeof(st_path), "%sscripts\\ipc_state.txt", g_module_dir);
        FILE* fp_st = fopen(st_path, "w");
        if (fp_st) {
            int eof_flag = g_bStreamDrained ? 1 : 0;
            int st_code  = (g_bStreamDrained && g_play_frame >= g_record_frame - 2) ? 3 : 0;
            fprintf(fp_st, "%d %d %d %d %d\n", g_play_frame, g_record_frame, eof_flag, st_code, g_play_frame);
            fclose(fp_st);
        }
    }

    EnforceHostGGPOSessionAlive();
    return ret;
}

// ----------------------------------------------------------------------------
// 核心攔截 2：ggpo_advance_frame
// ----------------------------------------------------------------------------
__declspec(dllexport) int __cdecl ggpo_advance_frame(void* session) {
    if (!hReal) InitRealDll();

    // 只要處於歷史回放、串流已到底、或該幀未推進真實串流，一律不呼叫 p_real_adv_frame
    if (g_bStreamDrained || g_skip_real_advance || (g_is_rewound && g_play_frame < g_record_frame)) {
        g_skip_real_advance = 0;
        return g_last_real_adv_ret;
    }

    if (p_real_adv_frame) {
        g_real_adv_calls++;
        int r = p_real_adv_frame(session);
        g_last_real_adv_ret = r;
        return r;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 導出給 Lua 的原子級記憶體通訊 API
// ----------------------------------------------------------------------------
__declspec(dllexport) int lua_get_input_frame(void* L) {
    EnforceHostGGPOSessionAlive();
    if (!p_lua_pushinteger) InitRealDll();
    LogEvent("AFTER", g_play_frame);

    if (p_lua_pushinteger && L) {
        p_lua_pushinteger(L, g_play_frame);
        p_lua_pushinteger(L, g_record_frame);
        int c_eof = g_bStreamDrained ? 1 : 0;
        p_lua_pushinteger(L, c_eof);
        p_lua_pushinteger(L, g_stream_starving);
        p_lua_pushinteger(L, (g_last_real_ret >> 8) & 0xFF);
        return 5;
    }
    return 0;
}

__declspec(dllexport) int lua_set_paused(void* L) {
    if (!p_lua_tointeger) InitRealDll();
    if (p_lua_tointeger && L) {
        int p = (int)p_lua_tointeger(L, 1);
        g_bManualPaused = (p != 0);
        return 0;
    }
    return 0;
}

__declspec(dllexport) int lua_set_rewind_frame(void* L) {
    EnforceHostGGPOSessionAlive();
    if (!p_lua_tointeger) InitRealDll();
    if (p_lua_tointeger && L) {
        int target = (int)p_lua_tointeger(L, 1);
        int delta = (p_lua_gettop && p_lua_gettop(L) >= 2) ? (int)p_lua_tointeger(L, 2) : 0;
        if (target < 0) target = 0;
        if (g_record_frame > 0 && target > g_record_frame) {
            target = g_record_frame;
        }

        if (target >= 0) {
            if (g_continuous_purify_enabled) {
                RunInputCensus_BeforeLoad(g_last_live_input, g_last_live_input_len);
            }

            g_play_frame = target + delta;
            if (g_record_frame > 0 && g_play_frame >= g_record_frame) {
                if (g_bStreamDrained) {
                    g_play_frame = g_record_frame - 1;
                    g_is_rewound = 1;
                } else {
                    g_play_frame = g_record_frame;
                    g_is_rewound = 0;
                }
            } else {
                g_is_rewound = 1;
            }
            g_bStreamEndedFreeze = FALSE; // 無條件解除撞尾凍結鎖！
            g_takeover_enabled = 0;
            g_takeover_sync_count = 0;
            g_skip_real_advance = 1;
            {
                char s_lp[MAX_PATH];
                snprintf(s_lp, sizeof(s_lp), "%sproxy_key.log", g_module_dir);
                FILE* fl = fopen(s_lp, "a");
                if (fl) {
                    fprintf(fl, "[LUA_SET_REWIND] target=%d delta=%d -> g_play_frame=%d rec=%d drained=%d\n",
                        target, delta, g_play_frame, g_record_frame, (int)g_bStreamDrained);
                    fclose(fl);
                }
            }

            // 讀取計數器同步旗標 (scripts\sync_counters_mode.txt)
            int sync_counters_enabled = 0;
            {
                char sc_path[MAX_PATH];
                snprintf(sc_path, sizeof(sc_path), "%sscripts\\sync_counters_mode.txt", g_module_dir);
                FILE* fsc = fopen(sc_path, "r");
                if (fsc) {
                    int v = 0;
                    if (fscanf(fsc, "%d", &v) == 1) sync_counters_enabled = (v != 0);
                    fclose(fsc);
                }
            }
            if (sync_counters_enabled && g_exe_base) {
                uintptr_t a1 = g_exe_base + 0x01C5673C;
                uintptr_t a2 = g_exe_base + 0x02D21B24; // g_cur
                uintptr_t a3 = g_exe_base + 0x02D21B2C; // g_emu
                uintptr_t a4 = g_exe_base + 0x02D2C9F4;
                uintptr_t a5 = g_exe_base + 0x02D72E38;

                uint32_t old1 = (!IsBadReadPtr((const void*)a1, 4)) ? *(uint32_t*)a1 : 0;
                uint32_t old2 = (!IsBadReadPtr((const void*)a2, 4)) ? *(uint32_t*)a2 : 0;
                uint32_t old3 = (!IsBadReadPtr((const void*)a3, 4)) ? *(uint32_t*)a3 : 0;
                uint32_t old4 = (!IsBadReadPtr((const void*)a4, 4)) ? *(uint32_t*)a4 : 0;
                uint32_t old5 = (!IsBadReadPtr((const void*)a5, 4)) ? *(uint32_t*)a5 : 0;

                if (!IsBadWritePtr((void*)a1, 4)) *(uint32_t*)a1 = (uint32_t)(target - 2);
                if (!IsBadWritePtr((void*)a2, 4)) *(uint32_t*)a2 = (uint32_t)(target - 1);
                if (!IsBadWritePtr((void*)a3, 4)) *(uint32_t*)a3 = (uint32_t)(target - 1);
                if (!IsBadWritePtr((void*)a4, 4)) *(uint32_t*)a4 = (uint32_t)(target - 2);
                if (!IsBadWritePtr((void*)a5, 4)) *(uint32_t*)a5 = (uint32_t)(target - 1);

                char s_log_sc[MAX_PATH];
                snprintf(s_log_sc, sizeof(s_log_sc), "%sproxy_key.log", g_module_dir);
                FILE* fp_sc = fopen(s_log_sc, "a");
                if (fp_sc) {
                    fprintf(fp_sc, "\n========== [DIAGNOSTIC COUNTER SYNC (target=%d)] ==========\n", target);
                    fprintf(fp_sc, "  [1. 0x01C5673C] Old=%u -> New=%u (T-2)\n", old1, (unsigned int)(target - 2));
                    fprintf(fp_sc, "  [2. 0x02D21B24] Old=%u -> New=%u (T-1, g_cur)\n", old2, (unsigned int)(target - 1));
                    fprintf(fp_sc, "  [3. 0x02D21B2C] Old=%u -> New=%u (T-1, g_emu)\n", old3, (unsigned int)(target - 1));
                    fprintf(fp_sc, "  [4. 0x02D2C9F4] Old=%u -> New=%u (T-2)\n", old4, (unsigned int)(target - 2));
                    fprintf(fp_sc, "  [5. 0x02D72E38] Old=%u -> New=%u (T-1)\n", old5, (unsigned int)(target - 1));
                    fprintf(fp_sc, "============================================================\n\n");
                    fclose(fp_sc);
                }
            }
            g_has_last_play = 0;
            g_check_window_frames = 0;
            g_match_count_300 = 0;
            g_mismatch_count_300 = 0;
            g_rewind_first_sync_done = 0;
            g_rewind_sync_count = 0;
            g_last_values_ptr = NULL;
            static char s_log_path[MAX_PATH] = {0};
            if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
            FILE* fp = fopen(s_log_path, "a");
            if (fp) {
                fprintf(fp, "\n[SEEK_TRIGGER] target=%d play=%d rec=%d\n", target, g_play_frame, g_record_frame);

                // 夥伴建議：傾印 target 前 4 幀至後 12 幀完整輸入序列 (涵蓋 T+5..T+10)
                int start_f = target - 4;
                if (start_f < 0) start_f = 0;
                int end_f = target + 12;
                if (end_f >= g_record_frame) end_f = g_record_frame - 1;

                fprintf(fp, "========== [HISTORY INPUT DUMP frames %d..%d] ==========\n", start_f, end_f);
                for (int f = start_f; f <= end_f; f++) {
                    int len = g_input_lens[f];
                    if (len <= 0) len = 9;
                    fprintf(fp, "[INP f=%d%s] ", f, (f == target) ? " TARGET*" : "");
                    for (int b = 0; b < len && b < 12; b++) {
                        fprintf(fp, "%02X ", g_input_history[f][b]);
                    }
                    if (f > start_f) {
                        fprintf(fp, "| XOR_prev: ");
                        for (int b = 0; b < len && b < 12; b++) {
                            fprintf(fp, "%02X ", g_input_history[f][b] ^ g_input_history[f-1][b]);
                        }
                    }
                    fprintf(fp, "\n");
                }
                fprintf(fp, "========== [PIPELINE EVENT RING (LAST 20)] ==========\n");
                int start_ev = (g_event_idx > 20) ? (g_event_idx - 20) : 0;
                for (int e = start_ev; e < g_event_idx; e++) {
                    int idx = e % EVENT_RING_SIZE;
                    int diff_c_i = (int)g_event_ring[idx].cur - g_event_ring[idx].inf;
                    fprintf(fp, "[EV #%d] %-6s | cur=%u inf=%d (cur-inf=%d)\n",
                        e, g_event_ring[idx].tag, g_event_ring[idx].cur, g_event_ring[idx].inf, diff_c_i);
                }
                fprintf(fp, "========================================================\n");
                fclose(fp);
            }
        }
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 夥伴指導：導出給 Lua 的快照後普查驗證與真實輸入狀態查詢 API
// ----------------------------------------------------------------------------
__declspec(dllexport) int lua_census_verify(void* L) {
    int target_f = g_play_frame;
    if (p_lua_tointeger && L && p_lua_gettop && p_lua_gettop(L) >= 1) {
        int t = (int)p_lua_tointeger(L, 1);
        if (t > 0) target_f = t;
    }
    int unrecovered = RunInputCensus_AfterLoad(target_f);
    if (p_lua_pushinteger && L) {
        p_lua_pushinteger(L, unrecovered);
        return 1;
    }
    return 0;
}

__declspec(dllexport) int lua_get_live_input_state(void* L) {
    int is_idle = 1;
    uint8_t b0 = 0, b1 = 0;
    if (g_last_live_input_len >= 2) {
        b0 = g_last_live_input[0];
        b1 = g_last_live_input[1];
        if (b0 != 0 || b1 != 0) is_idle = 0;
    }
    if (L) {
        if (p_lua_pushboolean) p_lua_pushboolean(L, is_idle);
        if (p_lua_pushinteger) {
            p_lua_pushinteger(L, b0);
            p_lua_pushinteger(L, b1);
        }
        return 3;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 外部輸入狀態淨化與快照擴充 (Snapshot Augmentation & Input State Reset)
// ----------------------------------------------------------------------------
static const uintptr_t s_exe_input_offsets[] = {
    // 群組 A: 8 個玩家/埠，間隔 0x98 (152) bytes
    0x15AEC18, 0x15AECB0, 0x15AED48, 0x15AEDE0,
    0x15AEE78, 0x15AEF10, 0x15AEFA8, 0x15AF040,

    // 群組 B: 7 個玩家/埠，間隔 0x98 bytes
    0x15B8BE8, 0x15B8C80, 0x15B8D18, 0x15B8DB0,
    0x15B8E48, 0x15B8EE0, 0x15B8F78,

    // 群組 C: 3 個玩家/埠，間隔 0x98 bytes
    0x18067E0, 0x1806878, 0x1806910,

    // 群組 D: 3 個玩家/埠，間隔 0x98 bytes
    0x1809E98, 0x1809F30, 0x1809FC8,

    // 驅動 values 緩衝區位址 (偏移 0x3D94528)
    0x3D94528
};
#define NUM_EXE_INPUT_TARGETS (sizeof(s_exe_input_offsets) / sizeof(s_exe_input_offsets[0]))

#define GROUP_A_BLOCK_SIZE (8 * 152) // 1216 bytes
#define GROUP_B_BLOCK_SIZE (7 * 152) // 1064 bytes
#define GROUP_C_BLOCK_SIZE (3 * 152) // 456 bytes
#define GROUP_D_BLOCK_SIZE (3 * 152) // 456 bytes
#define MAX_SAVESTATE_SLOTS 256

typedef struct {
    uint8_t data[NUM_EXE_INPUT_TARGETS][16];
    int valid;
} SlotInputBackup;

static SlotInputBackup g_slot_input_backups[MAX_SAVESTATE_SLOTS];
static uint8_t         g_group_a_save_buffer[MAX_SAVESTATE_SLOTS][GROUP_A_BLOCK_SIZE];
static uint8_t         g_group_b_save_buffer[MAX_SAVESTATE_SLOTS][GROUP_B_BLOCK_SIZE];
static uint8_t         g_group_c_save_buffer[MAX_SAVESTATE_SLOTS][GROUP_C_BLOCK_SIZE];
static uint8_t         g_group_d_save_buffer[MAX_SAVESTATE_SLOTS][GROUP_D_BLOCK_SIZE];
static int             g_groups_save_valid[MAX_SAVESTATE_SLOTS];

// 夥伴任務 6：模擬器牆上時間計數器快照槽位 (防止倒帶追趕導致回放提早結束)
static uint32_t        g_slot_wall_cur[MAX_SAVESTATE_SLOTS];
static uint32_t        g_slot_wall_emu[MAX_SAVESTATE_SLOTS];
static int             g_slot_wall_valid[MAX_SAVESTATE_SLOTS];

// 夥伴建議：在任何淨化/還原寫入之前，比對群組 A、B、C、D 連續結構，印出真實位元組
static void DumpSubGroupRingDiff(FILE* fp, const char* grp_name, uintptr_t base_rva, const uint8_t* saved, int num_slots) {
    if (!g_exe_base || !saved || !fp) return;
    uintptr_t cur_base = g_exe_base + base_rva;
    if (IsBadReadPtr((const void*)cur_base, num_slots * 152)) return;
    const uint8_t* live = (const uint8_t*)cur_base;

    int total_diff = 0;
    int diff_slots = 0;
    fprintf(fp, "\n--- [%s (Base=0x%08X, Slots=%d)] ---\n", grp_name, (unsigned int)cur_base, num_slots);

    for (int s = 0; s < num_slots; s++) {
        int off = s * 152;
        int s_diff = 0;
        for (int b = 0; b < 152; b++) {
            if (saved[off + b] != live[off + b]) {
                s_diff++;
                total_diff++;
            }
        }
        fprintf(fp, "  [Slot #%d (+0x%03X)] 相異位元組: %d\n", s, off, s_diff);
        fprintf(fp, "    Saved [+00..+0F]: ");
        for (int b = 0; b < 16; b++) fprintf(fp, "%02X ", saved[off + b]);
        fprintf(fp, "\n    Live  [+00..+0F]: ");
        for (int b = 0; b < 16; b++) fprintf(fp, "%02X ", live[off + b]);
        fprintf(fp, "\n");
        if (s_diff > 0) {
            diff_slots++;
            fprintf(fp, "    差異偏移: ");
            for (int b = 0; b < 152; b++) {
                if (saved[off + b] != live[off + b]) {
                    fprintf(fp, "+%02X(sv=%02X,lv=%02X) ", b, saved[off + b], live[off + b]);
                }
            }
            fprintf(fp, "\n");
        }
    }
    fprintf(fp, "  -> %s 總結: %d/%d Slots 出現差異，共 %d 位元組相異\n", grp_name, diff_slots, num_slots, total_diff);
}

static void DumpAllGroupsRingDiff(int slot) {
    if (!g_exe_base) return;
    if (slot < 0 || slot >= MAX_SAVESTATE_SLOTS || !g_groups_save_valid[slot]) return;

    static char s_log_path[MAX_PATH] = {0};
    if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
    FILE* fp = fopen(s_log_path, "a");
    if (!fp) return;

    fprintf(fp, "\n================================================================================\n");
    fprintf(fp, "========== [GROUPS A, B, C, D RING COMPARISON (BEFORE PURIFY, slot=%d)] ==========\n", slot);
    fprintf(fp, "================================================================================\n");

    DumpSubGroupRingDiff(fp, "Group A (P1/P2 Record)", s_group_A_offsets[0], g_group_a_save_buffer[slot], 8);
    DumpSubGroupRingDiff(fp, "Group B (Mirror)",       s_group_B_offsets[0], g_group_b_save_buffer[slot], 7);
    DumpSubGroupRingDiff(fp, "Group C (Aux 1)",        s_group_CD_offsets[0], g_group_c_save_buffer[slot], 3);
    DumpSubGroupRingDiff(fp, "Group D (Aux 2)",        s_group_CD_offsets[3], g_group_d_save_buffer[slot], 3);

    fprintf(fp, "================================================================================\n\n");
    fclose(fp);
}

// 存檔時：乾淨安全模式 (FBNeo savestate 本身已完整儲存 CPU/RAM，無需外部侵入)
__declspec(dllexport) int lua_snapshot_save_inputs(void* L) {
    return 0;
}

// 讀檔後：乾淨安全模式 (杜絕 0xc0000409 與 Desync，絕不篡改 EXE 內部記憶體與計數器)
__declspec(dllexport) int lua_snapshot_restore_inputs(void* L) {
    if (p_lua_pushinteger && L) {
        p_lua_pushinteger(L, 0);
        return 1;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// 夥伴實驗 A：每幀持續同步淨化 (Frame-by-frame Continuous Purification)
// ----------------------------------------------------------------------------
static void PurifyAllMirrorsFrameByFrame(int play_f) {
#ifndef ENABLE_LEGACY_DIAGNOSTICS
    (void)play_f;
    return;
#else
    if (!g_exe_base || play_f < 0 || play_f >= g_record_frame) return;

    uint8_t cur_hist_input[16] = {0};
    int len = g_input_lens[play_f];
    if (len <= 0) len = 9;
    if (len > 16) len = 16;
    memcpy(cur_hist_input, g_input_history[play_f], len);

    // 1. 同步寫入 19 個靜態鏡像位址 (Group A, B, CD, Values)
    for (size_t i = 0; i < NUM_EXE_INPUT_TARGETS; i++) {
        uintptr_t addr = g_exe_base + s_exe_input_offsets[i];
        if (!IsBadWritePtr((void*)addr, 9)) {
            memcpy((void*)addr, cur_hist_input, 9);
        }
    }

    // 2. 同步寫入普查捕獲的堆積鏡像位址
    if (g_census_cand_count > 0) {
        for (int i = 0; i < g_census_cand_count; i++) {
            uintptr_t addr = g_census_candidates[i];
            if (!IsBadWritePtr((void*)addr, 9)) {
                memcpy((void*)addr, cur_hist_input, 9);
            }
        }
    }
#endif
}

__declspec(dllexport) int lua_set_continuous_purify(void* L) {
    if (p_lua_tointeger && L) {
        g_continuous_purify_enabled = (int)p_lua_tointeger(L, 1);
        return 0;
    }
    return 0;
}

// ============================================================================
// Delta Debugging (ddmin) 核心實作
// ============================================================================
#define DATA_SEC_RVA  0x00E03000
#define DATA_SEC_SIZE 0x0600E300  // 完整虛擬資料區段 (96.05 MB，涵蓋 .data 與 .bss)

static uint8_t* g_data_sec_backup = NULL;
static size_t   g_data_sec_allocated = 0;
static int      g_data_sec_has_backup = 0;

#define MAX_DDMIN_DIFFS 65536
static uint32_t g_ddmin_diff_offsets[MAX_DDMIN_DIFFS];
static uint32_t g_ddmin_diff_saved_vals[MAX_DDMIN_DIFFS];
static uint32_t g_ddmin_diff_orig_vals[MAX_DDMIN_DIFFS];
static int      g_ddmin_diff_count = 0;

// 安全排除遮罩：禁止還原已知動態計數器、影像、視窗、繪圖、音訊與內部緩衝區指標
static int IsOffsetExcludedFromRestore(uint32_t off) {
    uintptr_t target_rva = off;
    
    // cur 與計數器
    if (target_rva == 0x2C23C40 || target_rva == 0x1F0673C || target_rva == 0x3C44528) return 1;
    
    // 排除特定繪圖系統全域指標區段 (0x2BD0000 ~ 0x2C30000)
    if (target_rva >= 0x2BD0000 && target_rva <= 0x2C30000) {
        return 1;
    }

    // 排除文字日誌輸出緩衝區 (避免改寫字串指標噪音)
    // 0x02D83000 ~ 0x02D84000 (ASCII 日誌文字)
    // 0x06D8C000 ~ 0x06D8E000 (Unicode 控制台日誌文字)
    if (target_rva >= 0x02D83000 && target_rva <= 0x02D84000) return 1;
    if (target_rva >= 0x06D8C000 && target_rva <= 0x06D8E000) return 1;

    return 0;
}

// 夥伴指導：結尾提早結束計數器寫回開關 (預設 0=關閉，安全第一；需先由測試證明問題存在)
__declspec(dllexport) int lua_set_counter_writeback(void* L) {
    if (p_lua_tointeger && L) {
        g_counter_writeback_enabled = (int)p_lua_tointeger(L, 1);
        static char s_log_path[MAX_PATH] = {0};
        if (!s_log_path[0]) snprintf(s_log_path, sizeof(s_log_path), "%sproxy_key.log", g_module_dir);
        FILE* fp = fopen(s_log_path, "a");
        if (fp) {
            fprintf(fp, "[COUNTER_WRITEBACK_CONFIG] 寫回狀態變更為: %d (白名單吻合: %d)\n",
                g_counter_writeback_enabled, g_exe_whitelist_matched);
            fclose(fp);
        }
    }
    return 0;
}


// ----------------------------------------------------------------------------
// 獨立導播控制台 GUI <-> Lua 雙向相對路徑通訊橋樑 (免 os.execute，跨電腦 100% 相容)
// ----------------------------------------------------------------------------
// 回傳 (cmd_code, cmd_val):
// cmd_code: 0=無指令, 1=SEEK絕對幀, 2=PAUSE切換, 3=DELTA相對幀, 4=PCT百分比(0..99)

// ============================================================================
// 進程內原生直出錄影引擎 (Native Direct Pipe Recorder Engine - Route A)
// 【視訊單管道 + 音訊極速暫存 WAV + 結束時 0.2 秒極速無失真封裝】
// 100% 根除 Windows 雙具名管道的所有競爭、死結與交錯讀取卡死問題！
// ============================================================================
static volatile int g_bNativeRecording = 0;
static volatile int g_bPipeVConnected = 0;
static HANDLE g_hPipeVideo = INVALID_HANDLE_VALUE;
static HANDLE g_hAudioFile = INVALID_HANDLE_VALUE;
static HANDLE g_hThreadV = NULL;
static PROCESS_INFORMATION g_ffmpeg_pi = {0};
static int g_rec_start_frame = 0;
static int g_rec_end_frame = 0;
static int g_rec_is_full = 0;
static int g_rec_is_turbo = 0;
static int g_rec_need_seek_back = 0;
static int g_rec_last_cur_frame = 0;
static int g_rec_scale_mode = 0;
static int g_rec_res_mode = 3;     // 1=原生 (1x 自動辨識), 2=720P, 3=1080P
static int g_rec_render_mode = 1;  // 1=CRT顯像管等比光柵, 2=刀鋒無損硬點陣, 3=柔和抗鋸齒
static int g_game_width = 320;
static int g_game_height = 224;
static int g_rec_width = 320;
static int g_rec_height = 224;
static char g_rec_out_mp4[MAX_PATH] = {0};
static char g_rec_temp_v_mp4[MAX_PATH] = {0};
static char g_rec_temp_a_wav[MAX_PATH] = {0};
static char g_rec_ffmpeg_path[MAX_PATH] = {0};
static char g_rec_pipe_v_name[64] = {0};
static uint32_t* g_rec_bgra_buf = NULL;
static size_t g_rec_bgra_cap = 0;
static int g_rec_frames_written = 0;
static int g_rec_has_reached_start = 0;
static DWORD g_rec_audio_bytes = 0;
static int g_rec_attempts = 0;
static volatile int g_rec_state_dirty = 0;
static int g_rec_show_osd = 1;
static char g_rec_p1_name[64] = "Player 1";
static char g_rec_p2_name[64] = "Player 2";
static char g_rec_p1_rank[16] = "C";
static char g_rec_p2_rank[16] = "B";
static char g_rec_match_ft[16] = "FT10";

static void LogRec(const char* fmt, ...) {
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

    char log_path[MAX_PATH];
    snprintf(log_path, sizeof(log_path), "%sscripts\\rewind_debug.log", g_module_dir);
    FILE* fp = fopen(log_path, "a");
    if (fp) {
        fprintf(fp, "[NATIVE_REC] %s\n", buf);
        fclose(fp);
    }
}

// ============================================================================
// 經典復古 8x8 點陣字型引擎 (支援即時動態比分與雙選手 ID 浮層 OSD)
// ============================================================================
static const uint8_t font8x8_osd[128][8] = {
    [' '] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    ['-'] = { 0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00 },
    ['.'] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00 },
    [':'] = { 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00 },
    ['['] = { 0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00 },
    [']'] = { 0x78, 0x18, 0x18, 0x18, 0x18, 0x18, 0x78, 0x00 },
    ['('] = { 0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00 },
    [')'] = { 0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00 },
    ['/'] = { 0x02, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x40, 0x00 },
    ['0'] = { 0x3C, 0x66, 0x6E, 0x76, 0x66, 0x66, 0x3C, 0x00 },
    ['1'] = { 0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00 },
    ['2'] = { 0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x7E, 0x00 },
    ['3'] = { 0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00 },
    ['4'] = { 0x0C, 0x1C, 0x34, 0x64, 0x7E, 0x04, 0x04, 0x00 },
    ['5'] = { 0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00 },
    ['6'] = { 0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00 },
    ['7'] = { 0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00 },
    ['8'] = { 0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00 },
    ['9'] = { 0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00 },
    ['A'] = { 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00 },
    ['B'] = { 0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00 },
    ['C'] = { 0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00 },
    ['D'] = { 0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00 },
    ['E'] = { 0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00 },
    ['F'] = { 0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00 },
    ['G'] = { 0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00 },
    ['H'] = { 0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00 },
    ['I'] = { 0x3C, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    ['J'] = { 0x0E, 0x06, 0x06, 0x06, 0x06, 0x66, 0x3C, 0x00 },
    ['K'] = { 0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00 },
    ['L'] = { 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00 },
    ['M'] = { 0x63, 0x77, 0x7F, 0x6B, 0x63, 0x63, 0x63, 0x00 },
    ['N'] = { 0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00 },
    ['O'] = { 0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00 },
    ['P'] = { 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00 },
    ['Q'] = { 0x3C, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x0E, 0x00 },
    ['R'] = { 0x7C, 0x66, 0x66, 0x7C, 0x78, 0x6C, 0x66, 0x00 },
    ['S'] = { 0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00 },
    ['T'] = { 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00 },
    ['U'] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00 },
    ['V'] = { 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00 },
    ['W'] = { 0x63, 0x63, 0x63, 0x6B, 0x7F, 0x77, 0x63, 0x00 },
    ['X'] = { 0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00 },
    ['Y'] = { 0x66, 0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x00 },
    ['Z'] = { 0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00 },
    ['a'] = { 0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3B, 0x00 },
    ['b'] = { 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00 },
    ['c'] = { 0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x00 },
    ['d'] = { 0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3B, 0x00 },
    ['e'] = { 0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00 },
    ['f'] = { 0x0E, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x18, 0x00 },
    ['g'] = { 0x00, 0x00, 0x3B, 0x66, 0x66, 0x3E, 0x06, 0x3C },
    ['h'] = { 0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00 },
    ['i'] = { 0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    ['j'] = { 0x06, 0x00, 0x0E, 0x06, 0x06, 0x66, 0x3C, 0x00 },
    ['k'] = { 0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00 },
    ['l'] = { 0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00 },
    ['m'] = { 0x00, 0x00, 0x76, 0x7F, 0x6B, 0x6B, 0x63, 0x00 },
    ['n'] = { 0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00 },
    ['o'] = { 0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00 },
    ['p'] = { 0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60 },
    ['q'] = { 0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06 },
    ['r'] = { 0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x00 },
    ['s'] = { 0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00 },
    ['t'] = { 0x18, 0x18, 0x7E, 0x18, 0x18, 0x18, 0x0E, 0x00 },
    ['u'] = { 0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3B, 0x00 },
    ['v'] = { 0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00 },
    ['w'] = { 0x00, 0x00, 0x63, 0x6B, 0x7F, 0x3E, 0x36, 0x00 },
    ['x'] = { 0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00 },
    ['y'] = { 0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C },
    ['z'] = { 0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00 },
    ['_'] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00 }
};

static void DrawRectAlpha(uint32_t* buf, int w, int h, int rx, int ry, int rw, int rh, uint32_t color, uint8_t alpha) {
    if (rx < 0) rx = 0;
    if (ry < 0) ry = 0;
    int x2 = rx + rw; if (x2 > w) x2 = w;
    int y2 = ry + rh; if (y2 > h) y2 = h;
    uint32_t inv_a = 255 - alpha;
    uint32_t cr = (color >> 16) & 0xFF;
    uint32_t cg = (color >> 8) & 0xFF;
    uint32_t cb = color & 0xFF;
    for (int y = ry; y < y2; y++) {
        uint32_t* row = buf + y * w;
        for (int x = rx; x < x2; x++) {
            uint32_t orig = row[x];
            uint32_t ob = orig & 0xFF;
            uint32_t og = (orig >> 8) & 0xFF;
            uint32_t or_ = (orig >> 16) & 0xFF;
            uint32_t nb = (cb * alpha + ob * inv_a) >> 8;
            uint32_t ng = (cg * alpha + og * inv_a) >> 8;
            uint32_t nr = (cr * alpha + or_ * inv_a) >> 8;
            row[x] = 0xFF000000 | (nr << 16) | (ng << 8) | nb;
        }
    }
}

static void DrawCharBGRA(uint32_t* buf, int w, int h, int cx, int cy, char ch, uint32_t color, uint32_t shadow, int scale) {
    if (ch < 0 || ch >= 128) ch = '?';
    const uint8_t* glyph = font8x8_osd[(int)ch];
    if (scale <= 1) {
        // 原廠細字 (8x8 點陣): 象牙金本體 + 1px 純黑陰影
        for (int y = 0; y < 8; y++) {
            int py = cy + y;
            if (py < 0 || py >= h) continue;
            uint8_t row = glyph[y];
            for (int x = 0; x < 8; x++) {
                int px = cx + x;
                if (px < 0 || px >= w) continue;
                if (row & (0x80 >> x)) {
                    if (px + 1 < w && py + 1 < h) {
                        buf[(py + 1) * w + (px + 1)] = shadow;
                    }
                }
            }
        }
        for (int y = 0; y < 8; y++) {
            int py = cy + y;
            if (py < 0 || py >= h) continue;
            uint8_t row = glyph[y];
            for (int x = 0; x < 8; x++) {
                int px = cx + x;
                if (px < 0 || px >= w) continue;
                if (row & (0x80 >> x)) {
                    buf[py * w + px] = color;
                }
            }
        }
    } else {
        // 原廠大(粗)字 (16x16 整數倍放大): 筆畫自然加粗
        for (int y = 0; y < 8; y++) {
            uint8_t row = glyph[y];
            for (int x = 0; x < 8; x++) {
                if (row & (0x80 >> x)) {
                    for (int sy = 0; sy < scale; sy++) {
                        int py = cy + y * scale + sy + 1;
                        if (py < 0 || py >= h) continue;
                        for (int sx = 0; sx < scale; sx++) {
                            int px = cx + x * scale + sx + 1;
                            if (px < 0 || px >= w) continue;
                            buf[py * w + px] = shadow;
                        }
                    }
                }
            }
        }
        for (int y = 0; y < 8; y++) {
            uint8_t row = glyph[y];
            for (int x = 0; x < 8; x++) {
                if (row & (0x80 >> x)) {
                    for (int sy = 0; sy < scale; sy++) {
                        int py = cy + y * scale + sy;
                        if (py < 0 || py >= h) continue;
                        for (int sx = 0; sx < scale; sx++) {
                            int px = cx + x * scale + sx;
                            if (px < 0 || px >= w) continue;
                            buf[py * w + px] = color;
                        }
                    }
                }
            }
        }
    }
}

static void DrawStringBGRA(uint32_t* buf, int w, int h, int x, int y, const char* str, uint32_t color, uint32_t shadow, int scale) {
    if (!str) return;
    if (scale <= 0) scale = 1;
    while (*str) {
        DrawCharBGRA(buf, w, h, x, y, *str, color, shadow, scale);
        x += 8 * scale;
        str++;
    }
}

// 原生安全讀取 FBNeo 記憶體中的選手名稱 (UTF-16LE 轉 ASCII)
static void SafeGetPlayerName(uint32_t va, char* out_buf, size_t max_len, const char* fallback) {
    if (!out_buf || max_len == 0) return;
    out_buf[0] = '\0';
    const wchar_t* pWide = (const wchar_t*)GetHostPtrByVa(va);
    if (pWide && !IsBadReadPtr(pWide, 4)) {
        size_t idx = 0;
        while (idx < max_len - 1 && !IsBadReadPtr(&pWide[idx], 2)) {
            wchar_t w = pWide[idx];
            if (w == 0) break;
            if (w >= 32 && w <= 126) {
                out_buf[idx] = (char)w;
            } else {
                out_buf[idx] = '?';
            }
            idx++;
        }
        out_buf[idx] = '\0';
    }
    if (out_buf[0] == '\0' && fallback) {
        strncpy(out_buf, fallback, max_len - 1);
        out_buf[max_len - 1] = '\0';
    }
}

static void ConvertToBGRA32(const void* src, uint32_t* dst, int w, int h, int pitch, int bpp, int maskType) {
    if (pitch <= 0 || pitch < w * (bpp == 4 ? 4 : 2)) {
        pitch = w * (bpp == 4 ? 4 : 2); // 100% NeoGeo 緊湊排列經典保底
    }
    // 【P2-3 零拷貝優化】：若已為 32-bit (bpp == 4) 且顯存為連續緊湊行 (pitch == w * 4)，整幀記憶體極速直出，完全免逐行迴圈！
    if (bpp == 4 && pitch == w * 4) {
        memcpy(dst, src, (size_t)w * h * 4);
        return;
    }
    for (int y = 0; y < h; y++) {
        const uint8_t* row_src = (const uint8_t*)src + (size_t)y * pitch;
        uint32_t* row_dst = dst + (size_t)y * w;
        if (bpp == 2) {
            const uint16_t* s = (const uint16_t*)row_src;
            if (maskType == 0x0F) { // 15-bit 555
                for (int x = 0; x < w; x++) {
                    uint16_t pix = s[x];
                    uint8_t r = (pix >> 10) & 0x1F;
                    uint8_t g = (pix >> 5) & 0x1F;
                    uint8_t b = pix & 0x1F;
                    row_dst[x] = ((uint32_t)((r << 3) | (r >> 2)) << 16) |
                                 ((uint32_t)((g << 3) | (g >> 2)) << 8)  |
                                 ((uint32_t)((b << 3) | (b >> 2)))       | 0xFF000000;
                }
            } else { // 16-bit 565
                for (int x = 0; x < w; x++) {
                    uint16_t pix = s[x];
                    uint8_t r = (pix >> 11) & 0x1F;
                    uint8_t g = (pix >> 5) & 0x3F;
                    uint8_t b = pix & 0x1F;
                    row_dst[x] = ((uint32_t)((r << 3) | (r >> 2)) << 16) |
                                 ((uint32_t)((g << 2) | (g >> 4)) << 8)  |
                                 ((uint32_t)((b << 3) | (b >> 2)))       | 0xFF000000;
                }
            }
        } else if (bpp == 4) {
            memcpy(row_dst, row_src, (size_t)w * 4);
        }
    }
}

static DWORD WINAPI PipeThreadV(LPVOID param) {
    if (g_hPipeVideo != INVALID_HANDLE_VALUE) {
        BOOL ok = ConnectNamedPipe(g_hPipeVideo, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (ok) {
            g_bPipeVConnected = 1;
            LogRec("Video Pipe connected successfully: %s", g_rec_pipe_v_name);
        } else {
            LogRec("Video Pipe connect failed, err=%lu", GetLastError());
        }
    }
    return 0;
}

static void WriteWavHeader(HANDLE hFile, DWORD dataSize) {
    DWORD dwWritten = 0;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    unsigned char h[44];
    memcpy(h, "RIFF", 4);
    DWORD fileSize = dataSize + 36;
    memcpy(h + 4, &fileSize, 4);
    memcpy(h + 8, "WAVEfmt ", 8);
    DWORD subchunk1Size = 16;
    memcpy(h + 16, &subchunk1Size, 4);
    WORD audioFormat = 1; // PCM
    memcpy(h + 20, &audioFormat, 2);
    WORD numChannels = 2; // 立體聲
    memcpy(h + 22, &numChannels, 2);
    DWORD sampleRate = 44100;
    memcpy(h + 24, &sampleRate, 4);
    DWORD byteRate = sampleRate * 2 * 2; // 44100 * 2 * 2 = 176400
    memcpy(h + 28, &byteRate, 4);
    WORD blockAlign = 4;
    memcpy(h + 32, &blockAlign, 2);
    WORD bitsPerSample = 16;
    memcpy(h + 34, &bitsPerSample, 2);
    memcpy(h + 36, "data", 4);
    memcpy(h + 40, &dataSize, 4);
    WriteFile(hFile, h, 44, &dwWritten, NULL);
}


// ============================================================================
// Turbo 模式動態逐幀全量渲染器 (Turbo Offline Fast-Render Hotpatch Engine)
// 動態替換 RVA 0x49E3A (74 05 -> 90 90 NOP NOP)，徹底解鎖 Turbo 下的 Frameskip 跳幀！
// ============================================================================
static int g_turbo_branch_patched = 0;
static int g_orig_always_draw = 0;

static void EnableTurboFullRender(int enable) {
    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) return;

    uint8_t* pTarget = (uint8_t*)(g_exe_base + 0x49E3A);
    int* pAlwaysDraw = (int*)(g_exe_base + 0x1D21690);

    DWORD oldProtect = 0;
    if (enable) {
        // 1. 動態記憶體啟用 bAlwaysDrawFrames = 1 (錄製期間強制滿幀渲染，消除跳幀)
        if (pAlwaysDraw && !IsBadWritePtr(pAlwaysDraw, 4)) {
            g_orig_always_draw = *pAlwaysDraw;
            *pAlwaysDraw = 1;
            LogRec("DYNAMIC_RENDER: Set bAlwaysDrawFrames = 1 in memory (was %d)", g_orig_always_draw);
        }

        // 2. 熱補丁 RVA 0x49E3A (解鎖 Turbo 繪圖分支)
        if (!g_turbo_branch_patched) {
            if (pTarget[0] == 0x74 && pTarget[1] == 0x05) {
                if (VirtualProtect(pTarget, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    pTarget[0] = 0x90;
                    pTarget[1] = 0x90;
                    VirtualProtect(pTarget, 2, oldProtect, &oldProtect);
                    FlushInstructionCache(GetCurrentProcess(), pTarget, 2);
                    g_turbo_branch_patched = 1;
                    LogRec("TURBO_RENDER_HOTPATCH: Successfully patched 0x49E3A to NOP NOP! Frameskip unlocked.");
                }
            } else {
                LogRec("TURBO_RENDER_HOTPATCH: Target bytes mismatch (0x%02X 0x%02X), skip patch.", pTarget[0], pTarget[1]);
            }
        }
    } else {
        // 1. 還原記憶體 bAlwaysDrawFrames (還原為跳幀極限加速模式，確保 2500 FPS 探底光速不受影響)
        if (pAlwaysDraw && !IsBadWritePtr(pAlwaysDraw, 4)) {
            *pAlwaysDraw = g_orig_always_draw;
            LogRec("DYNAMIC_RENDER: Restored bAlwaysDrawFrames = %d in memory", g_orig_always_draw);
        }

        // 2. 還原 RVA 0x49E3A
        if (g_turbo_branch_patched) {
            if (VirtualProtect(pTarget, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                pTarget[0] = 0x74;
                pTarget[1] = 0x05;
                VirtualProtect(pTarget, 2, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), pTarget, 2);
                g_turbo_branch_patched = 0;
                LogRec("TURBO_RENDER_HOTPATCH: Successfully restored 0x49E3A to 74 05.");
            }
        }
    }
}

typedef struct {
    HANDLE hFfmpegProcess;
    HANDLE hFfmpegThread;
    HANDLE hAudioFile;
    DWORD audioBytes;
    char ffmpegPath[MAX_PATH];
    char tempVMp4[MAX_PATH];
    char tempAWav[MAX_PATH];
    char outMp4[MAX_PATH];
    char moduleDir[MAX_PATH];
} RemuxJobArgs;

static DWORD WINAPI ThreadRemuxWorker(LPVOID lpParam) {
    RemuxJobArgs* args = (RemuxJobArgs*)lpParam;
    if (!args) return 0;

    LogRec("[ASYNC_REMUX] Worker started in background. Emulator main thread is 100% free!");

    // 1. 等待第一隻視訊 FFmpeg 完全退出，寫完 moov atom
    // 【P1-2 修復】: 10 秒超時主動 TerminateProcess，徹底杜絕孤兒進程常駐與檔案鎖死！
    if (args->hFfmpegProcess) {
        LogRec("[ASYNC_REMUX] Waiting for FFmpeg video stream to finalize...");
        DWORD waitRes = WaitForSingleObject(args->hFfmpegProcess, 10000);
        if (waitRes == WAIT_TIMEOUT) {
            LogRec("[ASYNC_REMUX] WARNING: Video FFmpeg stream timed out after 10s! Forcing termination.");
            TerminateProcess(args->hFfmpegProcess, 1);
        }
        CloseHandle(args->hFfmpegProcess);
        if (args->hFfmpegThread) CloseHandle(args->hFfmpegThread);
    }

    // 2. 回填音訊 WAV Header 並關閉音訊檔
    if (args->hAudioFile != INVALID_HANDLE_VALUE) {
        WriteWavHeader(args->hAudioFile, args->audioBytes);
        FlushFileBuffers(args->hAudioFile);
        CloseHandle(args->hAudioFile);
        LogRec("[ASYNC_REMUX] Audio WAV finalized (bytes=%lu)", args->audioBytes);
    }

    // 3. 執行無損快速合流
    if (GetFileAttributesA(args->tempVMp4) != INVALID_FILE_ATTRIBUTES) {
        WIN32_FILE_ATTRIBUTE_DATA fadV = {0}, fadA = {0};
        ULONGLONG szV = 0, szA = 0;
        if (GetFileAttributesExA(args->tempVMp4, GetFileExInfoStandard, &fadV)) {
            szV = ((ULONGLONG)fadV.nFileSizeHigh << 32) | fadV.nFileSizeLow;
        }
        if (GetFileAttributesA(args->tempAWav) != INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesExA(args->tempAWav, GetFileExInfoStandard, &fadA)) {
            szA = ((ULONGLONG)fadA.nFileSizeHigh << 32) | fadA.nFileSizeLow;
        }
        LogRec("[ASYNC_REMUX] Files status: temp_v=%llu bytes, temp_a=%llu bytes", szV, szA);

        if (szV > 0) {
            char mergeCmd[2048];
            if (szA > 44) {
                snprintf(mergeCmd, sizeof(mergeCmd),
                    "\"%s\" -y -i \"%s\" -ignore_length 1 -i \"%s\" -c:v copy -c:a aac -b:a 192k -af \"aresample=async=1000\" -shortest -movflags +faststart \"%s\"",
                    args->ffmpegPath, args->tempVMp4, args->tempAWav, args->outMp4);
            } else {
                snprintf(mergeCmd, sizeof(mergeCmd),
                    "\"%s\" -y -i \"%s\" -c:v copy \"%s\"",
                    args->ffmpegPath, args->tempVMp4, args->outMp4);
            }

            LogRec("[ASYNC_REMUX] Executing: %s", mergeCmd);

            char ffLogPath[MAX_PATH];
            snprintf(ffLogPath, sizeof(ffLogPath), "%sffmpeg_run.log", args->moduleDir);
            SECURITY_ATTRIBUTES sa;
            memset(&sa, 0, sizeof(sa));
            sa.nLength = sizeof(sa);
            sa.bInheritHandle = TRUE;
            HANDLE hLog = CreateFileA(ffLogPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            STARTUPINFOA siM;
            PROCESS_INFORMATION piM;
            memset(&siM, 0, sizeof(siM));
            memset(&piM, 0, sizeof(piM));
            siM.cb = sizeof(siM);
            siM.dwFlags = STARTF_USESHOWWINDOW | (hLog != INVALID_HANDLE_VALUE ? STARTF_USESTDHANDLES : 0);
            siM.wShowWindow = SW_HIDE;
            if (hLog != INVALID_HANDLE_VALUE) {
                siM.hStdOutput = hLog;
                siM.hStdError = hLog;
            }

            if (CreateProcessA(NULL, mergeCmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siM, &piM)) {
                if (hLog != INVALID_HANDLE_VALUE) CloseHandle(hLog);
                DWORD waitM = WaitForSingleObject(piM.hProcess, 15000);
                if (waitM == WAIT_TIMEOUT) {
                    LogRec("[ASYNC_REMUX] WARNING: Remux process timed out after 15s! Forcing termination.");
                    TerminateProcess(piM.hProcess, 1);
                }
                DWORD exitCode = 0;
                GetExitCodeProcess(piM.hProcess, &exitCode);
                CloseHandle(piM.hProcess);
                CloseHandle(piM.hThread);
                LogRec("[ASYNC_REMUX] Completed exitCode=%lu! Target: %s", exitCode, args->outMp4);
            } else {
                if (hLog != INVALID_HANDLE_VALUE) CloseHandle(hLog);
                LogRec("[ASYNC_REMUX] ERROR: CreateProcess failed for remux! err=%lu", GetLastError());
            }

            WIN32_FILE_ATTRIBUTE_DATA fadOut;
            if (GetFileAttributesExA(args->outMp4, GetFileExInfoStandard, &fadOut) &&
                (((ULONGLONG)fadOut.nFileSizeHigh << 32) | fadOut.nFileSizeLow) > 0) {
                LogRec("[ASYNC_REMUX] Final MP4 verified! Size=%lu bytes", fadOut.nFileSizeLow);
                DeleteFileA(args->tempVMp4);
                DeleteFileA(args->tempAWav);
            } else {
                LogRec("[ASYNC_REMUX] Emergency copy temp_v.mp4 to output!");
                CopyFileA(args->tempVMp4, args->outMp4, FALSE);
            }
        }
    }

    LogRec("[ASYNC_REMUX] Background worker finished.");
    free(args);
    return 0;
}

static void StopNativeRecording(const char* caller) {
    if (!g_bNativeRecording && g_hPipeVideo == INVALID_HANDLE_VALUE) return;
    LogRec("Stopping native recording (CALLER: %s)... Total frames written: %d", caller ? caller : "UNKNOWN", g_rec_frames_written);
    g_bNativeRecording = 0;
    g_rec_is_turbo = 0;
    g_bPipeVConnected = 0;
    g_rec_state_dirty = 1; // 確保 GUI 一定讀到 is_rec=0 的最終狀態
    EnableTurboFullRender(0);

    // 1. 先斷開並關閉視訊管道，送出 EOF 給第一個 FFmpeg
    if (g_hPipeVideo != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_hPipeVideo);
        CloseHandle(g_hPipeVideo);
        g_hPipeVideo = INVALID_HANDLE_VALUE;
    }

    if (g_hThreadV) {
        CloseHandle(g_hThreadV);
        g_hThreadV = NULL;
    }

    // 2. 封裝所有後台作業交由獨立 Worker 線程處理，模擬器主線程 0 毫秒立即返回，100% 保持 60 FPS！
    RemuxJobArgs* args = (RemuxJobArgs*)malloc(sizeof(RemuxJobArgs));
    if (args) {
        memset(args, 0, sizeof(RemuxJobArgs));
        args->hFfmpegProcess = g_ffmpeg_pi.hProcess;
        args->hFfmpegThread  = g_ffmpeg_pi.hThread;
        args->hAudioFile     = g_hAudioFile;
        args->audioBytes     = g_rec_audio_bytes;
        strncpy(args->ffmpegPath, g_rec_ffmpeg_path, sizeof(args->ffmpegPath) - 1);
        strncpy(args->tempVMp4,   g_rec_temp_v_mp4,   sizeof(args->tempVMp4) - 1);
        strncpy(args->tempAWav,   g_rec_temp_a_wav,   sizeof(args->tempAWav) - 1);
        strncpy(args->outMp4,     g_rec_out_mp4,     sizeof(args->outMp4) - 1);
        strncpy(args->moduleDir,  g_module_dir,       sizeof(args->moduleDir) - 1);

        memset(&g_ffmpeg_pi, 0, sizeof(g_ffmpeg_pi));
        g_hAudioFile = INVALID_HANDLE_VALUE;

        HANDLE hWorker = CreateThread(NULL, 0, ThreadRemuxWorker, args, 0, NULL);
        if (hWorker) {
            CloseHandle(hWorker);
        } else {
            // 【P1-4 修復】: 線程創建失敗時執行同步兜底釋放，防止三重洩漏
            LogRec("ERROR: CreateThread failed for remux worker! Fallback synchronous cleanup.");
            if (args->hFfmpegProcess) {
                TerminateProcess(args->hFfmpegProcess, 1);
                CloseHandle(args->hFfmpegProcess);
            }
            if (args->hFfmpegThread) CloseHandle(args->hFfmpegThread);
            if (args->hAudioFile != INVALID_HANDLE_VALUE) CloseHandle(args->hAudioFile);
            free(args);
        }
    }
    LogRec("StopNativeRecording returned immediately, zero lag for emulator!");
}

// ============================================================================
// 動態街機顯存架構解析引擎 (CPS3 384x224 / NeoGeo 320x224 / CPS1/2 384x224 自適應)
// ============================================================================
static void DetectGameResolution(int* out_w, int* out_h) {
    int w = 0, h = 0;
    if (!g_exe_base) DetectExeBase();
    if (g_exe_base) {
        // 1. 優先嘗試 FBNeo 底層渲染核心顯存 (nBurnWidth 0x0202d4b0, nBurnHeight 0x0202d4ac)
        int* pCoreW = (int*)GetHostPtrByVa(0x0202d4b0);
        int* pCoreH = (int*)GetHostPtrByVa(0x0202d4ac);
        if (pCoreW && pCoreH && !IsBadReadPtr(pCoreW, 4) && !IsBadReadPtr(pCoreH, 4)) {
            if (*pCoreW > 0 && *pCoreW <= 1920 && *pCoreH > 0 && *pCoreH <= 1080) {
                w = *pCoreW;
                h = *pCoreH;
            }
        }
        // 2. 次選: FBNeo Driver 結構體成員 (pDriver[nBurnDrvSelect]->nWidth +0x88, ->nHeight +0x8C)
        if (w <= 0 || h <= 0) {
            int* pDrvSel = (int*)GetHostPtrByVa(0x01209750);
            if (pDrvSel && !IsBadReadPtr(pDrvSel, 4)) {
                int drv_idx = *pDrvSel;
                if (drv_idx >= 0 && drv_idx < 20000) {
                    uintptr_t* pDriverArr = (uintptr_t*)GetHostPtrByVa(0x00f2b580);
                    if (pDriverArr && !IsBadReadPtr(&pDriverArr[drv_idx], sizeof(uintptr_t))) {
                        uintptr_t pDrv = pDriverArr[drv_idx];
                        if (pDrv && !IsBadReadPtr((void*)pDrv, 0x100)) {
                            // 【P0-1 修復】: pDrv 已為真實 Host 指標，直接型別轉換，嚴禁二次傳入 GetHostPtrByVa！
                            int* pDW = (int*)(pDrv + 0x88);
                            int* pDH = (int*)(pDrv + 0x8c);
                            if (pDW && pDH && !IsBadReadPtr(pDW, 4) && !IsBadReadPtr(pDH, 4)) {
                                if (*pDW > 0 && *pDW <= 1920 && *pDH > 0 && *pDH <= 1080) {
                                    w = *pDW;
                                    h = *pDH;
                                }
                            }
                        }
                    }
                }
            }
        }
        // 3. 第三備選: 舊有表面濾鏡寬高 (0x031943ac, 0x031943b0)
        if (w <= 0 || h <= 0) {
            int* pOldW = (int*)GetHostPtrByVa(0x031943ac);
            int* pOldH = (int*)GetHostPtrByVa(0x031943b0);
            if (pOldW && pOldH && !IsBadReadPtr(pOldW, 4) && !IsBadReadPtr(pOldH, 4)) {
                if (*pOldW > 0 && *pOldW <= 1920 && *pOldH > 0 && *pOldH <= 1080) {
                    w = *pOldW;
                    h = *pOldH;
                }
            }
        }
    }
    // 4. 第四備選: Lua 通報之即時遊戲畫面大小 (g_game_width, g_game_height)
    if (w <= 0 || h <= 0) {
        if (g_game_width > 0 && g_game_height > 0) {
            w = g_game_width;
            h = g_game_height;
        }
    }
    // 5. 終極保底: 320x224 (NeoGeo)
    if (w <= 0 || h <= 0) {
        w = 320;
        h = 224;
    }
    *out_w = w;
    *out_h = h;
}

// 純 C 靜態 95 字元 ASCII 像素寬度查表 (Segoe UI Bold 24px，零外部 DLL 依賴，100% 安全)
static int SafeCalcTextWidth24(const char* text) {
    if (!text) return 0;
    static const unsigned char w_table[95] = {
        7, 8, 12, 14, 14, 21, 20, 7, 9, 9, 11, 17, 7, 10, 7, 12,
        14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 7, 7, 17, 17, 17, 11,
        23, 17, 15, 15, 18, 13, 12, 17, 18, 8, 11, 16, 12, 23, 19, 18,
        15, 19, 17, 13, 14, 17, 16, 24, 16, 15, 15, 9, 12, 9, 17, 10,
        8, 13, 15, 12, 15, 13, 10, 15, 14, 7, 9, 14, 7, 22, 15, 15,
        15, 15, 10, 11, 9, 15, 13, 19, 14, 14, 12, 9, 8, 9, 17
    };
    int total = 0;
    for (const unsigned char* p = (const unsigned char*)text; *p; p++) {
        if (*p >= 32 && *p <= 126) total += w_table[*p - 32];
        else total += 14;
    }
    return total;
}

static const char* GetSafeFontOpt() {
    static char fontOpt[MAX_PATH] = {0};
    static int s_inited = 0;
    if (s_inited) return fontOpt;
    s_inited = 1;

    const char* candidates[] = {
        "C:\\Windows\\Fonts\\segoeuib.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\msyhbd.ttc",
        "C:\\Windows\\Fonts\\msyh.ttc"
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (GetFileAttributesA(candidates[i]) != INVALID_FILE_ATTRIBUTES) {
            char pBuf[MAX_PATH];
            strncpy(pBuf, candidates[i], sizeof(pBuf) - 1);
            pBuf[sizeof(pBuf) - 1] = '\0';
            for (char* p = pBuf; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            if (pBuf[1] == ':') {
                snprintf(fontOpt, sizeof(fontOpt), "fontfile='%c\\:%s':", pBuf[0], pBuf + 2);
            } else {
                snprintf(fontOpt, sizeof(fontOpt), "fontfile='%s':", pBuf);
            }
            return fontOpt;
        }
    }
    fontOpt[0] = '\0';
    return fontOpt;
}

static int g_has_nvenc = -1; // -1: 未探測, 0: 不支援, 1: 支援

static int DetectNvencSupport(const char* ffmpeg_path) {
    if (g_has_nvenc != -1) return g_has_nvenc;

    // 1. 微秒級 DLL 檢查 (若系統無 nvcuda.dll 則 100% 無 NVIDIA 顯卡)
    HMODULE hCuda = LoadLibraryA("nvcuda.dll");
    if (!hCuda) {
        g_has_nvenc = 0;
        LogRec("[NVENC_DETECT] nvcuda.dll not found, fallback to CPU libx264.");
        return 0;
    }
    FreeLibrary(hCuda);

    // 2. 0.01 秒極輕量編碼器測試 (驗證顯卡晶片是否真實支援 NVENC)
    char probeCmd[MAX_PATH * 2];
    snprintf(probeCmd, sizeof(probeCmd), "\"%s\" -hide_banner -f lavfi -i color=c=black:s=64x64:d=0.01 -c:v h264_nvenc -f null -", ffmpeg_path);
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));

    if (CreateProcessA(NULL, probeCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD waitRes = WaitForSingleObject(pi.hProcess, 1500);
        DWORD exitCode = 1;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (waitRes == WAIT_OBJECT_0 && exitCode == 0) {
            g_has_nvenc = 1;
            LogRec("[NVENC_DETECT] NVENC Hardware Acceleration is AVAILABLE! GPU encoding enabled.");
            return 1;
        }
    }

    g_has_nvenc = 0;
    LogRec("[NVENC_DETECT] NVENC probe failed or unsupported. Fallback to CPU libx264.");
    return 0;
}

static void StartNativeRecording(int start_f, int end_f, int scale_mode, const char* ffmpeg_path, const char* out_mp4, const char* p1, const char* p2, int show_osd) {
    if (g_bNativeRecording) {
        LogRec("Recording already in progress, ignoring duplicate start.");
        return;
    }

    g_rec_show_osd = show_osd;
    g_bManualPaused = FALSE; // 強制解除底層暫停狀態，確保幀數正常推進
    if (p1 && strlen(p1) > 0) strncpy(g_rec_p1_name, p1, sizeof(g_rec_p1_name) - 1);
    else strncpy(g_rec_p1_name, "Player 1", sizeof(g_rec_p1_name) - 1);
    if (p2 && strlen(p2) > 0) strncpy(g_rec_p2_name, p2, sizeof(g_rec_p2_name) - 1);
    else strncpy(g_rec_p2_name, "Player 2", sizeof(g_rec_p2_name) - 1);

    LogRec("StartNativeRecording requested: start_f=%d, end_f=%d, scale=%d, ffmpeg=%s, out=%s, P1=%s, P2=%s, OSD=%d",
        start_f, end_f, scale_mode, ffmpeg_path, out_mp4, g_rec_p1_name, g_rec_p2_name, g_rec_show_osd);

    if (GetFileAttributesA(ffmpeg_path) == INVALID_FILE_ATTRIBUTES) {
        LogRec("ERROR: Provided ffmpeg path not accessible: %s", ffmpeg_path);
        return;
    }
    strncpy(g_rec_ffmpeg_path, ffmpeg_path, sizeof(g_rec_ffmpeg_path) - 1);

    if (!g_exe_base) DetectExeBase();
    if (!g_exe_base) {
        LogRec("ERROR: DetectExeBase failed!");
        return;
    }

    int w = 0, h = 0;
    DetectGameResolution(&w, &h);
    g_rec_width = w;
    g_rec_height = h;

    // 【夥伴關鍵補強 1】：動態物理時脈幀率自動推導 (天才算法: 44100 / soundLen)
    // NeoGeo(745 samples) -> 59.1946 Hz, CPS2(740) -> 59.5946 Hz, 60Hz(735) -> 60.0000 Hz
    // 【P0-2 修復】: 加入 IsBadReadPtr 邊界保護，防止未初始化分頁引發 0xC0000005 崩潰
    int soundLen = 735;
    int* pSoundLen = (int*)GetHostPtrByVa(0x03121af8);
    if (pSoundLen && !IsBadReadPtr(pSoundLen, 4)) {
        if (*pSoundLen > 500 && *pSoundLen < 1500) {
            soundLen = *pSoundLen;
        }
    }
    double real_fps = 44100.0 / (double)soundLen;
    LogRec("Game native resolution: %dx%d | SoundLen: %d | Dynamic Hardware FPS: %.4f Hz", w, h, soundLen, real_fps);

    g_rec_start_frame = start_f;
    g_rec_end_frame = end_f;
    g_rec_is_full = (end_f <= 0);
    g_rec_scale_mode = scale_mode;
    g_rec_frames_written = 0;
    g_rec_has_reached_start = 0;
    g_rec_need_seek_back = 0;
    g_rec_audio_bytes = 0;
    g_rec_attempts = 0;
    strncpy(g_rec_out_mp4, out_mp4, sizeof(g_rec_out_mp4) - 1);

    // 1. 產生暫存檔路徑 (temp_v.mp4 與 temp_a.wav)
    DWORD tick = GetTickCount();
    // 暫存檔放在「輸出 MP4 同一資料夾」(該資料夾必定存在，由 GUI 事先建立)
    char out_dir[MAX_PATH] = {0};
    strncpy(out_dir, g_rec_out_mp4, sizeof(out_dir) - 1);
    {
        char* s1 = strrchr(out_dir, '\\');
        char* s2 = strrchr(out_dir, '/');
        char* sep = (s1 > s2) ? s1 : s2;
        if (sep) *(sep + 1) = '\0'; else out_dir[0] = '\0';
    }
    if (out_dir[0]) {
        CreateDirectoryA(out_dir, NULL);
    }
    snprintf(g_rec_temp_v_mp4, sizeof(g_rec_temp_v_mp4), "%stemp_v_%lu.mp4", out_dir, tick);
    snprintf(g_rec_temp_a_wav, sizeof(g_rec_temp_a_wav), "%stemp_a_%lu.wav", out_dir, tick);
    LogRec("Temp files: %s | %s", g_rec_temp_v_mp4, g_rec_temp_a_wav);

    // 2. 建立音訊暫存 WAV 檔並預留 44 bytes Header
    g_hAudioFile = CreateFileA(g_rec_temp_a_wav, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hAudioFile != INVALID_HANDLE_VALUE) {
        WriteWavHeader(g_hAudioFile, 0); // 先寫空白 Header，收尾時回填
    } else {
        LogRec("ERROR: Failed to create temp_a.wav! Err=%lu", GetLastError());
    }

    // 3. 建立視訊專屬唯一具名管道 (單管道 100% 絕不死結！)
    snprintf(g_rec_pipe_v_name, sizeof(g_rec_pipe_v_name), "\\\\.\\pipe\\fbneo_v_%lu", tick);
    g_hPipeVideo = CreateNamedPipeA(
        g_rec_pipe_v_name,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1, 4 * 1024 * 1024, 4 * 1024 * 1024, 0, NULL);

    if (g_hPipeVideo == INVALID_HANDLE_VALUE) {
        LogRec("ERROR: CreateNamedPipe failed for video! Err=%lu", GetLastError());
        if (g_hAudioFile != INVALID_HANDLE_VALUE) { CloseHandle(g_hAudioFile); g_hAudioFile = INVALID_HANDLE_VALUE; }
        return;
    }

    // 先啟動視訊監聽執行緒
    g_bPipeVConnected = 0;
    g_hThreadV = CreateThread(NULL, 0, PipeThreadV, NULL, 0, NULL);

    // 4. 啟動單管道 FFmpeg 純視訊轉碼進程 (精確帶入動態硬體幀率 %.4f！)
    // 【P1-3 修復】: 擴展緩衝區容量至 8192/4096，徹底杜絕長路徑或多層濾鏡引發的截斷崩潰！
    char cmdLine[8192];
    char osdFilter[4096] = {0};

    // 只有在 720P 或 1080P 且啟用現代條狀 HUD (show_osd == 1) 時才注入 FFmpeg 濾鏡！
    // 原生 1x 解析度絕不注入 1080p/720p 巨型濾鏡，而是由底層 DrawStringBGRA 繪製 8x8 點陣字，杜絕遮擋血條！
    if (g_rec_show_osd == 1 && g_rec_res_mode > 1) {
        char p1_n[64] = "Player 1", p2_n[64] = "Player 2";
        SafeGetPlayerName(0x0202FEB8, p1_n, sizeof(p1_n), "Player 1");
        SafeGetPlayerName(0x0202F080, p2_n, sizeof(p2_n), "Player 2");
        for (char* c = p1_n; *c; c++) { if (*c == 34 || *c == 39 || *c == ':' || *c == 92 || *c == '%' || (unsigned char)*c < 32) *c = ' '; }
        for (char* c = p2_n; *c; c++) { if (*c == 34 || *c == 39 || *c == ':' || *c == 92 || *c == '%' || (unsigned char)*c < 32) *c = ' '; }

        static const char* s_rank_names[] = { "?", "E", "D", "C", "B", "A", "S" };
        static const char* s_rank_colors[] = { "0x757575", "0xC27A3F", "0xB3B2B0", "0xF3C84A", "0x00A9DA", "0xA047B2", "0xE54875" };
        int r1_idx = 0, r2_idx = 0;
        int* pR1 = (int*)GetHostPtrByVa(0x02030828);
        int* pR2 = (int*)GetHostPtrByVa(0x0202F9F0);
        if (pR1 && !IsBadReadPtr(pR1, 4)) r1_idx = *pR1;
        if (pR2 && !IsBadReadPtr(pR2, 4)) r2_idx = *pR2;
        if (r1_idx < 0 || r1_idx > 6) r1_idx = 0;
        if (r2_idx < 0 || r2_idx > 6) r2_idx = 0;

        int match_ft_val = 0;
        int* pFt = (int*)GetHostPtrByVa(0x0312DBD0);
        if (pFt && !IsBadReadPtr(pFt, 4)) match_ft_val = *pFt;

        char ft_disp[32] = "VS";
        if (match_ft_val > 1) {
            snprintf(ft_disp, sizeof(ft_disp), "FT%d", match_ft_val);
        }

        int s1 = 0, s2 = 0;
        int* pScoreP1 = (int*)GetHostPtrByVa(0x03183210);
        int* pScoreP2 = (int*)GetHostPtrByVa(0x03183214);
        if (pScoreP1 && pScoreP2 && !IsBadReadPtr(pScoreP1, 4) && !IsBadReadPtr(pScoreP2, 4)) {
            s1 = *pScoreP1;
            s2 = *pScoreP2;
        }

        int p1_w = SafeCalcTextWidth24(p1_n);
        int p2_w = SafeCalcTextWidth24(p2_n);
        const char* fOpt = GetSafeFontOpt();

        if (g_rec_res_mode == 2) {
            // 【720P 高清 (1280x720) 條狀 HUD 自適應】
            // 字級 16px、基準 y=12、半透明黑條 480x32、中心點 x=640
            int p1_w16 = p1_w * 16 / 24;
            int p2_w16 = p2_w * 16 / 24;
            char p1_rank_opt[256] = {0};
            char p2_rank_opt[256] = {0};
            if (r1_idx > 0) {
                snprintf(p1_rank_opt, sizeof(p1_rank_opt),
                    ",drawtext=%stext='%s':x=640-50-%d-text_w:y=12:fontsize=16:fontcolor=%s:borderw=1:bordercolor=black",
                    fOpt, s_rank_names[r1_idx], p1_w16 + 6, s_rank_colors[r1_idx]);
            }
            if (r2_idx > 0) {
                snprintf(p2_rank_opt, sizeof(p2_rank_opt),
                    ",drawtext=%stext='%s':x=640+50+%d:y=12:fontsize=16:fontcolor=%s:borderw=1:bordercolor=black",
                    fOpt, s_rank_names[r2_idx], p2_w16 + 6, s_rank_colors[r2_idx]);
            }
            snprintf(osdFilter, sizeof(osdFilter),
                ",drawbox=x=(1280-480)/2:y=6:w=480:h=32:color=0x201C24@0.70:t=fill"
                "%s"
                ",drawtext=%stext='%s':x=640-50-text_w:y=12:fontsize=16:fontcolor=white:borderw=1:bordercolor=black"
                ",drawtext=%stext='%d':x=640-30-text_w:y=12:fontsize=16:fontcolor=0x66E9E0:borderw=1:bordercolor=black"
                ",drawtext=%stext='%s':x=(w-text_w)/2:y=12:fontsize=16:fontcolor=0x838584:borderw=1:bordercolor=black"
                ",drawtext=%stext='%d':x=640+30:y=12:fontsize=16:fontcolor=0x66E9E0:borderw=1:bordercolor=black"
                ",drawtext=%stext='%s':x=640+50:y=12:fontsize=16:fontcolor=white:borderw=1:bordercolor=black"
                "%s",
                p1_rank_opt, fOpt, p1_n, fOpt, s1, fOpt, ft_disp, fOpt, s2, fOpt, p2_n, p2_rank_opt);
        } else if (g_rec_res_mode == 4) {
            // 【1440P 2K 超清 (2560x1440) 條狀 HUD】
            // 字級 32px、基準 y=24、半透明黑條 960x62、中心點 x=1280
            int p1_w32 = p1_w * 32 / 24;
            int p2_w32 = p2_w * 32 / 24;
            char p1_rank_opt[256] = {0};
            char p2_rank_opt[256] = {0};
            if (r1_idx > 0) {
                snprintf(p1_rank_opt, sizeof(p1_rank_opt),
                    ",drawtext=%stext='%s':x=1280-100-%d-text_w:y=24:fontsize=32:fontcolor=%s:borderw=2:bordercolor=black",
                    fOpt, s_rank_names[r1_idx], p1_w32 + 10, s_rank_colors[r1_idx]);
            }
            if (r2_idx > 0) {
                snprintf(p2_rank_opt, sizeof(p2_rank_opt),
                    ",drawtext=%stext='%s':x=1280+100+%d:y=24:fontsize=32:fontcolor=%s:borderw=2:bordercolor=black",
                    fOpt, s_rank_names[r2_idx], p2_w32 + 10, s_rank_colors[r2_idx]);
            }
            snprintf(osdFilter, sizeof(osdFilter),
                ",drawbox=x=(2560-960)/2:y=10:w=960:h=62:color=0x201C24@0.70:t=fill"
                "%s"
                ",drawtext=%stext='%s':x=1280-100-text_w:y=24:fontsize=32:fontcolor=white:borderw=2:bordercolor=black"
                ",drawtext=%stext='%d':x=1280-60-text_w:y=24:fontsize=32:fontcolor=0x66E9E0:borderw=2:bordercolor=black"
                ",drawtext=%stext='%s':x=(w-text_w)/2:y=24:fontsize=32:fontcolor=0x838584:borderw=2:bordercolor=black"
                ",drawtext=%stext='%d':x=1280+60:y=24:fontsize=32:fontcolor=0x66E9E0:borderw=2:bordercolor=black"
                ",drawtext=%stext='%s':x=1280+100:y=24:fontsize=32:fontcolor=white:borderw=2:bordercolor=black"
                "%s",
                p1_rank_opt, fOpt, p1_n, fOpt, s1, fOpt, ft_disp, fOpt, s2, fOpt, p2_n, p2_rank_opt);
        } else {
            // 【1080P 全高清 (1920x1080) 條狀 HUD】
            char p1_rank_opt[256] = {0};
            char p2_rank_opt[256] = {0};
            if (r1_idx > 0) {
                snprintf(p1_rank_opt, sizeof(p1_rank_opt),
                    ",drawtext=%stext='%s':x=960-75-%d-text_w:y=18:fontsize=24:fontcolor=%s:borderw=2:bordercolor=black",
                    fOpt, s_rank_names[r1_idx], p1_w + 8, s_rank_colors[r1_idx]);
            }
            if (r2_idx > 0) {
                snprintf(p2_rank_opt, sizeof(p2_rank_opt),
                    ",drawtext=%stext='%s':x=960+75+%d:y=18:fontsize=24:fontcolor=%s:borderw=2:bordercolor=black",
                    fOpt, s_rank_names[r2_idx], p2_w + 8, s_rank_colors[r2_idx]);
            }
            snprintf(osdFilter, sizeof(osdFilter),
                ",drawbox=x=(1920-720)/2:y=8:w=720:h=46:color=0x201C24@0.70:t=fill"
                "%s"
                ",drawtext=%stext='%s':x=960-75-text_w:y=18:fontsize=24:fontcolor=white:borderw=2:bordercolor=black"
                ",drawtext=%stext='%d':x=960-45-text_w:y=18:fontsize=24:fontcolor=0x66E9E0:borderw=2:bordercolor=black"
                ",drawtext=%stext='%s':x=(w-text_w)/2:y=18:fontsize=24:fontcolor=0x838584:borderw=2:bordercolor=black"
                ",drawtext=%stext='%d':x=960+45:y=18:fontsize=24:fontcolor=0x66E9E0:borderw=2:bordercolor=black"
                ",drawtext=%stext='%s':x=960+75:y=18:fontsize=24:fontcolor=white:borderw=2:bordercolor=black"
                "%s",
                p1_rank_opt, fOpt, p1_n, fOpt, s1, fOpt, ft_disp, fOpt, s2, fOpt, p2_n, p2_rank_opt);
        }
    }

    char fullVfOpt[4096];
    if (g_rec_res_mode == 1) {
        // 【A1. 原生 1x (街機原生點對點，自動辨識 NEOGEO 320x224 / CPS1~3 384x224 / PGM 448x224)】
        if (g_rec_render_mode == 0) {
            // 模式 0: 原廠 AdvanceMAME Scale3x 復刻 (原生微光柵 + 溫和色彩回補 + BT.709 全色度)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"drawgrid=width=iw:height=2:thickness=1:color=black@0.16,eq=saturation=1.18:contrast=1.06:brightness=-0.008,scale=iw:ih:flags=neighbor+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709\"");
        } else if (g_rec_render_mode == 1) {
            // 模式 1: 輕微光柵 + 色彩微補償
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"drawgrid=width=iw:height=2:thickness=1:color=black@0.18,eq=saturation=1.08:contrast=1.03,scale=iw:ih:flags=neighbor+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709\"");
        } else if (g_rec_render_mode == 2) {
            // 模式 2: 刀鋒微銳化 + 色彩微補償
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"unsharp=3:3:0.4:3:3:0.0,eq=saturation=1.08:contrast=1.03,scale=iw:ih:flags=neighbor+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709\"");
        } else {
            // 模式 3: 純淨原汁原味直出 + 溫和色彩微補償
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"eq=saturation=1.08:contrast=1.03,scale=iw:ih:flags=neighbor+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709\"");
        }
    } else if (g_rec_res_mode == 2) {
        // 【A2. 720P 高清 (1280x720，等比居中 960x720 + 兩側補黑邊各 160px)】
        if (g_rec_render_mode == 0) {
            // 模式 0: 🕹️ 原廠 AdvanceMAME Scale3x + 像素列對齊掃描線 + Lanczos 無波紋二段縮放
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"epx=n=3,drawgrid=width=iw:height=3:thickness=1:color=black@0.24,scale=960:720:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.35:3:3:0.0,eq=saturation=1.18:contrast=1.08:brightness=-0.01,pad=1280:720:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else if (g_rec_render_mode == 1) {
            // 模式 1: 📺 CRT 顯像管等比光柵 (3x Prescale + 像素對齊光柵 + Lanczos + 微銳化)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=iw*3:ih*3:flags=neighbor,drawgrid=width=iw:height=3:thickness=1:color=black@0.26,scale=960:720:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.4:3:3:0.0,eq=saturation=1.08:contrast=1.03,pad=1280:720:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else if (g_rec_render_mode == 2) {
            // 模式 2: ⚡ 刀鋒無損硬點陣 (3x Prescale + Lanczos + 0.6 刀鋒電競銳化)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=iw*3:ih*3:flags=neighbor,scale=960:720:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.6:3:3:0.0,eq=saturation=1.08:contrast=1.03,pad=1280:720:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else {
            // 模式 3: 🕹️ 柔和雙立方抗鋸齒 (Bicubic 平滑縮放)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=960:720:flags=bicubic+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,eq=saturation=1.08:contrast=1.03,pad=1280:720:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        }
    } else if (g_rec_res_mode == 4) {
        // 【A4. 1440P 2K 超清 (2560x1440，等比居中 1920x1440 + 兩側補黑邊各 320px，YouTube 強制 VP9 專項)】
        if (g_rec_render_mode == 0) {
            // 模式 0: 🕹️ 原廠 AdvanceMAME Scale3x + 像素列對齊掃描線 + Lanczos 2K 超清縮放
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"epx=n=3,drawgrid=width=iw:height=3:thickness=1:color=black@0.26,scale=1920:1440:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.40:3:3:0.0,eq=saturation=1.18:contrast=1.08:brightness=-0.01,pad=2560:1440:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else if (g_rec_render_mode == 1) {
            // 模式 1: 📺 CRT 顯像管等比光柵 (6x Prescale + 像素對齊光柵 + Lanczos 2K)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=iw*6:ih*6:flags=neighbor,drawgrid=width=iw:height=6:thickness=2:color=black@0.28,scale=1920:1440:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.45:3:3:0.0,eq=saturation=1.08:contrast=1.03,pad=2560:1440:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else if (g_rec_render_mode == 2) {
            // 模式 2: ⚡ 刀鋒無損硬點陣 (6x Prescale + Lanczos 2K + 0.65 刀鋒電競銳化)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=iw*6:ih*6:flags=neighbor,scale=1920:1440:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.65:3:3:0.0,eq=saturation=1.08:contrast=1.03,pad=2560:1440:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else {
            // 模式 3: 🕹️ 柔和雙立方抗鋸齒 (Bicubic 2K 平滑縮放)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=1920:1440:flags=bicubic+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,eq=saturation=1.08:contrast=1.03,pad=2560:1440:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        }
    } else {
        // 【A3. 1080P 全高清 (1920x1080，等比居中 1440x1080 + 兩側補黑邊各 240px)】
        if (g_rec_render_mode == 0) {
            // 模式 0: 🕹️ 原廠 AdvanceMAME Scale3x + 像素列對齊掃描線 + Lanczos 無波紋二段縮放 [原廠 1:1 復刻升級版]
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"epx=n=3,drawgrid=width=iw:height=3:thickness=1:color=black@0.26,scale=1440:1080:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.35:3:3:0.0,eq=saturation=1.18:contrast=1.08:brightness=-0.01,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else if (g_rec_render_mode == 1) {
            // 模式 1: 📺 CRT 顯像管等比光柵 (4x Prescale + 像素對齊光柵 + Lanczos + 微銳化)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=iw*4:ih*4:flags=neighbor,drawgrid=width=iw:height=4:thickness=1:color=black@0.28,scale=1440:1080:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.4:3:3:0.0,eq=saturation=1.08:contrast=1.03,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else if (g_rec_render_mode == 2) {
            // 模式 2: ⚡ 刀鋒無損硬點陣 (4x Prescale + Lanczos + 0.6 刀鋒電競銳化)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=iw*4:ih*4:flags=neighbor,scale=1440:1080:flags=lanczos+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,unsharp=3:3:0.6:3:3:0.0,eq=saturation=1.08:contrast=1.03,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        } else {
            // 模式 3: 🕹️ 柔和雙立方抗鋸齒 (Bicubic 平滑縮放)
            snprintf(fullVfOpt, sizeof(fullVfOpt), "-vf \"scale=1440:1080:flags=bicubic+accurate_rnd+full_chroma_int+full_chroma_inp:out_color_matrix=bt709,eq=saturation=1.08:contrast=1.03,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:black%s\"", osdFilter);
        }
    }

    int use_nvenc = DetectNvencSupport(g_rec_ffmpeg_path);
    const char* enc_opts = use_nvenc ?
        "-c:v h264_nvenc -preset p5 -tune hq -rc vbr -cq 16 -b:v 0 -g 60 -pix_fmt yuv420p -colorspace bt709 -color_primaries bt709 -color_trc bt709" :
        "-c:v libx264 -preset fast -crf 16 -aq-mode 2 -g 60 -pix_fmt yuv420p -colorspace bt709 -color_primaries bt709 -color_trc bt709";

    snprintf(cmdLine, sizeof(cmdLine),
        "\"%s\" -y "
        "-probesize 32 -analyzeduration 0 "
        "-f rawvideo -pixel_format bgra -video_size %dx%d -framerate %.4f -i %s "
        "%s "
        "%s "
        "-an \"%s\"",
        g_rec_ffmpeg_path, w, h, real_fps, g_rec_pipe_v_name, fullVfOpt, enc_opts, g_rec_temp_v_mp4);

    LogRec("Spawning Enhanced Single-Pipe FFmpeg: %s", cmdLine);

    char ffLogPath[MAX_PATH];
    snprintf(ffLogPath, sizeof(ffLogPath), "%sffmpeg_run.log", g_module_dir);
    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hLog = CreateFileA(ffLogPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | (hLog != INVALID_HANDLE_VALUE ? STARTF_USESTDHANDLES : 0);
    si.wShowWindow = SW_HIDE;
    if (hLog != INVALID_HANDLE_VALUE) {
        si.hStdOutput = hLog;
        si.hStdError = hLog;
    }

    memset(&g_ffmpeg_pi, 0, sizeof(g_ffmpeg_pi));
    BOOL cp_ok = CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &g_ffmpeg_pi);
    if (hLog != INVALID_HANDLE_VALUE) CloseHandle(hLog);
    if (!cp_ok) {
        DWORD err = GetLastError();
        LogRec("CRITICAL: Failed to spawn FFmpeg process! err=%lu, cmdLine=%s", err, cmdLine);
        StopNativeRecording("SPAWN_FFMPEG_FAIL");
        return;
    }

    if (!cp_ok) {
        LogRec("ERROR: CreateProcess failed for FFmpeg! Err=%lu", GetLastError());
        CloseHandle(g_hPipeVideo); g_hPipeVideo = INVALID_HANDLE_VALUE;
        if (g_hAudioFile != INVALID_HANDLE_VALUE) { CloseHandle(g_hAudioFile); g_hAudioFile = INVALID_HANDLE_VALUE; }
        return;
    }

    g_bNativeRecording = 1;
    LogRec("Route A with Partner Enhancements successfully started!");
    EnableTurboFullRender(1);
}

__declspec(dllexport) int lua_poll_gui_cmd(void* L) {
    if (!p_lua_pushinteger) InitRealDll();
    if (!p_lua_pushinteger || !L) return 0;

    int cmd_code = 0;
    int cmd_val  = 0;

    static char cmd_path[MAX_PATH] = {0};
    if (!cmd_path[0]) {
        snprintf(cmd_path, sizeof(cmd_path), "%sscripts\\ipc_cmd.txt", g_module_dir);
    }

    // 【極速空檔案短路】：先由系統快取檢查檔案大小，若為 0 bytes 則直接返回，徹底消除每秒數百次 fopen/fclose！
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(cmd_path, GetFileExInfoStandard, &fad) ||
        (fad.nFileSizeLow == 0 && fad.nFileSizeHigh == 0)) {
        p_lua_pushinteger(L, 0);
        p_lua_pushinteger(L, 0);
        return 2;
    }

    int need_clear_file = 0;
    FILE* fp = fopen(cmd_path, "r");
    if (fp) {
        char buf[512] = {0};
        if (fgets(buf, sizeof(buf) - 1, fp)) {
            if (strncmp(buf, "REC_START ", 10) == 0) {
                int s_f = 0, e_f = 0, sc_m = 0;
                char* rest = NULL;
                if (sscanf(buf + 10, "%d %d %d", &s_f, &e_f, &sc_m) == 3) {
                    rest = buf + 10;
                    for (int i = 0; i < 3; i++) {
                        while (*rest && *rest != ' ') rest++;
                        while (*rest && *rest == ' ') rest++;
                    }
                    char* pipe_sep = strchr(rest, '|');
                    if (pipe_sep) {
                        *pipe_sep = '\0';
                        char* ff_p = rest;
                        char* out_p = pipe_sep + 1;
                        char* nl = strpbrk(out_p, "\r\n");
                        if (nl) *nl = '\0';
                        if (s_f <= 0) s_f = 30; // 街機開局錨點保護
                        char* p1_name = "Player 1";
                        char* p2_name = "Player 2";
                        int show_osd = 1;
                        char* osd_sep = NULL;
                        char* p1_sep = strchr(out_p, '|');
                        if (p1_sep) {
                            *p1_sep = '\0';
                            p1_name = p1_sep + 1;
                            char* p2_sep = strchr(p1_name, '|');
                            if (p2_sep) {
                                *p2_sep = '\0';
                                p2_name = p2_sep + 1;
                                osd_sep = strchr(p2_name, '|');
                                if (osd_sep) {
                                    *osd_sep = '\0';
                                    show_osd = atoi(osd_sep + 1);
                                }
                            }
                        }
                        char* nl1 = strpbrk(p1_name, "\r\n"); if (nl1) *nl1 = '\0';
                        char* nl2 = strpbrk(p2_name, "\r\n"); if (nl2) *nl2 = '\0';

                        if (osd_sep) {
                            char* r1_sep = strchr(osd_sep + 1, '|');
                            if (r1_sep) {
                                *r1_sep = '\0';
                                char* r1_val = r1_sep + 1;
                                char* r2_sep = strchr(r1_val, '|');
                                if (r2_sep) {
                                    *r2_sep = '\0';
                                    char* r2_val = r2_sep + 1;
                                    char* ft_sep = strchr(r2_val, '|');
                                    if (ft_sep) {
                                        *ft_sep = '\0';
                                        char* ft_val = ft_sep + 1;
                                        char* tb_sep = strchr(ft_val, '|');
                                        if (tb_sep) {
                                            *tb_sep = '\0';
                                            char* tb_val = tb_sep + 1;
                                            char* rm_sep = strchr(tb_val, '|');
                                            if (rm_sep) {
                                                *rm_sep = '\0';
                                                char* rm_val = rm_sep + 1;
                                                g_rec_render_mode = atoi(rm_val);
                                                g_rec_res_mode = sc_m;
                                            } else {
                                                // 舊版指令相容邏輯 (0=1080柔和, 1=1080光柵, 2=1080刀鋒, 3=1x原生)
                                                if (sc_m == 3) { g_rec_res_mode = 1; g_rec_render_mode = 2; }
                                                else if (sc_m == 1) { g_rec_res_mode = 3; g_rec_render_mode = 1; }
                                                else if (sc_m == 2) { g_rec_res_mode = 3; g_rec_render_mode = 2; }
                                                else { g_rec_res_mode = 3; g_rec_render_mode = 0; }
                                            }
                                            g_rec_is_turbo = atoi(tb_val);
                                        } else {
                                            g_rec_is_turbo = 0;
                                            if (sc_m == 3) { g_rec_res_mode = 1; g_rec_render_mode = 2; }
                                            else { g_rec_res_mode = 3; g_rec_render_mode = 1; }
                                        }
                                        strncpy(g_rec_match_ft, ft_val, sizeof(g_rec_match_ft) - 1);
                                        g_rec_match_ft[sizeof(g_rec_match_ft) - 1] = '\0';
                                        g_rec_scale_mode = g_rec_res_mode;
                                    } else {
                                        g_rec_is_turbo = 0;
                                    }
                                    strncpy(g_rec_p2_rank, r2_val, sizeof(g_rec_p2_rank) - 1);
                                    g_rec_p2_rank[sizeof(g_rec_p2_rank) - 1] = '\0';
                                }
                                strncpy(g_rec_p1_rank, r1_val, sizeof(g_rec_p1_rank) - 1);
                                g_rec_p1_rank[sizeof(g_rec_p1_rank) - 1] = '\0';
                            }
                        }

                        StartNativeRecording(s_f, e_f, sc_m, ff_p, out_p, p1_name, p2_name, show_osd);
                        cmd_code = 1; // 確保一定清空 ipc_cmd.txt 並執行 Seek
                        cmd_val  = s_f;
                    }
                }
            } else if (strncmp(buf, "REC_STOP", 8) == 0) {
                StopNativeRecording("IPC_REC_STOP");
                need_clear_file = 1;
            } else if (strncmp(buf, "PROBE_EOF", 9) == 0) {
                cmd_code = 5;
                cmd_val  = 0;
            } else if (strncmp(buf, "FFWD", 4) == 0) {
                cmd_code = 6;
                cmd_val  = 0;
            } else if (strncmp(buf, "SEEK ", 5) == 0) {
                cmd_code = 1;
                cmd_val  = atoi(buf + 5);
            } else if (strncmp(buf, "PAUSE", 5) == 0) {
                cmd_code = 2;
                cmd_val  = 0;
            } else if (strncmp(buf, "DELTA ", 6) == 0) {
                cmd_code = 3;
                cmd_val  = atoi(buf + 6);
            } else if (strncmp(buf, "PCT ", 4) == 0) {
                cmd_code = 4;
                cmd_val  = atoi(buf + 4);
            }
        }
        fclose(fp);
        if (cmd_code != 0 || need_clear_file) {
            if (cmd_code == 1 || cmd_code == 3 || cmd_code == 4 || cmd_code == 5 || cmd_code == 6) {
                g_bManualPaused = FALSE;
            }
            FILE* fpw = fopen(cmd_path, "w");
            if (fpw) fclose(fpw);
        }
    }

    p_lua_pushinteger(L, cmd_code);
    p_lua_pushinteger(L, cmd_val);
    return 2;
}

__declspec(dllexport) int lua_is_turbo_rec(void* L) {
    if (!p_lua_pushinteger) InitRealDll();
    if (!p_lua_pushinteger || !L) return 0;
    int active = (g_bNativeRecording && g_rec_is_turbo && g_rec_has_reached_start) ? 1 : 0;
    p_lua_pushinteger(L, active);
    return 1;
}

__declspec(dllexport) int lua_update_gui_state(void* L) {
    if (!p_lua_tointeger) return 0;

    int cur_f    = (int)p_lua_tointeger(L, 1);
    int max_f    = (int)p_lua_tointeger(L, 2);
    int is_eof   = (int)p_lua_tointeger(L, 3);
    int state_c  = (int)p_lua_tointeger(L, 4);
    int target_f = (int)p_lua_tointeger(L, 5);
    int lua_w    = (int)p_lua_tointeger(L, 6);
    int lua_h    = (int)p_lua_tointeger(L, 7);
    int force_fl = (p_lua_gettop && p_lua_gettop(L) >= 8) ? (int)p_lua_tointeger(L, 8) : 0;
    if (lua_w > 0 && lua_h > 0) {
        g_game_width = lua_w;
        g_game_height = lua_h;
        if (!g_bNativeRecording) {
            g_rec_width = lua_w;
            g_rec_height = lua_h;
        }
    } else if (!g_bNativeRecording) {
        int dw = 0, dh = 0;
        DetectGameResolution(&dw, &dh);
        g_game_width = dw;
        g_game_height = dh;
        g_rec_width = dw;
        g_rec_height = dh;
    }

    g_last_lua_state_tick = GetTickCount();
    g_rec_last_cur_frame = cur_f;

    if (g_bNativeRecording) {
        if (!g_rec_has_reached_start) {
            int ready = g_rec_is_turbo ? (cur_f >= g_rec_start_frame) : (state_c == 0 && cur_f >= g_rec_start_frame);
            if (ready) {
                g_rec_has_reached_start = 1;
                LogRec("Playback reached start frame (cur_f=%d >= start=%d, state=%d, turbo=%d), streaming active!", cur_f, g_rec_start_frame, state_c, g_rec_is_turbo);
            }
        }

        if (g_rec_has_reached_start && g_exe_base) {
            // 1. 視訊單管道傳輸 (60 FPS 幀幀直通)；只有「真的寫入成功」才算一幀
            int vid_ok = 0;
            int d_w = g_rec_width;
            int d_h = g_rec_height;
            int d_bpp = *(int*)GetHostPtrByVa(0x03173bb0);
            const void* d_pDraw = *(const void**)GetHostPtrByVa(0x03173bb4);
            if (g_bPipeVConnected) {
                int w = d_w;
                int h = d_h;
                int bpp = d_bpp;
                int maskType = *(int*)GetHostPtrByVa(0x03173bac);
                const void* pDraw = d_pDraw;

                if (pDraw && w > 0 && h > 0 && (bpp == 2 || bpp == 4)) {
                    // 【精確行跨距】直接讀取 FBNeo 核心 nBurnPitch (0x03173b98)
                    // CPS3 (384x224): 384 * 2 = 768 bytes; NeoGeo (320x224): 320 * 2 = 640 bytes
                    int pitch = *(int*)GetHostPtrByVa(0x03173b98);
                    if (pitch <= 0 || pitch < w * (bpp == 4 ? 4 : 2)) {
                        pitch = w * (bpp == 4 ? 4 : 2);
                    }
                    size_t req_bytes = (size_t)w * h * 4;
                    size_t src_req_bytes = (size_t)pitch * (h > 0 ? (h - 1) : 0) + (size_t)w * (bpp == 4 ? 4 : 2);

                    if (g_rec_bgra_cap < req_bytes) {
                        if (g_rec_bgra_buf) free(g_rec_bgra_buf);
                        g_rec_bgra_buf = (uint32_t*)malloc(req_bytes);
                        g_rec_bgra_cap = req_bytes;
                    }

                    if (g_rec_bgra_buf) {
                        // 【金鐘罩防護】：嚴格驗證 pDraw 包含 row-pitch 的完整可讀記憶體頁面
                        // 徹底解決 CPS1/2/3 顯存行跨距錯位導致的花屏！
                        if (!IsBadReadPtr(pDraw, src_req_bytes)) {
                            ConvertToBGRA32(pDraw, g_rec_bgra_buf, w, h, pitch, bpp, maskType);
                        } else {
                            // 瞬態記憶體未就緒 (如 Seek/轉場瞬間)：填入純黑畫面，保證串流時間軸絕對連續不掉幀
                            memset(g_rec_bgra_buf, 0, req_bytes);
                            for (size_t px = 0; px < (size_t)w * h; px++) {
                                g_rec_bgra_buf[px] = 0xFF000000;
                            }
                        }

                        // 繪製頂部比賽 OSD 資訊浮層 (即時動態比分與雙選手 ID)
                        // g_rec_show_osd: 0=關閉, 1=原汁原味細字 (Scale 1), 2=原汁原味大粗字 (Scale 2)
                        // 100% 比照 Fightcade 原廠色彩與排版: 白色選手ID + 亮青色比分 + 白色 vs (1px 純黑硬陰影，無黑條)
                        if (((g_rec_res_mode == 1 && g_rec_show_osd != 0) || g_rec_show_osd == 2) && g_rec_bgra_buf) { // 原生解析度或顯式選點陣時自動採用 8x8 精準點陣
                            int scale = 1;
                            int p1_score = 0, p2_score = 0;
                            int* pScoreP1 = (int*)GetHostPtrByVa(0x03183210);
                            int* pScoreP2 = (int*)GetHostPtrByVa(0x03183214);
                            if (pScoreP1 && pScoreP2 && !IsBadReadPtr(pScoreP1, 4) && !IsBadReadPtr(pScoreP2, 4)) {
                                p1_score = *pScoreP1;
                                p2_score = *pScoreP2;
                            }

                            // 自動原生感測 1P 與 2P 選手名稱 (免手動輸入)
                            char p1_name[64], p2_name[64];
                            SafeGetPlayerName(0x0202FEB8, p1_name, sizeof(p1_name), g_rec_p1_name);
                            SafeGetPlayerName(0x0202F080, p2_name, sizeof(p2_name), g_rec_p2_name);

                            // 原廠配色定義 (取樣自官方 FBNeo 畫面)
                            uint32_t col_gold   = 0xFFFDB813; // 亮金色 (賽制 FT)
                            uint32_t col_white  = 0xFFFFFFFF; // 純白色 (選手 ID)
                            uint32_t col_cyan   = 0xFF33F1E5; // 原廠經典亮青藍色 (比分數字)
                            uint32_t col_shadow = 0xFF000000; // 1px 純黑立體硬陰影
                            int top_y = 2;

                            char s1[16], s2[16];
                            snprintf(s1, sizeof(s1), "%d", p1_score);
                            snprintf(s2, sizeof(s2), "%d", p2_score);

                            // 官方真實段位等級感測: *(int*)0x02030828 (1P) 與 *(int*)0x0202F9F0 (2P)
                            // 官方 7 大段位色彩 (0xAARRGGBB):
                            // 0: ?, 1: E (0xC27A3F), 2: D (0xB3B2B0), 3: C (0xF3C84A), 4: B (0x00A9DA), 5: A (0xA047B2), 6: S (0xE54875)
                            static const char* s_rank_names[] = { "?", "E", "D", "C", "B", "A", "S" };
                            static const uint32_t s_rank_bgra[] = {
                                0xFF757575, // 0: ?
                                0xFFC27A3F, // 1: E (古銅)
                                0xFFB3B2B0, // 2: D (白銀)
                                0xFFF3C84A, // 3: C (亮金)
                                0xFF00A9DA, // 4: B (天藍)
                                0xFFA047B2, // 5: A (紫晶)
                                0xFFE54875  // 6: S (赤紅)
                            };

                            int r1_idx = 0, r2_idx = 0;
                            int* pR1 = (int*)GetHostPtrByVa(0x02030828);
                            int* pR2 = (int*)GetHostPtrByVa(0x0202F9F0);
                            if (pR1 && !IsBadReadPtr(pR1, 4)) r1_idx = *pR1;
                            if (pR2 && !IsBadReadPtr(pR2, 4)) r2_idx = *pR2;
                            if (r1_idx < 0 || r1_idx > 6) r1_idx = 0;
                            if (r2_idx < 0 || r2_idx > 6) r2_idx = 0;

                            char r1_buf[16] = {0};
                            char r2_buf[16] = {0};
                            uint32_t col_r1 = 0xFFF3C84A;
                            uint32_t col_r2 = 0xFF00A9DA;

                            // 1P 段位: 優先從記憶體自動感測；若無且未手動指定有效段位，則完全不顯示（嚴格過濾 NONE / AUTO）
                            if (r1_idx > 0) {
                                snprintf(r1_buf, sizeof(r1_buf), "[%s]", s_rank_names[r1_idx]);
                                col_r1 = s_rank_bgra[r1_idx];
                            } else if (g_rec_p1_rank[0] && _stricmp(g_rec_p1_rank, "NONE") != 0 && _stricmp(g_rec_p1_rank, "AUTO") != 0 && _stricmp(g_rec_p1_rank, "?") != 0) {
                                snprintf(r1_buf, sizeof(r1_buf), "[%s]", g_rec_p1_rank);
                            }

                            // 2P 段位: 同理嚴格過濾
                            if (r2_idx > 0) {
                                snprintf(r2_buf, sizeof(r2_buf), "[%s]", s_rank_names[r2_idx]);
                                col_r2 = s_rank_bgra[r2_idx];
                            } else if (g_rec_p2_rank[0] && _stricmp(g_rec_p2_rank, "NONE") != 0 && _stricmp(g_rec_p2_rank, "AUTO") != 0 && _stricmp(g_rec_p2_rank, "?") != 0) {
                                snprintf(r2_buf, sizeof(r2_buf), "[%s]", g_rec_p2_rank);
                            }

                            const char* ft_str = (g_rec_match_ft[0] ? g_rec_match_ft : "vs");

                            int r1_l = (int)strlen(r1_buf);
                            int r2_l = (int)strlen(r2_buf);
                            int ft_l = (int)strlen(ft_str);
                            int p1_l = (int)strlen(p1_name);
                            int p2_l = (int)strlen(p2_name);
                            int s1_l = (int)strlen(s1);
                            int s2_l = (int)strlen(s2);

                            // 動態居中排版計算 (無段位時不佔寬度，徹底消除 NONE 且保證完美對稱居中)
                            int total_chars = 0;
                            if (r1_l > 0) total_chars += (r1_l + 1); // "[C] "
                            total_chars += p1_l + 2;                // "P1  "
                            total_chars += s1_l + 2;                // "0  "
                            total_chars += ft_l + 2;                // "FT10  " 或 "vs  "
                            total_chars += s2_l + 2;                // "0  "
                            total_chars += p2_l;                    // "P2"
                            if (r2_l > 0) total_chars += (1 + r2_l);// " [B]"

                            int start_x = (w - total_chars * 8 * scale) / 2;
                            if (start_x < 2) start_x = 2;

                            int cur_x = start_x;
                            // 1. 1P 等級徽章 (若有才繪製)
                            if (r1_l > 0) {
                                DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, r1_buf, col_r1, col_shadow, scale);
                                cur_x += (r1_l + 1) * 8 * scale;
                            }

                            // 2. 1P 選手 ID (純白色)
                            DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, p1_name, col_white, col_shadow, scale);
                            cur_x += (p1_l + 2) * 8 * scale;

                            // 3. 1P 比數 (亮青色)
                            DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, s1, col_cyan, col_shadow, scale);
                            cur_x += (s1_l + 2) * 8 * scale;

                            // 4. 原廠賽制標記 (亮金色 FT10 或 vs)
                            DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, ft_str, col_gold, col_shadow, scale);
                            cur_x += (ft_l + 2) * 8 * scale;

                            // 5. 2P 比數 (亮青色)
                            DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, s2, col_cyan, col_shadow, scale);
                            cur_x += (s2_l + 2) * 8 * scale;

                            // 6. 2P 選手 ID (純白色)
                            DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, p2_name, col_white, col_shadow, scale);
                            cur_x += p2_l * 8 * scale;

                            // 7. 2P 等級徽章 (若有才繪製)
                            if (r2_l > 0) {
                                cur_x += 1 * 8 * scale;
                                DrawStringBGRA(g_rec_bgra_buf, w, h, cur_x, top_y, r2_buf, col_r2, col_shadow, scale);
                            }
                        }

                        DWORD dwWritten = 0;
                        if (!WriteFile(g_hPipeVideo, g_rec_bgra_buf, (DWORD)req_bytes, &dwWritten, NULL)) {
                            LogRec("WriteFile video failed err=%lu", GetLastError());
                            StopNativeRecording("WRITE_VIDEO_FAIL");
                        } else {
                            vid_ok = 1;
                        }
                    }
                }
            }

            // 2. 音訊極速循序寫入 temp_a.wav (每秒僅 176 KB，極致輕量無死鎖)
            if (vid_ok && g_hAudioFile != INVALID_HANDLE_VALUE) {
                const short* pSound = *(const short**)GetHostPtrByVa(0x03172bb8);
                int soundLen = *(int*)GetHostPtrByVa(0x03121af8);
                DWORD sz = (DWORD)(soundLen * 4);
                // 【金鐘罩防護】：驗證音訊緩衝區可讀性，防止野指標崩潰
                if (pSound && soundLen > 0 && soundLen < 8192 && !IsBadReadPtr(pSound, sz)) {
                    DWORD dwWritten = 0;
                    WriteFile(g_hAudioFile, pSound, sz, &dwWritten, NULL);
                    g_rec_audio_bytes += dwWritten;
                } else {
                    static short s_silence[735 * 2] = {0};
                    DWORD dwWritten = 0;
                    WriteFile(g_hAudioFile, s_silence, sizeof(s_silence), &dwWritten, NULL);
                    g_rec_audio_bytes += sizeof(s_silence);
                }
            }

            g_rec_attempts++;
            if (vid_ok) g_rec_frames_written++;
            if (g_rec_attempts <= 5 || g_rec_attempts % 60 == 0) {
                LogRec("DIAG attempt=%d ok=%d written=%d | pipeV=%d w=%d h=%d bpp=%d pDraw=%p | cur_f=%d state=%d",
                    g_rec_attempts, vid_ok, g_rec_frames_written, (int)g_bPipeVConnected, d_w, d_h, d_bpp, d_pDraw, cur_f, state_c);
            }
            if (g_bNativeRecording && g_rec_attempts >= 300 && g_rec_frames_written == 0) {
                LogRec("ABORT: 300 attempts but 0 video frames written (pipeV=%d pDraw=%p bpp=%d). Video source unavailable.",
                    (int)g_bPipeVConnected, d_pDraw, d_bpp);
                StopNativeRecording("NO_VIDEO_DATA");
            }
            if (g_bNativeRecording && vid_ok) {

                if (g_rec_frames_written <= 5 || g_rec_frames_written % 60 == 0) {
                    int quota = g_rec_is_full ? 0 : (g_rec_end_frame - g_rec_start_frame);
                    int dbg_sl = *(int*)GetHostPtrByVa(0x03121af8);
                    const void* dbg_ps = *(const void**)GetHostPtrByVa(0x03172bb8);
                    LogRec("Recording in progress: written=%d / %d quota (cur_f=%d, audio_bytes=%lu, soundLen=%d, pSound=%p)",
                        g_rec_frames_written, quota, cur_f, g_rec_audio_bytes, dbg_sl, dbg_ps);
                }

                if (g_rec_is_full) {
                    if (is_eof == 1 && cur_f >= max_f - 2 && g_rec_frames_written >= 30) {
                        LogRec("Full match reached EOF, finalizing recording (written=%d).", g_rec_frames_written);
                        StopNativeRecording("FULL_EOF");
                    }
                } else {
                    int target_quota = g_rec_end_frame - g_rec_start_frame;
                    if (target_quota <= 0) target_quota = 600;

                    if (g_rec_frames_written >= target_quota) {
                        LogRec("Clip fulfilled absolute frame quota (%d >= %d), finalizing recording.",
                            g_rec_frames_written, target_quota);
                        StopNativeRecording("CLIP_END");
                    }
                }
            }
        }
    }

    // 正常播放每 15 幀寫入一次；快進/探底狂奔 (state_c == 2) 時每 60 幀 (約 0.1 秒) 寫入一次；
    // 若狀態改變 (如撞尾/暫停/啟動快進) 或收到 force_fl 則當幀 100% 立即落盤！
    int write_interval = (state_c == 2) ? 60 : 15;
    static int s_last_state_c = -1;
    static int s_last_is_eof  = -1;
    int state_changed = (state_c != s_last_state_c) || (is_eof != s_last_is_eof);
    s_last_state_c = state_c;
    s_last_is_eof  = is_eof;

    if (force_fl || state_changed || (cur_f % write_interval == 0) || g_rec_state_dirty || (g_bNativeRecording && g_rec_frames_written % 5 == 0)) {
        g_rec_state_dirty = 0;
        static char st_path[MAX_PATH] = {0};
        if (!st_path[0]) {
            snprintf(st_path, sizeof(st_path), "%sscripts\\ipc_state.txt", g_module_dir);
        }

        FILE* fp = fopen(st_path, "w");
        if (fp) {
            fprintf(fp, "%d %d %d %d %d %d %d\n", cur_f, max_f, is_eof, state_c, target_f, g_bNativeRecording, g_rec_frames_written);
            fclose(fp);
        }
    }
    return 0;
}

// ============================================================================
// 進程內原生音訊控制器 (In-Process Native Audio Session Controller)
// 100% 零跨進程枚舉、零驅動相依性、零註冊表殘留，標準 COM DirectSound/WASAPI 控制
// ============================================================================
#define CLSCTX_INPROC_SERVER 1

static const GUID CLSID_MMDeviceEnumerator_Val = {
    0xBCDE0395, 0xE52F, 0x467C, {0x8E, 0x3D, 0xC4, 0x57, 0x92, 0x91, 0x69, 0x2E}
};
static const GUID IID_IMMDeviceEnumerator_Val = {
    0xA95664D2, 0x9614, 0x4F35, {0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6}
};
static const GUID IID_IAudioSessionManager_Val = {
    0xBFA971F1, 0x4D5E, 0x40BB, {0x93, 0x5E, 0x96, 0x70, 0x39, 0xBF, 0xBE, 0xE4}
};

typedef enum { eRender_Aud = 0, eCapture_Aud = 1, eAll_Aud = 2 } EDataFlow_Aud;
typedef enum { eConsole_Aud = 0, eMultimedia_Aud = 1, eCommunications_Aud = 2 } ERole_Aud;

typedef struct IMMDeviceEnumerator_AudVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, const GUID *riid, void **ppvObject);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *EnumAudioEndpoints)(void *This, EDataFlow_Aud dataFlow, DWORD dwStateMask, void **ppDevices);
    HRESULT (STDMETHODCALLTYPE *GetDefaultAudioEndpoint)(void *This, EDataFlow_Aud dataFlow, ERole_Aud role, void **ppEndpoint);
} IMMDeviceEnumerator_AudVtbl;

typedef struct IMMDevice_AudVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, const GUID *riid, void **ppvObject);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *Activate)(void *This, const GUID *iid, DWORD dwClsCtx, void *pActivationParams, void **ppInterface);
} IMMDevice_AudVtbl;

typedef struct IAudioSessionManager_AudVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, const GUID *riid, void **ppvObject);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *GetAudioSessionControl)(void *This, const GUID *AudioSessionGuid, DWORD StreamFlags, void **AudioSessionControl);
    HRESULT (STDMETHODCALLTYPE *GetSimpleAudioVolume)(void *This, const GUID *AudioSessionGuid, DWORD StreamFlags, void **AudioVolume);
} IAudioSessionManager_AudVtbl;

typedef struct ISimpleAudioVolume_AudVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, const GUID *riid, void **ppvObject);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *SetMasterVolume)(void *This, float fLevel, const GUID *EventContext);
    HRESULT (STDMETHODCALLTYPE *GetMasterVolume)(void *This, float *pfLevel);
    HRESULT (STDMETHODCALLTYPE *SetMute)(void *This, const BOOL bMute, const GUID *EventContext);
    HRESULT (STDMETHODCALLTYPE *GetMute)(void *This, BOOL *pbMute);
} ISimpleAudioVolume_AudVtbl;

typedef struct { struct IMMDeviceEnumerator_AudVtbl *lpVtbl; } IAudMMDeviceEnumerator;
typedef struct { struct IMMDevice_AudVtbl *lpVtbl; } IAudMMDevice;
typedef struct { struct IAudioSessionManager_AudVtbl *lpVtbl; } IAudAudioSessionManager;
typedef struct { struct ISimpleAudioVolume_AudVtbl *lpVtbl; } IAudSimpleAudioVolume;

typedef HRESULT (WINAPI *pfn_AudCoInitialize)(LPVOID);
typedef void    (WINAPI *pfn_AudCoUninitialize)(void);
typedef HRESULT (WINAPI *pfn_AudCoCreateInstance)(const GUID*, void*, DWORD, const GUID*, void**);

static IAudSimpleAudioVolume* s_pSimpleAudioVolume = NULL;
static BOOL s_bAudioComInited = FALSE;
static BOOL s_bCurrentMuteState = FALSE;

static IAudSimpleAudioVolume* GetProcessAudioVolume(void) {
    if (s_pSimpleAudioVolume) return s_pSimpleAudioVolume;

    HMODULE hOle = GetModuleHandleA("ole32.dll");
    if (!hOle) hOle = LoadLibraryA("ole32.dll");
    if (!hOle) return NULL;

    pfn_AudCoInitialize pCoInit = (pfn_AudCoInitialize)GetProcAddress(hOle, "CoInitialize");
    pfn_AudCoCreateInstance pCoCreate = (pfn_AudCoCreateInstance)GetProcAddress(hOle, "CoCreateInstance");
    if (!pCoCreate) return NULL;

    if (!s_bAudioComInited && pCoInit) {
        pCoInit(NULL);
        s_bAudioComInited = TRUE;
    }

    IAudMMDeviceEnumerator* pEnum = NULL;
    HRESULT hr = pCoCreate(&CLSID_MMDeviceEnumerator_Val, NULL, CLSCTX_INPROC_SERVER,
                           &IID_IMMDeviceEnumerator_Val, (void**)&pEnum);
    if (SUCCEEDED(hr) && pEnum) {
        IAudMMDevice* pDevice = NULL;
        hr = pEnum->lpVtbl->GetDefaultAudioEndpoint(pEnum, eRender_Aud, eConsole_Aud, (void**)&pDevice);
        if (SUCCEEDED(hr) && pDevice) {
            IAudAudioSessionManager* pMgr = NULL;
            hr = pDevice->lpVtbl->Activate(pDevice, &IID_IAudioSessionManager_Val, CLSCTX_INPROC_SERVER, NULL, (void**)&pMgr);
            if (SUCCEEDED(hr) && pMgr) {
                IAudSimpleAudioVolume* pVol = NULL;
                hr = pMgr->lpVtbl->GetSimpleAudioVolume(pMgr, NULL, 0, (void**)&pVol);
                if (SUCCEEDED(hr) && pVol) {
                    s_pSimpleAudioVolume = pVol;
                }
                pMgr->lpVtbl->Release(pMgr);
            }
            pDevice->lpVtbl->Release(pDevice);
        }
        pEnum->lpVtbl->Release(pEnum);
    }
    return s_pSimpleAudioVolume;
}

static void SetProcessInternalMute(BOOL bMute) {
    s_bCurrentMuteState = bMute;
    IAudSimpleAudioVolume* pVol = GetProcessAudioVolume();
    if (pVol) {
        pVol->lpVtbl->SetMute(pVol, bMute, NULL);
    }
}

static void CleanupInternalAudio(void) {
    if (s_pSimpleAudioVolume) {
        s_pSimpleAudioVolume->lpVtbl->SetMute(s_pSimpleAudioVolume, FALSE, NULL);
        s_pSimpleAudioVolume->lpVtbl->Release(s_pSimpleAudioVolume);
        s_pSimpleAudioVolume = NULL;
    }
    if (s_bAudioComInited) {
        HMODULE hOle = GetModuleHandleA("ole32.dll");
        if (hOle) {
            pfn_AudCoUninitialize pCoUninit = (pfn_AudCoUninitialize)GetProcAddress(hOle, "CoUninitialize");
            if (pCoUninit) pCoUninit();
        }
        s_bAudioComInited = FALSE;
    }
}

__declspec(dllexport) int lua_set_audio_mute(void* L) {
    if (!p_lua_tointeger) InitRealDll();
    if (p_lua_tointeger && L) {
        int mute = (int)p_lua_tointeger(L, 1);
        SetProcessInternalMute(mute ? TRUE : FALSE);
    }
    return 0;
}



// ----------------------------------------------------------------------------
// 初始化模組目錄與寫入啟動日誌
// ----------------------------------------------------------------------------

// ============================================================================
// 自由對戰 / 排位 比分時光倒流同步 API (Score Timeline Synchronization)
// ============================================================================
typedef void (__fastcall *pfn_FBNeo_SetScores)(int p1, int p2);

// 讀取當前 FBNeo 檢測器比分整數 (p1, p2)
__declspec(dllexport) int lua_get_scores(void* L) {
    if (!p_lua_pushinteger) InitRealDll();
    if (!p_lua_pushinteger || !L) return 0;

    int p1 = 0;
    int p2 = 0;

    if (!g_exe_base) DetectExeBase();
    if (g_exe_base && g_exe_whitelist_matched) {
        int* pScoreP1 = (int*)(g_exe_base + 0x02D83210);
        int* pScoreP2 = (int*)(g_exe_base + 0x02D83214);
        static int s_score_ptrs_ok = 0;
        if (!s_score_ptrs_ok) {
            if (!IsBadReadPtr(pScoreP1, sizeof(int)) && !IsBadReadPtr(pScoreP2, sizeof(int))) {
                s_score_ptrs_ok = 1;
            }
        }
        if (s_score_ptrs_ok) {
            p1 = *pScoreP1;
            p2 = *pScoreP2;
        }
    }

    p_lua_pushinteger(L, p1);
    p_lua_pushinteger(L, p2);
    return 2;
}

// 設定當前 FBNeo 檢測器比分並立即刷新 UI 浮層
__declspec(dllexport) int lua_set_scores(void* L) {
    if (!p_lua_tointeger) InitRealDll();
    if (!p_lua_tointeger || !L) return 0;

    int p1 = (int)p_lua_tointeger(L, 1);
    int p2 = (int)p_lua_tointeger(L, 2);

    if (!g_exe_base) DetectExeBase();
    if (g_exe_base && g_exe_whitelist_matched) {
        int* pScoreP1 = (int*)(g_exe_base + 0x02D83210);
        int* pScoreP2 = (int*)(g_exe_base + 0x02D83214);
        pfn_FBNeo_SetScores pSetScores = (pfn_FBNeo_SetScores)(g_exe_base + 0x0020B0C0);

        if (!IsBadWritePtr(pScoreP1, sizeof(int)) && !IsBadWritePtr(pScoreP2, sizeof(int))) {
            *pScoreP1 = p1;
            *pScoreP2 = p2;
            if (pSetScores && !IsBadCodePtr((FARPROC)pSetScores)) {
                pSetScores(p1, p2);
            }
        }
    }
    return 0;
}

static void InitModuleDir(HINSTANCE hinstDLL) {
    g_my_dll_base = (uintptr_t)hinstDLL;
    DetectExeBase();
    char path[MAX_PATH] = {0};
    if (GetModuleFileNameA(hinstDLL, path, MAX_PATH)) {
        char szSha[65] = {0};
        CalcFileSHA256(path, szSha, sizeof(szSha));

        char* p = strrchr(path, '\\');
            if (p) {
                *(p + 1) = '\0';
                strncpy(g_module_dir, path, MAX_PATH - 1);
                snprintf(g_real_dll_path, sizeof(g_real_dll_path), "%sggponet_real.dll", g_module_dir);

                char env_buf[32] = {0};
                if (GetEnvironmentVariableA("FCADE_REWIND", env_buf, sizeof(env_buf)) > 0 && strcmp(env_buf, "1") == 0) {
                    g_bRewindModeActive = TRUE;
                } else {
                    char lua_chk[MAX_PATH] = {0};
                    snprintf(lua_chk, sizeof(lua_chk), "%sscripts\\rewind_core.lua", g_module_dir);
                    if (GetFileAttributesA(lua_chk) != INVALID_FILE_ATTRIBUTES) {
                        g_bRewindModeActive = TRUE;
                    }
                }

                ValidateExeWhitelist();

                // 清空上一場殘留的 IPC 指令與狀態檔
                {
                    char c_path[MAX_PATH] = {0};
                    snprintf(c_path, sizeof(c_path), "%sscripts\\ipc_cmd.txt", g_module_dir);
                    FILE* fc = fopen(c_path, "w");
                    if (fc) fclose(fc);

                    char s_path[MAX_PATH] = {0};
                    snprintf(s_path, sizeof(s_path), "%sscripts\\ipc_state.txt", g_module_dir);
                    FILE* fs = fopen(s_path, "w");
                    if (fs) {
                        fprintf(fs, "0 0 0 0 0\n");
                        fclose(fs);
                    }
                }

            char log_path[MAX_PATH] = {0};
            snprintf(log_path, sizeof(log_path), "%sproxy_key.log", g_module_dir);
            FILE* fp = fopen(log_path, "a");
            if (fp) {
                fprintf(fp, "\n=== [PROXY_GGPO LOADED] Version: %s | SHA256: %s | Build: %s | ExeBase: 0x%p | MyBase: 0x%p | RewindMode: %d | ExeWhitelist: %s ===\n",
                    GGPONET_PROXY_VERSION, szSha, PROXY_BUILD_TIMESTAMP, (void*)g_exe_base, (void*)g_my_dll_base, g_bRewindModeActive,
                    g_exe_whitelist_matched ? "MATCHED (0x668BA427)" : "MISMATCH (DISABLED)");
                fclose(fp);
            }

            char r_log_path[MAX_PATH] = {0};
            snprintf(r_log_path, sizeof(r_log_path), "%sscripts\\rewind_debug.log", g_module_dir);
            FILE* fpr = fopen(r_log_path, "a");
            if (fpr) {
                fprintf(fpr, "[PROXY_SELF_AUDIT] ggponet.dll %s | SHA256=%s | Build=%s | ExeWhitelist=%d | Path=%s\n",
                    GGPONET_PROXY_VERSION, szSha, PROXY_BUILD_TIMESTAMP, g_exe_whitelist_matched, path);
                fclose(fpr);
            }
        }
    }
}

// ----------------------------------------------------------------------------
// DllMain
// ----------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_main_tid = GetCurrentThreadId();
        InitModuleDir(hinstDLL);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        StopNativeRecording("DLL_DETACH"); CleanupInternalAudio(); if (g_rec_bgra_buf) { free(g_rec_bgra_buf); g_rec_bgra_buf = NULL; }
        if (lpvReserved == NULL && hReal) {
            FreeLibrary(hReal);
            hReal = NULL;
        }
    }
    return TRUE;
}
