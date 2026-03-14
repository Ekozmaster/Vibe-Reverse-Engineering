/*
 * DX9 Shader-to-FFP Proxy - Main Entry
 *
 * Generic template for converting shader-based DX9 games to fixed-function
 * pipeline rendering (primarily for RTX Remix compatibility).
 *
 * Chain loading order:
 *   Game EXE
 *     -> d3d9.dll (this proxy)
 *       -> d3d9_remix.dll (RTX Remix, if enabled in proxy.ini)
 *         -> system d3d9.dll
 *       -> system d3d9.dll (if Remix disabled)
 *
 * Users: copy this template, discover your game's specifics with the
 * analysis scripts and retools, then modify the proxy code to match.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* ---- Logging ---- */

static HANDLE g_logFile = INVALID_HANDLE_VALUE;

void log_open(void) {
    g_logFile = CreateFileA("ffp_proxy.log",
        GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void log_str(const char *s) {
    DWORD written;
    if (g_logFile != INVALID_HANDLE_VALUE) {
        int len = 0;
        while (s[len]) len++;
        WriteFile(g_logFile, s, len, &written, NULL);
    }
}

void log_hex(const char *prefix, unsigned int val) {
    char buf[64];
    const char *hex = "0123456789ABCDEF";
    int i, p = 0;
    while (prefix[p]) { buf[p] = prefix[p]; p++; }
    buf[p++] = '0'; buf[p++] = 'x';
    for (i = 7; i >= 0; i--)
        buf[p++] = hex[(val >> (i * 4)) & 0xF];
    buf[p++] = '\r'; buf[p++] = '\n'; buf[p] = 0;
    log_str(buf);
}

void log_floats(const char *prefix, float *data, unsigned int count) {
    char buf[16];
    const char *hex = "0123456789ABCDEF";
    unsigned int i, val;
    int j;
    log_str(prefix);
    for (i = 0; i < count; i++) {
        val = *(unsigned int*)&data[i];
        for (j = 7; j >= 0; j--)
            buf[j] = hex[(val >> ((7-j) * 4)) & 0xF];
        buf[8] = (i + 1 < count) ? ' ' : '\r';
        buf[9] = (i + 1 < count) ? '\0' : '\n';
        if (i + 1 < count) {
            buf[9] = '\0';
            log_str(buf);
        } else {
            buf[9] = '\n';
            buf[10] = '\0';
            log_str(buf);
        }
    }
}

void log_int(const char *prefix, int val) {
    char buf[64];
    int p = 0, start, end;
    while (prefix[p]) { buf[p] = prefix[p]; p++; }
    if (val < 0) { buf[p++] = '-'; val = -val; }
    if (val == 0) { buf[p++] = '0'; }
    else {
        start = p;
        while (val > 0) { buf[p++] = '0' + (val % 10); val /= 10; }
        end = p - 1;
        while (start < end) { char t = buf[start]; buf[start] = buf[end]; buf[end] = t; start++; end--; }
    }
    buf[p++] = '\r'; buf[p++] = '\n'; buf[p] = 0;
    log_str(buf);
}

void log_float_val(const char *prefix, float f) {
    unsigned int bits = *(unsigned int*)&f;
    log_hex(prefix, bits);
}

/* Write a single float as crude decimal: +/-NNNN.NN (no CRT) */
static void write_float_dec(float f) {
    char buf[24];
    int p = 0;
    unsigned int bits = *(unsigned int*)&f;
    int sign, biasedExp, exp;
    unsigned int mantissa, ipart, frac;

    if ((bits & 0x7F800000) == 0x7F800000) {
        if (bits & 0x007FFFFF) { log_str("NaN"); return; }
        log_str((bits & 0x80000000) ? "-Inf" : "Inf"); return;
    }
    if ((bits & 0x7FFFFFFF) == 0) { log_str((bits & 0x80000000) ? "-0.00" : "0.00"); return; }

    sign = (bits >> 31) & 1;
    biasedExp = (bits >> 23) & 0xFF;
    exp = biasedExp - 127;
    mantissa = (bits & 0x007FFFFF) | 0x00800000;

    if (sign) buf[p++] = '-';

    if (exp < 0) {
        ipart = 0;
    } else if (exp >= 23) {
        ipart = mantissa << (exp - 23);
    } else {
        ipart = mantissa >> (23 - exp);
    }

    if (exp < 0) {
        if (exp >= -8) {
            frac = (mantissa * 100) >> (23 - exp);
        } else {
            frac = 0;
        }
    } else if (exp < 23) {
        unsigned int fracBits = mantissa & ((1 << (23 - exp)) - 1);
        frac = (fracBits * 100) >> (23 - exp);
    } else {
        frac = 0;
    }
    if (frac > 99) frac = 99;

    if (ipart == 0) {
        buf[p++] = '0';
    } else {
        int start = p, end;
        unsigned int tmp = ipart;
        while (tmp > 0) { buf[p++] = '0' + (tmp % 10); tmp /= 10; }
        end = p - 1;
        while (start < end) { char t = buf[start]; buf[start] = buf[end]; buf[end] = t; start++; end--; }
    }
    buf[p++] = '.';
    buf[p++] = '0' + (frac / 10);
    buf[p++] = '0' + (frac % 10);
    buf[p] = '\0';
    log_str(buf);
}

void log_floats_dec(const char *prefix, float *data, unsigned int count) {
    unsigned int i;
    log_str(prefix);
    for (i = 0; i < count; i++) {
        write_float_dec(data[i]);
        if (i + 1 < count) log_str(" ");
    }
    log_str("\r\n");
}

void log_close(void) {
    if (g_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
}

/* ---- Forward declarations ---- */

typedef void* (__stdcall *PFN_Direct3DCreate9)(unsigned int);

static HMODULE g_realD3D9 = NULL;
static HMODULE g_preloadDLL = NULL;
static PFN_Direct3DCreate9 g_realDirect3DCreate9 = NULL;
HINSTANCE g_hInstance = NULL;

typedef struct WrappedD3D9 WrappedD3D9;
typedef struct WrappedDevice WrappedDevice;

/* From d3d9_wrapper.c */
WrappedD3D9* WrappedD3D9_Create(void* pRealD3D9);

/* Build the full path to a file in the same directory as our DLL */
static void get_dll_sibling_path(char *out, int outSize, const char *filename) {
    int i, lastSlash = -1, p;
    GetModuleFileNameA(g_hInstance, out, outSize);
    for (i = 0; out[i]; i++) {
        if (out[i] == '\\' || out[i] == '/') lastSlash = i;
    }
    p = (lastSlash >= 0) ? lastSlash + 1 : 0;
    for (i = 0; filename[i]; i++) out[p++] = filename[i];
    out[p] = '\0';
}

/* ---- Exported: Direct3DCreate9 ---- */

__declspec(dllexport) void* __stdcall Direct3DCreate9(unsigned int SDKVersion) {
    char pathBuf[MAX_PATH];
    char iniBuf[MAX_PATH];
    void *pReal;
    int useRemix = 0;

    if (!g_realD3D9) {
        log_open();
        log_str("=== DX9 Shader-to-FFP Proxy ===\r\n");

        /* Read proxy.ini from the same directory as this DLL */
        get_dll_sibling_path(iniBuf, MAX_PATH, "proxy.ini");
        useRemix = GetPrivateProfileIntA("Remix", "Enabled", 0, iniBuf);

        /*
         * PreloadDLL: load a DLL for its side effects (DllMain patches).
         * Used for game-fix wrappers that patch game memory at load time.
         * The DLL stays loaded but isn't in the D3D9 call chain.
         */
        {
            char preloadName[MAX_PATH];
            GetPrivateProfileStringA("Chain", "PreloadDLL", "",
                preloadName, MAX_PATH, iniBuf);
            if (preloadName[0]) {
                get_dll_sibling_path(pathBuf, MAX_PATH, preloadName);
                log_str("Preloading DLL: ");
                log_str(pathBuf);
                log_str("\r\n");
                g_preloadDLL = LoadLibraryA(pathBuf);
                if (g_preloadDLL) {
                    log_str("  Preload OK\r\n");
                } else {
                    log_str("  WARNING: Preload failed\r\n");
                }
            }
        }

        if (useRemix) {
            char remixDLL[MAX_PATH];
            GetPrivateProfileStringA("Remix", "DLLName", "d3d9_remix.dll",
                remixDLL, MAX_PATH, iniBuf);
            get_dll_sibling_path(pathBuf, MAX_PATH, remixDLL);
            log_str("Remix enabled, loading: ");
            log_str(pathBuf);
            log_str("\r\n");
            g_realD3D9 = LoadLibraryA(pathBuf);
            if (!g_realD3D9) {
                log_str("WARNING: Remix DLL not found, falling back to system d3d9.dll\r\n");
                useRemix = 0;
            }
        }

        if (!g_realD3D9) {
            GetSystemDirectoryA(pathBuf, MAX_PATH);
            {
                int i = 0;
                while (pathBuf[i]) i++;
                pathBuf[i++] = '\\';
                pathBuf[i++] = 'd'; pathBuf[i++] = '3'; pathBuf[i++] = 'd';
                pathBuf[i++] = '9'; pathBuf[i++] = '.'; pathBuf[i++] = 'd';
                pathBuf[i++] = 'l'; pathBuf[i++] = 'l'; pathBuf[i] = 0;
            }
            log_str("Loading system d3d9.dll: ");
            log_str(pathBuf);
            log_str("\r\n");
            g_realD3D9 = LoadLibraryA(pathBuf);
        }

        if (!g_realD3D9) {
            log_str("FATAL: Failed to load d3d9 backend\r\n");
            log_close();
            return NULL;
        }

        g_realDirect3DCreate9 = (PFN_Direct3DCreate9)GetProcAddress(g_realD3D9, "Direct3DCreate9");
        if (!g_realDirect3DCreate9) {
            log_str("FATAL: Direct3DCreate9 not found in loaded d3d9\r\n");
            log_close();
            return NULL;
        }
    }

    log_hex("Direct3DCreate9 called, SDK version: ", SDKVersion);

    pReal = g_realDirect3DCreate9(SDKVersion);
    if (!pReal) {
        log_str("ERROR: Real Direct3DCreate9 returned NULL\r\n");
        return NULL;
    }

    log_hex("Real IDirect3D9: ", (unsigned int)pReal);
    return (void*)WrappedD3D9_Create(pReal);
}

/* ---- DllMain ---- */

int __stdcall _DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        log_str("Proxy unloading\r\n");
        log_close();
        if (g_realD3D9) {
            FreeLibrary(g_realD3D9);
            g_realD3D9 = NULL;
        }
        if (g_preloadDLL) {
            FreeLibrary(g_preloadDLL);
            g_preloadDLL = NULL;
        }
    }
    return 1;
}

int _fltused = 0;
