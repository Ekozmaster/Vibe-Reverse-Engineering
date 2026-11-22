/*
 * D3D9 Frame Trace - Main Entry
 *
 * Chain loading order:
 *   Game EXE
 *     -> d3d9.dll (this trace proxy)
 *       -> [ChainDLL from proxy.ini] OR system d3d9.dll
 *
 * Uses CRT (stdio, string) since this is a diagnostic tool.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ---- Configuration ---- */

int g_cfgCaptureFrames = 2;
int g_cfgCaptureInit   = 1;

/* ---- Logging ---- */

static HANDLE g_logFile = INVALID_HANDLE_VALUE;

void log_open(void) {
    g_logFile = CreateFileA("dxtrace_proxy.log",
        GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

void log_str(const char *s) {
    DWORD written;
    if (g_logFile != INVALID_HANDLE_VALUE) {
        int len = (int)strlen(s);
        WriteFile(g_logFile, s, len, &written, NULL);
    }
}

void log_hex(const char *prefix, unsigned int val) {
    char buf[128];
    sprintf(buf, "%s0x%08X\r\n", prefix, val);
    log_str(buf);
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
static PFN_Direct3DCreate9 g_realDirect3DCreate9 = NULL;
HINSTANCE g_hInstance = NULL;

typedef struct WrappedD3D9 WrappedD3D9;
typedef struct TracedDevice TracedDevice;

/* From d3d9_trace_wrapper.c */
WrappedD3D9* WrappedD3D9_Create(void* pRealD3D9);

/* From d3d9_trace_device.c */
void TraceLock_Init(void);

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
    char chainDLL[MAX_PATH];
    void *pReal;

    if (!g_realD3D9) {
        log_open();
        log_str("=== D3D9 Frame Trace Proxy ===\r\n");

        get_dll_sibling_path(iniBuf, MAX_PATH, "proxy.ini");

        g_cfgCaptureFrames = GetPrivateProfileIntA("Trace", "CaptureFrames", 2, iniBuf);
        g_cfgCaptureInit   = GetPrivateProfileIntA("Trace", "CaptureInit", 1, iniBuf);

        {
            char buf[128];
            sprintf(buf, "Config: CaptureFrames=%d CaptureInit=%d\r\n",
                    g_cfgCaptureFrames, g_cfgCaptureInit);
            log_str(buf);
        }

        GetPrivateProfileStringA("Chain", "DLL", "",
            chainDLL, MAX_PATH, iniBuf);

        if (chainDLL[0]) {
            get_dll_sibling_path(pathBuf, MAX_PATH, chainDLL);
            log_str("Chain loading: ");
            log_str(pathBuf);
            log_str("\r\n");
            g_realD3D9 = LoadLibraryA(pathBuf);
            if (!g_realD3D9) {
                log_str("WARNING: Chain DLL not found, falling back to system d3d9.dll\r\n");
            }
        }

        if (!g_realD3D9) {
            GetSystemDirectoryA(pathBuf, MAX_PATH);
            strcat(pathBuf, "\\d3d9.dll");
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
            log_str("FATAL: Direct3DCreate9 not found\r\n");
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

    log_hex("Real IDirect3D9: ", (unsigned int)(size_t)pReal);
    return (void*)WrappedD3D9_Create(pReal);
}

/* ---- DllMain ---- */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_hInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        TraceLock_Init();
    }
    if (fdwReason == DLL_PROCESS_DETACH) {
        log_str("Trace proxy unloading\r\n");
        log_close();
        if (g_realD3D9) {
            FreeLibrary(g_realD3D9);
            g_realD3D9 = NULL;
        }
    }
    return TRUE;
}
