/*
 * D3D9 Frame Trace - Device Wrapper
 *
 * Wraps all 119 IDirect3DDevice9 methods via code-generated TRACE_WRAP macros.
 * When capture is active, logs every call as JSONL with args, backtraces,
 * and followed pointer data (constants, matrices, shader bytecodes).
 *
 * When not capturing, overhead is a single predicted-not-taken branch per call.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ---- Configuration (set from proxy.ini by d3d9_trace_main.c) ---- */

extern int g_cfgCaptureFrames;
extern int g_cfgCaptureInit;

/* ---- Logging (from d3d9_trace_main.c) ---- */

extern void log_str(const char *s);
extern void log_hex(const char *prefix, unsigned int val);

/* ---- Traced Device ---- */

typedef struct TracedDevice {
    void **vtable;
    void  *pReal;
} TracedDevice;

#define REAL(self) (((TracedDevice*)(self))->pReal)
#define REAL_VT(self) (*(void***)(((TracedDevice*)(self))->pReal))

/* ---- Generated tables, slot defines, domain constants ---- */

#define DXTRACE_TABLES
#include "d3d9_trace_hooks.inc"
#undef DXTRACE_TABLES

/* ---- Capture state ---- */

#define MAX_BT_FRAMES       32
#define FLUSH_INTERVAL_MASK  0xFF
#define FLOATS_PER_VEC4      4

static volatile int  g_capturing    = 0;
static int           g_captureInit  = 0;
static int           g_frameTarget  = 2;
static int           g_currentFrame = 0;
static int           g_seq          = 0;
static FILE         *g_jsonlFile    = NULL;
static char          g_jsonlPath[MAX_PATH];
static char          g_progressPath[MAX_PATH];
static char          g_triggerPath[MAX_PATH];

/* ---- JSONL writing helpers ---- */

static void json_begin(FILE *f) { fputc('{', f); }
static void json_end(FILE *f)   { fputs("}\n", f); }

static void json_key_int(FILE *f, const char *key, int val, int comma) {
    if (comma) fputc(',', f);
    fprintf(f, "\"%s\":%d", key, val);
}

static void json_key_str(FILE *f, const char *key, const char *val, int comma) {
    if (comma) fputc(',', f);
    fprintf(f, "\"%s\":\"%s\"", key, val);
}

static void json_key_hex(FILE *f, const char *key, unsigned int val, int comma) {
    if (comma) fputc(',', f);
    fprintf(f, "\"%s\":\"0x%08X\"", key, val);
}

static void json_write_float(FILE *f, float val) {
    unsigned int bits = *(unsigned int*)&val;
    unsigned int exp_mask = 0x7F800000;
    if ((bits & exp_mask) == exp_mask) {
        fprintf(f, "null");
    } else {
        fprintf(f, "%.8g", val);
    }
}

/* ---- Backtrace capture (stack-scan for FPO-compiled code) ---- */

#define MAX_CODE_RANGES 128

typedef struct { DWORD base, end; } CodeRange;

static CodeRange g_codeRanges[MAX_CODE_RANGES];
static int       g_numCodeRanges = 0;
static BOOL      g_codeRangesInit = FALSE;

static void init_code_ranges(void) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD addr = 0x10000;
    g_numCodeRanges = 0;
    while (addr < 0x7FFF0000 && g_numCodeRanges < MAX_CODE_RANGES) {
        if (VirtualQuery((void *)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                DWORD b = (DWORD)(size_t)mbi.BaseAddress;
                DWORD e = b + (DWORD)mbi.RegionSize;
                if (g_numCodeRanges > 0 && g_codeRanges[g_numCodeRanges - 1].end == b)
                    g_codeRanges[g_numCodeRanges - 1].end = e;
                else {
                    g_codeRanges[g_numCodeRanges].base = b;
                    g_codeRanges[g_numCodeRanges].end  = e;
                    g_numCodeRanges++;
                }
                addr = e;
            } else {
                addr = (DWORD)(size_t)mbi.BaseAddress + (DWORD)mbi.RegionSize;
            }
        } else {
            addr += 0x10000;
        }
    }
    g_codeRangesInit = TRUE;
}

static int addr_in_code(DWORD a) {
    int i;
    for (i = 0; i < g_numCodeRanges; i++)
        if (a >= g_codeRanges[i].base && a < g_codeRanges[i].end) return 1;
    return 0;
}

static int looks_like_retaddr(DWORD a) {
    unsigned char *p;
    if (!addr_in_code(a)) return 0;
    p = (unsigned char *)(size_t)a;
    __try {
        if (p[-5] == 0xE8) return 1;                                           /* call rel32       */
        if (p[-6] == 0xFF && p[-5] == 0x15) return 1;                          /* call [imm32]     */
        if (p[-2] == 0xFF && p[-1] >= 0xD0 && p[-1] <= 0xD7) return 1;        /* call reg         */
        if (p[-2] == 0xFF && p[-1] >= 0x10 && p[-1] <= 0x17
                          && p[-1] != 0x14) return 1;                          /* call [reg]       */
        if (p[-3] == 0xFF && p[-2] >= 0x50 && p[-2] <= 0x57
                          && p[-2] != 0x54) return 1;                          /* call [reg+d8]    */
        if (p[-6] == 0xFF && p[-5] >= 0x90 && p[-5] <= 0x97
                          && p[-5] != 0x94) return 1;                          /* call [reg+d32]   */
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 0;
}

static int capture_backtrace(void **frames, int max_frames) {
    DWORD esp_val;
    DWORD *scan, *scan_end;
    int count = 0, j;

    if (!g_codeRangesInit) init_code_ranges();

    __asm { mov esp_val, esp }

    scan     = (DWORD *)esp_val;
    scan_end = scan + 4096;  /* 16 KB of stack */

    __try {
        while (scan < scan_end && count < max_frames) {
            DWORD val = *scan;
            if (looks_like_retaddr(val)) {
                /* deduplicate: skip if already captured */
                for (j = 0; j < count; j++)
                    if ((DWORD)(size_t)frames[j] == val) break;
                if (j == count)
                    frames[count++] = (void *)(size_t)val;
            }
            scan++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    return count;
}

static void json_write_backtrace(FILE *f, void **frames, int count) {
    int i;
    fprintf(f, ",\"backtrace\":[");
    for (i = 0; i < count; i++) {
        if (i) fputc(',', f);
        fprintf(f, "\"0x%08X\"", (unsigned int)(size_t)frames[i]);
    }
    fputc(']', f);
}

/* ---- Shader disassembly via D3DX (lazy-loaded from host process d3dx9) ---- */

typedef void *LPD3DXBUFFER;  /* ID3DXBuffer* */

typedef HRESULT (__stdcall *PFN_D3DXDisassembleShader)(
    const DWORD *pShader, BOOL EnableColorCode,
    const char *pComments, LPD3DXBUFFER *ppDisassembly
);

static PFN_D3DXDisassembleShader g_pfnDisasm = NULL;
static int g_disasmSearched = 0;

static void ensure_disasm_loaded(void) {
    static const char *d3dx_names[] = {
        "d3dx9_43.dll", "d3dx9_42.dll", "d3dx9_41.dll",
        "d3dx9_40.dll", "d3dx9_39.dll", "d3dx9_38.dll",
        "d3dx9_37.dll", "d3dx9_36.dll", NULL,
    };
    int i;
    HMODULE hMod;

    if (g_disasmSearched) return;
    g_disasmSearched = 1;

    for (i = 0; d3dx_names[i]; i++) {
        hMod = GetModuleHandleA(d3dx_names[i]);
        if (!hMod) hMod = LoadLibraryA(d3dx_names[i]);
        if (hMod) {
            g_pfnDisasm = (PFN_D3DXDisassembleShader)
                GetProcAddress(hMod, "D3DXDisassembleShader");
            if (g_pfnDisasm) {
                log_str("Shader disasm: loaded from ");
                log_str(d3dx_names[i]);
                log_str("\r\n");
                return;
            }
        }
    }
    log_str("Shader disasm: d3dx9 not found (disassembly disabled)\r\n");
}

/* Write JSON-escaped string (handles \n, \r, \t, \\, \") */
static void json_write_escaped_string(FILE *f, const char *s, int maxlen) {
    int i;
    fputc('"', f);
    for (i = 0; s[i] && i < maxlen; i++) {
        switch (s[i]) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f);  break;
        case '\r': break;
        case '\t': fputs("\\t", f);  break;
        default:
            if ((unsigned char)s[i] >= 0x20)
                fputc(s[i], f);
            break;
        }
    }
    fputc('"', f);
}

static void write_shader_disasm(FILE *f, const DWORD *pFunc) {
    LPD3DXBUFFER pBuf = NULL;
    HRESULT hr;

    ensure_disasm_loaded();
    if (!g_pfnDisasm) return;

    hr = g_pfnDisasm(pFunc, FALSE, NULL, &pBuf);
    if (hr == 0 && pBuf) {
        /* ID3DXBuffer vtable: [QI, AddRef, Release, GetBufferPointer, GetBufferSize] */
        void **vtbl = *(void***)pBuf;
        typedef void* (__stdcall *FnGetBuf)(void*);
        typedef DWORD (__stdcall *FnRelease)(void*);
        const char *text = (const char*)((FnGetBuf)vtbl[3])(pBuf);
        if (text && text[0]) {
            fprintf(f, ",\"disasm\":");
            json_write_escaped_string(f, text, 32000);
        }
        ((FnRelease)vtbl[2])(pBuf);
    }
}

/* ---- Data readers (pointer follow for specific method slots) ---- */

static void write_data_readers(FILE *f, int slot, int argc, DWORD *args) {
    fprintf(f, ",\"data\":{");
    switch (slot) {
    case SLOT_SetTransform:
    case SLOT_MultiplyTransform:
        if (args[1]) {
            __try {
                float *p = (float*)(size_t)args[1];
                int i;
                fprintf(f, "\"matrix\":[");
                for (i = 0; i < MATRIX_FLOAT_COUNT; i++) {
                    if (i) fputc(',', f);
                    json_write_float(f, p[i]);
                }
                fputc(']', f);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;

    case SLOT_CreateVertexDeclaration: {
        if (args[0]) {
            const unsigned char *p = (const unsigned char*)(size_t)args[0];
            __try {
                int ei;
                fprintf(f, "\"elements\":[");
                for (ei = 0; ei < MAX_VTXDECL_ELEMENTS; ei++) {
                    const unsigned char *e = p + ei * 8;
                    unsigned short stream = *(unsigned short*)e;
                    unsigned short offset = *(unsigned short*)(e + 2);
                    if (stream == D3DDECL_END_STREAM) break;
                    if (ei) fputc(',', f);
                    fprintf(f, "{\"Stream\":%u,\"Offset\":%u,\"Type\":%u,"
                               "\"Method\":%u,\"Usage\":%u,\"UsageIndex\":%u}",
                            stream, offset, e[4], e[5], e[6], e[7]);
                }
                fputc(']', f);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;
    }

    case SLOT_CreateVertexShader:
    case SLOT_CreatePixelShader:
        if (args[0]) {
            const DWORD *pFunc = (const DWORD*)(size_t)args[0];
            int blen = 0;
            __try {
                for (blen = 0; blen < MAX_SHADER_DWORDS; blen++) {
                    if (pFunc[blen] == SHADER_END_TOKEN) { blen++; break; }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) { blen = 0; }
            if (blen > 0) {
                int bi;
                fprintf(f, "\"bytecode\":\"");
                for (bi = 0; bi < blen; bi++)
                    fprintf(f, "%08X", pFunc[bi]);
                fputc('"', f);
                write_shader_disasm(f, pFunc);
            }
        }
        break;

    case SLOT_SetVertexShaderConstantF:
    case SLOT_SetPixelShaderConstantF:
        if (args[1] && args[2] > 0 && args[2] <= MAX_CONST_REGISTERS) {
            __try {
                float *p = (float*)(size_t)args[1];
                int count = (int)args[2] * FLOATS_PER_VEC4;
                int i;
                fprintf(f, "\"constants\":[");
                for (i = 0; i < count; i++) {
                    if (i) fputc(',', f);
                    json_write_float(f, p[i]);
                }
                fputc(']', f);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;

    case SLOT_SetVertexShaderConstantI:
    case SLOT_SetPixelShaderConstantI:
        if (args[1] && args[2] > 0 && args[2] <= MAX_CONST_REGISTERS) {
            __try {
                int *p = (int*)(size_t)args[1];
                int count = (int)args[2] * FLOATS_PER_VEC4;
                int i;
                fprintf(f, "\"constants\":[");
                for (i = 0; i < count; i++) {
                    if (i) fputc(',', f);
                    fprintf(f, "%d", p[i]);
                }
                fputc(']', f);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;

    case SLOT_SetVertexShaderConstantB:
    case SLOT_SetPixelShaderConstantB:
        if (args[1] && args[2] > 0 && args[2] <= MAX_CONST_REGISTERS) {
            __try {
                int *p = (int*)(size_t)args[1];
                int count = (int)args[2];
                int i;
                fprintf(f, "\"constants\":[");
                for (i = 0; i < count; i++) {
                    if (i) fputc(',', f);
                    fprintf(f, "%d", p[i]);
                }
                fputc(']', f);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;

    case SLOT_Clear:
        {
            unsigned int bits = args[4];
            float z = *(float*)&bits;
            fprintf(f, "\"Flags\":%u,\"Color\":\"0x%08X\",\"Z\":",
                    args[2], args[3]);
            json_write_float(f, z);
            fprintf(f, ",\"Stencil\":%u", args[5]);
        }
        break;
    }
    fputc('}', f);
}

static void trace_on_present(void);

/* ---- Core trace functions ---- */

/* "<frame> <calls>" while capturing. The last write adds " done", once every
 * captured call is in the JSONL file: "trigger --wait" takes that word for
 * the capture being complete. The file is rewritten in place rather than
 * replaced by a rename: a reader holding it open blocks a rename, which would
 * lose the final line, while a half-written read is retried by the reader. */
static void write_progress(int done) {
    FILE *pf = fopen(g_progressPath, "w");
    if (pf) {
        fprintf(pf, done ? "%d %d done\n" : "%d %d\n", g_currentFrame, g_seq);
        fclose(pf);
    }
}

static void trace_pre(int slot, void *pThis, int argc, DWORD *args) {
    int is_init_slot;
    void *bt_frames[MAX_BT_FRAMES];
    int bt_count, i;

    is_init_slot = g_initCapture[slot];

    if (!g_capturing && !(g_captureInit && is_init_slot))
        return;

    if (!g_jsonlFile) return;

    bt_count = capture_backtrace(bt_frames, MAX_BT_FRAMES);

    json_begin(g_jsonlFile);

    json_key_int(g_jsonlFile, "frame",
                 g_capturing ? g_currentFrame : -1, 0);
    json_key_int(g_jsonlFile, "seq", g_seq, 1);
    json_key_int(g_jsonlFile, "slot", slot, 1);
    json_key_str(g_jsonlFile, "method", g_methodNames[slot], 1);

    /* Named args: pointers as hex strings, integers as JSON numbers */
    fprintf(g_jsonlFile, ",\"args\":{");
    for (i = 0; i < argc; i++) {
        if (i) fputc(',', g_jsonlFile);
        if (g_argIsPtr[slot][i])
            fprintf(g_jsonlFile, "\"%s\":\"0x%08X\"",
                    g_methodArgNames[slot][i], args[i]);
        else
            fprintf(g_jsonlFile, "\"%s\":%u",
                    g_methodArgNames[slot][i], args[i]);
    }
    fputc('}', g_jsonlFile);

    /* Data readers */
    if (g_hasDataReader[slot])
        write_data_readers(g_jsonlFile, slot, argc, args);

    /* Backtrace */
    json_write_backtrace(g_jsonlFile, bt_frames, bt_count);

    /* Timestamp */
    json_key_int(g_jsonlFile, "ts", (int)GetTickCount(), 1);

    g_seq++;
}

static void write_post_data(FILE *f, int slot, DWORD *args) {
    if (!args) return;
    switch (slot) {
    case SLOT_CreateVertexDeclaration:
    case SLOT_CreateVertexShader:
    case SLOT_CreatePixelShader:
        if (args[1]) {
            __try {
                DWORD created = *(DWORD*)(size_t)args[1];
                fprintf(f, ",\"created_handle\":\"0x%08X\"", created);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;
    }
}

static void trace_post(int slot, DWORD retval, DWORD *args) {
    if (g_jsonlFile && (g_capturing || (g_captureInit && g_initCapture[slot]))) {
        json_key_hex(g_jsonlFile, "ret", retval, 1);
        write_post_data(g_jsonlFile, slot, args);
        json_end(g_jsonlFile);

        if ((g_seq & FLUSH_INTERVAL_MASK) == 0) {
            fflush(g_jsonlFile);
            if (g_capturing)
                write_progress(0);
        }
    }

    if (slot == SLOT_Present)
        trace_on_present();
}

/* ---- Frame boundary: called from Present wrapper ---- */

/* Frames the trigger file asks for ("frames=N", as "trigger" writes it);
 * [Trace] CaptureFrames for a trigger file that names no count. */
static int trigger_frames(void) {
    char buf[256] = {0};
    const char *p;
    int frames = 0;
    FILE *tf = fopen(g_triggerPath, "r");
    if (tf) {
        fread(buf, 1, sizeof(buf) - 1, tf);
        fclose(tf);
    }
    p = strstr(buf, "frames=");
    if (p) sscanf(p + 7, "%d", &frames);
    return frames >= 1 ? frames : g_cfgCaptureFrames;
}

static void trace_on_present(void) {
    if (!g_capturing) {
        DWORD attr = GetFileAttributesA(g_triggerPath);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            int frames = trigger_frames();

            /* The capture file exists before the trigger goes: "trigger --wait"
             * takes a missing trigger for a capture under way */
            if (!g_jsonlFile) {
                g_jsonlFile = fopen(g_jsonlPath, "w");
            }
            DeleteFileA(g_triggerPath);
            if (g_jsonlFile) {
                g_capturing = 1;
                g_currentFrame = 0;
                g_seq = 0;
                g_frameTarget = frames;
                init_code_ranges(); /* refresh: DLLs may have loaded since init */
                log_str("=== CAPTURE STARTED ===\r\n");
                write_progress(0);
            }
        }
        return;
    }

    g_currentFrame++;
    if (g_currentFrame < g_frameTarget) {
        write_progress(0);
        return;
    }

    g_capturing = 0;
    fflush(g_jsonlFile);
    /* With init capture on, the file stays open for later Create* calls */
    if (!g_captureInit) {
        fclose(g_jsonlFile);
        g_jsonlFile = NULL;
    }
    write_progress(1);

    log_str("=== CAPTURE DONE ===\r\n");
    {
        char buf[64];
        sprintf(buf, "  Frames: %d  Calls: %d\r\n", g_frameTarget, g_seq);
        log_str(buf);
    }
}

/* ---- TRACE_WRAP macros ---- */

typedef DWORD (__stdcall *FN0)(void*);
typedef DWORD (__stdcall *FN1)(void*, DWORD);
typedef DWORD (__stdcall *FN2)(void*, DWORD, DWORD);
typedef DWORD (__stdcall *FN3)(void*, DWORD, DWORD, DWORD);
typedef DWORD (__stdcall *FN4)(void*, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (__stdcall *FN5)(void*, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (__stdcall *FN6)(void*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (__stdcall *FN7)(void*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (__stdcall *FN8)(void*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (__stdcall *FN9)(void*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);

#define TRACE_WRAP_0(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis) { \
        DWORD hr; \
        trace_pre(SLOT, pThis, 0, NULL); \
        hr = ((FN0)REAL_VT(pThis)[SLOT])(REAL(pThis)); \
        trace_post(SLOT, hr, NULL); \
        return hr; \
    }

#define TRACE_WRAP_1(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1) { \
        DWORD args[] = {a1}; DWORD hr; \
        trace_pre(SLOT, pThis, 1, args); \
        hr = ((FN1)REAL_VT(pThis)[SLOT])(REAL(pThis), a1); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_2(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2) { \
        DWORD args[] = {a1, a2}; DWORD hr; \
        trace_pre(SLOT, pThis, 2, args); \
        hr = ((FN2)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_3(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3) { \
        DWORD args[] = {a1, a2, a3}; DWORD hr; \
        trace_pre(SLOT, pThis, 3, args); \
        hr = ((FN3)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_4(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4) { \
        DWORD args[] = {a1, a2, a3, a4}; DWORD hr; \
        trace_pre(SLOT, pThis, 4, args); \
        hr = ((FN4)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_5(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { \
        DWORD args[] = {a1, a2, a3, a4, a5}; DWORD hr; \
        trace_pre(SLOT, pThis, 5, args); \
        hr = ((FN5)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_6(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6}; DWORD hr; \
        trace_pre(SLOT, pThis, 6, args); \
        hr = ((FN6)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_7(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6, a7}; DWORD hr; \
        trace_pre(SLOT, pThis, 7, args); \
        hr = ((FN7)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6, a7); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_8(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7, DWORD a8) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6, a7, a8}; DWORD hr; \
        trace_pre(SLOT, pThis, 8, args); \
        hr = ((FN8)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6, a7, a8); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_9(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7, DWORD a8, DWORD a9) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6, a7, a8, a9}; DWORD hr; \
        trace_pre(SLOT, pThis, 9, args); \
        hr = ((FN9)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6, a7, a8, a9); \
        trace_post(SLOT, hr, args); \
        return hr; \
    }

/* Pull in the generated wrappers + vtable */
#define DXTRACE_HOOKS
#include "d3d9_trace_hooks.inc"
#undef DXTRACE_HOOKS

/* ---- Public API ---- */

TracedDevice* TracedDevice_Create(void *pRealDevice) {
    TracedDevice *td;
    char dllDir[MAX_PATH];
    int i, lastSlash = -1;

    td = (TracedDevice*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TracedDevice));
    if (!td) return NULL;

    td->vtable = g_traceVtable;
    td->pReal  = pRealDevice;

    /* Build paths relative to the DLL's directory */
    GetModuleFileNameA(NULL, dllDir, MAX_PATH);
    for (i = 0; dllDir[i]; i++) {
        if (dllDir[i] == '\\' || dllDir[i] == '/') lastSlash = i;
    }
    if (lastSlash >= 0) dllDir[lastSlash + 1] = '\0';
    else dllDir[0] = '\0';

    sprintf(g_triggerPath,  "%sdxtrace_capture.trigger", dllDir);
    sprintf(g_jsonlPath,    "%sdxtrace_frame.jsonl",     dllDir);
    sprintf(g_progressPath, "%sdxtrace_progress.txt",    dllDir);

    g_captureInit = g_cfgCaptureInit;
    g_frameTarget = g_cfgCaptureFrames;

    if (g_captureInit) {
        g_jsonlFile = fopen(g_jsonlPath, "w");
        if (g_jsonlFile) {
            log_str("Init capture enabled -- logging Create* calls\r\n");
        }
    }

    log_hex("TracedDevice created at ", (unsigned int)(size_t)td);
    log_hex("  Real device: ", (unsigned int)(size_t)pRealDevice);

    return td;
}
