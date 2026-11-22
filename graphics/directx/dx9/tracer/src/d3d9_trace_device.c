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
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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
/* "trigger --frames" refuses a count outside 1..MAX_CAPTURE_FRAMES */
#define MAX_CAPTURE_FRAMES   100000
#define CAPTURE_ID_LENGTH    16

/* Guards the capture state below, the JSONL file and the progress file. A
 * thread holds it to write the finished record of a call and to end a frame,
 * never across the real call: records of two threads do not interleave, a
 * capture neither starts nor ends inside a record, and a call that waits in
 * the driver for another thread's call does not keep that thread out. */
static CRITICAL_SECTION g_traceLock;

/* Written under the lock; read without it only to skip calls that are not recorded */
static volatile int  g_capturing    = 0;
/* Captures started so far, which numbers the running one. Written under the
 * lock; read without it to note the capture a call is made in. */
static volatile LONG g_captureNumber = 0;
static int           g_captureInit  = 0;
/* Frames the running capture is to record, and those it has finished */
static int           g_frameTarget  = 0;
static int           g_currentFrame = 0;
/* Records written to the JSONL file since it was opened */
static int           g_seq          = 0;
/* What the running capture started at in the file: the number of its first
 * frame and the g_seq of its first record. Neither is 0 for a capture that
 * follows another in a file kept open for init records. */
static int           g_firstFrame   = 0;
static int           g_firstSeq     = 0;
static FILE         *g_jsonlFile    = NULL;
/* Id of the trigger file that started the capture; "-" when it carried none */
static char          g_captureId[CAPTURE_ID_LENGTH + 1] = "-";
/* Id of a trigger file that was taken and could not be deleted, which starts
 * no capture again; empty once that file is gone */
static char          g_undeletedTriggerId[CAPTURE_ID_LENGTH + 1] = "";
static int           g_progressFailureLogged = 0;
static int           g_filesNamed   = 0;
static char          g_jsonlPath[MAX_PATH];
static char          g_progressPath[MAX_PATH];
static char          g_triggerPath[MAX_PATH];

/* Called once, before a device exists to be called through */
void TraceLock_Init(void) {
    InitializeCriticalSection(&g_traceLock);
}

/* ---- Record text ---- */

#define RECORD_FIRST_CAPACITY 512

/* The JSON text of one call's record, from behind its "seq" on. The thread
 * making the call builds it with no lock held, so it belongs to the frame of
 * the wrapper that made the call. text is NULL for a call that is not
 * recorded, and for a record that ran out of memory, which is not written. */
typedef struct Record {
    char  *text;
    size_t length;
    size_t capacity;
    /* g_captureNumber as the call was made */
    LONG   capture;
} Record;

static void record_begin(Record *r) {
    r->length = 0;
    r->capacity = RECORD_FIRST_CAPACITY;
    r->text = (char*)malloc(r->capacity);
}

static void record_drop(Record *r) {
    free(r->text);
    r->text = NULL;
}

/* Makes room for count more characters and a terminator; 0 when the record is dropped */
static int record_reserve(Record *r, size_t count) {
    size_t capacity = r->capacity;
    char *grown;
    if (!r->text) return 0;
    if (r->length + count < capacity) return 1;
    while (r->length + count >= capacity) capacity *= 2;
    grown = (char*)realloc(r->text, capacity);
    if (!grown) {
        record_drop(r);
        return 0;
    }
    r->text = grown;
    r->capacity = capacity;
    return 1;
}

static void record_putc(Record *r, char c) {
    if (record_reserve(r, 1))
        r->text[r->length++] = c;
}

static void record_puts(Record *r, const char *s) {
    size_t count = strlen(s);
    if (record_reserve(r, count)) {
        memcpy(r->text + r->length, s, count);
        r->length += count;
    }
}

static void record_printf(Record *r, const char *fmt, ...) {
    va_list ap;
    int count;
    if (!r->text) return;
    va_start(ap, fmt);
    count = vsnprintf(r->text + r->length, r->capacity - r->length, fmt, ap);
    va_end(ap);
    if (count < 0) {
        record_drop(r);
        return;
    }
    if ((size_t)count >= r->capacity - r->length) {
        if (!record_reserve(r, (size_t)count)) return;
        va_start(ap, fmt);
        vsnprintf(r->text + r->length, r->capacity - r->length, fmt, ap);
        va_end(ap);
    }
    r->length += (size_t)count;
}

/* Takes back what was written past length: a field whose data could not be read to its end */
static void record_cut(Record *r, size_t length) {
    if (r->text) r->length = length;
}

static void json_write_float(Record *r, float val) {
    unsigned int bits = *(unsigned int*)&val;
    unsigned int exp_mask = 0x7F800000;
    if ((bits & exp_mask) == exp_mask) {
        record_puts(r, "null");
    } else {
        record_printf(r, "%.8g", val);
    }
}

/* ---- Backtrace capture (stack-scan for FPO-compiled code) ---- */

#define MAX_CODE_RANGES 128

typedef struct { DWORD base, end; } CodeRange;

/* Read by every thread that records a call, rebuilt when a capture starts */
static SRWLOCK   g_codeRangesLock = SRWLOCK_INIT;
static CodeRange g_codeRanges[MAX_CODE_RANGES];
static int       g_numCodeRanges = 0;

static void refresh_code_ranges(void) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD addr = 0x10000;
    AcquireSRWLockExclusive(&g_codeRangesLock);
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
    ReleaseSRWLockExclusive(&g_codeRangesLock);
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

    __asm { mov esp_val, esp }

    scan     = (DWORD *)esp_val;
    scan_end = scan + 4096;  /* 16 KB of stack */

    AcquireSRWLockShared(&g_codeRangesLock);
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
    ReleaseSRWLockShared(&g_codeRangesLock);

    return count;
}

static void json_write_backtrace(Record *r, void **frames, int count) {
    int i;
    record_puts(r, ",\"backtrace\":[");
    for (i = 0; i < count; i++) {
        if (i) record_putc(r, ',');
        record_printf(r, "\"0x%08X\"", (unsigned int)(size_t)frames[i]);
    }
    record_putc(r, ']');
}

/* ---- Shader disassembly via D3DX (lazy-loaded from host process d3dx9) ---- */

typedef void *LPD3DXBUFFER;  /* ID3DXBuffer* */

typedef HRESULT (__stdcall *PFN_D3DXDisassembleShader)(
    const DWORD *pShader, BOOL EnableColorCode,
    const char *pComments, LPD3DXBUFFER *ppDisassembly
);

/* g_disasmSearched is set once g_pfnDisasm holds the outcome of the search.
 * Threads that create their first shaders at the same moment may each run the
 * search; they find the same function. */
static volatile PFN_D3DXDisassembleShader g_pfnDisasm = NULL;
static volatile LONG g_disasmSearched = 0;

static void ensure_disasm_loaded(void) {
    static const char *d3dx_names[] = {
        "d3dx9_43.dll", "d3dx9_42.dll", "d3dx9_41.dll",
        "d3dx9_40.dll", "d3dx9_39.dll", "d3dx9_38.dll",
        "d3dx9_37.dll", "d3dx9_36.dll", NULL,
    };
    PFN_D3DXDisassembleShader found = NULL;
    int i;
    HMODULE hMod;

    if (g_disasmSearched) return;

    for (i = 0; d3dx_names[i] && !found; i++) {
        hMod = GetModuleHandleA(d3dx_names[i]);
        if (!hMod) hMod = LoadLibraryA(d3dx_names[i]);
        if (hMod) {
            found = (PFN_D3DXDisassembleShader)
                GetProcAddress(hMod, "D3DXDisassembleShader");
            if (found) {
                log_str("Shader disasm: loaded from ");
                log_str(d3dx_names[i]);
                log_str("\r\n");
            }
        }
    }
    if (!found)
        log_str("Shader disasm: d3dx9 not found (disassembly disabled)\r\n");
    g_pfnDisasm = found;
    g_disasmSearched = 1;
}

/* Write JSON-escaped string (handles \n, \r, \t, \\, \") */
static void json_write_escaped_string(Record *r, const char *s, int maxlen) {
    int i;
    record_putc(r, '"');
    for (i = 0; s[i] && i < maxlen; i++) {
        switch (s[i]) {
        case '"':  record_puts(r, "\\\""); break;
        case '\\': record_puts(r, "\\\\"); break;
        case '\n': record_puts(r, "\\n");  break;
        case '\r': break;
        case '\t': record_puts(r, "\\t");  break;
        default:
            if ((unsigned char)s[i] >= 0x20)
                record_putc(r, s[i]);
            break;
        }
    }
    record_putc(r, '"');
}

static void write_shader_disasm(Record *r, const DWORD *pFunc) {
    PFN_D3DXDisassembleShader disassemble;
    LPD3DXBUFFER pBuf = NULL;
    HRESULT hr;

    ensure_disasm_loaded();
    disassemble = g_pfnDisasm;
    if (!disassemble) return;

    hr = disassemble(pFunc, FALSE, NULL, &pBuf);
    if (hr == 0 && pBuf) {
        /* ID3DXBuffer vtable: [QI, AddRef, Release, GetBufferPointer, GetBufferSize] */
        void **vtbl = *(void***)pBuf;
        typedef void* (__stdcall *FnGetBuf)(void*);
        typedef DWORD (__stdcall *FnRelease)(void*);
        const char *text = (const char*)((FnGetBuf)vtbl[3])(pBuf);
        if (text && text[0]) {
            record_puts(r, ",\"disasm\":");
            json_write_escaped_string(r, text, 32000);
        }
        ((FnRelease)vtbl[2])(pBuf);
    }
}

/* ---- Data readers (pointer follow for specific method slots) ---- */

/* A field whose data lies behind a pointer the game passed is written whole or
 * not at all: when reading it faults, the record is cut back to where the
 * field began. */
static void write_data_readers(Record *r, int slot, int argc, DWORD *args) {
    size_t field;
    record_puts(r, ",\"data\":{");
    field = r->length;
    switch (slot) {
    case SLOT_SetTransform:
    case SLOT_MultiplyTransform:
        if (args[1]) {
            __try {
                float *p = (float*)(size_t)args[1];
                int i;
                record_puts(r, "\"matrix\":[");
                for (i = 0; i < MATRIX_FLOAT_COUNT; i++) {
                    if (i) record_putc(r, ',');
                    json_write_float(r, p[i]);
                }
                record_putc(r, ']');
            } __except(EXCEPTION_EXECUTE_HANDLER) { record_cut(r, field); }
        }
        break;

    case SLOT_CreateVertexDeclaration: {
        if (args[0]) {
            const unsigned char *p = (const unsigned char*)(size_t)args[0];
            __try {
                int ei;
                record_puts(r, "\"elements\":[");
                for (ei = 0; ei < MAX_VTXDECL_ELEMENTS; ei++) {
                    const unsigned char *e = p + ei * 8;
                    unsigned short stream = *(unsigned short*)e;
                    unsigned short offset = *(unsigned short*)(e + 2);
                    if (stream == D3DDECL_END_STREAM) break;
                    if (ei) record_putc(r, ',');
                    record_printf(r, "{\"Stream\":%u,\"Offset\":%u,\"Type\":%u,"
                                     "\"Method\":%u,\"Usage\":%u,\"UsageIndex\":%u}",
                                  stream, offset, e[4], e[5], e[6], e[7]);
                }
                record_putc(r, ']');
            } __except(EXCEPTION_EXECUTE_HANDLER) { record_cut(r, field); }
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
                record_puts(r, "\"bytecode\":\"");
                for (bi = 0; bi < blen; bi++)
                    record_printf(r, "%08X", pFunc[bi]);
                record_putc(r, '"');
                write_shader_disasm(r, pFunc);
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
                record_puts(r, "\"constants\":[");
                for (i = 0; i < count; i++) {
                    if (i) record_putc(r, ',');
                    json_write_float(r, p[i]);
                }
                record_putc(r, ']');
            } __except(EXCEPTION_EXECUTE_HANDLER) { record_cut(r, field); }
        }
        break;

    case SLOT_SetVertexShaderConstantI:
    case SLOT_SetPixelShaderConstantI:
        if (args[1] && args[2] > 0 && args[2] <= MAX_CONST_REGISTERS) {
            __try {
                int *p = (int*)(size_t)args[1];
                int count = (int)args[2] * FLOATS_PER_VEC4;
                int i;
                record_puts(r, "\"constants\":[");
                for (i = 0; i < count; i++) {
                    if (i) record_putc(r, ',');
                    record_printf(r, "%d", p[i]);
                }
                record_putc(r, ']');
            } __except(EXCEPTION_EXECUTE_HANDLER) { record_cut(r, field); }
        }
        break;

    case SLOT_SetVertexShaderConstantB:
    case SLOT_SetPixelShaderConstantB:
        if (args[1] && args[2] > 0 && args[2] <= MAX_CONST_REGISTERS) {
            __try {
                int *p = (int*)(size_t)args[1];
                int count = (int)args[2];
                int i;
                record_puts(r, "\"constants\":[");
                for (i = 0; i < count; i++) {
                    if (i) record_putc(r, ',');
                    record_printf(r, "%d", p[i]);
                }
                record_putc(r, ']');
            } __except(EXCEPTION_EXECUTE_HANDLER) { record_cut(r, field); }
        }
        break;

    case SLOT_Clear:
        {
            unsigned int bits = args[4];
            float z = *(float*)&bits;
            record_printf(r, "\"Flags\":%u,\"Color\":\"0x%08X\",\"Z\":",
                          args[2], args[3]);
            json_write_float(r, z);
            record_printf(r, ",\"Stencil\":%u", args[5]);
        }
        break;
    }
    record_putc(r, '}');
}

/* ---- Progress file ---- */

/* The progress file holds one line: "<frame> <calls> <id>" while capturing,
 * with " done" added by the last write, once every captured call is in the
 * JSONL file; or "0 0 <id> failed <reason>" for a capture that cannot start.
 * <frame> and <calls> count the frames finished and the calls recorded by
 * this capture. <id> is g_captureId, by which "trigger --wait" tells the
 * capture it asked for from any other. The file is rewritten in place, not
 * replaced by a rename: a reader holding it open blocks a rename but not a
 * rewrite, and the reader reads again when it finds a line without its
 * newline. A capture whose progress cannot be written says so in the log,
 * once: "trigger --wait" sends its user there.
 * Callers hold g_traceLock. */
static void write_progress_line(const char *format, ...) {
    FILE *pf = fopen(g_progressPath, "w");
    /* Of the first call that failed: a later one that succeeds may change errno */
    int write_errno = errno;
    int written = 0;
    char reason[MAX_PATH + 128];

    if (pf) {
        va_list ap;
        va_start(ap, format);
        written = vfprintf(pf, format, ap) > 0;
        va_end(ap);
        if (!written) write_errno = errno;
        if (fclose(pf) != 0 && written) {
            written = 0;
            write_errno = errno;
        }
    }
    if (written || g_progressFailureLogged) return;

    g_progressFailureLogged = 1;
    _snprintf(reason, sizeof(reason), "ERROR: cannot write %s: %s\r\n",
              g_progressPath, strerror(write_errno));
    reason[sizeof(reason) - 1] = 0;
    log_str(reason);
}

static void write_progress(int done) {
    write_progress_line(done ? "%d %d %s done\n" : "%d %d %s\n",
                        g_currentFrame, g_seq - g_firstSeq, g_captureId);
}

/* For a capture that did not start.
 * reason: one line of text, which "trigger --wait" prints as it stands */
static void write_capture_failure(const char *reason) {
    write_progress_line("0 0 %s failed %s\n", g_captureId, reason);
}

/* Ends the running capture, if any, over a JSONL file that no longer takes
 * what is written to it: the capture is reported failed at the frame and the
 * calls it had reached, never done. The file is closed by now.
 * Callers hold g_traceLock. */
static void report_capture_file_lost(int write_errno) {
    char reason[MAX_PATH + 128];
    _snprintf(reason, sizeof(reason), "cannot write %s: %s",
              g_jsonlPath, strerror(write_errno));
    reason[sizeof(reason) - 1] = 0;
    log_str("ERROR: ");
    log_str(reason);
    log_str("\r\n");

    if (!g_capturing) return;
    g_capturing = 0;
    write_progress_line("%d %d %s failed %s\n",
                        g_currentFrame, g_seq - g_firstSeq, g_captureId, reason);
}

/* The next capture opens the file anew.
 * Callers hold g_traceLock. */
static void abandon_capture_file(int write_errno) {
    fclose(g_jsonlFile);
    g_jsonlFile = NULL;
    report_capture_file_lost(write_errno);
}

/* ---- Core trace functions ---- */

static int records_slot(int slot) {
    return g_capturing || (g_captureInit && g_initCapture[slot]);
}

/* Begins the record of a call: what is known before the real call, read while
 * the pointers the game passed are still good. trace_post ends the record and
 * writes it. Between the two the thread holds no lock and nothing but
 * *record says that a record is open, so an exception that unwinds through
 * the real call loses that record's text and nothing else. */
static void trace_pre(int slot, int argc, DWORD *args, Record *record) {
    void *bt_frames[MAX_BT_FRAMES];
    int bt_count, i;

    record->text = NULL;
    if (!records_slot(slot))
        return;

    bt_count = capture_backtrace(bt_frames, MAX_BT_FRAMES);

    record_begin(record);
    record->capture = g_captureNumber;
    record_printf(record, ",\"slot\":%d,\"method\":\"%s\"", slot, g_methodNames[slot]);

    /* Named args: pointers as hex strings, integers as JSON numbers */
    record_puts(record, ",\"args\":{");
    for (i = 0; i < argc; i++) {
        if (i) record_putc(record, ',');
        if (g_argIsPtr[slot][i])
            record_printf(record, "\"%s\":\"0x%08X\"",
                          g_methodArgNames[slot][i], args[i]);
        else
            record_printf(record, "\"%s\":%u",
                          g_methodArgNames[slot][i], args[i]);
    }
    record_putc(record, '}');

    if (g_hasDataReader[slot])
        write_data_readers(record, slot, argc, args);

    json_write_backtrace(record, bt_frames, bt_count);

    record_printf(record, ",\"ts\":%d", (int)GetTickCount());
}

static void write_post_data(Record *r, int slot, DWORD *args) {
    if (!args) return;
    switch (slot) {
    case SLOT_CreateVertexDeclaration:
    case SLOT_CreateVertexShader:
    case SLOT_CreatePixelShader:
        if (args[1]) {
            __try {
                DWORD created = *(DWORD*)(size_t)args[1];
                record_printf(r, ",\"created_handle\":\"0x%08X\"", created);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        break;
    }
}

/* A record belongs to the capture its call was made in: a call that returns
 * once that capture has ended is in no frame of it, nor of a later capture.
 * Callers hold g_traceLock. */
static int in_running_capture(const Record *record) {
    return g_capturing && record->capture == g_captureNumber;
}

/* Writes a finished record as one line, numbered by its place in the file and
 * by the frame being captured as it is written. A record that is in no frame
 * of the running capture is written only as an init record, with frame -1.
 * "seq" counts the lines that reached the stream: a write that fails ends
 * the use of the file.
 * Callers hold g_traceLock. */
static void write_record(int slot, const Record *record) {
    int in_capture = in_running_capture(record);
    if (!g_jsonlFile || !(in_capture || (g_captureInit && g_initCapture[slot])))
        return;

    fprintf(g_jsonlFile, "{\"frame\":%d,\"seq\":%d",
            in_capture ? g_firstFrame + g_currentFrame : -1, g_seq);
    fwrite(record->text, 1, record->length, g_jsonlFile);
    if (ferror(g_jsonlFile)) {
        abandon_capture_file(errno);
        return;
    }
    g_seq++;

    if ((g_seq & FLUSH_INTERVAL_MASK) == 0) {
        if (fflush(g_jsonlFile) != 0) {
            abandon_capture_file(errno);
            return;
        }
        if (g_capturing)
            write_progress(0);
    }
}

static void on_present(void);

/* record: what trace_pre began for this call */
static void trace_post(int slot, Record *record, DWORD retval, DWORD *args) {
    if (!record->text && slot != SLOT_Present)
        return;

    if (record->text) {
        record_printf(record, ",\"ret\":\"0x%08X\"", retval);
        write_post_data(record, slot, args);
        record_puts(record, "}\n");
    }

    EnterCriticalSection(&g_traceLock);
    if (record->text)
        write_record(slot, record);
    if (slot == SLOT_Present)
        on_present();
    LeaveCriticalSection(&g_traceLock);

    record_drop(record);
}

/* ---- Frame boundary: called from Present wrapper ---- */

/* What follows key on the line of the trigger file that starts with it
 * ("frames=N" and "id=TOKEN", as "trigger" writes them); NULL without one. */
static const char *trigger_value(const char *trigger, const char *key) {
    size_t key_length = strlen(key);
    const char *line = trigger;
    while (line) {
        if (strncmp(line, key, key_length) == 0)
            return line + key_length;
        line = strchr(line, '\n');
        if (line) line++;
    }
    return NULL;
}

static int blank_to_end_of_line(const char *text) {
    while (*text && *text != '\n') {
        if (!isspace((unsigned char)*text)) return 0;
        text++;
    }
    return 1;
}

/* Frames the trigger file asks for, or [Trace] CaptureFrames when it names no
 * count: within 1..MAX_CAPTURE_FRAMES. 0 unless "frames=" is followed at once
 * by the digits of a number of at least 1, with nothing but blanks behind
 * them on the line. */
static int trigger_frames(const char *trigger) {
    const char *value = trigger_value(trigger, "frames=");
    long frames = g_cfgCaptureFrames;
    if (value) {
        char *end;
        /* strtol alone would skip blanks, line ends among them, and take a sign */
        if (!isdigit((unsigned char)*value))
            return 0;
        frames = strtol(value, &end, 10);
        if (!blank_to_end_of_line(end) || frames < 1)
            return 0;
    }
    if (frames < 1) return 1;
    if (frames > MAX_CAPTURE_FRAMES) return MAX_CAPTURE_FRAMES;
    return (int)frames;
}

/* id: receives the trigger file's id, CAPTURE_ID_LENGTH lowercase hex digits
 * with nothing but blanks behind them on the line; "-" for a trigger file
 * that carries none. */
static void trigger_id(const char *trigger, char *id) {
    const char *value = trigger_value(trigger, "id=");
    if (value && strspn(value, "0123456789abcdef") == CAPTURE_ID_LENGTH
            && blank_to_end_of_line(value + CAPTURE_ID_LENGTH)) {
        memcpy(id, value, CAPTURE_ID_LENGTH);
        id[CAPTURE_ID_LENGTH] = '\0';
    } else {
        strcpy(id, "-");
    }
}

/* Numbering starts over with the file. Returns 0 and leaves errno set when the file cannot be opened. */
static int open_capture_file(void) {
    g_jsonlFile = fopen(g_jsonlPath, "w");
    g_seq = 0;
    g_firstFrame = 0;
    return g_jsonlFile != NULL;
}

#define OPEN_FAILURE_CAPACITY (MAX_PATH + 128)

/* reason: receives why the JSONL file was not opened, OPEN_FAILURE_CAPACITY characters at most */
static void describe_open_failure(char *reason, int open_errno) {
    _snprintf(reason, OPEN_FAILURE_CAPACITY, "cannot open %s: %s",
              g_jsonlPath, strerror(open_errno));
    reason[OPEN_FAILURE_CAPACITY - 1] = 0;
}

static void report_capture_file_error(int open_errno) {
    char reason[OPEN_FAILURE_CAPACITY];
    describe_open_failure(reason, open_errno);
    log_str("ERROR: capture not started, ");
    log_str(reason);
    log_str("\r\n");
    write_capture_failure(reason);
}

/* Takes the trigger file whether or not the capture can start: left in place,
 * it would be retried on every Present. The trigger goes only after the
 * capture file exists and the progress file names the trigger's id:
 * "trigger --wait" takes a missing trigger for a capture whose progress it
 * can read. A trigger file that cannot be deleted is taken once all the same,
 * and deleted at the first later Present at which it can be: left in the
 * folder, it would start a capture in the next run of the game. */
static void start_capture_on_trigger(void) {
    char trigger[256] = {0};
    char id[CAPTURE_ID_LENGTH + 1];
    int open_errno = 0;
    int frames;
    FILE *tf = fopen(g_triggerPath, "r");

    if (!tf) return;
    fread(trigger, 1, sizeof(trigger) - 1, tf);
    fclose(tf);
    trigger_id(trigger, id);
    if (strcmp(id, g_undeletedTriggerId) == 0) {
        if (DeleteFileA(g_triggerPath))
            g_undeletedTriggerId[0] = '\0';
        return;
    }

    strcpy(g_captureId, id);
    g_progressFailureLogged = 0;
    frames = trigger_frames(trigger);

    if (frames && !g_jsonlFile && !open_capture_file())
        open_errno = errno;
    if (!frames) {
        log_str("ERROR: capture not started, the trigger's frames= is not a number of frames from 1 up\r\n");
        write_capture_failure("the trigger's frames= is not a number of frames from 1 up");
    } else if (g_jsonlFile) {
        g_captureNumber++;
        g_capturing = 1;
        g_currentFrame = 0;
        g_firstSeq = g_seq;
        g_frameTarget = frames;
        refresh_code_ranges(); /* DLLs may have loaded since the device was created */
        log_str("=== CAPTURE STARTED ===\r\n");
        write_progress(0);
    } else {
        report_capture_file_error(open_errno);
    }

    if (DeleteFileA(g_triggerPath)) {
        g_undeletedTriggerId[0] = '\0';
    } else {
        log_hex("ERROR: trigger file not deleted, GetLastError ", GetLastError());
        strcpy(g_undeletedTriggerId, id);
    }
}

static void end_captured_frame(void) {
    g_currentFrame++;
    if (g_currentFrame < g_frameTarget) {
        write_progress(0);
        return;
    }

    /* "done" is reported only of records that are in the file */
    if (fflush(g_jsonlFile) != 0) {
        abandon_capture_file(errno);
        return;
    }
    /* With init capture on, the file stays open for later Create* calls and for
     * the next capture, whose frames are numbered on from this one's */
    if (g_captureInit) {
        g_firstFrame += g_currentFrame;
    } else {
        int closed = fclose(g_jsonlFile) == 0;
        g_jsonlFile = NULL;
        if (!closed) {
            report_capture_file_lost(errno);
            return;
        }
    }
    g_capturing = 0;
    write_progress(1);

    log_str("=== CAPTURE DONE ===\r\n");
    {
        char buf[64];
        sprintf(buf, "  Frames: %d  Calls: %d\r\n", g_frameTarget, g_seq - g_firstSeq);
        log_str(buf);
    }
}

/* A trigger file found while a capture runs stays where it is, and starts
 * the next capture at the first Present after this one has ended.
 * Callers hold g_traceLock. */
static void on_present(void) {
    if (g_capturing)
        end_captured_frame();
    else if (GetFileAttributesA(g_triggerPath) != INVALID_FILE_ATTRIBUTES)
        start_capture_on_trigger();
    else
        g_undeletedTriggerId[0] = '\0';
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
        DWORD hr; Record record; \
        trace_pre(SLOT, 0, NULL, &record); \
        hr = ((FN0)REAL_VT(pThis)[SLOT])(REAL(pThis)); \
        trace_post(SLOT, &record, hr, NULL); \
        return hr; \
    }

#define TRACE_WRAP_1(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1) { \
        DWORD args[] = {a1}; DWORD hr; Record record; \
        trace_pre(SLOT, 1, args, &record); \
        hr = ((FN1)REAL_VT(pThis)[SLOT])(REAL(pThis), a1); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_2(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2) { \
        DWORD args[] = {a1, a2}; DWORD hr; Record record; \
        trace_pre(SLOT, 2, args, &record); \
        hr = ((FN2)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_3(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3) { \
        DWORD args[] = {a1, a2, a3}; DWORD hr; Record record; \
        trace_pre(SLOT, 3, args, &record); \
        hr = ((FN3)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_4(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4) { \
        DWORD args[] = {a1, a2, a3, a4}; DWORD hr; Record record; \
        trace_pre(SLOT, 4, args, &record); \
        hr = ((FN4)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_5(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) { \
        DWORD args[] = {a1, a2, a3, a4, a5}; DWORD hr; Record record; \
        trace_pre(SLOT, 5, args, &record); \
        hr = ((FN5)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_6(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6}; DWORD hr; Record record; \
        trace_pre(SLOT, 6, args, &record); \
        hr = ((FN6)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_7(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6, a7}; DWORD hr; Record record; \
        trace_pre(SLOT, 7, args, &record); \
        hr = ((FN7)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6, a7); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_8(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7, DWORD a8) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6, a7, a8}; DWORD hr; Record record; \
        trace_pre(SLOT, 8, args, &record); \
        hr = ((FN8)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6, a7, a8); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

#define TRACE_WRAP_9(SLOT) \
    static DWORD __stdcall TH_##SLOT(void *pThis, DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7, DWORD a8, DWORD a9) { \
        DWORD args[] = {a1, a2, a3, a4, a5, a6, a7, a8, a9}; DWORD hr; Record record; \
        trace_pre(SLOT, 9, args, &record); \
        hr = ((FN9)REAL_VT(pThis)[SLOT])(REAL(pThis), a1, a2, a3, a4, a5, a6, a7, a8, a9); \
        trace_post(SLOT, &record, hr, args); \
        return hr; \
    }

/* Pull in the generated wrappers + vtable */
#define DXTRACE_HOOKS
#include "d3d9_trace_hooks.inc"
#undef DXTRACE_HOOKS

/* ---- Public API ---- */

static int file_path(char *path, const char *folder, const char *name) {
    int length = _snprintf(path, MAX_PATH, "%s%s", folder, name);
    return length > 0 && length < MAX_PATH;
}

/* Names the tracer's files, which lie beside the game's executable. Returns 0,
 * with the reason in the log, when they cannot be named. */
static int name_files(void) {
    char folder[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, folder, MAX_PATH);
    char *name;

    if (length == 0) {
        log_hex("ERROR: not tracing, the path of the game's executable is not known, GetLastError ",
                GetLastError());
        return 0;
    }
    if (length < MAX_PATH) {
        name = folder + length;
        while (name > folder && name[-1] != '\\' && name[-1] != '/') name--;
        *name = '\0';

        if (file_path(g_triggerPath,  folder, "dxtrace_capture.trigger")
                && file_path(g_jsonlPath,    folder, "dxtrace_frame.jsonl")
                && file_path(g_progressPath, folder, "dxtrace_progress.txt"))
            return 1;
    }
    log_str("ERROR: not tracing, the path of the game's folder is too long for the tracer's files\r\n");
    return 0;
}

static void open_file_for_init_records(void) {
    char reason[OPEN_FAILURE_CAPACITY];
    if (open_capture_file()) {
        log_str("Init capture enabled -- logging Create* calls\r\n");
        return;
    }
    describe_open_failure(reason, errno);
    log_str("ERROR: init records not captured, ");
    log_str(reason);
    log_str("\r\n");
}

/* What the first device sets up serves every later one: a game that creates
 * another device goes on writing the same file, and a capture that is running
 * keeps its frame count. Returns 0 when nothing can be traced. */
static int prepare_tracing(void) {
    int ready;
    EnterCriticalSection(&g_traceLock);
    if (!g_filesNamed && name_files()) {
        g_filesNamed = 1;
        g_captureInit = g_cfgCaptureInit;
        refresh_code_ranges();
        if (g_captureInit)
            open_file_for_init_records();
    }
    ready = g_filesNamed;
    LeaveCriticalSection(&g_traceLock);
    return ready;
}

TracedDevice* TracedDevice_Create(void *pRealDevice) {
    TracedDevice *td;

    if (!prepare_tracing())
        return NULL;

    td = (TracedDevice*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TracedDevice));
    if (!td) return NULL;

    td->vtable = g_traceVtable;
    td->pReal  = pRealDevice;

    log_hex("TracedDevice created at ", (unsigned int)(size_t)td);
    log_hex("  Real device: ", (unsigned int)(size_t)pRealDevice);

    return td;
}
