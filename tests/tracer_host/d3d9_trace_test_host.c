/*
 * D3D9 Frame Trace - Test Host
 *
 * Stands in for a game and for the Direct3D 9 behind the trace proxy, so the
 * built d3d9.dll can be run without a display device. The program loads the
 * d3d9.dll beside it, whose proxy.ini names this program as the chain DLL:
 * the proxy then wraps the device made here, whose methods do nothing but what
 * a test needs of them.
 *
 * Usage: PROGRAM COMMAND...   (run in its own folder)
 *   frames N           N frames of BeginScene, SetRenderState, DrawPrimitive, EndScene, Present
 *   trigger FILE       copy FILE to dxtrace_capture.trigger
 *   make-trigger-writable
 *                      clear the read-only attribute of dxtrace_capture.trigger
 *   device             create another device and go on with that one
 *   shader             CreateVertexShader
 *   unreadable-constants
 *                      SetVertexShaderConstantF with a pointer to no memory
 *   raise              a SetRenderState out of which the driver raises an exception
 *   blocked-call       a SetRenderState that returns only once a call made on another
 *                      thread has returned; prints whether it did
 *   hold-call          a SetRenderState, made on another thread, that stays in the driver
 *   hold-shader        a CreateVertexShader, made on another thread, that stays in the driver
 *   release-call       let the held call return, and wait until it has
 *   lock-capture-file  lock dxtrace_frame.jsonl, so that no write reaches it from then on
 *   threads N CALLS FRAMES
 *                      N threads make CALLS calls each while this one presents
 *                      at most FRAMES frames, spread over the time they take
 *
 * Build (x86): cl /nologo /W3 /I <the tracer's src folder> d3d9_trace_test_host.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The proxy looks its chain DLL up by this name */
#pragma comment(linker, "/EXPORT:Direct3DCreate9=_Direct3DCreate9@4")

/* The slot and the argument count of each device method */
#define DXTRACE_TABLES
#include "d3d9_trace_hooks.inc"
#undef DXTRACE_TABLES

#define DEVICE_SLOT_COUNT           ((int)(sizeof(g_methodArgCounts) / sizeof(g_methodArgCounts[0])))
#define D3D9_SLOT_CreateDevice      16
#define D3D9_SLOT_COUNT             17
#define D3DERR_INVALIDCALL          ((HRESULT)0x8876086CL)

#define STATE_DRIVER_RAISES         0x7001
#define STATE_WAITS_FOR_OTHER_CALL  0x7002
#define STATE_HELD_IN_DRIVER        0x7003
#define STATE_OF_THREAD             0x8000
#define OTHER_CALL_TIMEOUT_MS       5000
#define CALLS_PER_SHADER            16

typedef struct ComObject { void **vtbl; } ComObject;

typedef HRESULT (__stdcall *Method0)(void *self);
typedef HRESULT (__stdcall *Method2)(void *self, DWORD a, DWORD b);
typedef HRESULT (__stdcall *Method3)(void *self, DWORD a, DWORD b, DWORD c);
typedef HRESULT (__stdcall *Method4)(void *self, DWORD a, DWORD b, DWORD c, DWORD d);
typedef HRESULT (__stdcall *CreateDeviceMethod)(void *self, UINT adapter, UINT type, void *window,
                                                DWORD flags, void *parameters, void **device);

/* ---- The Direct3D 9 behind the proxy ---- */

/* Every method can be called: Windows itself calls into the IDirect3D9 a
 * program gets, through its compatibility layer, the first time the program
 * runs from a folder. A method no test needs refuses the call. */
static HRESULT __stdcall Refuse0(void *self) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse1(void *self, DWORD a) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse2(void *self, DWORD a, DWORD b) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse3(void *self, DWORD a, DWORD b, DWORD c) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse4(void *self, DWORD a, DWORD b, DWORD c, DWORD d) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse5(void *self, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse6(void *self, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e, DWORD f) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse7(void *self, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e, DWORD f, DWORD g) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse8(void *self, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e, DWORD f, DWORD g, DWORD h) { return D3DERR_INVALIDCALL; }
static HRESULT __stdcall Refuse9(void *self, DWORD a, DWORD b, DWORD c, DWORD d, DWORD e, DWORD f, DWORD g, DWORD h, DWORD i) { return D3DERR_INVALIDCALL; }

static void *const g_refuse[] = {
    (void *)Refuse0, (void *)Refuse1, (void *)Refuse2, (void *)Refuse3, (void *)Refuse4,
    (void *)Refuse5, (void *)Refuse6, (void *)Refuse7, (void *)Refuse8, (void *)Refuse9,
};

static HRESULT __stdcall Driver_QueryInterface(void *self, const void *iid, void **object) {
    *object = NULL;
    return E_NOINTERFACE;
}

/* The objects are never destroyed */
static ULONG __stdcall Driver_AddRefOrRelease(void *self) {
    return 1;
}

static HANDLE g_insideWaitingCall;
static HANDLE g_otherCallReturned;
static HANDLE g_insideHeldCall;
static HANDLE g_heldCallReleased;
static LONG   g_nextShaderIsHeld;
static LONG   g_shadersCreated;

static HRESULT __stdcall Driver_Succeed0(void *self) { return S_OK; }
static HRESULT __stdcall Driver_Succeed3(void *self, DWORD a, DWORD b, DWORD c) { return S_OK; }
static HRESULT __stdcall Driver_Succeed4(void *self, DWORD a, DWORD b, DWORD c, DWORD d) { return S_OK; }

static HRESULT __stdcall Driver_SetRenderState(void *self, DWORD state, DWORD value) {
    if (state == STATE_DRIVER_RAISES)
        RaiseException(0xE0000001, 0, 0, NULL);
    if (state == STATE_WAITS_FOR_OTHER_CALL) {
        SetEvent(g_insideWaitingCall);
        if (WaitForSingleObject(g_otherCallReturned, OTHER_CALL_TIMEOUT_MS) != WAIT_OBJECT_0)
            return E_FAIL;
    }
    if (state == STATE_HELD_IN_DRIVER) {
        SetEvent(g_insideHeldCall);
        if (WaitForSingleObject(g_heldCallReleased, OTHER_CALL_TIMEOUT_MS) != WAIT_OBJECT_0)
            return E_FAIL;
    }
    return S_OK;
}

static HRESULT __stdcall Driver_CreateVertexShader(void *self, DWORD function, DWORD shader) {
    if (InterlockedExchange(&g_nextShaderIsHeld, 0)) {
        SetEvent(g_insideHeldCall);
        if (WaitForSingleObject(g_heldCallReleased, OTHER_CALL_TIMEOUT_MS) != WAIT_OBJECT_0)
            return E_FAIL;
    }
    *(DWORD *)(size_t)shader = 0x0B000000 + 0x10 * InterlockedIncrement(&g_shadersCreated);
    return S_OK;
}

static void *g_deviceVtbl[DEVICE_SLOT_COUNT];
static ComObject g_device = { g_deviceVtbl };

static HRESULT __stdcall Driver_CreateDevice(void *self, UINT adapter, UINT type, void *window,
                                             DWORD flags, void *parameters, void **device) {
    int slot;
    for (slot = 0; slot < DEVICE_SLOT_COUNT; slot++)
        g_deviceVtbl[slot] = g_refuse[g_methodArgCounts[slot]];
    g_deviceVtbl[SLOT_QueryInterface]           = (void *)Driver_QueryInterface;
    g_deviceVtbl[SLOT_AddRef]                   = (void *)Driver_AddRefOrRelease;
    g_deviceVtbl[SLOT_Release]                  = (void *)Driver_AddRefOrRelease;
    g_deviceVtbl[SLOT_Present]                  = (void *)Driver_Succeed4;
    g_deviceVtbl[SLOT_BeginScene]               = (void *)Driver_Succeed0;
    g_deviceVtbl[SLOT_EndScene]                 = (void *)Driver_Succeed0;
    g_deviceVtbl[SLOT_SetRenderState]           = (void *)Driver_SetRenderState;
    g_deviceVtbl[SLOT_DrawPrimitive]            = (void *)Driver_Succeed3;
    g_deviceVtbl[SLOT_SetVertexShaderConstantF] = (void *)Driver_Succeed3;
    g_deviceVtbl[SLOT_CreateVertexShader]       = (void *)Driver_CreateVertexShader;
    *device = &g_device;
    return S_OK;
}

static void *g_d3d9Vtbl[D3D9_SLOT_COUNT];
static ComObject g_d3d9 = { g_d3d9Vtbl };

void *__stdcall Direct3DCreate9(UINT sdkVersion) {
    /* IDirect3D9, from QueryInterface to CreateDevice */
    static const int argument_counts[D3D9_SLOT_COUNT] = { 2, 0, 0, 1, 0, 3, 2, 4, 2, 5, 6, 6, 5, 4, 3, 1, 6 };
    int slot;
    for (slot = 0; slot < D3D9_SLOT_COUNT; slot++)
        g_d3d9Vtbl[slot] = g_refuse[argument_counts[slot]];
    g_d3d9Vtbl[SLOT_QueryInterface]    = (void *)Driver_QueryInterface;
    g_d3d9Vtbl[SLOT_AddRef]            = (void *)Driver_AddRefOrRelease;
    g_d3d9Vtbl[SLOT_Release]           = (void *)Driver_AddRefOrRelease;
    g_d3d9Vtbl[D3D9_SLOT_CreateDevice] = (void *)Driver_CreateDevice;
    return &g_d3d9;
}

/* ---- The game ---- */

static ComObject *g_proxyD3D9;
static ComObject *g_proxyDevice;

static void fail(const char *what) {
    fprintf(stderr, "%s failed\n", what);
    exit(1);
}

static void create_device(void) {
    void *device = NULL;
    HRESULT hr = ((CreateDeviceMethod)g_proxyD3D9->vtbl[D3D9_SLOT_CreateDevice])(
        g_proxyD3D9, 0, 1, NULL, 0, NULL, &device);
    if (FAILED(hr) || !device) fail("CreateDevice");
    g_proxyDevice = (ComObject *)device;
}

static HRESULT set_render_state(DWORD state, DWORD value) {
    return ((Method2)g_proxyDevice->vtbl[SLOT_SetRenderState])(g_proxyDevice, state, value);
}

static void create_vertex_shader(void) {
    static const DWORD vs_3_0_without_code[] = { 0xFFFE0300, 0x0000FFFF };
    void *shader = NULL;
    ((Method2)g_proxyDevice->vtbl[SLOT_CreateVertexShader])(
        g_proxyDevice, (DWORD)(size_t)vs_3_0_without_code, (DWORD)(size_t)&shader);
    if (!shader) fail("CreateVertexShader");
}

static void draw_frame(void) {
    ((Method0)g_proxyDevice->vtbl[SLOT_BeginScene])(g_proxyDevice);
    set_render_state(7, 1);
    ((Method3)g_proxyDevice->vtbl[SLOT_DrawPrimitive])(g_proxyDevice, 4, 0, 2);
    ((Method0)g_proxyDevice->vtbl[SLOT_EndScene])(g_proxyDevice);
    ((Method4)g_proxyDevice->vtbl[SLOT_Present])(g_proxyDevice, 0, 0, 0, 0);
}

static void raise_from_the_driver(void) {
    __try {
        set_render_state(STATE_DRIVER_RAISES, 0);
        fail("raising from the driver");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static DWORD WINAPI call_while_another_call_waits(void *unused) {
    (void)unused;
    WaitForSingleObject(g_insideWaitingCall, INFINITE);
    ((Method0)g_proxyDevice->vtbl[SLOT_BeginScene])(g_proxyDevice);
    SetEvent(g_otherCallReturned);
    return 0;
}

static void make_a_call_that_waits_for_another(void) {
    HANDLE other = CreateThread(NULL, 0, call_while_another_call_waits, NULL, 0, NULL);
    HRESULT hr = set_render_state(STATE_WAITS_FOR_OTHER_CALL, 0);
    WaitForSingleObject(other, INFINITE);
    CloseHandle(other);
    printf("blocked-call: %s\n", SUCCEEDED(hr) ? "returned" : "timed out");
}

static HANDLE g_heldCallThread;

static DWORD WINAPI make_held_call(void *unused) {
    (void)unused;
    return (DWORD)set_render_state(STATE_HELD_IN_DRIVER, 0);
}

static DWORD WINAPI make_held_shader(void *unused) {
    (void)unused;
    create_vertex_shader();
    return (DWORD)S_OK;
}

static void hold_a_call_in_the_driver(LPTHREAD_START_ROUTINE make_call) {
    g_heldCallThread = CreateThread(NULL, 0, make_call, NULL, 0, NULL);
    if (!g_heldCallThread) fail("starting the held call");
    WaitForSingleObject(g_insideHeldCall, INFINITE);
}

static void release_the_held_call(void) {
    DWORD result = (DWORD)E_FAIL;
    if (!g_heldCallThread) fail("releasing a call that is not held");
    SetEvent(g_heldCallReleased);
    WaitForSingleObject(g_heldCallThread, INFINITE);
    GetExitCodeThread(g_heldCallThread, &result);
    CloseHandle(g_heldCallThread);
    g_heldCallThread = NULL;
    if (FAILED((HRESULT)result)) fail("holding the call until its release");
}

/* The lock is held to the end of the run: the handle is never closed */
static void lock_capture_file(void) {
    HANDLE file = CreateFileA("dxtrace_frame.jsonl", GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE || !LockFile(file, 0, 0, MAXDWORD, MAXDWORD))
        fail("locking the capture file");
}

static int  g_callsPerThread;
static LONG g_threadCallsMade;

/* Each call names its thread and its place among that thread's calls, which the capture then shows */
static DWORD WINAPI make_calls(void *thread_index) {
    int call;
    for (call = 0; call < g_callsPerThread; call++) {
        set_render_state(STATE_OF_THREAD + (DWORD)(size_t)thread_index, (DWORD)call);
        if (call % CALLS_PER_SHADER == 0)
            create_vertex_shader();
        InterlockedIncrement(&g_threadCallsMade);
    }
    return 0;
}

static void call_from_threads(int thread_count, int calls, int frames) {
    HANDLE threads[MAXIMUM_WAIT_OBJECTS];
    LONG calls_per_frame, calls_at_next_frame;
    int i;
    if (thread_count < 1 || thread_count > MAXIMUM_WAIT_OBJECTS || frames < 1) fail("reading the thread arguments");
    g_callsPerThread = calls;
    g_threadCallsMade = 0;
    calls_per_frame = calls_at_next_frame = thread_count * calls / frames + 1;
    for (i = 0; i < thread_count; i++)
        threads[i] = CreateThread(NULL, 0, make_calls, (void *)(size_t)i, 0, NULL);
    while (WaitForMultipleObjects((DWORD)thread_count, threads, TRUE, 0) == WAIT_TIMEOUT) {
        if (g_threadCallsMade < calls_at_next_frame) {
            SwitchToThread();
            continue;
        }
        draw_frame();
        calls_at_next_frame += calls_per_frame;
    }
    for (i = 0; i < thread_count; i++)
        CloseHandle(threads[i]);
}

int main(int argc, char **argv) {
    typedef void *(__stdcall *CreateD3D9)(UINT);
    HMODULE proxy = LoadLibraryA("d3d9.dll");
    CreateD3D9 create;
    int i;

    if (!proxy) fail("loading d3d9.dll");
    create = (CreateD3D9)GetProcAddress(proxy, "Direct3DCreate9");
    if (!create) fail("finding Direct3DCreate9");
    g_insideWaitingCall = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_otherCallReturned = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_insideHeldCall = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_heldCallReleased = CreateEventA(NULL, FALSE, FALSE, NULL);
    g_proxyD3D9 = (ComObject *)create(32);
    if (!g_proxyD3D9) fail("Direct3DCreate9");
    create_device();

    for (i = 1; i < argc; i++) {
        const char *command = argv[i];
        if (strcmp(command, "frames") == 0 && i + 1 < argc) {
            int frame, count = atoi(argv[++i]);
            for (frame = 0; frame < count; frame++) draw_frame();
        } else if (strcmp(command, "trigger") == 0 && i + 1 < argc) {
            if (!CopyFileA(argv[++i], "dxtrace_capture.trigger", FALSE)) fail("placing the trigger");
        } else if (strcmp(command, "make-trigger-writable") == 0) {
            if (!SetFileAttributesA("dxtrace_capture.trigger", FILE_ATTRIBUTE_NORMAL)) fail("making the trigger writable");
        } else if (strcmp(command, "device") == 0) {
            create_device();
        } else if (strcmp(command, "shader") == 0) {
            create_vertex_shader();
        } else if (strcmp(command, "unreadable-constants") == 0) {
            ((Method3)g_proxyDevice->vtbl[SLOT_SetVertexShaderConstantF])(g_proxyDevice, 0, 1, 4);
        } else if (strcmp(command, "raise") == 0) {
            raise_from_the_driver();
        } else if (strcmp(command, "blocked-call") == 0) {
            make_a_call_that_waits_for_another();
        } else if (strcmp(command, "hold-call") == 0) {
            hold_a_call_in_the_driver(make_held_call);
        } else if (strcmp(command, "hold-shader") == 0) {
            g_nextShaderIsHeld = 1;
            hold_a_call_in_the_driver(make_held_shader);
        } else if (strcmp(command, "release-call") == 0) {
            release_the_held_call();
        } else if (strcmp(command, "lock-capture-file") == 0) {
            lock_capture_file();
        } else if (strcmp(command, "threads") == 0 && i + 3 < argc) {
            int thread_count = atoi(argv[++i]);
            int calls = atoi(argv[++i]);
            call_from_threads(thread_count, calls, atoi(argv[++i]));
        } else {
            fprintf(stderr, "unknown command: %s\n", command);
            return 2;
        }
    }
    return 0;
}
