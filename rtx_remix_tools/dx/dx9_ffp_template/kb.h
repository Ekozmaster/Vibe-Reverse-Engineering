/*
 * Knowledge Base — discovered types, function signatures, and globals.
 *
 * This file accumulates RE discoveries. Pass it to the decompiler:
 *   python -m retools.decompiler game.exe 0x401000 --types kb.h
 *
 * Format:
 *   - C type definitions (structs, enums, typedefs) — no prefix
 *   - Function signatures at addresses — @ prefix
 *   - Global variables at addresses — $ prefix
 *
 * Examples:
 *
 *   struct RenderState {
 *       IDirect3DDevice9* pDevice;    // +0x00
 *       int drawCallCount;            // +0x04
 *       float viewMatrix[16];         // +0x08
 *   };
 *
 *   enum ShaderType { VS_WORLD=0, VS_SKIN=1, VS_UI=2 };
 *
 *   @ 0x00401000 void __cdecl RenderScene(RenderState* state);
 *   @ 0x00402000 void __thiscall Mesh_Draw(Mesh* this, int flags);
 *
 *   $ 0x01F206D4 IDirect3DDevice9* g_pD3DDevice
 *   $ 0x01F20700 RenderState* g_pRenderState
 */
