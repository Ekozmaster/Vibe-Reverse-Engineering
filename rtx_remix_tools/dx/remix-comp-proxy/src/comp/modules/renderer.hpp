#pragma once

namespace comp
{
	namespace tex_addons
	{
		extern bool initialized;
		extern LPDIRECT3DTEXTURE9 icon;
		extern void init_texture_addons(bool release = false);
	}

	/*
	 * RAII-style save/restore context for D3D9 state around a single draw call.
	 * Callers save specific state before modifying it, then call restore_all()
	 * or per-state restore methods after the draw, then reset_context().
	 */
	class drawcall_mod_context
	{
	public:
		bool has_saved_renderstate(const D3DRENDERSTATETYPE& state) const;
		bool has_saved_renderstate(const uint32_t& state) const;

		void set_texture_transform(IDirect3DDevice9* device, const D3DXMATRIX* matrix);
		void save_vs(IDirect3DDevice9* device);
		void save_ps(IDirect3DDevice9* device);
		void save_texture(IDirect3DDevice9* device, const bool stage);
		bool save_rs(IDirect3DDevice9* device, const D3DRENDERSTATETYPE& state);
		bool save_rs(IDirect3DDevice9* device, const uint32_t& state);
		void save_ss(IDirect3DDevice9* device, const D3DSAMPLERSTATETYPE& state);
		bool save_tss(IDirect3DDevice9* device, const D3DTEXTURESTAGESTATETYPE& type);
		void save_view_transform(IDirect3DDevice9* device);
		void save_projection_transform(IDirect3DDevice9* device);

		void restore_vs(IDirect3DDevice9* device);
		void restore_ps(IDirect3DDevice9* device);
		void restore_texture(IDirect3DDevice9* device, const bool stage);
		void restore_render_state(IDirect3DDevice9* device, const D3DRENDERSTATETYPE& state);
		void restore_sampler_state(IDirect3DDevice9* device, const D3DSAMPLERSTATETYPE& state);
		void restore_texture_stage_state(IDirect3DDevice9* device, const D3DTEXTURESTAGESTATETYPE& type);
		void restore_texture_transform(IDirect3DDevice9* device);
		void restore_view_transform(IDirect3DDevice9* device);
		void restore_projection_transform(IDirect3DDevice9* device);
		void restore_all(IDirect3DDevice9* device);

		void reset_context();

		struct modifiers_s
		{
			bool do_not_render = false;
			void reset() { do_not_render = false; }
		};
		modifiers_s modifiers;

		struct info_s
		{
			IDirect3DDevice9* device_ptr = nullptr;
			void reset() { device_ptr = nullptr; }
		};
		info_s info;

		drawcall_mod_context() = default;

	private:
		IDirect3DVertexShader9* vs_ = nullptr;
		IDirect3DPixelShader9* ps_ = nullptr;
		IDirect3DBaseTexture9* tex0_ = nullptr;
		IDirect3DBaseTexture9* tex1_ = nullptr;
		bool vs_set_ = false;
		bool ps_set_ = false;
		bool tex0_set_ = false;
		bool tex1_set_ = false;
		bool tex0_transform_set_ = false;
		char pad1[3];

		D3DMATRIX view_transform_ = {};
		D3DMATRIX projection_transform_ = {};
		bool view_transform_set_ = false;
		bool projection_transform_set_ = false;
		char pad2[2];

		std::unordered_map<D3DRENDERSTATETYPE, DWORD> saved_render_state_;
		std::unordered_map<D3DSAMPLERSTATETYPE, DWORD> saved_sampler_state_;
		std::unordered_map<D3DTEXTURESTAGESTATETYPE, DWORD> saved_texture_stage_state_;
	};

	// ----

	class renderer final : public shared::common::loader::component_module
	{
	public:
		renderer();
		~renderer();

		static inline renderer* p_this = nullptr;
		static renderer* get() { return p_this; }

		static bool is_initialized()
		{
			if (const auto mod = get(); mod && mod->m_initialized) {
				return true;
			}
			return false;
		}

		void manually_trigger_remix_injection(IDirect3DDevice9* dev);
		HRESULT on_draw_primitive(IDirect3DDevice9* dev, const D3DPRIMITIVETYPE& PrimitiveType, const UINT& StartVertex, const UINT& PrimitiveCount);
		HRESULT on_draw_indexed_prim(IDirect3DDevice9* dev, const D3DPRIMITIVETYPE& PrimitiveType, const INT& BaseVertexIndex, const UINT& MinVertexIndex, const UINT& NumVertices, const UINT& startIndex, const UINT& primCount);

		bool m_triggered_remix_injection = false;
		static inline drawcall_mod_context dc_ctx {};

	private:
		bool m_initialized = false;
	};
}
