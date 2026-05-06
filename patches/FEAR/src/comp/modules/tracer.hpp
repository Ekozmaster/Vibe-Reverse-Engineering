#pragma once

namespace comp
{
	enum trace_category : uint32_t
	{
		TRACE_DRAW       = 1 << 0,  // DrawPrimitive, DrawIndexedPrimitive, DrawPrimitiveUP, DrawIndexedPrimitiveUP
		TRACE_STATE      = 1 << 1,  // SetRenderState, SetTextureStageState, SetSamplerState, StateBlock
		TRACE_SHADERS    = 1 << 2,  // Set/Create VertexShader, PixelShader, ShaderConstant*
		TRACE_TEXTURES   = 1 << 3,  // SetTexture, CreateTexture, CreateCubeTexture, CreateVolumeTexture
		TRACE_TRANSFORMS = 1 << 4,  // SetTransform, SetViewport, SetMaterial, SetLight, LightEnable
		TRACE_VERTEX     = 1 << 5,  // SetStreamSource, SetIndices, SetFVF, SetVertexDeclaration, CreateVertex/IndexBuffer
		TRACE_RESOURCES  = 1 << 6,  // CreateRenderTarget, CreateDepthStencil, SetRenderTarget, surface ops
		TRACE_SCENE      = 1 << 7,  // BeginScene, EndScene, Present, Clear, Reset
		TRACE_GETTERS    = 1 << 8,  // All Get* calls
		TRACE_MISC       = 1 << 9,  // Everything else (IUnknown, cursor, gamma, etc.)

		TRACE_ALL        = 0xFFFFFFFF,
		TRACE_DEFAULT    = TRACE_ALL & ~TRACE_GETTERS & ~TRACE_MISC,
	};

	class tracer final : public shared::common::loader::component_module
	{
	public:
		tracer();
		~tracer();

		static inline tracer* p_this = nullptr;
		static tracer* get() { return p_this; }

		// Hot-path check: single bool test, predicted not-taken
		static bool is_active() { return p_this && p_this->capturing_; }
		static tracer& ref() { return *p_this; }

		// Delayed capture: starts after countdown expires
		void start_capture_delayed(int num_frames, const std::string& filename, float delay_seconds);
		void cancel_delayed();
		bool is_waiting() const { return waiting_; }
		float delay_remaining() const;

		// Capture control
		void start_capture(int num_frames, const std::string& filename);
		void stop_capture();
		bool is_capturing() const { return capturing_; }

		// Frame boundary hooks (called from d3d9ex.cpp)
		void on_present();
		void on_reset();

		// JSONL builder API (called from generated dispatch functions)
		void record_begin(const char* method, int slot);
		void record_arg_uint(const char* name, DWORD val);
		void record_arg_int(const char* name, INT val);
		void record_arg_float(const char* name, float val);
		void record_arg_ptr(const char* name, const void* val);
		void record_data_float(const char* name, const float* data, UINT count);
		void record_data_int(const char* name, const int* data, UINT count);
		void record_data_shader(const char* name, const DWORD* bytecode);
		void record_data_vtxdecl(const char* name, const BYTE* elements);
		void record_clear_data(DWORD flags, DWORD color, float z, DWORD stencil);
		void record_backtrace();
		void record_end();

		// Post-call: capture created handles for Create* methods
		void record_created_handle(const void* handle);

		// Category filter
		uint32_t category_mask() const { return category_mask_; }
		void set_category_mask(uint32_t mask) { category_mask_ = mask; }
		static uint32_t classify_method(const char* method);

		// ImGui state accessors
		int frames_to_capture() const { return frames_to_capture_; }
		void set_frames_to_capture(int n) { frames_to_capture_ = n; }
		int frames_captured() const { return frames_captured_; }
		int sequence() const { return sequence_; }
		int backtrace_depth() const { return backtrace_depth_; }
		void set_backtrace_depth(int d) { backtrace_depth_ = d; }
		const std::string& last_capture_path() const { return last_capture_path_; }
		uint64_t last_capture_size() const { return last_capture_size_; }
		int last_capture_records() const { return last_capture_records_; }
		const std::string& output_dir() const { return output_dir_; }

		// Generate a default timestamped filename (without extension)
		static std::string generate_default_filename();

	private:
		// Capture state
		bool capturing_ = false;
		int frames_to_capture_ = 2;
		int frames_captured_ = 0;
		int sequence_ = 0;
		int frame_index_ = 0;

		// File I/O
		HANDLE log_file_ = INVALID_HANDLE_VALUE;
		static constexpr size_t BUFFER_SIZE = 4 * 1024 * 1024;
		static constexpr size_t FLUSH_THRESHOLD = 3 * 1024 * 1024;
		char* buffer_ = nullptr;
		size_t write_pos_ = 0;

		// JSON state machine
		bool first_arg_ = true;
		bool args_open_ = false;
		bool data_open_ = false;

		// Config
		int backtrace_depth_ = 8;
		std::string output_dir_ = "captures";
		uint32_t category_mask_ = TRACE_DEFAULT;

		// Per-record skip flag (set by record_begin when method is filtered out)
		bool skipping_ = false;

		// Last capture info
		std::string last_capture_path_;
		uint64_t last_capture_size_ = 0;
		int last_capture_records_ = 0;

		// FFP state saved before capture (to restore after)
		bool ffp_was_enabled_ = false;

		// Delayed start state
		bool waiting_ = false;
		DWORD delay_start_tick_ = 0;
		DWORD delay_ms_ = 0;
		int pending_frames_ = 0;
		std::string pending_filename_;

		// Trigger file watching
		void check_trigger_file();

		// Helpers
		void flush_buffer();
		void buf_append(const char* str, size_t len);
		void buf_printf(const char* fmt, ...);
		void buf_write_float(float val);
		void close_sections();
	};
}
