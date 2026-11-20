#pragma once

namespace shared::common
{
	class config
	{
	public:
		static config& get();

		void load(const std::string& ini_path);
		bool is_loaded() const { return loaded_; }

		int get_int(const char* section, const char* key, int default_val) const;
		std::string get_string(const char* section, const char* key, const char* default_val) const;
		float get_float(const char* section, const char* key, float default_val) const;
		bool get_bool(const char* section, const char* key, bool default_val) const;

		struct ffp_settings
		{
			bool enabled = true;
			int albedo_stage = 0;

			// Vertex shader constant registers the game uploads each matrix to.
			// An end is one past the last register of the matrix.
			struct register_layout
			{
				int view_start = 0;
				int view_end = 4;
				int proj_start = 4;
				int proj_end = 8;
				int world_start = 16;
				int world_end = 20;
			} registers;
		} ffp;

		struct skinning_settings
		{
			bool enabled = false;

			// Which SetVertexShaderConstantF uploads are taken as a bone palette
			int bone_threshold = 20;	// lowest register an upload may start at
			int regs_per_bone = 3;		// 3 for packed 4x3 matrices, 4 for 4x4
			int bone_min_regs = 3;		// smallest upload, in registers
		} skinning;

		struct diagnostics_settings
		{
			bool enabled = true;
			bool auto_capture = true;
			int delay_ms = 50000;
			int log_frames = 3;

			// Log categories (defaults, overridable from ImGui at runtime)
			bool log_draw_calls = true;
			bool log_vs_constants = true;
			bool log_vertex_data = true;
			bool log_declarations = true;
			bool log_textures = true;
			bool log_present_info = true;
		} diagnostics;

		struct remix_settings
		{
			bool enabled = true;
			std::string dll_name = "d3d9_remix.dll";
		} remix;

		struct chain_settings
		{
			std::string preload;   // semicolon-separated DLLs/ASIs loaded before d3d9 chain
			std::string postload;  // semicolon-separated DLLs/ASIs loaded after init
		} chain;

		struct tracer_settings
		{
			int backtrace_depth = 8;
			std::string output_dir = "captures";
		} tracer;

	private:
		std::string ini_path_;
		bool loaded_ = false;

		void parse_all();

		// An absent or empty value gives default_val; any other value that is not a decimal
		// number is logged and gives default_val too.
		template <typename T>
		T get_number(const char* section, const char* key, T default_val) const;
	};
}
