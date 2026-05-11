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

			// Runtime albedo selection: per-frame LUT-exclusion heuristic.
			// Counts each texture's per-draw appearances across all 8 stages;
			// textures with count >= ceil(albedo_lut_ratio * draws_in_frame) are
			// treated as shared LUTs (shadow / lighting / env maps) and excluded
			// from albedo stage 0 rebinding. Falls back to static albedo_stage
			// when the pool is empty or no stage 0..4 holds a non-LUT texture.
			//
			// Ratio is the threshold expressed as a fraction of per-frame draws,
			// so it scales with scene complexity. Default 0.086 = 500/5800 from
			// the FEAR analysis where 13 LUTs were detected in a 5800-DIP frame.
			bool albedo_lut_exclusion = true;
			float albedo_lut_ratio = 0.086f;

			// Translucent-pass passthrough: when D3DRS_ALPHABLENDENABLE=TRUE
			// AND D3DRS_ZWRITEENABLE=FALSE, skip FFP engage and let the original
			// shader path run. Preserves alpha blending for water / particles /
			// glass that LithTech splits into a separate translucent queue.
			bool translucent_passthrough = true;
		} ffp;

		struct skinning_settings
		{
			bool enabled = false;
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
	};
}
