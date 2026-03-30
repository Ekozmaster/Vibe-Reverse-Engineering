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

			int vs_reg_view_start = 0;
			int vs_reg_view_end = 4;
			int vs_reg_proj_start = 4;
			int vs_reg_proj_end = 8;
			int vs_reg_world_start = 16;
			int vs_reg_world_end = 20;

			int vs_reg_bone_threshold = 20;
			int vs_regs_per_bone = 3;
			int vs_bone_min_regs = 3;
		} ffp;

		struct skinning_settings
		{
			bool enabled = false;
		} skinning;

		struct diagnostics_settings
		{
			bool enabled = true;
			int delay_ms = 50000;
			int log_frames = 3;
		} diagnostics;

		struct remix_settings
		{
			bool enabled = true;
			std::string dll_name = "d3d9_remix.dll";
		} remix;

		struct chain_settings
		{
			std::string preload_dll;
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
