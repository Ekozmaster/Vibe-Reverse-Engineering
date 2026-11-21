#include "std_include.hpp"
#include "config.hpp"

#include <charconv>

namespace shared::common
{
	namespace
	{
		// ffp_state keeps c0-c255 and reads a matrix as four registers from its start
		constexpr int CAPTURED_VS_REGISTERS = 256;
		constexpr int MATRIX_REGISTERS = 4;

		bool holds_matrix(const int start, const int end)
		{
			return start >= 0 && start <= CAPTURED_VS_REGISTERS - MATRIX_REGISTERS && end == start + MATRIX_REGISTERS;
		}

		// A bone palette is any upload from BoneThreshold on, so a matrix there could be taken for bones
		bool below_bones(const config::ffp_settings::register_layout& regs, const int bone_threshold)
		{
			return regs.view_end <= bone_threshold && regs.proj_end <= bone_threshold && regs.world_end <= bone_threshold;
		}

		// The value without an inline ';' comment and the blanks around it
		std::string_view number_text(const std::string& value)
		{
			std::string_view text = value;
			text = text.substr(0, text.find(';'));
			const auto first = text.find_first_not_of(" \t");
			if (first == std::string_view::npos) return {};
			return text.substr(first, text.find_last_not_of(" \t") - first + 1);
		}
	}

	config& config::get()
	{
		static config instance;
		return instance;
	}

	void config::load(const std::string& path)
	{
		ini_path_ = path;

		// Check if the INI file actually exists — GetPrivateProfileString silently
		// returns defaults for missing files, making it look like settings are ignored.
		if (GetFileAttributesA(ini_path_.c_str()) == INVALID_FILE_ATTRIBUTES)
		{
			log("Config", std::format("INI NOT FOUND: {} — using all defaults!", ini_path_),
				LOG_TYPE::LOG_TYPE_ERROR, true);
			loaded_ = false;
			return;
		}

		loaded_ = true;
		parse_all();
	}

	std::string config::get_string(const char* section, const char* key, const char* default_val) const
	{
		if (!loaded_) return default_val;
		char buf[512];
		GetPrivateProfileStringA(section, key, default_val, buf, sizeof(buf), ini_path_.c_str());
		return buf;
	}

	template <typename T>
	T config::get_number(const char* section, const char* key, T default_val) const
	{
		const auto value_text = get_string(section, key, "");
		const auto text = number_text(value_text);
		if (text.empty()) return default_val;

		// Apart from a comment, the whole value has to be a decimal number, "+" allowed:
		// "c8" or "0x10" keep the default
		const char* begin = text.data() + (text.size() > 1 && text[0] == '+' && text[1] != '-' ? 1 : 0);
		const char* end = text.data() + text.size();
		T value{};
		const auto [stop, error] = std::from_chars(begin, end, value);
		if (error == std::errc() && stop == end) return value;

		log("Config", std::format("[{}] {}={} is not a decimal number; using {}", section, key, value_text, default_val),
			LOG_TYPE::LOG_TYPE_ERROR, true);
		return default_val;
	}

	int config::get_int(const char* section, const char* key, int default_val) const
	{
		return get_number(section, key, default_val);
	}

	float config::get_float(const char* section, const char* key, float default_val) const
	{
		return get_number(section, key, default_val);
	}

	bool config::get_bool(const char* section, const char* key, bool default_val) const
	{
		return get_int(section, key, default_val ? 1 : 0) != 0;
	}

	void config::parse_all()
	{
		// [Remix]
		remix.enabled = get_bool("Remix", "Enabled", true);
		remix.dll_name = get_string("Remix", "DLLName", "d3d9_remix.dll");

		// [Chain]
		chain.preload = get_string("Chain", "PreLoad", "");
		chain.postload = get_string("Chain", "PostLoad", "");

		// [FFP]
		ffp.enabled = get_bool("FFP", "Enabled", true);
		ffp.albedo_stage = get_int("FFP", "AlbedoStage", 0);
		if (ffp.albedo_stage < 0 || ffp.albedo_stage > 7)
			ffp.albedo_stage = 0;

		// [FFP.Registers]
		auto& regs = ffp.registers;
		regs.view_start = get_int("FFP.Registers", "ViewStart", regs.view_start);
		regs.view_end = get_int("FFP.Registers", "ViewEnd", regs.view_end);
		regs.proj_start = get_int("FFP.Registers", "ProjStart", regs.proj_start);
		regs.proj_end = get_int("FFP.Registers", "ProjEnd", regs.proj_end);
		regs.world_start = get_int("FFP.Registers", "WorldStart", regs.world_start);
		regs.world_end = get_int("FFP.Registers", "WorldEnd", regs.world_end);
		if (!holds_matrix(regs.view_start, regs.view_end) ||
			!holds_matrix(regs.proj_start, regs.proj_end) ||
			!holds_matrix(regs.world_start, regs.world_end))
		{
			log("Config", "[FFP.Registers] names a matrix outside c0-c255 or an End that is not its Start + 4; using the default layout",
				LOG_TYPE::LOG_TYPE_ERROR, true);
			regs = {};
		}

		// [Skinning]
		const auto use_default_bone_layout = [this]
		{
			const skinning_settings defaults;
			skinning.bone_threshold = defaults.bone_threshold;
			skinning.regs_per_bone = defaults.regs_per_bone;
			skinning.bone_min_regs = defaults.bone_min_regs;
		};
		skinning.enabled = get_bool("Skinning", "Enabled", false);
		skinning.bone_threshold = get_int("Skinning", "BoneThreshold", skinning.bone_threshold);
		skinning.regs_per_bone = get_int("Skinning", "RegsPerBone", skinning.regs_per_bone);
		skinning.bone_min_regs = get_int("Skinning", "BoneMinRegs", skinning.bone_min_regs);
		if (skinning.bone_threshold < 0 || skinning.bone_threshold >= CAPTURED_VS_REGISTERS ||
			(skinning.regs_per_bone != 3 && skinning.regs_per_bone != 4) ||
			skinning.bone_min_regs < 1)
		{
			log("Config", "[Skinning] needs BoneThreshold in 0-255, RegsPerBone 3 or 4 and BoneMinRegs 1 or more; using the default bone layout",
				LOG_TYPE::LOG_TYPE_ERROR, true);
			use_default_bone_layout();
		}

		// The default register layout and bone layout do not overlap
		if (skinning.enabled && !below_bones(regs, skinning.bone_threshold))
		{
			log("Config", std::format("[Skinning] BoneThreshold={} is not above every matrix in [FFP.Registers], whose uploads would be "
				"taken for bones; using the default layouts", skinning.bone_threshold), LOG_TYPE::LOG_TYPE_ERROR, true);
			regs = {};
			use_default_bone_layout();
		}

		// [Diagnostics]
		diagnostics.enabled = get_bool("Diagnostics", "Enabled", true);
		diagnostics.auto_capture = get_bool("Diagnostics", "AutoCapture", true);
		diagnostics.delay_ms = get_int("Diagnostics", "DelayMs", 50000);
		diagnostics.log_frames = get_int("Diagnostics", "LogFrames", 3);
		diagnostics.log_draw_calls = get_bool("Diagnostics", "LogDrawCalls", true);
		diagnostics.log_vs_constants = get_bool("Diagnostics", "LogVSConstants", true);
		diagnostics.log_vertex_data = get_bool("Diagnostics", "LogVertexData", true);
		diagnostics.log_declarations = get_bool("Diagnostics", "LogDeclarations", true);
		diagnostics.log_textures = get_bool("Diagnostics", "LogTextures", true);
		diagnostics.log_present_info = get_bool("Diagnostics", "LogPresentInfo", true);

		// [Tracer]
		tracer.backtrace_depth = get_int("Tracer", "BacktraceDepth", 8);
		tracer.output_dir = get_string("Tracer", "OutputDir", "captures");

		log("Config", std::format("Loaded from: {}", ini_path_));
		log("Config", std::format("FFP={} AlbedoStage={}", ffp.enabled ? 1 : 0, ffp.albedo_stage));
		if (skinning.enabled)
			log("Config", std::format("Skinning ENABLED: bones from c{}, {} registers each, uploads of {} registers or more",
				skinning.bone_threshold, skinning.regs_per_bone, skinning.bone_min_regs), LOG_TYPE::LOG_TYPE_WARN);
	}
}
