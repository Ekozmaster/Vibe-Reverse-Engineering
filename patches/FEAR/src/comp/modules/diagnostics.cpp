#include "std_include.hpp"
#include "diagnostics.hpp"

#include "shared/common/config.hpp"
#include "shared/common/ffp_state.hpp"

namespace comp
{
	diagnostics::diagnostics()
	{
		p_this = this;
		create_tick_ = GetTickCount();

		auto& cfg = shared::common::config::get().diagnostics;
		delay_ms_ = static_cast<DWORD>(cfg.delay_ms);
		auto_max_frames_ = cfg.log_frames;
		auto_enabled_ = cfg.auto_capture;

		// Load log category defaults from config
		cat_draw_calls = cfg.log_draw_calls;
		cat_vs_constants = cfg.log_vs_constants;
		cat_vertex_data = cfg.log_vertex_data;
		cat_declarations = cfg.log_declarations;
		cat_textures = cfg.log_textures;
		cat_present_info = cfg.log_present_info;

		// Open log file for auto-capture mode
		if (auto_enabled_)
		{
			std::string path = shared::globals::root_path + "\\rtx_comp\\diagnostics.log";
			open_log(path);
		}

		shared::common::log("Diagnostics", std::format("Module initialized, auto={} delay={}ms frames={}",
			auto_enabled_ ? 1 : 0, delay_ms_, auto_max_frames_));
	}

	diagnostics::~diagnostics()
	{
		close_log();
		p_this = nullptr;
	}

	// ---- File management ----

	void diagnostics::open_log(const std::string& path)
	{
		close_log();
		log_file_ = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
			nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (log_file_ != INVALID_HANDLE_VALUE)
		{
			log_str("FFP Proxy Diagnostic Log\r\n");
			log_str("========================\r\n\r\n");
			last_log_path_ = path;
		}
	}

	void diagnostics::close_log()
	{
		if (log_file_ != INVALID_HANDLE_VALUE)
		{
			CloseHandle(log_file_);
			log_file_ = INVALID_HANDLE_VALUE;
		}
	}

	// ---- Capture control ----

	bool diagnostics::auto_is_active() const
	{
		return auto_enabled_ &&
			auto_logged_frames_ < auto_max_frames_ &&
			(GetTickCount() - create_tick_) >= delay_ms_;
	}

	bool diagnostics::is_active() const
	{
		return on_demand_active_ || auto_is_active();
	}

	void diagnostics::start_capture(int frames)
	{
		if (on_demand_active_) return;

		// Open a new log file for on-demand capture
		SYSTEMTIME st;
		GetLocalTime(&st);
		char buf[128];
		snprintf(buf, sizeof(buf), "diag_%04d%02d%02d_%02d%02d%02d.log",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond);

		std::string path = shared::globals::root_path + "\\rtx_comp\\" + buf;
		open_log(path);

		if (log_file_ == INVALID_HANDLE_VALUE)
		{
			shared::common::log("Diagnostics",
				std::format("Failed to create: {}", path),
				shared::common::LOG_TYPE::LOG_TYPE_ERROR);
			return;
		}

		// Log capture settings
		log_str(std::format("Capture: {} frames\r\n", frames).c_str());
		log_str(std::format("Categories: draws={} vsconst={} vtxdata={} decls={} tex={} present={}\r\n\r\n",
			cat_draw_calls ? 1 : 0, cat_vs_constants ? 1 : 0, cat_vertex_data ? 1 : 0,
			cat_declarations ? 1 : 0, cat_textures ? 1 : 0, cat_present_info ? 1 : 0).c_str());

		// Reset dedup state
		logged_decl_count_ = 0;
		std::memset(logged_decls_, 0, sizeof(logged_decls_));
		reset_frame_diag();

		on_demand_frames_ = frames;
		on_demand_logged_ = 0;
		on_demand_active_ = true;

		shared::common::log("Diagnostics",
			std::format("Capture started: {} frames -> {}", frames, path));
	}

	void diagnostics::stop_capture()
	{
		if (!on_demand_active_) return;
		on_demand_active_ = false;

		log_str("\r\n==== Capture complete ====\r\n");
		close_log();

		// Re-open the auto log file if auto mode is enabled and not done
		if (auto_enabled_ && auto_logged_frames_ < auto_max_frames_)
		{
			std::string path = shared::globals::root_path + "\\rtx_comp\\diagnostics.log";
			log_file_ = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
				nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (log_file_ != INVALID_HANDLE_VALUE)
				SetFilePointer(log_file_, 0, nullptr, FILE_END);
		}

		shared::common::log("Diagnostics",
			std::format("Capture done: {} frames", on_demand_logged_));
	}

	// ---- Hook callbacks ----

	void diagnostics::on_draw_indexed_prim(UINT draw_count, IDirect3DDevice9* /*dev*/,
		D3DPRIMITIVETYPE pt, INT base_vtx, UINT num_verts, UINT prim_count)
	{
		if (!is_active() || draw_count > 200) return;

		auto& ffp = shared::common::ffp_state::get();

		if (cat_draw_calls)
		{
			log_int("  DIP #", static_cast<int>(draw_count));
			log_hex("    decl=", reinterpret_cast<unsigned int>(ffp.last_decl()));
			log_int("    type=", static_cast<int>(pt));
			log_int("    baseVtx=", base_vtx);
			log_int("    numVerts=", static_cast<int>(num_verts));
			log_int("    primCount=", static_cast<int>(prim_count));
			log_int("    stride0=", static_cast<int>(ffp.stream_stride(0)));

			if (ffp.cur_decl_is_skinned())
			{
				log_str("    [SKINNED]\r\n");
				log_int("    boneStart=", ffp.bone_start_reg());
				log_int("    numBones=", ffp.num_bones());
			}

			log_int("    hasNormal=", ffp.cur_decl_has_normal() ? 1 : 0);
			log_int("    hasTexcoord=", ffp.cur_decl_has_texcoord() ? 1 : 0);
			log_int("    tcType=", ffp.cur_decl_texcoord_type());
		}

		// Log texture bindings
		if (cat_textures)
		{
			for (int ts = 0; ts < 8; ts++)
			{
				if (ffp.cur_texture(ts))
				{
					log_int("    tex", ts);
					log_hex("     =", reinterpret_cast<unsigned int>(ffp.cur_texture(ts)));
				}
			}
		}

		// Log raw vertex bytes for early calls
		if (cat_vertex_data && draw_count <= 10 && ffp.stream_vb(0) && ffp.stream_stride(0) > 0)
		{
			auto* vb = ffp.stream_vb(0);
			UINT stride = ffp.stream_stride(0);
			UINT read_off = ffp.stream_offset(0) + static_cast<UINT>(base_vtx) * stride;
			unsigned char* data = nullptr;

			if (SUCCEEDED(vb->Lock(read_off, stride * 2, reinterpret_cast<void**>(&data), D3DLOCK_READONLY)))
			{
				log_int("    vtx0 raw (", static_cast<int>(stride));
				log_str(" bytes):\r\n      ");

				for (UINT b = 0; b < stride && b < 64; b++)
				{
					char hx[4];
					static const char* hex_chars = "0123456789ABCDEF";
					hx[0] = hex_chars[(data[b] >> 4) & 0xF];
					hx[1] = hex_chars[data[b] & 0xF];
					hx[2] = ' '; hx[3] = 0;
					log_str(hx);
					if (b == 11 || b == 15 || b == 19 || b == 23 || b == 27 || b == 31)
						log_str("| ");
				}
				log_str("\r\n");

				if (stride >= 12)
				{
					auto* fp = reinterpret_cast<float*>(data);
					log_floats_dec("      pos: ", fp, 3);
				}

				vb->Unlock();
			}
		}

		// Log key VS constant blocks for first 5 calls
		if (cat_vs_constants && draw_count <= 5)
		{
			auto* vs = ffp.vs_const_data();
			if (shared::common::ffp_state::mat4_is_interesting(&vs[0]))       log_matrix("    c0-c3", &vs[0]);
			if (shared::common::ffp_state::mat4_is_interesting(&vs[4*4]))     log_matrix("    c4-c7", &vs[4*4]);
			if (shared::common::ffp_state::mat4_is_interesting(&vs[8*4]))     log_matrix("    c8-c11", &vs[8*4]);
			if (shared::common::ffp_state::mat4_is_interesting(&vs[12*4]))    log_matrix("    c12-c15", &vs[12*4]);
			if (shared::common::ffp_state::mat4_is_interesting(&vs[16*4]))    log_matrix("    c16-c19", &vs[16*4]);
			if (shared::common::ffp_state::mat4_is_interesting(&vs[20*4]))    log_matrix("    c20-c23", &vs[20*4]);
		}

		// Track unique textures per stage
		if (cat_textures)
			track_unique_textures();

		// Log vertex declaration (deduplicated)
		if (cat_declarations && ffp.last_decl())
			log_decl(ffp.last_decl());
	}

	void diagnostics::on_draw_primitive(UINT draw_count, D3DPRIMITIVETYPE pt,
		UINT start_vtx, UINT prim_count)
	{
		if (!is_active() || !cat_draw_calls || draw_count > 200) return;

		log_int("  DP #", static_cast<int>(draw_count));
		log_int("    type=", static_cast<int>(pt));
		log_int("    startVtx=", static_cast<int>(start_vtx));
		log_int("    primCount=", static_cast<int>(prim_count));
	}

	void diagnostics::on_present(UINT frame_count, UINT draw_count, UINT scene_count)
	{
		if (!is_active()) return;

		if (cat_present_info)
		{
			auto& ffp = shared::common::ffp_state::get();

			log_str("==== PRESENT frame ");
			log_int("", static_cast<int>(frame_count));
			log_int("  diagFrame: ", on_demand_active_ ? on_demand_logged_ : auto_logged_frames_);
			log_int("  drawCalls: ", static_cast<int>(draw_count));
			log_int("  scenes: ", static_cast<int>(scene_count));

			// Log which VS registers were written
			auto* write_log = ffp.vs_const_write_log();
			log_str("  VS regs written: ");
			for (int r = 0; r < 256; r++)
			{
				if (write_log[r])
					log_int("c", r);
			}
			log_str("\r\n");

			// Log unique texture counts per stage
			if (cat_textures)
			{
				log_str("  Unique textures per stage:\r\n");
				for (int ts = 0; ts < 8; ts++)
				{
					if (diag_tex_uniq_[ts] > 0)
					{
						log_int("    stage ", ts);
						log_int("      unique=", diag_tex_uniq_[ts]);
					}
				}
			}
		}

		// Advance frame counter
		if (on_demand_active_)
		{
			on_demand_logged_++;
			if (on_demand_logged_ >= on_demand_frames_)
				stop_capture();
		}
		else
		{
			auto_logged_frames_++;
		}

		reset_frame_diag();
	}

	void diagnostics::on_begin_scene(UINT scene_count)
	{
		if (!is_active() || !cat_present_info) return;

		log_str("-- BeginScene #");
		log_int("", static_cast<int>(scene_count));
	}

	void diagnostics::on_set_vertex_shader(void* shader_ptr)
	{
		if (!is_active() || !cat_vs_constants) return;

		log_hex("  SetVS shader=", reinterpret_cast<unsigned int>(shader_ptr));
	}

	void diagnostics::on_set_vs_const_f(UINT start_reg, const float* data, UINT count)
	{
		if (!is_active() || !cat_vs_constants) return;

		log_int("  SetVSConstF start=", static_cast<int>(start_reg));
		log_int("    count=", static_cast<int>(count));

		if (count == 16)
		{
			// 16-register pack: log as 4 separate 4x4 matrices
			for (int m = 0; m < 4; m++)
			{
				int s = static_cast<int>(start_reg) + m * 4;
				auto label = std::format("    c{}-c{}", s, s + 3);
				log_matrix(label.c_str(), &data[m * 16]);
			}
		}
		else if (count == 4)
		{
			auto label = std::format("    c{}-c{}", start_reg, start_reg + 3);
			log_matrix(label.c_str(), data);
		}
		else if (count >= 1 && count <= 2)
		{
			log_floats_dec("    data: ", data, count * 4);
		}
		else if (count >= 5)
		{
			log_str("    (large write, first 4x4):\r\n");
			log_floats_dec("      ", data, 16);
		}
	}

	void diagnostics::log_decl(IDirect3DVertexDeclaration9* decl)
	{
		// Check if already logged
		for (int i = 0; i < logged_decl_count_; i++)
		{
			if (logged_decls_[i] == decl) return;
		}
		if (logged_decl_count_ >= 32) return;
		logged_decls_[logged_decl_count_++] = decl;

		static const char* usage_names[] = {
			"POSITION", "BLENDWEIGHT", "BLENDINDICES", "NORMAL",
			"PSIZE", "TEXCOORD", "TANGENT", "BINORMAL",
			"TESSFACTOR", "POSITIONT", "COLOR", "FOG", "DEPTH", "SAMPLE"
		};
		static const char* type_names[] = {
			"FLOAT1", "FLOAT2", "FLOAT3", "FLOAT4", "D3DCOLOR",
			"UBYTE4", "SHORT2", "SHORT4", "UBYTE4N", "SHORT2N",
			"SHORT4N", "USHORT2N", "USHORT4N", "UDEC3", "DEC3N",
			"FLOAT16_2", "FLOAT16_4", "UNUSED"
		};

		UINT num_elems = 0;
		if (FAILED(decl->GetDeclaration(nullptr, &num_elems))) return;

		D3DVERTEXELEMENT9 elems[32];
		if (FAILED(decl->GetDeclaration(elems, &num_elems))) return;

		log_hex("  DECL decl=", reinterpret_cast<unsigned int>(decl));
		log_int("    numElems=", static_cast<int>(num_elems));

		auto& ffp = shared::common::ffp_state::get();
		if (ffp.cur_decl_is_skinned())
			log_int("    SKINNED numWeights=", ffp.cur_decl_num_weights());
		if (ffp.cur_decl_has_pos_t())
			log_str("    POSITIONT\r\n");

		for (UINT e = 0; e < num_elems; e++)
		{
			const auto& el = elems[e];
			if (el.Stream == 0xFF) break;

			auto line = std::format("    [s{} +{}] {}{} {}\r\n",
				el.Stream, el.Offset,
				(el.Usage < 14) ? usage_names[el.Usage] : "usage=?",
				std::format("[{}]", el.UsageIndex),
				(el.Type <= 17) ? type_names[el.Type] : "type=?");
			log_str(line.c_str());
		}
	}

	// ---- Low-level log helpers ----

	void diagnostics::log_str(const char* s)
	{
		if (log_file_ == INVALID_HANDLE_VALUE || !s) return;
		DWORD written;
		WriteFile(log_file_, s, static_cast<DWORD>(strlen(s)), &written, nullptr);
	}

	void diagnostics::log_int(const char* prefix, int val)
	{
		auto s = std::format("{}{}\r\n", prefix, val);
		log_str(s.c_str());
	}

	void diagnostics::log_hex(const char* prefix, unsigned int val)
	{
		auto s = std::format("{}{:#010x}\r\n", prefix, val);
		log_str(s.c_str());
	}

	void diagnostics::log_floats_dec(const char* prefix, const float* data, unsigned int count)
	{
		std::string s = prefix;
		for (unsigned int i = 0; i < count; i++)
		{
			s += std::format("{:.6f}", data[i]);
			if (i + 1 < count) s += ", ";
		}
		s += "\r\n";
		log_str(s.c_str());
	}

	void diagnostics::log_matrix(const char* name, const float* m)
	{
		log_str(name);
		log_str(":\r\n");
		log_floats_dec("  row0: ", &m[0], 4);
		log_floats_dec("  row1: ", &m[4], 4);
		log_floats_dec("  row2: ", &m[8], 4);
		log_floats_dec("  row3: ", &m[12], 4);
	}

	void diagnostics::track_unique_textures()
	{
		auto& ffp = shared::common::ffp_state::get();
		for (int ts = 0; ts < 8; ts++)
		{
			auto* tex = ffp.cur_texture(ts);
			if (!tex) continue;

			bool found = false;
			for (int k = 0; k < diag_tex_uniq_[ts] && k < 32; k++)
			{
				if (diag_tex_seen_[ts][k] == tex) { found = true; break; }
			}
			if (!found && diag_tex_uniq_[ts] < 32)
			{
				diag_tex_seen_[ts][diag_tex_uniq_[ts]] = tex;
				diag_tex_uniq_[ts]++;
			}
		}
	}

	void diagnostics::reset_frame_diag()
	{
		for (int ts = 0; ts < 8; ts++)
			diag_tex_uniq_[ts] = 0;
	}
}
