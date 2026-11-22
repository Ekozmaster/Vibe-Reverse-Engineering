#include "std_include.hpp"
#include "tracer.hpp"

#include "shared/common/config.hpp"
#include "shared/common/ffp_state.hpp"
#define HAS_FFP_STATE 1

#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <optional>
#include <string_view>

namespace comp
{
	namespace
	{
		constexpr int DEFAULT_TRIGGER_FRAMES = 2;
		constexpr long MAX_TRIGGER_FRAMES = 100000;

		// dxtrace_progress.txt holds one line at any time: "<frame> <calls> <id>" while capturing,
		// " done" added once the capture file is closed, or "0 0 <id> failed <reason>" for a
		// capture that could not start. <id> is the id of the trigger that asked for the capture,
		// NO_TRIGGER_ID without one. The standalone tracer writes the same format, which
		// "trigger --wait" follows. When it finds no progress it sends its user to the log, so a
		// capture, or a trigger that starts none, whose progress cannot be written says so there, once.
		// Read and written under the tracer's record mutex, as the progress file is.
		bool progress_failure_logged = false;

		void write_progress_line(const std::string& line)
		{
			const std::string path = shared::globals::root_path + "\\dxtrace_progress.txt";
			FILE* f = fopen(path.c_str(), "w");
			// Of the first call that failed: a later one that succeeds may change errno
			int write_errno = errno;
			bool written = false;
			if (f)
			{
				written = fprintf(f, "%s\n", line.c_str()) > 0;
				if (!written)
					write_errno = errno;
				if (fclose(f) != 0 && written)
				{
					written = false;
					write_errno = errno;
				}
			}
			if (written || progress_failure_logged)
				return;

			progress_failure_logged = true;
			shared::common::log("Tracer", std::format("Cannot write {}: {}", path, strerror(write_errno)),
				shared::common::LOG_TYPE::LOG_TYPE_ERROR);
		}

		void write_progress(int frame, int calls, const std::string& trigger_id, bool done)
		{
			write_progress_line(std::format("{} {} {}{}", frame, calls, trigger_id, done ? " done" : ""));
		}

		void write_capture_failure(const std::string& trigger_id, const std::string& reason)
		{
			write_progress_line(std::format("0 0 {} failed {}", trigger_id, reason));
		}

		// The value of the line "<key>=<value>" of a trigger file; nullopt when it has no such line
		std::optional<std::string> trigger_value(std::string_view text, std::string_view key)
		{
			while (!text.empty())
			{
				const size_t line_end = text.find('\n');
				std::string_view line = text.substr(0, line_end);
				text.remove_prefix(line_end == std::string_view::npos ? text.size() : line_end + 1);

				if (!line.empty() && line.back() == '\r')
					line.remove_suffix(1);
				if (line.size() >= key.size() + 1 && line.starts_with(key) && line[key.size()] == '=')
					return std::string(line.substr(key.size() + 1));
			}
			return std::nullopt;
		}

		bool is_blank(std::string_view text)
		{
			return text.find_first_not_of(" \t\r\v\f") == std::string_view::npos;
		}

		// The id a trigger carries: 16 lowercase hex digits with nothing but blanks behind them
		// on the line. NO_TRIGGER_ID for a trigger without one.
		std::string trigger_id(std::string_view text)
		{
			constexpr size_t ID_LENGTH = 16;
			const auto token = trigger_value(text, "id");
			if (!token || token->size() < ID_LENGTH || !is_blank(std::string_view(*token).substr(ID_LENGTH)))
				return tracer::NO_TRIGGER_ID;

			const std::string id = token->substr(0, ID_LENGTH);
			return id.find_first_not_of("0123456789abcdef") == std::string::npos ? id : tracer::NO_TRIGGER_ID;
		}

		// The frame count a trigger asks for, at most MAX_TRIGGER_FRAMES; nullopt unless the
		// token starts with the digits of a number from 1 up and has nothing but blanks behind them
		std::optional<int> trigger_frame_count(const std::string& token)
		{
			// strtol alone would skip blanks and take a sign
			if (token.empty() || !isdigit(static_cast<unsigned char>(token.front())))
				return std::nullopt;

			char* end = nullptr;
			const long frames = strtol(token.c_str(), &end, 10);
			if (!is_blank(end) || frames < 1)
				return std::nullopt;
			return static_cast<int>((std::min)(frames, MAX_TRIGGER_FRAMES));
		}
	}

	tracer::tracer()
	{
		p_this = this;
		buffer_ = new char[BUFFER_SIZE];

		auto& cfg = shared::common::config::get();
		backtrace_depth_ = cfg.tracer.backtrace_depth;
		output_dir_ = cfg.tracer.output_dir;

		shared::common::log("Tracer", "Module initialized.",
			shared::common::LOG_TYPE::LOG_TYPE_DEFAULT, false);
	}

	tracer::~tracer()
	{
		if (capturing_)
			stop_capture();

		delete[] buffer_;
		buffer_ = nullptr;
		p_this = nullptr;
	}

	// ---- Capture control ----

	std::string tracer::generate_default_filename()
	{
		SYSTEMTIME st;
		GetLocalTime(&st);
		char buf[64];
		snprintf(buf, sizeof(buf), "dxtrace_%04d%02d%02d_%02d%02d%02d",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond);
		return buf;
	}

	uint32_t tracer::classify_method(const char* method)
	{
		// Get* calls
		if (strncmp(method, "Get", 3) == 0)
			return TRACE_GETTERS;

		// Draw calls
		if (strncmp(method, "Draw", 4) == 0 || strcmp(method, "ProcessVertices") == 0)
			return TRACE_DRAW;

		// Scene flow
		if (strcmp(method, "BeginScene") == 0 || strcmp(method, "EndScene") == 0 ||
			strcmp(method, "Present") == 0 || strcmp(method, "Clear") == 0 ||
			strcmp(method, "Reset") == 0)
			return TRACE_SCENE;

		// Shaders & shader constants
		if (strstr(method, "Shader"))
			return TRACE_SHADERS;

		// Render state, texture stage state, sampler state, state blocks
		if (strstr(method, "RenderState") || strstr(method, "StageState") ||
			strstr(method, "SamplerState") || strstr(method, "StateBlock") ||
			strcmp(method, "BeginStateBlock") == 0 || strcmp(method, "EndStateBlock") == 0)
			return TRACE_STATE;

		// Textures (SetTexture, CreateTexture, CreateVolumeTexture, CreateCubeTexture)
		if (strcmp(method, "SetTexture") == 0 ||
			(strncmp(method, "Create", 6) == 0 && strstr(method, "Texture")))
			return TRACE_TEXTURES;

		// Transforms, viewport, materials, lights
		if (strstr(method, "Transform") || strstr(method, "Viewport") ||
			strstr(method, "Material") || strstr(method, "Light") ||
			strcmp(method, "SetClipPlane") == 0)
			return TRACE_TRANSFORMS;

		// Vertex setup: stream source, indices, FVF, vertex declarations, VB/IB creation
		if (strstr(method, "StreamSource") || strstr(method, "Indices") ||
			strstr(method, "FVF") || strstr(method, "VertexDeclaration") ||
			strcmp(method, "CreateVertexBuffer") == 0 || strcmp(method, "CreateIndexBuffer") == 0 ||
			strstr(method, "StreamSourceFreq"))
			return TRACE_VERTEX;

		// Resource creation & surface ops
		if (strncmp(method, "Create", 6) == 0 ||
			strstr(method, "RenderTarget") || strstr(method, "DepthStencil") ||
			strstr(method, "Surface") || strcmp(method, "StretchRect") == 0 ||
			strcmp(method, "ColorFill") == 0 || strcmp(method, "UpdateTexture") == 0)
			return TRACE_RESOURCES;

		return TRACE_MISC;
	}

	void tracer::start_capture(int num_frames, const std::string& filename, const std::string& trigger_id)
	{
		std::lock_guard<std::recursive_mutex> lock(record_mutex_);
		if (capturing_) return;
		progress_failure_logged = false;

		// Ensure output directory exists
		std::string dir_path = shared::globals::root_path + "\\" + output_dir_;
		CreateDirectoryA(dir_path.c_str(), nullptr);

		// Build full path
		std::string full_path = dir_path + "\\" + filename + ".jsonl";

		log_file_ = CreateFileA(full_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
			nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (log_file_ == INVALID_HANDLE_VALUE)
		{
			const std::string reason = std::format("cannot create {}: Windows error {}", full_path, GetLastError());
			shared::common::log("Tracer", "Capture not started, " + reason, shared::common::LOG_TYPE::LOG_TYPE_ERROR);
			write_capture_failure(trigger_id, reason);
			return;
		}

		sequence_ = 0;
		frame_index_ = 0;
		frames_captured_ = 0;
		frames_to_capture_ = num_frames;
		write_pos_ = 0;

#ifdef HAS_FFP_STATE
		// Save FFP state and disable during capture to record unmodified game calls
		ffp_was_enabled_ = shared::common::ffp_state::get().is_enabled();
		shared::common::ffp_state::get().set_enabled(false);
#endif

		capturing_ = true;
		capture_trigger_id_ = trigger_id;
		last_capture_path_ = full_path;
		write_progress(frame_index_, sequence_, capture_trigger_id_, false);

		shared::common::log("Tracer",
			std::format("Capture started: {} frames -> {}", num_frames, full_path));
	}

	void tracer::stop_capture()
	{
		std::lock_guard<std::recursive_mutex> lock(record_mutex_);
		if (!capturing_) return;
		capturing_ = false;

		flush_buffer();

		// Get file size before closing
		LARGE_INTEGER file_size;
		file_size.QuadPart = 0;
		if (log_file_ != INVALID_HANDLE_VALUE)
			GetFileSizeEx(log_file_, &file_size);

		last_capture_size_ = static_cast<uint64_t>(file_size.QuadPart);
		last_capture_records_ = sequence_;

		if (log_file_ != INVALID_HANDLE_VALUE)
		{
			CloseHandle(log_file_);
			log_file_ = INVALID_HANDLE_VALUE;
		}
		write_progress(frames_captured_, sequence_, capture_trigger_id_, true);

#ifdef HAS_FFP_STATE
		// Restore FFP to its pre-capture state (don't force it on if config had it off)
		shared::common::ffp_state::get().set_enabled(ffp_was_enabled_);
#endif

		shared::common::log("Tracer",
			std::format("Capture done: {} frames, {} calls, {:.1f} KB",
				frames_captured_, sequence_, last_capture_size_ / 1024.0));
	}

	void tracer::start_capture_delayed(int num_frames, const std::string& filename, float delay_seconds)
	{
		if (capturing_ || waiting_) return;

		if (delay_seconds <= 0.0f)
		{
			start_capture(num_frames, filename);
			return;
		}

		pending_frames_ = num_frames;
		pending_filename_ = filename;
		delay_ms_ = static_cast<DWORD>(delay_seconds * 1000.0f);
		delay_start_tick_ = GetTickCount();
		waiting_ = true;

		shared::common::log("Tracer",
			std::format("Capture will start in {:.1f}s", delay_seconds));
	}

	void tracer::cancel_delayed()
	{
		if (!waiting_) return;
		waiting_ = false;
		shared::common::log("Tracer", "Delayed capture cancelled");
	}

	float tracer::delay_remaining() const
	{
		if (!waiting_) return 0.0f;
		DWORD elapsed = GetTickCount() - delay_start_tick_;
		if (elapsed >= delay_ms_) return 0.0f;
		return static_cast<float>(delay_ms_ - elapsed) / 1000.0f;
	}

	void tracer::check_trigger_file()
	{
		std::lock_guard<std::recursive_mutex> lock(record_mutex_);
		const std::string trigger_path = shared::globals::root_path + "\\dxtrace_capture.trigger";

		// No trigger, or one its writer still has open: that one is taken at a later frame
		HANDLE hf = CreateFileA(trigger_path.c_str(), GENERIC_READ, FILE_SHARE_READ,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hf == INVALID_HANDLE_VALUE)
		{
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
				undeleted_trigger_id_.clear();
			return;
		}

		char buf[256] = {};
		DWORD bytes_read = 0;
		ReadFile(hf, buf, sizeof(buf) - 1, &bytes_read, nullptr);
		CloseHandle(hf);

		const std::string_view text(buf, bytes_read);
		const std::string id = trigger_id(text);
		if (id == undeleted_trigger_id_)
		{
			// Left in the folder, it would start a capture in the next run of the game
			if (DeleteFileA(trigger_path.c_str()))
				undeleted_trigger_id_.clear();
			return;
		}

		const auto frames_line = trigger_value(text, "frames");
		const auto frames = frames_line ? trigger_frame_count(*frames_line) : DEFAULT_TRIGGER_FRAMES;

		if (frames)
		{
			shared::common::log("Tracer", std::format("External trigger: {} frames", *frames));
			start_capture(*frames, generate_default_filename(), id);
		}
		else
		{
			progress_failure_logged = false;
			write_capture_failure(id, std::format("frames={} is not a number of frames from 1 up", *frames_line));
		}

		// Deleted only now that the progress file answers it, so whoever wrote the trigger
		// never finds it gone with the answer still to come
		if (DeleteFileA(trigger_path.c_str()))
		{
			undeleted_trigger_id_.clear();
		}
		else
		{
			shared::common::log("Tracer", std::format("Trigger file not deleted: Windows error {}", GetLastError()),
				shared::common::LOG_TYPE::LOG_TYPE_ERROR);
			undeleted_trigger_id_ = id;
		}
	}

	void tracer::on_present()
	{
		// A capture the trigger file starts begins with the next frame, as a delayed one does
		if (!capturing_ && !waiting_)
		{
			check_trigger_file();
			return;
		}

		// Check delayed start countdown
		if (waiting_)
		{
			DWORD elapsed = GetTickCount() - delay_start_tick_;
			if (elapsed >= delay_ms_)
			{
				waiting_ = false;
				start_capture(pending_frames_, pending_filename_);
			}
			return;
		}

		// stop_capture can have run on another thread since capturing_ was read above
		std::lock_guard<std::recursive_mutex> lock(record_mutex_);
		if (!capturing_) return;

		flush_buffer();
		frame_index_++;
		frames_captured_ = frame_index_;

		if (frame_index_ >= frames_to_capture_)
			stop_capture();
		else
			write_progress(frame_index_, sequence_, capture_trigger_id_, false);
	}

	void tracer::on_reset()
	{
		if (capturing_)
			stop_capture();
	}

	// ---- Buffer management ----

	void tracer::flush_buffer()
	{
		if (write_pos_ == 0 || log_file_ == INVALID_HANDLE_VALUE) return;
		DWORD written;
		WriteFile(log_file_, buffer_, static_cast<DWORD>(write_pos_), &written, nullptr);
		write_pos_ = 0;
	}

	void tracer::buf_append(const char* str, size_t len)
	{
		if (write_pos_ + len >= BUFFER_SIZE)
			flush_buffer();
		if (len >= BUFFER_SIZE)
			return; // single record too large, skip

		memcpy(buffer_ + write_pos_, str, len);
		write_pos_ += len;
	}

	void tracer::buf_printf(const char* fmt, ...)
	{
		if (write_pos_ >= FLUSH_THRESHOLD)
			flush_buffer();

		va_list ap;
		va_list ap_again;
		va_start(ap, fmt);
		va_copy(ap_again, ap);
		int n = vsnprintf(buffer_ + write_pos_, BUFFER_SIZE - write_pos_, fmt, ap);
		va_end(ap);

		// Text too long for the room behind what is buffered goes into the emptied buffer
		if (n >= 0 && static_cast<size_t>(n) >= BUFFER_SIZE - write_pos_)
		{
			flush_buffer();
			n = vsnprintf(buffer_ + write_pos_, BUFFER_SIZE - write_pos_, fmt, ap_again);
		}
		va_end(ap_again);

		// vsnprintf returns the length of the whole text, which is in the buffer only if it fit
		if (n > 0 && static_cast<size_t>(n) < BUFFER_SIZE - write_pos_)
			write_pos_ += static_cast<size_t>(n);
	}

	void tracer::buf_write_float(float val)
	{
		// Handle special float values for JSON compatibility
		DWORD bits;
		memcpy(&bits, &val, sizeof(bits));
		bool is_nan = ((bits & 0x7F800000) == 0x7F800000) && (bits & 0x007FFFFF);
		bool is_inf = ((bits & 0x7FFFFFFF) == 0x7F800000);

		if (is_nan || is_inf)
			buf_append("null", 4);
		else
			buf_printf("%.8g", val);
	}

	void tracer::close_sections()
	{
		if (args_open_)
		{
			buf_append("}", 1);
			args_open_ = false;
		}
		if (data_open_)
		{
			buf_append("}", 1);
			data_open_ = false;
		}
	}

	// ---- JSONL builder ----

	void tracer::record_begin(const char* method, int slot)
	{
		if (!(classify_method(method) & category_mask_))
		{
			skipping_ = true;
			return;
		}
		skipping_ = false;

		buf_printf("{\"frame\":%d,\"seq\":%d,\"slot\":%d,\"method\":\"%s\",\"args\":{",
			frame_index_, sequence_, slot, method);
		first_arg_ = true;
		args_open_ = true;
		data_open_ = false;
	}

	void tracer::record_arg_uint(const char* name, DWORD val)
	{
		if (skipping_) return;
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":%u", name, val);
		first_arg_ = false;
	}

	void tracer::record_arg_int(const char* name, INT val)
	{
		if (skipping_) return;
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":%d", name, val);
		first_arg_ = false;
	}

	void tracer::record_arg_float(const char* name, float val)
	{
		if (skipping_) return;
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":", name);
		buf_write_float(val);
		first_arg_ = false;
	}

	void tracer::record_arg_ptr(const char* name, const void* val)
	{
		if (skipping_) return;
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":\"0x%08X\"", name, reinterpret_cast<DWORD>(val)); // x64: use uintptr_t
		first_arg_ = false;
	}

	void tracer::record_data_float(const char* name, const float* data, UINT count)
	{
		if (skipping_ || !data || count == 0) return;

		// Open data section (close args first)
		if (args_open_)
		{
			buf_append("},\"data\":{", 10);
			args_open_ = false;
			data_open_ = true;
		}
		else if (data_open_)
		{
			buf_append(",", 1);
		}

		buf_printf("\"%s\":[", name);

		__try
		{
			for (UINT i = 0; i < count && i < 1024; i++)
			{
				if (i > 0) buf_append(",", 1);
				buf_write_float(data[i]);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			// Pointer was invalid; output what we have
		}

		buf_append("]", 1);
	}

	void tracer::record_data_int(const char* name, const int* data, UINT count)
	{
		if (skipping_ || !data || count == 0) return;

		if (args_open_)
		{
			buf_append("},\"data\":{", 10);
			args_open_ = false;
			data_open_ = true;
		}
		else if (data_open_)
		{
			buf_append(",", 1);
		}

		buf_printf("\"%s\":[", name);

		__try
		{
			for (UINT i = 0; i < count && i < 1024; i++)
			{
				if (i > 0) buf_append(",", 1);
				buf_printf("%d", data[i]);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

		buf_append("]", 1);
	}

	void tracer::record_data_shader(const char* name, const DWORD* bytecode)
	{
		if (skipping_ || !bytecode) return;

		if (args_open_)
		{
			buf_append("},\"data\":{", 10);
			args_open_ = false;
			data_open_ = true;
		}
		else if (data_open_)
		{
			buf_append(",", 1);
		}

		buf_printf("\"%s\":\"", name);

		__try
		{
			for (int i = 0; i < 16384; i++)
			{
				DWORD token = bytecode[i];
				buf_printf("%08X", token);
				if ((token & 0x0000FFFF) == 0x0000FFFF)
					break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

		buf_append("\"", 1);
	}

	void tracer::record_data_vtxdecl(const char* name, const BYTE* elements)
	{
		if (skipping_ || !elements) return;

		if (args_open_)
		{
			buf_append("},\"data\":{", 10);
			args_open_ = false;
			data_open_ = true;
		}
		else if (data_open_)
		{
			buf_append(",", 1);
		}

		buf_printf("\"%s\":[", name);

		__try
		{
			// D3DVERTEXELEMENT9: {WORD Stream, WORD Offset, BYTE Type, BYTE Method, BYTE Usage, BYTE UsageIndex}
			struct VtxElem { WORD Stream; WORD Offset; BYTE Type; BYTE Method; BYTE Usage; BYTE UsageIndex; };
			const auto* el = reinterpret_cast<const VtxElem*>(elements);

			for (int i = 0; i < 64; i++)
			{
				if (el[i].Stream == 0xFF) break;
				if (i > 0) buf_append(",", 1);
				buf_printf("{\"Stream\":%u,\"Offset\":%u,\"Type\":%u,\"Method\":%u,\"Usage\":%u,\"UsageIndex\":%u}",
					el[i].Stream, el[i].Offset, el[i].Type, el[i].Method, el[i].Usage, el[i].UsageIndex);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

		buf_append("]", 1);
	}

	void tracer::record_clear_data(DWORD flags, DWORD color, float z, DWORD stencil)
	{
		if (skipping_) return;
		if (args_open_)
		{
			buf_append("},\"data\":{", 10);
			args_open_ = false;
			data_open_ = true;
		}

		buf_printf("\"Flags\":%u,\"Color\":\"0x%08X\",\"Z\":", flags, color);
		buf_write_float(z);
		buf_printf(",\"Stencil\":%u", stencil);
	}

	void tracer::record_backtrace()
	{
		if (skipping_ || backtrace_depth_ <= 0) return;

		close_sections();

		void* frames[16];
		int depth = backtrace_depth_;
		if (depth > 16) depth = 16;

		USHORT count = CaptureStackBackTrace(2, static_cast<DWORD>(depth), frames, nullptr);

		if (count > 0)
		{
			buf_append(",\"backtrace\":[", 14);
			for (USHORT i = 0; i < count; i++)
			{
				if (i > 0) buf_append(",", 1);
				buf_printf("\"0x%08X\"", reinterpret_cast<DWORD>(frames[i])); // x64: use uintptr_t
			}
			buf_append("]", 1);
		}
	}

	void tracer::record_created_handle(const void* handle)
	{
		if (skipping_ || !handle) return;
		// Append created_handle field before record_end closes the line
		close_sections();
		buf_printf(",\"created_handle\":\"0x%08X\"", reinterpret_cast<DWORD>(handle)); // x64: use uintptr_t
	}

	void tracer::record_end()
	{
		if (skipping_)
		{
			skipping_ = false;
			return;
		}

		close_sections();
		buf_printf(",\"ts\":%u}\n", static_cast<DWORD>(GetTickCount()));
		sequence_++;

		if (write_pos_ >= FLUSH_THRESHOLD)
			flush_buffer();
	}
}
