#include "std_include.hpp"
#include "tracer.hpp"

#include "shared/common/config.hpp"
#include "shared/common/ffp_state.hpp"
#define HAS_FFP_STATE 1

#include <cstdarg>
#include <cstdio>
#include <cmath>

namespace comp
{
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

	void tracer::start_capture(int num_frames, const std::string& filename)
	{
		if (capturing_) return;

		// Ensure output directory exists
		std::string dir_path = shared::globals::root_path + "\\" + output_dir_;
		CreateDirectoryA(dir_path.c_str(), nullptr);

		// Build full path
		std::string full_path = dir_path + "\\" + filename + ".jsonl";

		log_file_ = CreateFileA(full_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
			nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (log_file_ == INVALID_HANDLE_VALUE)
		{
			shared::common::log("Tracer",
				std::format("Failed to create: {}", full_path),
				shared::common::LOG_TYPE::LOG_TYPE_ERROR);
			return;
		}

		sequence_ = 0;
		frame_index_ = 0;
		frames_captured_ = 0;
		frames_to_capture_ = num_frames;
		write_pos_ = 0;

#ifdef HAS_FFP_STATE
		// Disable FFP during capture to record unmodified game calls
		shared::common::ffp_state::get().set_enabled(false);
#endif

		capturing_ = true;
		last_capture_path_ = full_path;

		shared::common::log("Tracer",
			std::format("Capture started: {} frames -> {}", num_frames, full_path));
	}

	void tracer::stop_capture()
	{
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

#ifdef HAS_FFP_STATE
		// Re-enable FFP
		shared::common::ffp_state::get().set_enabled(true);
#endif

		shared::common::log("Tracer",
			std::format("Capture done: {} frames, {} calls, {:.1f} KB",
				frames_captured_, sequence_, last_capture_size_ / 1024.0));
	}

	void tracer::on_present()
	{
		if (!capturing_) return;

		flush_buffer();
		frame_index_++;
		frames_captured_ = frame_index_;

		if (frame_index_ >= frames_to_capture_)
			stop_capture();
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
		va_start(ap, fmt);
		int n = vsnprintf(buffer_ + write_pos_, BUFFER_SIZE - write_pos_, fmt, ap);
		va_end(ap);

		if (n > 0)
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
		buf_printf("{\"frame\":%d,\"seq\":%d,\"slot\":%d,\"method\":\"%s\",\"args\":{",
			frame_index_, sequence_, slot, method);
		first_arg_ = true;
		args_open_ = true;
		data_open_ = false;
	}

	void tracer::record_arg_uint(const char* name, DWORD val)
	{
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":%u", name, val);
		first_arg_ = false;
	}

	void tracer::record_arg_int(const char* name, INT val)
	{
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":%d", name, val);
		first_arg_ = false;
	}

	void tracer::record_arg_float(const char* name, float val)
	{
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":", name);
		buf_write_float(val);
		first_arg_ = false;
	}

	void tracer::record_arg_ptr(const char* name, const void* val)
	{
		if (!first_arg_) buf_append(",", 1);
		buf_printf("\"%s\":\"0x%08X\"", name, reinterpret_cast<DWORD>(val));
		first_arg_ = false;
	}

	void tracer::record_data_float(const char* name, const float* data, UINT count)
	{
		if (!data || count == 0) return;

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
		if (!data || count == 0) return;

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
		if (!bytecode) return;

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
		if (!elements) return;

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
		if (backtrace_depth_ <= 0) return;

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
				buf_printf("\"0x%08X\"", reinterpret_cast<DWORD>(frames[i]));
			}
			buf_append("]", 1);
		}
	}

	void tracer::record_created_handle(const void* handle)
	{
		if (!handle) return;
		// Append created_handle field before record_end closes the line
		close_sections();
		buf_printf(",\"created_handle\":\"0x%08X\"", reinterpret_cast<DWORD>(handle));
	}

	void tracer::record_end()
	{
		close_sections();
		buf_printf(",\"ts\":%u}\n", static_cast<DWORD>(GetTickCount()));
		sequence_++;

		if (write_pos_ >= FLUSH_THRESHOLD)
			flush_buffer();
	}
}
