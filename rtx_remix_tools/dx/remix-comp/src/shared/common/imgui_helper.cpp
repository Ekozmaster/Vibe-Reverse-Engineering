#include "std_include.hpp"

#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui_internal.h"
#include "imgui_helper.hpp"

namespace ImGui
{
	void Spacing(const float& x, const float& y) {
		Dummy(ImVec2(x, y));
	}

	void CenterText(const char* text, bool disabled)
	{
		const auto text_width = CalcTextSize(text).x;
		SetCursorPosX(GetContentRegionAvail().x * 0.5f - text_width * 0.5f);
		if (!disabled) {
			TextUnformatted(text);
		}
		else {
			TextDisabled("%s", text);
		}
	}

	void AddUnterline(ImColor col)
	{
		ImVec2 min = GetItemRectMin();
		ImVec2 max = GetItemRectMax();
		min.y = max.y;
		GetWindowDrawList()->AddLine(min, max, col, 1.0f);
	}

	void TextURL(const char* name, const char* url, bool use_are_you_sure_popup)
	{
		TextUnformatted(name);
		if (IsItemHovered())
		{
			if (IsMouseClicked(0))
			{
				if (use_are_you_sure_popup)
				{
					if (!IsPopupOpen("Are You Sure?"))
					{
						PushID(name);
						OpenPopup("Are You Sure?");
						PopID();
					}
				}
				else
				{
					ImGuiIO& io = GetIO();
					io.AddMouseButtonEvent(0, false);
					io.AddMousePosEvent(0, 0);
					ShellExecuteA(nullptr, nullptr, url, nullptr, nullptr, SW_SHOW);
				}
			}

			AddUnterline(GetStyle().Colors[ImGuiCol_TabHovered]);
			SetTooltip("Clicking this will open the following link:\n[%s]", url);
		}
		else {
			AddUnterline(GetStyle().Colors[ImGuiCol_Button]);
		}

		PushID(name);
		if (BeginPopupModal("Are You Sure?", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings))
		{
			Spacing(0.0f, 0.0f);

			const auto half_width = GetContentRegionMax().x * 0.5f;
			auto line1_str = "This will open the following link:";

			Spacing();
			SetCursorPosX(5.0f + half_width - (CalcTextSize(line1_str).x * 0.5f));
			TextUnformatted(line1_str);

			SetCursorPosX(5.0f + half_width - (CalcTextSize(url).x * 0.5f));
			TextUnformatted(url);

			InvisibleButton("##spacer", ImVec2(CalcTextSize(url).x, 1));

			Spacing(0, 8);
			Spacing(0, 0); SameLine();

			ImVec2 button_size(half_width - 6.0f - GetStyle().WindowPadding.x, 0.0f);
			if (Button("Open", button_size))
			{
				ImGuiIO& io = GetIO();
				io.AddMouseButtonEvent(0, false);
				io.AddMousePosEvent(0, 0);
				CloseCurrentPopup();
				ShellExecuteA(nullptr, nullptr, url, nullptr, nullptr, SW_SHOW);
			}

			SameLine(0, 6.0f);
			if (Button("Cancel", button_size)) {
				CloseCurrentPopup();
			}

			EndPopup();
		}
		PopID();
	}

	void SetCursorForCenteredText(const char* text)
	{
		const auto text_width = CalcTextSize(text).x;
		SetCursorPosX(GetContentRegionAvail().x * 0.5f - text_width * 0.5f);
	}
}
