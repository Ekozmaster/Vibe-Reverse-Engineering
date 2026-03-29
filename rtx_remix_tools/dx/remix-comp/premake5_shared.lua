-- premake5_shared.lua
-- Shared static library and dependencies for remix-comp.
-- Include this from per-game premake files via: dofile(REMIX_COMP .. "/premake5_shared.lua")
--
-- Expects REMIX_COMP_SRC to be set to the absolute or relative path to remix-comp/
-- before calling dofile. Example:
--   REMIX_COMP_SRC = "../../../../rtx_remix_tools/dx/remix-comp"
--   dofile(REMIX_COMP_SRC .. "/premake5_shared.lua")

if not REMIX_COMP_SRC then
	REMIX_COMP_SRC = "."
end

dependencies = {
	basePath = REMIX_COMP_SRC .. "/deps"
}

function dependencies.load()
	dir = path.join(dependencies.basePath, "premake/*.lua")
	deps = os.matchfiles(dir)

	for i, dep in pairs(deps) do
		dep = dep:gsub(".lua", "")
		require(dep)
	end
end

function dependencies.imports()
	for i, proj in pairs(dependencies) do
		if type(i) == 'number' then
			proj.import()
		end
	end
end

function dependencies.projects()
	for i, proj in pairs(dependencies) do
		if type(i) == 'number' then
			proj.project()
		end
	end
end

dependencies.load()

-- Shared static library project
project "_shared"
	kind "StaticLib"
	language "C++"

	targetdir "bin/%{cfg.buildcfg}"
	objdir "obj/%{cfg.buildcfg}"

	pchheader "std_include.hpp"
	pchsource(REMIX_COMP_SRC .. "/src/shared/std_include.cpp")

	files {
		REMIX_COMP_SRC .. "/src/shared/**.hpp",
		REMIX_COMP_SRC .. "/src/shared/**.cpp",
	}

	includedirs {
		"%{prj.location}/src",
		REMIX_COMP_SRC .. "/src",
	}

	resincludedirs {
		"$(ProjectDir)src"
	}

	buildoptions {
		"/Zm100 -Zm100"
	}

	flags {
		"UndefinedIdentifiers"
	}

	warnings "Extra"
	dependencies.imports()

	group "Dependencies"
		dependencies.projects()
	group ""
