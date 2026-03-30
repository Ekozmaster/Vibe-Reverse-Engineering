@echo off
setlocal enabledelayedexpansion

:: remix-comp build script
:: Usage: build.bat [release|debug] [--name OutputName] [--comp CompDir]
::
:: Examples:
::   build.bat                          Build release remix-comp.asi
::   build.bat debug                    Build debug remix-comp.asi
::   build.bat release --name Warband   Build release Warband-comp.asi
::   build.bat release --name Warband --comp ..\..\patches\Warband\proxy\comp
::                                      Build per-game variant from custom comp dir

set "ROOT=%~dp0"
set "CONFIG=release"
set "NAME=remix-comp"
set "COMP_DIR=%ROOT%src\comp"
set "CUSTOM_COMP=0"

:: Parse args
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="release" ( set "CONFIG=release" & shift & goto :parse_args )
if /i "%~1"=="debug"   ( set "CONFIG=debug"   & shift & goto :parse_args )
if /i "%~1"=="--name"  ( set "NAME=%~2-comp"  & shift & shift & goto :parse_args )
if /i "%~1"=="--comp"  ( set "COMP_DIR=%~2" & set "CUSTOM_COMP=1" & shift & shift & goto :parse_args )
echo Unknown argument: %~1
exit /b 1
:args_done

:: Find Visual Studio
set "VCVARS="
for %%p in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
) do (
    if exist %%p set "VCVARS=%%~p"
)
if "%VCVARS%"=="" (
    echo ERROR: Visual Studio 2022 not found
    exit /b 1
)
call "%VCVARS%" x86 >nul 2>&1
if errorlevel 1 ( echo ERROR: vcvarsall.bat failed & exit /b 1 )

:: Paths
set "SRC=%ROOT%src"
set "DEPS=%ROOT%deps"
set "OUT=%ROOT%build\bin\%CONFIG%"
set "OBJ=%ROOT%build\obj\%CONFIG%"

:: Per-game output: .asi goes to the game's patches folder when --comp is custom
if "!CUSTOM_COMP!"=="1" (
    for %%G in ("!COMP_DIR!\..\..") do set "GAME_DIR=%%~fG"
    set "GAME_OUT=!GAME_DIR!\build\!CONFIG!"
    set "GAME_OBJ=!GAME_DIR!\build\obj\!CONFIG!"
) else (
    set "GAME_OUT=!OUT!"
    set "GAME_OBJ=!OBJ!\comp"
)

mkdir "%OUT%" 2>nul
mkdir "%OBJ%\minhook" 2>nul
mkdir "%OBJ%\imgui" 2>nul
mkdir "%OBJ%\shared" 2>nul
mkdir "%GAME_OUT%" 2>nul
mkdir "%GAME_OBJ%" 2>nul

:: Include paths
set "INC=/I"%SRC%" /I"%DEPS%\bridge_api" /I"%DEPS%\dxsdk\Include" /I"%DEPS%\imgui" /I"%DEPS%\minhook\include""

:: Lib search path
set "LIBPATH=/LIBPATH:"%DEPS%\dxsdk\Lib\x86""

:: Common compiler flags
set "CF=/nologo /std:c++latest /W4 /MP /EHsc /Zm100"
set "CF=%CF% /wd4239 /wd4369 /wd4505 /wd4996 /wd5311 /wd6001 /wd6385 /wd6386 /wd26812"
set "CF=%CF% /D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS /D_WINDOWS /DWIN32"

:: Config-specific flags
if /i "%CONFIG%"=="release" (
    set "CF=%CF% /O2 /GL /Gy /Oi /GF /MT /Zi /DNDEBUG /WX"
    set "LF=/LTCG /OPT:REF /OPT:ICF"
) else (
    set "CF=%CF% /Od /MTd /ZI /DDEBUG /D_DEBUG"
    set "LF="
)

echo.
echo === remix-comp build ===
echo Config:  %CONFIG%
echo Output:  %GAME_OUT%\%NAME%.asi
echo CompDir: %COMP_DIR%
echo.

:: -------------------------------------------------------
:: Step 1: minhook (C static lib)
:: -------------------------------------------------------
echo [1/4] minhook
set "MH_SRC=%DEPS%\minhook\src"
cl /nologo /c /W0 /MP /MT /O2 ^
    /I"%DEPS%\minhook\include" ^
    /Fo"%OBJ%\minhook\\" ^
    "%MH_SRC%\buffer.c" ^
    "%MH_SRC%\hook.c" ^
    "%MH_SRC%\trampoline.c" ^
    "%MH_SRC%\hde\hde32.c" ^
    "%MH_SRC%\hde\hde64.c"
if errorlevel 1 goto :fail
lib /nologo /OUT:"%OUT%\minhook.lib" "%OBJ%\minhook\*.obj"
if errorlevel 1 goto :fail

:: -------------------------------------------------------
:: Step 2: imgui (C++ static lib, no PCH)
:: -------------------------------------------------------
echo [2/4] imgui
set "IM=%DEPS%\imgui"
cl /nologo /c /W0 /MP /std:c++latest /MT /O2 /EHsc ^
    /I"%IM%" ^
    /Fo"%OBJ%\imgui\\" ^
    "%IM%\imgui.cpp" ^
    "%IM%\imgui_demo.cpp" ^
    "%IM%\imgui_draw.cpp" ^
    "%IM%\imgui_tables.cpp" ^
    "%IM%\imgui_widgets.cpp" ^
    "%IM%\backends\imgui_impl_dx9.cpp" ^
    "%IM%\backends\imgui_impl_win32.cpp" ^
    "%IM%\misc\cpp\imgui_stdlib.cpp"
if errorlevel 1 goto :fail
lib /nologo /OUT:"%OUT%\imgui.lib" "%OBJ%\imgui\*.obj"
if errorlevel 1 goto :fail

:: -------------------------------------------------------
:: Step 3: _shared (C++ static lib with PCH)
:: -------------------------------------------------------
echo [3/4] _shared

:: Create PCH
cl /nologo /c %CF% %INC% ^
    /Yc"std_include.hpp" /Fp"%OBJ%\shared\shared.pch" ^
    /Fo"%OBJ%\shared\std_include.obj" ^
    "%SRC%\shared\std_include.cpp"
if errorlevel 1 goto :fail

:: Compile sources
cl /nologo /c %CF% %INC% ^
    /Yu"std_include.hpp" /Fp"%OBJ%\shared\shared.pch" ^
    /Fo"%OBJ%\shared\\" ^
    "%SRC%\shared\common\config.cpp" ^
    "%SRC%\shared\common\dinput_hook_v1.cpp" ^
    "%SRC%\shared\common\dinput_hook_v2.cpp" ^
    "%SRC%\shared\common\ffp_state.cpp" ^
    "%SRC%\shared\common\flags.cpp" ^
    "%SRC%\shared\common\imgui_helper.cpp" ^
    "%SRC%\shared\common\loader.cpp" ^
    "%SRC%\shared\common\remix_api.cpp" ^
    "%SRC%\shared\globals.cpp" ^
    "%SRC%\shared\utils\hooking.cpp" ^
    "%SRC%\shared\utils\memory.cpp" ^
    "%SRC%\shared\utils\utils.cpp"
if errorlevel 1 goto :fail
lib /nologo /OUT:"%OUT%\_shared.lib" "%OBJ%\shared\*.obj"
if errorlevel 1 goto :fail

:: -------------------------------------------------------
:: Step 4: comp DLL (C++ with PCH, links everything)
:: -------------------------------------------------------
echo [4/4] %NAME%

:: Create PCH
cl /nologo /c %CF% %INC% /I"%COMP_DIR%\.." ^
    /Yc"std_include.hpp" /Fp"%GAME_OBJ%\comp.pch" ^
    /Fo"%GAME_OBJ%\std_include.obj" ^
    "%COMP_DIR%\std_include.cpp"
if errorlevel 1 goto :fail

:: Compile sources -- glob all .cpp files in comp dir (except std_include.cpp)
set "COMP_SRCS="
for /r "%COMP_DIR%" %%f in (*.cpp) do (
    if /i not "%%~nxf"=="std_include.cpp" (
        set "COMP_SRCS=!COMP_SRCS! "%%f""
    )
)

cl /nologo /c %CF% %INC% /I"%COMP_DIR%\.." ^
    /Yu"std_include.hpp" /Fp"%GAME_OBJ%\comp.pch" ^
    /Fo"%GAME_OBJ%\\" ^
    %COMP_SRCS%
if errorlevel 1 goto :fail

:: Link DLL
link /nologo /DLL /SUBSYSTEM:WINDOWS /DEBUG /PDBCompress %LF% %LIBPATH% ^
    /OUT:"%GAME_OUT%\%NAME%.dll" ^
    /PDB:"%GAME_OUT%\%NAME%.pdb" ^
    "%GAME_OBJ%\*.obj" ^
    "%OUT%\_shared.lib" ^
    "%OUT%\imgui.lib" ^
    "%OUT%\minhook.lib" ^
    d3d9.lib d3dx9.lib psapi.lib user32.lib gdi32.lib shell32.lib advapi32.lib ole32.lib
if errorlevel 1 goto :fail

:: Rename to .asi
move /y "%GAME_OUT%\%NAME%.dll" "%GAME_OUT%\%NAME%.asi" >nul
if errorlevel 1 goto :fail

:: Copy deploy files to game build folder
if "!CUSTOM_COMP!"=="1" (
    if exist "%ROOT%assets\dinput8.dll" (
        copy /y "%ROOT%assets\dinput8.dll" "%GAME_OUT%\dinput8.dll" >nul
    )
    if exist "!GAME_DIR!\remix-comp.ini" (
        copy /y "!GAME_DIR!\remix-comp.ini" "%GAME_OUT%\remix-comp.ini" >nul
    )
)

echo.
echo === Build succeeded: %GAME_OUT%\%NAME%.asi ===
exit /b 0

:fail
echo.
echo === Build FAILED ===
exit /b 1
