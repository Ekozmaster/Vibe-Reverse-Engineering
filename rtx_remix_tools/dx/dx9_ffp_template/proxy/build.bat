@echo off
REM ================================================================
REM DX9 FFP Proxy - Build Script (MSVC x86, no CRT)
REM
REM Prerequisites:
REM   - Visual Studio with C++ desktop workload (Build Tools)
REM
REM Output: d3d9.dll in this directory
REM ================================================================

REM Auto-find Visual Studio via vswhere
for /f "tokens=*" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2^>nul') do set VSDIR=%%i

if not defined VSDIR (
    echo ERROR: Visual Studio not found. Install VS Build Tools.
    exit /b 1
)

set VCVARSALL=%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat
if not exist "%VCVARSALL%" (
    echo ERROR: vcvarsall.bat not found at %VCVARSALL%
    exit /b 1
)

echo Setting up x86 build environment...
call "%VCVARSALL%" x86 >nul 2>&1

echo.
echo Compiling d3d9_main.c...
cl.exe /nologo /O1 /GS- /W3 /Zl /c /D "WIN32" /D "NDEBUG" d3d9_main.c
if errorlevel 1 goto :error

echo Compiling d3d9_wrapper.c...
cl.exe /nologo /O1 /GS- /W3 /Zl /c /D "WIN32" /D "NDEBUG" d3d9_wrapper.c
if errorlevel 1 goto :error

echo Compiling d3d9_device.c...
cl.exe /nologo /O1 /Oi /GS- /W3 /Zl /c /D "WIN32" /D "NDEBUG" d3d9_device.c
if errorlevel 1 goto :error

echo Linking d3d9.dll...
link.exe /nologo /DLL /NODEFAULTLIB /ENTRY:_DllMainCRTStartup@12 /DEF:d3d9.def /OUT:d3d9.dll d3d9_main.obj d3d9_wrapper.obj d3d9_device.obj kernel32.lib
if errorlevel 1 goto :error

echo.
echo === Build successful: d3d9.dll ===
echo.
echo Deploy: copy d3d9.dll and proxy.ini to your game directory.
echo Make sure d3d9_remix.dll (RTX Remix) is also present if chain loading.

REM Clean intermediates
del *.obj *.lib *.exp 2>nul

exit /b 0

:error
echo.
echo === BUILD FAILED ===
exit /b 1
