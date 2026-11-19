"""Build the proxy template and the toy Direct3D 9 program, run the toy, and read its picture.

``proxy_toy/toy.cpp`` draws one shape per cell of a 3x3 grid, each through a vertex
shader and a pixel shader that paints it red, with a green texture bound that only
a fixed-function draw samples. Run against the system d3d9.dll it gives the
reference picture; run with the proxy beside it, a shape the proxy converted is
green and has to cover the same pixels.
"""

import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from proxy_template import TEMPLATE

TOY_SOURCE = Path(__file__).resolve().parent / "proxy_toy" / "toy.cpp"

# Where every Visual Studio installer since 2017 puts its locator, under Program Files (x86)
_LOCATOR = Path("Microsoft Visual Studio") / "Installer" / "vswhere.exe"

# (row, column) of each shape in the toy's picture
CELLS = {
    "rigid quad": (0, 0),
    "rigid triangle": (0, 1),
    "quad without a normal": (0, 2),
    "skinned strip": (1, 0),
    "skinned strip behind offsets": (1, 1),
    "skinned strip with four weights": (1, 2),
    "rigid quad after the strips": (2, 0),
    "skinned strip on a large palette": (2, 1),
}
_GRID = 3
_BACKGROUND = (0, 0, 64)
_COLOUR_NAMES = {(255, 0, 0): "red", (0, 255, 0): "green", (0, 0, 255): "blue"}



class Unavailable(Exception):
    """This machine cannot build or run the toy."""


@dataclass(frozen=True)
class Layout:
    """First constant register of each matrix and of the bone palette."""
    view: int
    proj: int
    world: int
    bones: int

    @property
    def toy_arguments(self) -> list[str]:
        return ["--view", str(self.view), "--proj", str(self.proj), "--world", str(self.world), "--bones", str(self.bones)]

    @property
    def ini(self) -> dict[str, dict[str, int]]:
        """The INI settings that name this layout."""
        return {
            "FFP.Registers": {
                "ViewStart": self.view, "ViewEnd": self.view + 4,
                "ProjStart": self.proj, "ProjEnd": self.proj + 4,
                "WorldStart": self.world, "WorldEnd": self.world + 4,
            },
            "Skinning": {"BoneThreshold": self.bones},
        }


# The toy uploads View and Projection in one call when their registers are adjacent,
# as in the layout the shipped INI names, and one at a time when they are apart.
SHIPPED_LAYOUT = Layout(view=0, proj=4, world=16, bones=20)
MOVED_LAYOUT = Layout(view=8, proj=16, world=24, bones=40)
PROJECTION_FIRST_LAYOUT = Layout(view=16, proj=8, world=24, bones=40)


@dataclass(frozen=True)
class Shape:
    colours: frozenset[str]
    pixels: frozenset[tuple[int, int]]


@dataclass(frozen=True)
class Frame:
    shapes: dict[str, Shape]
    log: str
    folder: Path    # where the toy ran; the proxy writes its own files there


def find_vcvarsall() -> Path | None:
    """vcvarsall.bat of the newest Visual Studio (2022 or later) that has the C++ tools, or None."""
    locator = Path(os.environ.get("ProgramFiles(x86)", "")) / _LOCATOR
    if not locator.is_file():
        return None
    installation = subprocess.run(
        [str(locator), "-latest", "-products", "*", "-version", "17.0",
         "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
        capture_output=True, text=True).stdout.strip()
    vcvarsall = Path(installation) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
    return vcvarsall if installation and vcvarsall.is_file() else None


def environment_with_relocated_visual_studio(scratch: Path) -> dict[str, str]:
    """An environment in which Visual Studio is not where its installer puts it by default.

    Both Program Files variables name folders under *scratch* that hold nothing but
    the Visual Studio locator, which goes on reporting the real installation.
    """
    program_files = scratch / "Program Files"
    program_files_x86 = scratch / "Program Files (x86)"
    program_files.mkdir()
    (program_files_x86 / _LOCATOR).parent.mkdir(parents=True)
    shutil.copyfile(Path(os.environ["ProgramFiles(x86)"]) / _LOCATOR, program_files_x86 / _LOCATOR)
    return {**os.environ, "ProgramFiles": str(program_files), "ProgramFiles(x86)": str(program_files_x86)}


def build_toy(folder: Path, vcvarsall: Path) -> Path:
    folder.mkdir(parents=True)
    script = folder / "build.cmd"
    script.write_text(
        "@echo off\n"
        f'call "{vcvarsall}" x86 >nul 2>&1 || exit /b 1\n'
        f'cl /nologo /W4 /WX /EHsc /O2 /std:c++17 "{TOY_SOURCE}" /Fe:toy.exe /link d3d9.lib d3dcompiler.lib user32.lib\n',
        encoding="ascii")
    done = subprocess.run(["cmd", "/c", str(script)], cwd=folder, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(f"the toy does not build:\n{done.stdout}\n{done.stderr}")
    return folder / "toy.exe"


def _with_settings(ini_text: str, settings: dict[str, dict[str, object]]) -> str:
    """*ini_text* with each key of *settings* ({section: {key: value}}) given its new value."""
    lines = ini_text.splitlines()
    for section, keys in settings.items():
        start = lines.index(f"[{section}]")
        end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("[")), len(lines))
        for key, value in keys.items():
            at = next(i for i in range(start + 1, end) if lines[i].split("=")[0] == key)
            lines[at] = f"{key}={value}"
    return "\r\n".join(lines) + "\r\n"


def _read_frame(path: Path) -> dict[str, Shape]:
    data = path.read_bytes()
    width, height = struct.unpack_from("<II", data)
    shapes = {}
    for name, (row, column) in CELLS.items():
        colours, pixels = set(), set()
        for y in range(row * height // _GRID, (row + 1) * height // _GRID):
            for x in range(column * width // _GRID, (column + 1) * width // _GRID):
                blue, green, red, _ = struct.unpack_from("<4B", data, 8 + (y * width + x) * 4)
                if (red, green, blue) != _BACKGROUND:
                    colours.add(_COLOUR_NAMES.get((red, green, blue), f"#{red:02X}{green:02X}{blue:02X}"))
                    pixels.add((x, y))
        shapes[name] = Shape(frozenset(colours), frozenset(pixels))
    return shapes


class ProxyToy:
    """The toy, and a build of the template as it is in the working tree."""

    def __init__(self, scratch: Path):
        vcvarsall = find_vcvarsall()
        if os.name != "nt" or vcvarsall is None:
            raise Unavailable("needs Windows with the C++ tools of Visual Studio 2022 or later")
        self._scratch = scratch
        self._template_copy = scratch / "proxy"
        shutil.copytree(TEMPLATE, self._template_copy, ignore=shutil.ignore_patterns("build", ".claude"))
        self.release_build = self.build("release")
        self.proxy_dir = self._template_copy / "build" / "bin" / "release"
        self._toy = build_toy(scratch / "toy", vcvarsall)

    def build(self, config: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        """Run build.bat for *config* ("release" or "debug") in the copy of the template.

        Args:
            env: The environment build.bat runs in; this process's environment when None.
        """
        script = self._template_copy / "build.bat"
        return subprocess.run(["cmd", "/c", str(script), config], cwd=self._template_copy, capture_output=True, text=True, env=env)

    def frame(self, name: str, layout: Layout, *, ini: dict | None = None, proxy: bool = True, albedo_stage: int = 0,
              files: dict[str, bytes] | None = None) -> Frame:
        """Run the toy in a folder of its own and return what it drew.

        Args:
            name: Folder name for this run.
            layout: Registers the toy uploads its matrices and bones to.
            ini: {section: {key: value}} to change in the shipped remix-comp-proxy.ini.
            proxy: Put the built proxy and its INI beside the toy. Without it the toy
                uses the system d3d9.dll.
            albedo_stage: Texture stage the toy binds its green texture to.
            files: {path inside the folder: content} to put there before the run.

        Raises:
            Unavailable: The toy could not create a Direct3D 9 device without the proxy.
            RuntimeError: The toy failed in any other case, or saved its frame before the
                proxy had loaded its modules.
        """
        folder = self._scratch / name
        folder.mkdir()
        shutil.copy(self._toy, folder)
        for path, content in (files or {}).items():
            (folder / path).parent.mkdir(parents=True, exist_ok=True)
            (folder / path).write_bytes(content)
        if proxy:
            shutil.copy(self.proxy_dir / "d3d9.dll", folder)
            shipped = (self.proxy_dir / "remix-comp-proxy.ini").read_text(encoding="utf-8")
            (folder / "remix-comp-proxy.ini").write_text(_with_settings(shipped, ini or {}), encoding="utf-8", newline="")

        # A hidden console of its own: the proxy opens a console window when the process has none
        hidden = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE)
        done = subprocess.run(
            [str(folder / "toy.exe"), "--out", "frame.raw", *layout.toy_arguments, "--albedo-stage", str(albedo_stage), "-nobeep"],
            cwd=folder, capture_output=True, text=True, timeout=120,
            startupinfo=hidden, creationflags=subprocess.CREATE_NEW_CONSOLE)
        if done.returncode != 0:
            failure = f"{name}: the toy exited with {done.returncode}: {done.stderr.strip()}"
            if not proxy and "CreateDevice" in done.stderr:
                raise Unavailable(failure)
            raise RuntimeError(failure)

        log = (folder / "rtx_comp" / "console.log").read_text(encoding="utf-8", errors="replace") if proxy else ""
        if proxy and "[Renderer] Module initialized." not in log:
            raise RuntimeError(f"{name}: the proxy had not loaded its modules when the toy saved its frame. Its log: {log!r}")
        return Frame(_read_frame(folder / "frame.raw"), log, folder)
