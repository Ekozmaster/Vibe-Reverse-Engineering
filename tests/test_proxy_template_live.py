"""The remix-comp-proxy template, built from the working tree and run in front of a toy program.

Needs Windows, the Visual Studio 2022 C++ tools and a Direct3D 9 device; skipped
without them. The toy and what its picture means are described in ``proxy_live``.
"""

import struct
import zlib

import pefile
import pytest

import proxy_live
from proxy_live import CELLS, MOVED_LAYOUT, PROJECTION_FIRST_LAYOUT, SHIPPED_LAYOUT

RIGID = ["rigid quad", "rigid triangle", "rigid quad after the strips"]
SKINNED = [name for name in CELLS if name.startswith("skinned strip")]
SKINNING_ON = {"Skinning": {"Enabled": 1}}
ICON = "rtx_comp/textures/icon.png"


def _png(width: int, height: int, rgba: tuple[int, int, int, int]) -> bytes:
    """A PNG file of one colour."""
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    signature = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    unfiltered_row = bytes([0]) + bytes(rgba) * width
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return signature + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(unfiltered_row * height)) + chunk(b"IEND", b"")


def _merged(*settings):
    merged = {}
    for one in settings:
        for section, keys in one.items():
            merged.setdefault(section, {}).update(keys)
    return merged


@pytest.fixture(scope="module")
def builds(tmp_path_factory):
    """The template and the toy, built. Skips without the Visual Studio 2022 C++ tools."""
    try:
        return proxy_live.ProxyToy(tmp_path_factory.mktemp("proxy_toy"))
    except proxy_live.Unavailable as reason:
        pytest.skip(str(reason))


@pytest.fixture(scope="module")
def reference(builds):
    """The picture the toy's own shaders draw, with no proxy in front. Skips without a Direct3D 9 device."""
    try:
        return builds.frame("reference", MOVED_LAYOUT, proxy=False)
    except proxy_live.Unavailable as reason:
        pytest.skip(str(reason))


@pytest.fixture(scope="module")
def toy(builds, reference):
    """The builds, on a machine where the toy runs."""
    return builds


def assert_drawn_by(frame, reference, shape, colour):
    """*shape* has the one *colour* and covers the pixels the reference shape covers."""
    drawn, expected = frame.shapes[shape], reference.shapes[shape]
    assert drawn.colours == {colour}
    misplaced = len(drawn.pixels ^ expected.pixels)
    assert misplaced == 0, f"{misplaced} pixels differ from the {len(expected.pixels)} the toy's shaders draw"


class TestBuild:
    def test_a_fresh_copy_of_the_template_builds(self, builds):
        build = builds.release_build
        assert build.returncode == 0, build.stdout[-3000:] + build.stderr[-3000:]

    def test_the_debug_configuration_builds(self, builds):
        build = builds.build("debug")
        assert build.returncode == 0, build.stdout[-3000:] + build.stderr[-3000:]

    def test_the_proxy_needs_no_d3dx_dll(self, builds):
        proxy = pefile.PE(str(builds.proxy_dir / "d3d9.dll"))
        imported = {entry.dll.decode().lower() for entry in proxy.DIRECTORY_ENTRY_IMPORT}
        assert not [dll for dll in imported if dll.startswith("d3dx")]


class TestReference:
    def test_every_shape_is_drawn_by_its_shaders(self, reference):
        for name, shape in reference.shapes.items():
            assert shape.colours == {"red"}, name


class TestFfpDisabled:
    def test_every_shape_is_left_to_its_shaders(self, toy, reference):
        frame = toy.frame("ffp_off", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON, {"FFP": {"Enabled": 0}}))
        for shape in CELLS:
            assert_drawn_by(frame, reference, shape, "red")


class TestShippedIni:
    """The INI as shipped, in front of a toy that uses the registers it names."""

    @pytest.fixture(scope="class")
    def frame(self, toy):
        return toy.frame("shipped_ini", SHIPPED_LAYOUT)

    @pytest.mark.parametrize("shape", RIGID)
    def test_rigid_draw_is_converted(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")

    def test_draw_without_a_normal_keeps_its_shaders(self, frame, reference):
        assert_drawn_by(frame, reference, "quad without a normal", "red")

    @pytest.mark.parametrize("shape", SKINNED)
    def test_skinned_draw_keeps_its_shaders(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "red")


class TestRegistersFromIni:
    """Matrices and bones at other registers, named in [FFP.Registers] and [Skinning]."""

    @pytest.fixture(scope="class")
    def frame(self, toy):
        return toy.frame("moved_layout", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON))

    def test_the_log_names_the_layout(self, frame):
        assert "Registers: View=c8-c11 Proj=c16-c19 World=c24-c27" in frame.log
        assert "bones from c40" in frame.log

    @pytest.mark.parametrize("shape", RIGID[:2])
    def test_rigid_draw_is_converted(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")

    @pytest.mark.parametrize("shape", SKINNED)
    def test_skinned_draw_is_converted(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")

    def test_rigid_draw_after_skinned_draws_keeps_its_world_matrix(self, frame, reference):
        assert_drawn_by(frame, reference, "rigid quad after the strips", "green")


class TestProjectionBeforeView:
    """The Projection matrix in lower registers than the View matrix."""

    @pytest.fixture(scope="class")
    def frame(self, toy):
        return toy.frame("projection_first", PROJECTION_FIRST_LAYOUT, ini=_merged(PROJECTION_FIRST_LAYOUT.ini, SKINNING_ON))

    @pytest.mark.parametrize("shape", RIGID + SKINNED)
    def test_draw_is_converted(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")


class TestRegistersOutOfRange:
    def test_the_default_layout_is_used_and_the_log_says_so(self, toy, reference):
        frame = toy.frame("bad_layout", SHIPPED_LAYOUT, ini={"FFP.Registers": {"WorldStart": 254, "WorldEnd": 258}})
        assert "[FFP.Registers]" in frame.log and "using the default layout" in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "green")


class TestOverlayIcon:
    """rtx_comp/textures/icon.png, which the proxy decodes for its overlay when the file is there."""

    def test_a_png_is_loaded(self, toy):
        frame = toy.frame("icon", SHIPPED_LAYOUT, files={ICON: _png(4, 4, (255, 128, 0, 255))})
        assert "Failed to load" not in frame.log

    def test_a_file_that_is_no_image_is_reported(self, toy):
        frame = toy.frame("no_image", SHIPPED_LAYOUT, files={ICON: b"not an image"})
        assert "Failed to load rtx_comp" in frame.log


class TestAlbedoStage:
    """The albedo texture on stage 1, a different texture on stage 0."""

    @pytest.fixture(scope="class")
    def frame(self, toy):
        settings = _merged(MOVED_LAYOUT.ini, SKINNING_ON, {"FFP": {"AlbedoStage": 1}})
        return toy.frame("albedo_stage", MOVED_LAYOUT, ini=settings, albedo_stage=1)

    @pytest.mark.parametrize("shape", RIGID + SKINNED)
    def test_converted_draw_samples_the_albedo_stage(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")
