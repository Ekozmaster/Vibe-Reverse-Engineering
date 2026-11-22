"""The remix-comp-proxy template, built from the working tree and run in front of a toy program.

Needs Windows, the C++ tools of Visual Studio 2022 or later and a Direct3D 9 device;
skipped without them. The toy and what its picture means are described in ``proxy_live``.
"""

import json
import re
import struct
import zlib

import pefile
import pytest

import proxy_live
from proxy_live import CELLS, MOVED_LAYOUT, PROJECTION_FIRST_LAYOUT, SHIPPED_LAYOUT, Layout

RIGID = ["rigid quad", "rigid triangle", "rigid quad after the strips"]
SKINNED = [name for name in CELLS if name.startswith("skinned strip")]
SKINNING_ON = {"Skinning": {"Enabled": 1}}
ICON = "rtx_comp/textures/icon.png"

# Where the toy saves the frame of a second device, beside the frame of the first
SECOND_DEVICE_FRAME = "frame.raw.second-device"


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
    """The template and the toy, built. Skips without the C++ tools of Visual Studio 2022 or later."""
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


def variant_frames(toy, variant):
    """The toy drawing its last cell as *variant*: the frame behind the proxy with skinning on, and its own reference."""
    reference = toy.frame(f"reference_{variant}", MOVED_LAYOUT, proxy=False, variant=variant)
    frame = toy.frame(variant, MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON), variant=variant)
    return frame, reference


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

    def test_visual_studio_is_found_outside_its_default_folders(self, builds, tmp_path):
        relocated = proxy_live.environment_with_relocated_visual_studio(tmp_path)
        build = builds.build("debug", env=relocated)
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
    @classmethod
    def frame(cls, toy):
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
    @classmethod
    def frame(cls, toy):
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
    @classmethod
    def frame(cls, toy):
        return toy.frame("projection_first", PROJECTION_FIRST_LAYOUT, ini=_merged(PROJECTION_FIRST_LAYOUT.ini, SKINNING_ON))

    @pytest.mark.parametrize("shape", RIGID + SKINNED)
    def test_draw_is_converted(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")


class TestProjectionWithoutView:
    """Projection uploaded below the View registers the INI names, and nothing ever uploaded there."""

    def test_every_draw_keeps_its_shaders(self, toy, reference):
        layout_with_view_elsewhere = Layout(view=32, proj=PROJECTION_FIRST_LAYOUT.proj, world=24, bones=40)
        frame = toy.frame("projection_without_view", layout_with_view_elsewhere,
                          ini=_merged(PROJECTION_FIRST_LAYOUT.ini, SKINNING_ON))
        for shape in CELLS:
            assert_drawn_by(frame, reference, shape, "red")


class TestSkinnedDrawWithoutPalette:
    """Skinning on, but no upload qualifies as a bone palette."""

    @pytest.fixture(scope="class")
    @classmethod
    def frame(cls, toy):
        return toy.frame("no_palette", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON, {"Skinning": {"BoneThreshold": 230}}))

    @pytest.mark.parametrize("shape", SKINNED)
    def test_skinned_draw_keeps_its_shaders(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "red")

    @pytest.mark.parametrize("shape", RIGID)
    def test_rigid_draw_is_converted(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")


class TestSkinnedDrawPastTheEndOfItsBuffer:
    def test_only_the_vertices_in_the_buffer_are_converted(self, toy, reference):
        frame = toy.frame("loose_vertex_count", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON), extra_vertices=100_000)
        for shape in SKINNED:
            assert_drawn_by(frame, reference, shape, "green")


class TestIniValueThatIsNoNumber:
    def test_the_default_is_kept_and_the_log_says_so(self, toy, reference):
        frame = toy.frame("register_prefix", SHIPPED_LAYOUT, ini={"FFP.Registers": {"WorldStart": "c16"}})
        assert "[FFP.Registers] WorldStart=c16 is not a decimal number; using 16" in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "green")


class TestRegistersOutOfRange:
    def test_the_default_layout_is_used_and_the_log_says_so(self, toy, reference):
        frame = toy.frame("bad_layout", SHIPPED_LAYOUT, ini={"FFP.Registers": {"WorldStart": 254, "WorldEnd": 258}})
        assert "[FFP.Registers]" in frame.log and "using the default layout" in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "green")

    def test_a_start_so_large_that_adding_to_it_overflows_is_out_of_range(self, toy, reference):
        wrapped_end = 2147483647 + 4 - 2**32
        frame = toy.frame("overflowing_layout", SHIPPED_LAYOUT,
                          ini={"FFP.Registers": {"ViewStart": 2147483647, "ViewEnd": wrapped_end}})
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


TRIGGER = "dxtrace_capture.trigger"
TRIGGER_ID = "0123456789abcdef"


def trigger(frames, trigger_id=TRIGGER_ID):
    return {TRIGGER: f"frames={frames}\nid={trigger_id}\n".encode()}


def progress_of(frame):
    return (frame.folder / "dxtrace_progress.txt").read_text()


def captures_of(frame):
    return list((frame.folder / "captures").glob("dxtrace_*.jsonl"))


class TestBuiltInTracer:
    """A capture of two frames, started by the trigger file the proxy's tracer looks for."""

    @pytest.fixture(scope="class")
    @classmethod
    def frame(cls, toy):
        return toy.frame("tracer", SHIPPED_LAYOUT, files=trigger(2))

    @pytest.fixture(scope="class")
    @classmethod
    def capture(cls, frame):
        captures = captures_of(frame)
        assert len(captures) == 1, frame.log
        return captures[0].read_text(encoding="utf-8").splitlines()

    def test_every_line_is_one_record(self, capture):
        broken = []
        for number, line in enumerate(capture, 1):
            try:
                json.loads(line)
            except ValueError:
                broken.append((number, line[:80]))
        assert not broken

    def test_record_of_a_creation_names_the_object_created(self, capture):
        records = [json.loads(line) for line in capture if line.startswith("{")]
        creations = [record for record in records if record.get("method") == "CreateVertexDeclaration"]
        assert creations    # the toy creates one declaration per frame
        for record in creations:
            assert re.fullmatch("0x[0-9A-F]{8}", record.get("created_handle", "")), record

    def test_the_finished_capture_is_reported_under_the_id_of_its_trigger(self, frame):
        assert re.fullmatch(rf"2 \d+ {TRIGGER_ID} done\n", progress_of(frame)), frame.log

    def test_the_trigger_is_taken(self, frame):
        assert not (frame.folder / TRIGGER).exists()


class TestBuiltInTracerTrigger:
    def test_a_trigger_without_an_id_is_reported_under_a_dash(self, toy):
        frame = toy.frame("tracer_no_id", SHIPPED_LAYOUT, files={TRIGGER: b"frames=2"})
        assert re.fullmatch(r"2 \d+ - done\n", progress_of(frame)), frame.log

    @pytest.mark.parametrize("name, frames", [("word", "two"), ("trailing", "2x"), ("zero", "0"), ("negative", "-3"), ("empty", "")])
    def test_a_frame_count_that_is_no_number_from_1_up_starts_no_capture(self, toy, name, frames):
        frame = toy.frame(f"tracer_frames_{name}", SHIPPED_LAYOUT, files=trigger(frames))
        assert progress_of(frame).startswith(f"0 0 {TRIGGER_ID} failed "), frame.log
        assert progress_of(frame).count("\n") == 1
        assert not captures_of(frame)
        assert not (frame.folder / TRIGGER).exists()

    def test_a_frame_count_above_the_limit_is_cut_to_it(self, toy):
        frame = toy.frame("tracer_frames_huge", SHIPPED_LAYOUT, files=trigger(99999999999))
        assert "External trigger: 100000 frames" in frame.log
        assert re.fullmatch(rf"\d+ \d+ {TRIGGER_ID}\n", progress_of(frame))

    def test_an_id_that_is_not_16_hex_digits_counts_as_none(self, toy):
        frame = toy.frame("tracer_bad_id", SHIPPED_LAYOUT, files=trigger(2, "two words"))
        assert re.fullmatch(r"2 \d+ - done\n", progress_of(frame)), frame.log


class TestBuiltInTracerCannotStart:
    """A trigger taken while the capture file cannot be created."""

    def test_the_reason_is_in_the_progress_file(self, toy):
        frame = toy.frame("tracer_cannot_start", SHIPPED_LAYOUT,
                          files={**trigger(2), "captures": b"a file where the folder goes"})

        assert progress_of(frame).startswith(f"0 0 {TRIGGER_ID} failed cannot create "), frame.log
        assert not (frame.folder / TRIGGER).exists()


class TestBuiltInTracerTriggerWithBlanks:
    def test_a_frame_count_followed_by_blanks_is_taken(self, toy):
        frame = toy.frame("tracer_frames_blanks", SHIPPED_LAYOUT,
                          files={TRIGGER: f"frames=2 \t\r\nid={TRIGGER_ID}\r\n".encode()})
        assert re.fullmatch(rf"2 \d+ {TRIGGER_ID} done\n", progress_of(frame)), frame.log


class TestBuiltInTracerCannotReport:
    """A capture whose progress file cannot be written."""

    def test_the_log_says_so_once(self, toy):
        frame = toy.frame("tracer_cannot_report", SHIPPED_LAYOUT,
                          files={**trigger(2), "dxtrace_progress.txt/a folder where the file goes": b""})
        assert frame.log.count("dxtrace_progress.txt") == 1, frame.log
        assert len(captures_of(frame)) == 1


class TestBuiltInTracerTriggerSpelling:
    """What both tracers take for a frame count and for an id."""

    def test_a_frame_count_behind_a_blank_starts_no_capture(self, toy):
        frame = toy.frame("tracer_frames_behind_blank", SHIPPED_LAYOUT,
                          files={TRIGGER: f"frames= 2\nid={TRIGGER_ID}\n".encode()})
        assert progress_of(frame).startswith(f"0 0 {TRIGGER_ID} failed "), frame.log
        assert not captures_of(frame)

    def test_an_id_followed_by_blanks_is_taken(self, toy):
        frame = toy.frame("tracer_id_blanks", SHIPPED_LAYOUT,
                          files={TRIGGER: f"frames=2\r\nid={TRIGGER_ID} \t\r\n".encode()})
        assert re.fullmatch(rf"2 \d+ {TRIGGER_ID} done\n", progress_of(frame)), frame.log


class TestBuiltInTracerUndeletableTrigger:
    """A trigger file the toy has made read-only: the tracer can read it and not delete it."""

    def test_it_starts_one_capture(self, toy):
        frame = toy.frame("tracer_read_only", SHIPPED_LAYOUT, files=trigger(1), variant="read-only-trigger")
        assert frame.log.count("Capture started") == 1, frame.log
        assert frame.log.count("Trigger file not deleted") == 1
        assert re.fullmatch(rf"1 \d+ {TRIGGER_ID} done\n", progress_of(frame))

    def test_one_that_names_no_frame_count_is_answered_once(self, toy):
        frame = toy.frame("tracer_read_only_no_count", SHIPPED_LAYOUT, files=trigger("two"), variant="read-only-trigger")
        assert frame.log.count("Trigger file not deleted") == 1, frame.log
        assert progress_of(frame).startswith(f"0 0 {TRIGGER_ID} failed ")

    def test_it_is_deleted_once_it_can_be(self, toy):
        frame = toy.frame("tracer_read_only_for_a_while", SHIPPED_LAYOUT, files=trigger(1),
                          variant="read-only-trigger-until-replacement")
        assert frame.log.count("Capture started") == 1, frame.log
        assert not (frame.folder / TRIGGER).exists()


class TestAlbedoStage:
    """The albedo texture on stage 1, a different texture on stage 0."""

    @pytest.fixture(scope="class")
    @classmethod
    def frame(cls, toy):
        settings = _merged(MOVED_LAYOUT.ini, SKINNING_ON, {"FFP": {"AlbedoStage": 1}})
        return toy.frame("albedo_stage", MOVED_LAYOUT, ini=settings, albedo_stage=1)

    @pytest.mark.parametrize("shape", RIGID + SKINNED)
    def test_converted_draw_samples_the_albedo_stage(self, frame, reference, shape):
        assert_drawn_by(frame, reference, shape, "green")


class TestSkinnedVertexFormats:
    """The strip in the last cell, drawn as one of the toy's variants, against its own reference."""

    def test_blend_indices_in_a_d3dcolor_decoded_with_d3dcolortoubyte4_are_converted(self, toy):
        frame, reference = variant_frames(toy, "color-indices")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")

    def test_blend_weights_in_a_format_the_expansion_cannot_read_keep_their_shaders(self, toy):
        frame, reference = variant_frames(toy, "ushort-weights")
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    def test_blend_index_past_the_last_uploaded_bone_keeps_its_shaders(self, toy):
        frame, reference = variant_frames(toy, "partial-palette")
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    def test_blend_index_past_the_palette_whose_weight_is_zero_is_converted(self, toy):
        frame, reference = variant_frames(toy, "junk-unused-index")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")

    @pytest.mark.parametrize("variant", ["short-texcoord", "half-normal"])
    def test_an_element_in_a_format_the_expansion_cannot_read_keeps_the_draw_on_its_shaders(self, toy, variant):
        frame, reference = variant_frames(toy, variant)
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    @pytest.mark.parametrize("variant", ["normal-on-stream-1", "texcoord-on-stream-1"])
    def test_an_element_the_expansion_reads_on_another_stream_keeps_the_draw_on_its_shaders(self, toy, variant):
        frame, reference = variant_frames(toy, variant)
        assert_drawn_by(frame, reference, "skinned strip variant", "red")


class TestSkinnedSourceBuffer:
    """The strip in the last cell, in a vertex buffer created with a usage of its own."""

    def test_a_dynamic_buffer_the_toy_rewrites_keeps_its_shaders(self, toy):
        frame, reference = variant_frames(toy, "dynamic-rewritten")
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    def test_a_write_only_buffer_in_the_managed_pool_is_converted(self, toy):
        frame, reference = variant_frames(toy, "writeonly")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")

    def test_a_write_only_buffer_in_the_default_pool_keeps_its_shaders(self, toy):
        frame, reference = variant_frames(toy, "writeonly-default")
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    def test_the_buffer_a_state_block_bound_is_the_one_converted(self, toy):
        frame, reference = variant_frames(toy, "state-block-stream")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")

    def test_a_draw_whose_declaration_a_state_block_changed_keeps_its_shaders(self, toy):
        frame, reference = variant_frames(toy, "state-block-declaration")
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    def test_a_negative_base_vertex_index_is_followed(self, toy):
        frame, reference = variant_frames(toy, "negative-base")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")


class TestFvf:
    """SetFVF in the last cell, after the skinned strip's declaration was set."""

    def test_an_fvf_draw_is_not_read_with_the_declaration_set_before_it(self, toy):
        frame, reference = variant_frames(toy, "fvf-after-skinned")
        assert_drawn_by(frame, reference, "skinned strip variant", "red")

    def test_an_fvf_of_zero_leaves_the_declaration_in_use(self, toy):
        frame, reference = variant_frames(toy, "fvf-zero")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")


class TestStateKeptAcrossFrames:
    """A draw with the declaration, buffers and shaders the frame before left on the device."""

    def test_a_rigid_draw_is_converted(self, toy):
        frame, reference = variant_frames(toy, "state-kept-across-frames")
        assert_drawn_by(frame, reference, RIGID[0], "green")


class TestConstantUploadOutOfRange:
    """A shader constant upload that starts at a register near UINT_MAX, which Direct3D refuses."""

    def test_a_vertex_shader_upload_changes_nothing(self, toy):
        frame, reference = variant_frames(toy, "vs-constants-out-of-range")
        for shape in RIGID + SKINNED:
            assert_drawn_by(frame, reference, shape, "green")

    def test_a_pixel_shader_upload_changes_nothing(self, toy):
        # View and Projection in the last vertex shader registers, which the pixel shader
        # registers follow in the proxy's memory
        layout = Layout(view=248, proj=252, world=24, bones=40)
        variant = "ps-constants-out-of-range"
        reference = toy.frame(f"reference_{variant}", layout, proxy=False, variant=variant)
        frame = toy.frame(variant, layout, ini=layout.ini, variant=variant)
        for shape in RIGID:
            assert_drawn_by(frame, reference, shape, "green")


class TestUserPointerDrawAfterConvertedDraw:
    """A quad drawn converted, then drawn again from user memory with the shaders set before both."""

    @pytest.mark.parametrize("variant", ["up-after-converted", "indexed-up-after-converted"])
    def test_the_user_pointer_draw_keeps_its_shaders(self, toy, variant):
        frame, reference = variant_frames(toy, variant)
        assert_drawn_by(frame, reference, "skinned strip variant", "red")


class TestRigidNormalOnAnotherStream:
    """A rigid quad whose only normal is on stream 1.

    Converted draws are unlit, so the picture shows that the declaration counts as one with
    a normal and not whether Direct3D or Remix reads that normal.
    """

    def test_the_declaration_counts_as_having_a_normal_and_the_draw_is_converted(self, toy):
        frame, reference = variant_frames(toy, "rigid-normal-on-stream-1")
        assert_drawn_by(frame, reference, "skinned strip variant", "green")


class TestShadersSetAfterConvertedDraw:
    """A quad drawn converted, the blue vertex shader set, and the quad drawn again on its shaders.

    The proxy holds back a shader set after a converted draw. Blue says the second draw
    used the shader set last, red the one from before the converted draw.
    """

    @pytest.mark.parametrize("variant", ["new-vs-after-converted", "new-vs-up-after-converted"])
    def test_a_vertex_shader_set_alone_draws_with_the_pixel_shader_from_before(self, toy, variant):
        frame, reference = variant_frames(toy, variant)
        assert_drawn_by(frame, reference, "skinned strip variant", "blue")

    def test_get_vertex_shader_and_get_pixel_shader_return_them(self, toy):
        frame, reference = variant_frames(toy, "get-shaders-after-converted")
        assert_drawn_by(frame, reference, "skinned strip variant", "blue")

    @pytest.mark.parametrize("variant", ["state-block-created-after-converted", "state-block-recorded-after-converted"])
    def test_a_state_block_holds_them(self, toy, variant):
        frame, reference = variant_frames(toy, variant)
        assert_drawn_by(frame, reference, "skinned strip variant", "blue")

    def test_process_vertices_runs_them(self, toy):
        frame, reference = variant_frames(toy, "process-vertices-after-converted")
        assert_drawn_by(frame, reference, "skinned strip variant", "blue")

    @pytest.mark.parametrize("variant", ["rect-patch-after-converted", "tri-patch-after-converted"])
    def test_the_device_has_them_after_a_patch_draw(self, toy, variant):
        frame, reference = variant_frames(toy, variant)
        assert_drawn_by(frame, reference, "skinned strip variant", "blue")


class TestDeviceReplaced:
    """Two thirds into the run the toy resets its device, or creates another before or after releasing it.

    The toy itself fails when the last Release of a device it lets go of does not return 0.
    """

    @pytest.mark.parametrize("variant", ["reset", "second-device", "overlapping-devices"])
    def test_draws_are_converted_on_the_device_that_follows(self, toy, variant):
        reference = toy.frame(f"reference_{variant}", MOVED_LAYOUT, proxy=False, variant=variant)
        frame = toy.frame(variant, MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON), variant=variant,
                          files={ICON: _png(4, 4, (255, 128, 0, 255))})

        # The proxy logs the line each time it lets go of what it has on a device. The first
        # time is the replacement, and by then its modules were loaded and had objects there.
        # The toy releases a device at its end only where devices overlap.
        assert frame.log.index("Skinning] Module initialized.") < frame.log.index("FFP] State reset"), frame.log
        assert frame.log.count("FFP] State reset") == (2 if variant == "overlapping-devices" else 1), frame.log
        assert "Failed to load" not in frame.log
        for shape in RIGID + SKINNED:
            assert_drawn_by(frame, reference, shape, "green")


class TestFirstDeviceInUseBesideASecond:
    """The toy creates a second device and goes on using the first.

    The proxy converts the draws of the device created last. The toy itself fails when
    the last Release of either device does not return 0.
    """

    def test_the_first_device_draws_on_its_shaders_and_the_second_is_converted(self, toy):
        variant = "first-device-drawn-on"
        reference = toy.frame(f"reference_{variant}", MOVED_LAYOUT, proxy=False, variant=variant)
        frame = toy.frame(variant, MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON), variant=variant)

        for shape in CELLS:
            assert_drawn_by(frame, reference, shape, "red")
        second = proxy_live.read_frame(frame.folder / SECOND_DEVICE_FRAME)
        second_reference = proxy_live.read_frame(reference.folder / SECOND_DEVICE_FRAME)
        for shape in RIGID + SKINNED:
            drawn, expected = second[shape], second_reference[shape]
            assert drawn.colours == {"green"} and drawn.pixels == expected.pixels, shape
        assert frame.log.count("FFP] State reset") == 2, frame.log

    def test_the_first_device_has_its_shaders_back_when_the_second_is_created_after_a_converted_draw(self, toy):
        frame, reference = variant_frames(toy, "second-device-mid-frame")
        assert_drawn_by(frame, reference, "rigid quad after the strips", "red")
        for shape in set(RIGID + SKINNED) - {"rigid quad after the strips"}:
            assert_drawn_by(frame, reference, shape, "green")


class TestD3D9Ex:
    """A device created through Direct3DCreate9Ex, which has no managed pool."""

    @pytest.fixture(scope="class")
    @classmethod
    def ex_reference(cls, toy):
        return toy.frame("reference_d3d9ex", MOVED_LAYOUT, proxy=False, d3d9ex=True)

    @pytest.fixture(scope="class")
    @classmethod
    def frame(cls, toy):
        return toy.frame("d3d9ex", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON), d3d9ex=True,
                         files={ICON: _png(4, 4, (255, 128, 0, 255))})

    def test_the_overlay_icon_is_loaded(self, frame):
        assert "Failed to load" not in frame.log

    @pytest.mark.parametrize("shape", RIGID + SKINNED)
    def test_draw_is_converted(self, frame, ex_reference, shape):
        assert_drawn_by(frame, ex_reference, shape, "green")


class TestMatrixEndNotFourPastItsStart:
    def test_the_default_layout_is_used_and_the_log_says_so(self, toy, reference):
        frame = toy.frame("short_view_range", SHIPPED_LAYOUT, ini={"FFP.Registers": {"ViewEnd": 1}})
        assert "[FFP.Registers]" in frame.log and "using the default layout" in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "green")


class TestBonesOverlappingAMatrix:
    """BoneThreshold at c20, below the World matrix at c24."""

    OVERLAPPING = {"Skinning": {"BoneThreshold": 20}}

    def test_with_skinning_on_the_default_layouts_are_used_and_the_log_says_so(self, toy):
        frame = toy.frame("bones_over_world", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, SKINNING_ON, self.OVERLAPPING))
        assert "[Skinning] BoneThreshold=20" in frame.log and "using the default layouts" in frame.log
        assert "Registers: View=c0-c3 Proj=c4-c7 World=c16-c19" in frame.log

    def test_with_skinning_off_the_layout_is_kept(self, toy, reference):
        frame = toy.frame("bones_over_world_unused", MOVED_LAYOUT, ini=_merged(MOVED_LAYOUT.ini, self.OVERLAPPING))
        assert "using the default" not in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "green")


class TestIniNumberWithComment:
    def test_a_comment_after_a_switch_is_ignored(self, toy, reference):
        frame = toy.frame("switch_with_comment", SHIPPED_LAYOUT, ini={"FFP": {"Enabled": "0  ; passthrough"}})
        assert "is not a decimal number" not in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "red")

    def test_a_number_with_a_sign_and_a_comment_is_read(self, toy, reference):
        frame = toy.frame("register_with_comment", SHIPPED_LAYOUT, ini={"FFP.Registers": {"WorldStart": "+16 ; world"}})
        assert "is not a decimal number" not in frame.log
        assert_drawn_by(frame, reference, "rigid quad", "green")
