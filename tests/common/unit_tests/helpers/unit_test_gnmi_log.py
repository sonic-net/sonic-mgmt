"""Unit tests for rotation-safe gNMI log byte markers."""

import importlib.util
import gzip
import subprocess
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[2] / "helpers" / "gnmi_log.py"


def _load_gnmi_log():
    spec = importlib.util.spec_from_file_location(
        "unit_target_gnmi_log", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_script(script, *args):
    return subprocess.check_output(
        [sys.executable, "-c", script, *map(str, args)],
        text=True,
    )


def _mark(gnmi_log, path):
    return gnmi_log.parse_log_marker(
        _run_script(gnmi_log.MARK_LOG_SCRIPT, path)
    )


def _read(gnmi_log, path, marker):
    encoded = _run_script(
        gnmi_log.READ_LOG_SCRIPT,
        path,
        marker.inode,
        marker.offset,
        marker.anchor,
    )
    return gnmi_log.decode_log_bytes(encoded)


def test_read_log_bytes_appended_after_marker(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("old bytes\n")
    marker = _mark(gnmi_log, path)

    with path.open("a") as log_file:
        log_file.write("new bytes\n")

    assert _read(gnmi_log, path, marker) == "new bytes\n"


def test_read_log_bytes_after_truncation(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("stale revoked diagnostic\n")
    marker = _mark(gnmi_log, path)

    path.write_text("new generation\n")

    assert _read(gnmi_log, path, marker) == "new generation\n"


def test_read_log_bytes_after_truncate_and_regrow(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("stale marker bytes\n")
    marker = _mark(gnmi_log, path)

    path.write_text("new generation with unrelated content beyond old size\n")

    assert _read(gnmi_log, path, marker).startswith("new generation")


def test_read_log_bytes_across_rotation(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("old bytes\n")
    marker = _mark(gnmi_log, path)

    with path.open("a") as log_file:
        log_file.write("rotated tail\n")
    path.rename(tmp_path / "gnmi.log.1")
    path.write_text("new file\n")

    assert _read(gnmi_log, path, marker) == "rotated tail\nnew file\n"


def test_read_log_bytes_across_compressed_rotation(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("old bytes\n")
    marker = _mark(gnmi_log, path)

    with gzip.open(tmp_path / "gnmi.log.1.gz", "wb") as rotated:
        rotated.write(path.read_bytes() + b"rotated tail\n")
    path.write_text("new file\n")

    assert _read(gnmi_log, path, marker) == "rotated tail\nnew file\n"


def test_read_log_bytes_across_multiple_rotations(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("old bytes\n")
    marker = _mark(gnmi_log, path)

    with path.open("a") as log_file:
        log_file.write("first tail\n")
    path.rename(tmp_path / "gnmi.log.2")
    (tmp_path / "gnmi.log.1").write_text("second generation\n")
    path.write_text("current generation\n")

    assert _read(gnmi_log, path, marker) == (
        "first tail\nsecond generation\ncurrent generation\n"
    )


def test_read_log_bytes_are_bounded_to_latest_megabyte_after_marker(tmp_path):
    gnmi_log = _load_gnmi_log()
    path = tmp_path / "gnmi.log"
    path.write_text("old bytes\n")
    marker = _mark(gnmi_log, path)

    with path.open("ab") as log_file:
        log_file.write(b"a" * (1024 * 1024))
        log_file.write(b"latest")

    output = _read(gnmi_log, path, marker)
    assert len(output.encode()) == 1024 * 1024
    assert output == "a" * (1024 * 1024 - len("latest")) + "latest"
