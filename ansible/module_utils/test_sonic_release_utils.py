"""Unit tests for ansible/module_utils/sonic_release_utils.py.

Run from the repo root with:
    python -m pytest --noconftest ansible/module_utils/test_sonic_release_utils.py -v

The module under test is pure (stdlib ``re`` only), so it is loaded directly from
its file path to avoid any Ansible / sonic_py_common import dependency.
"""
import importlib.util
import os

import pytest

_MODULE_PATH = os.path.join(os.path.dirname(__file__), "sonic_release_utils.py")
_spec = importlib.util.spec_from_file_location("sonic_release_utils", _MODULE_PATH)
sonic_release_utils = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sonic_release_utils)
guess_release_from_build_version = sonic_release_utils.guess_release_from_build_version


class TestGuessReleaseFromBuildVersion:
    @pytest.mark.parametrize("release, build_version, expected", [
        # An already-stamped release (real HW image) is returned unchanged and
        # takes precedence over whatever build_version says.
        ("202405", "202605.1166406-18a25e93d", "202405"),
        ("202511", "", "202511"),
        ("master", "202405.1-abc", "master"),
    ])
    def test_existing_release_is_kept(self, release, build_version, expected):
        assert guess_release_from_build_version(release, build_version) == expected

    @pytest.mark.parametrize("empty_release", [None, "", "none"])
    @pytest.mark.parametrize("build_version, expected", [
        ("202605.1166406-18a25e93d", "202605"),
        ("202012.123-deadbeef", "202012"),
        ("202205.7", "202205"),
        ("202211.10-abc", "202211"),
        ("202305.1", "202305"),
        ("202311.2", "202311"),
        ("202405.3", "202405"),
        ("202411.4", "202411"),
        ("202505.5", "202505"),
        ("202511.6", "202511"),
    ])
    def test_release_guessed_from_build_version(self, empty_release, build_version, expected):
        assert guess_release_from_build_version(empty_release, build_version) == expected

    @pytest.mark.parametrize("empty_release", [None, "", "none"])
    @pytest.mark.parametrize("build_version, expected", [
        # Old date-stamped official images: leading 6 digits are the release.
        ("20181130.31", "201811"),
        ("20191130.44", "201911"),
    ])
    def test_old_date_stamped_images(self, empty_release, build_version, expected):
        assert guess_release_from_build_version(empty_release, build_version) == expected

    @pytest.mark.parametrize("empty_release", [None, "", "none"])
    @pytest.mark.parametrize("build_version", [
        "master.1-abcdef",
        "master.20240101",
    ])
    def test_master_build_version(self, empty_release, build_version):
        assert guess_release_from_build_version(empty_release, build_version) == "master"

    @pytest.mark.parametrize("empty_release", [None, "", "none"])
    @pytest.mark.parametrize("build_version", [
        "",
        None,
        "foobar",
        "1902-not-a-release",
        "1234567",
    ])
    def test_unparseable_build_version_is_unknown(self, empty_release, build_version):
        assert guess_release_from_build_version(empty_release, build_version) == "unknown"

    def test_release_token_not_confused_with_build_number(self):
        # '202605' is the release; the 7-digit build number '1166406' must not
        # be picked up (anchored match at the start of the string).
        assert guess_release_from_build_version("", "202605.1166406-18a25e93d") == "202605"

    def test_regression_modern_release_no_longer_collapses_to_unknown(self):
        # Before this helper the fallback only knew 201811/201911/master, so a
        # 202605 VS image resolved to 'unknown' and defeated release-based
        # conditional_mark skips. It must now resolve to the real release.
        assert guess_release_from_build_version("none", "202605.1166406-18a25e93d") == "202605"
        assert guess_release_from_build_version("none", "202605.1166406-18a25e93d") != "unknown"
