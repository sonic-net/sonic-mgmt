"""Unit tests for the upgrade-path error classification ("exit points").

Covers the review findings on PR #26491:
  * per-test result keys: one test's pass/skip cannot clear another test's
    failure classification before the session-level CustomMsg emission
  * nested exception classification: an outer, coarser handler (e.g.
    RELOADTEST_VERIFICATION) must not overwrite a more specific label
    (e.g. INSTALL_TARGET_IMAGE_FAILED) already recorded for the same test
  * pytest.fail-based failures (BaseException-derived) are still classified
    at the boot/install exit points
  * skipped tests whose teardown failed keep their classification

Run with::

    python3 -m pytest --noconftest \
        tests/common/unit_tests/fixtures/unit_test_upgrade_path_exit_points.py -v
"""

import importlib
import importlib.util
import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# The repo's pytest log_format uses a custom 'funcNamewithModule' record field that
# is normally injected by a conftest-loaded plugin; --noconftest skips it, so add it
# here to keep these tests runnable via `pytest --noconftest`.
_old_record_factory = logging.getLogRecordFactory()


def _record_factory(*args, **kwargs):
    record = _old_record_factory(*args, **kwargs)
    record.funcNamewithModule = "%s.%s" % (record.module, record.funcName)
    return record


logging.setLogRecordFactory(_record_factory)

_REPO_TESTS_DIR = Path(__file__).resolve().parents[3]
_REPO_ROOT = _REPO_TESTS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Stub the heavy testbed-facing dependencies so the real advanced_reboot,
# upgrade_path conftest and test_upgrade_path modules can be loaded without
# an ansible/testbed environment. Full dotted names in sys.modules are used
# directly by the import system, so parent packages (tests.common.__init__,
# which drags in the whole testbed stack) are never executed.
_STUB_MODULE_NAMES = [
    "six",
    "tests.ptf_runner",
    "tests.common.mellanox_data",
    "tests.common.platform.ssh_utils",
    "tests.common.platform.device_utils",
    "tests.common.platform.warmboot_sad_cases",
    "tests.common.reboot",
    "tests.common.utilities",
    "tests.common.helpers.sad_path",
    "tests.common.helpers.assertions",
    "tests.common.helpers.upgrade_helpers",
    "tests.common.helpers.multi_thread_utils",
    "tests.common.helpers.dut_ports",
    "tests.common.dualtor.data_plane_utils",
    "tests.common.dualtor.dual_tor_utils",
    "tests.common.fixtures.duthost_utils",
    "tests.common.fixtures.ptfhost_utils",
    "tests.common.fixtures.consistency_checker.consistency_checker",
    "tests.upgrade_path.utilities",
]

# Real modules loaded by path but registered under their dotted names so the
# modules under test resolve them from sys.modules.
_REGISTERED_REAL_MODULE_NAMES = [
    "tests.common.helpers.constants",
    "tests.common.helpers.custom_msg_utils",
    "tests.common.fixtures.advanced_reboot",
]


def _load_by_path(module_name, path, register=False):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    if register:
        sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# Install the stubs and load the target modules in a temporary import context:
# snapshot sys.modules first and restore it afterwards, so the stubs never leak
# into other unit test modules collected later (the loaded modules keep their
# stub references through their own globals).
_touched = _STUB_MODULE_NAMES + _REGISTERED_REAL_MODULE_NAMES
_saved_modules = {name: sys.modules[name] for name in _touched if name in sys.modules}
try:
    for _name in _STUB_MODULE_NAMES:
        if _name not in sys.modules:
            _stub = types.ModuleType(_name)
            _stub.__getattr__ = lambda attr, _name=_name: MagicMock(name="{}.{}".format(_name, attr))
            sys.modules[_name] = _stub

    _constants = _load_by_path("tests.common.helpers.constants",
                               _REPO_TESTS_DIR / "common" / "helpers" / "constants.py", register=True)
    _load_by_path("tests.common.helpers.custom_msg_utils",
                  _REPO_TESTS_DIR / "common" / "helpers" / "custom_msg_utils.py", register=True)
    advanced_reboot = _load_by_path(
        "tests.common.fixtures.advanced_reboot",
        _REPO_TESTS_DIR / "common" / "fixtures" / "advanced_reboot.py", register=True)

    upgrade_path_conftest = _load_by_path(
        "unit_target_upgrade_path_conftest", _REPO_TESTS_DIR / "upgrade_path" / "conftest.py")
    test_upgrade_path = _load_by_path(
        "unit_target_test_upgrade_path", _REPO_TESTS_DIR / "upgrade_path" / "test_upgrade_path.py")
finally:
    for _name in _touched:
        if _name in _saved_modules:
            sys.modules[_name] = _saved_modules[_name]
        else:
            sys.modules.pop(_name, None)

ErrorType = advanced_reboot.ErrorType
get_upgrade_path_result_key = advanced_reboot.get_upgrade_path_result_key
set_upgrade_path_error_result_custom_msg = advanced_reboot.set_upgrade_path_error_result_custom_msg
CUSTOM_MSG_PREFIX = _constants.CUSTOM_MSG_PREFIX


class FakeCache:
    """Dict-backed stand-in for pytest's config.cache."""

    def __init__(self, cachedir):
        self._store = {}
        self._cachedir = cachedir

    def get(self, key, default):
        value = self._store.get(key, default)
        return default if value is None else value

    def set(self, key, value):
        self._store[key] = value


class FakeConfig:
    def __init__(self, cachedir, options=None):
        self.cache = FakeCache(cachedir)
        self._options = options or {}

    def getoption(self, name, default=None):
        return self._options.get(name, default)


class FakeNode:
    def __init__(self, name):
        self.name = name


class FakeRequest:
    def __init__(self, config, node_name):
        self.config = config
        self.node = FakeNode(node_name)


class FakeReport:
    def __init__(self, passed=False, skipped=False):
        self.passed = passed
        self.skipped = skipped


class FakeItem:
    def __init__(self, config, name):
        self.config = config
        self.name = name


class FakeCall:
    def __init__(self, when, excinfo=None):
        self.when = when
        self.excinfo = excinfo


_UPGRADE_OPTIONS = {
    "base_image_list": "http://base-image",
    "target_image_list": "http://target-image",
    "multi_hop_upgrade_path": None,
}


def _cache_key(node_name):
    return "{}.{}".format(CUSTOM_MSG_PREFIX, get_upgrade_path_result_key(node_name))


def _cached_error_type(config, node_name):
    value = config.cache.get(_cache_key(node_name), None)
    return value.get("error_type") if isinstance(value, dict) else value


def _run_makereport(item, call):
    gen = upgrade_path_conftest.pytest_runtest_makereport(item, call)
    next(gen)
    with pytest.raises(StopIteration):
        gen.send(None)


@pytest.fixture
def config(tmp_path):
    return FakeConfig(tmp_path, dict(_UPGRADE_OPTIONS))


def test_result_key_is_per_test_and_sanitized():
    key_one = get_upgrade_path_result_key("test_upgrade[img-1.2.3/sub\\x]")
    key_two = get_upgrade_path_result_key("test_cancelled_upgrade[img-1.2.3]")
    # '.' (CustomMsg nesting delimiter) and path separators must be replaced.
    assert key_one == "upgrade_path_result.test_upgrade[img-1_2_3_sub_x]"
    assert key_one != key_two
    assert key_two.startswith("upgrade_path_result.")


def test_outer_handler_does_not_overwrite_specific_classification(config):
    """Nested exception: a coarse outer label never replaces a specific inner one."""
    request = FakeRequest(config, "test_upgrade[a]")
    set_upgrade_path_error_result_custom_msg(request, ErrorType.INSTALL_TARGET_IMAGE_FAILED)
    set_upgrade_path_error_result_custom_msg(request, ErrorType.RELOADTEST_VERIFICATION)
    set_upgrade_path_error_result_custom_msg(request, ErrorType.POST_RELOADTEST_VERIFICATION)
    assert _cached_error_type(config, "test_upgrade[a]") == ErrorType.INSTALL_TARGET_IMAGE_FAILED.value


def test_specific_classification_replaces_unknown_seed(config):
    request = FakeRequest(config, "test_upgrade[a]")
    set_upgrade_path_error_result_custom_msg(request, ErrorType.UNKNOWN)
    set_upgrade_path_error_result_custom_msg(request, ErrorType.BOOT_INTO_BASE_IMAGE_FAILED)
    assert _cached_error_type(config, "test_upgrade[a]") == ErrorType.BOOT_INTO_BASE_IMAGE_FAILED.value
    # ... and UNKNOWN can never demote it back.
    set_upgrade_path_error_result_custom_msg(request, ErrorType.UNKNOWN)
    assert _cached_error_type(config, "test_upgrade[a]") == ErrorType.BOOT_INTO_BASE_IMAGE_FAILED.value


def test_no_write_without_upgrade_path_options(tmp_path):
    config = FakeConfig(tmp_path, {})
    request = FakeRequest(config, "test_other")
    set_upgrade_path_error_result_custom_msg(request, ErrorType.RELOADTEST_VERIFICATION)
    assert config.cache._store == {}


def test_multi_test_run_preserves_earlier_failure(config):
    """A later passing/skipped test must not clear an earlier test's classification
    before the session-level CustomMsg emission on the last test's teardown."""
    failing, passing, skipping = "test_upgrade[a]", "test_upgrade[b]", "test_upgrade[c]"

    # Test 1: seeded, then classified at an exit point, then fails (call.excinfo set).
    item_fail = FakeItem(config, failing)
    upgrade_path_conftest.pytest_runtest_setup(item_fail)
    assert _cached_error_type(config, failing) == ErrorType.UNKNOWN.value
    set_upgrade_path_error_result_custom_msg(
        FakeRequest(config, failing), ErrorType.INSTALL_TARGET_IMAGE_FAILED)
    item_fail.rep_setup = FakeReport(passed=True)
    item_fail.rep_call = FakeReport(passed=False)
    _run_makereport(item_fail, FakeCall("teardown"))

    # Test 2: passes; only its own key is cleared.
    item_pass = FakeItem(config, passing)
    upgrade_path_conftest.pytest_runtest_setup(item_pass)
    item_pass.rep_setup = FakeReport(passed=True)
    item_pass.rep_call = FakeReport(passed=True)
    _run_makereport(item_pass, FakeCall("teardown"))

    # Test 3: skipped; only its own key is cleared.
    item_skip = FakeItem(config, skipping)
    upgrade_path_conftest.pytest_runtest_setup(item_skip)
    item_skip.rep_setup = FakeReport(skipped=True)
    item_skip.rep_call = None
    _run_makereport(item_skip, FakeCall("teardown"))

    assert _cached_error_type(config, failing) == ErrorType.INSTALL_TARGET_IMAGE_FAILED.value
    assert config.cache._store.get(_cache_key(passing)) is None
    assert config.cache._store.get(_cache_key(skipping)) is None


def test_skip_with_teardown_failure_keeps_classification(config):
    """A skipped/passed setup+call with a failing teardown must keep the seed."""
    item = FakeItem(config, "test_upgrade[a]")
    upgrade_path_conftest.pytest_runtest_setup(item)
    item.rep_setup = FakeReport(skipped=True)
    item.rep_call = None
    _run_makereport(item, FakeCall("teardown", excinfo=MagicMock()))
    assert _cached_error_type(config, "test_upgrade[a]") == ErrorType.UNKNOWN.value


@pytest.mark.parametrize("raiser", [
    pytest.fail.Exception("pytest_assert in boot health check"),
    RuntimeError("plain exception"),
])
def test_boot_into_base_image_failure_is_classified(config, monkeypatch, raiser):
    """pytest.fail-based failures derive from BaseException and must still be
    caught and classified at the boot-into-base-image exit point."""
    request = FakeRequest(config, "test_upgrade[a]")
    monkeypatch.setattr(test_upgrade_path, "cleanup_prev_images", MagicMock())
    monkeypatch.setattr(
        test_upgrade_path, "boot_into_base_image", MagicMock(side_effect=raiser))
    with pytest.raises(type(raiser)):
        test_upgrade_path.setup_upgrade_test(
            request, MagicMock(), MagicMock(), "from-img", "to-img",
            {"topo": {"type": "t0"}}, "warm")
    assert _cached_error_type(config, "test_upgrade[a]") == ErrorType.BOOT_INTO_BASE_IMAGE_FAILED.value


@pytest.mark.parametrize("raiser", [
    pytest.fail.Exception("pytest_assert during install"),
    RuntimeError("plain exception"),
])
def test_install_target_image_failure_is_classified(config, monkeypatch, raiser):
    request = FakeRequest(config, "test_upgrade[a]")
    monkeypatch.setattr(test_upgrade_path, "cleanup_prev_images", MagicMock())
    monkeypatch.setattr(test_upgrade_path, "boot_into_base_image", MagicMock())
    monkeypatch.setattr(
        test_upgrade_path, "install_sonic", MagicMock(side_effect=raiser))
    with pytest.raises(type(raiser)):
        test_upgrade_path.setup_upgrade_test(
            request, MagicMock(), MagicMock(), "from-img", "to-img",
            {"topo": {"type": "t0"}}, "warm")
    assert _cached_error_type(config, "test_upgrade[a]") == ErrorType.INSTALL_TARGET_IMAGE_FAILED.value
