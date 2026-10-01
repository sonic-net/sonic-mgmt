"""Verify real package-suite collection profiles without DUT fixture execution."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SUITE = ROOT / "tests" / "sonic_operations"
CPHC = "test_cphc_package_nightly.py::"
SUP = "test_postupgrade_package_nightly.py::"
DOWNLOAD = "test_package_download_nightly.py::"
DEFAULT = {
    CPHC + "test_cphc_package_install_from_image_server",
    CPHC + "test_cphc_package_rejects_corrupted_download",
    SUP + "test_postupgrade_package_integrity",
    SUP + "test_postupgrade_package_runs_directly",
    DOWNLOAD + "test_image_server_is_reachable",
} | {
    DOWNLOAD + name + "[" + package + "]"
    for package in ("cphc", "postupgrade")
    for name in (
        "test_package_downloads_with_curl", "test_md5_file_is_parseable_by_both_consumers",
        "test_tarball_matches_published_md5", "test_tarball_is_a_readable_archive",
        "test_tarball_contains_expected_members", "test_corrupted_tarball_fails_md5",
        "test_truncated_tarball_is_rejected",
    )
}
INTEGRATION = {
    CPHC + "test_cphc_package_downloads_via_real_preload_firmware",
    CPHC + "test_real_preload_firmware_rejects_corrupted_package",
    SUP + "test_postupgrade_wrapper_runs_real_script",
    SUP + "test_wrapper_rejects_corrupted_cached_package",
    SUP + "test_postupgrade_package_downloads_via_real_preload_firmware",
    SUP + "test_real_preload_firmware_rejects_corrupted_postupgrade_package",
    SUP + "test_postupgrade_hwproxy_flow_end_to_end",
}

DRIVER = """
import json, sys
from pathlib import Path
import pytest

record = {'selected': [], 'deselected': [], 'fixtures': [], 'outcomes': []}
def key(item):
    return Path(str(item.fspath)).name + '::' + item.name
class Observe:
    def pytest_deselected(self, items):
        record['deselected'].extend(key(item) for item in items)
    def pytest_collection_finish(self, session):
        record['selected'] = [key(item) for item in session.items]
        record['registered'] = any(
            marker.startswith('sonic_operations_integration:')
            for marker in session.config.getini('markers'))
        record['enabled'] = session.config.getoption('--sonic_operations_integration')
    def pytest_fixture_setup(self, fixturedef, request):
        record['fixtures'].append(fixturedef.argname)
        raise AssertionError('No fixture may execute in this collection regression')
    def pytest_runtest_logreport(self, report):
        if report.when == 'call':
            record['outcomes'].append(report.outcome)

result = pytest.main(sys.argv[2:], plugins=[Observe()])
Path(sys.argv[1]).write_text(json.dumps(record))
sys.exit(result)
"""


def collect(tmp_path, options=(), nodes=(), execute=False, unrelated=None, expected_exit=None):
    """Use actual suite conftest, marker registry and collection hook in a fresh pytest process."""
    output = tmp_path / "collection.json"
    targets = ([str(SUITE / node) for node in nodes] if nodes else [
        str(SUITE / filename) for filename in
        ("test_package_download_nightly.py", "test_cphc_package_nightly.py", "test_postupgrade_package_nightly.py")
    ])
    if unrelated:
        targets.append(str(unrelated))
    args = ["-c", str(ROOT / "tests" / "pytest.ini"), "--confcutdir=" + str(SUITE), "--strict-markers",
            "-q", "--tb=short", "-o", "log_format=%(message)s", "-o", "log_cli_format=%(message)s"]
    if not execute:
        args.append("--collect-only")
    environment = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, "-c", DRIVER, str(output), *args, *targets, *options],
                            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
    if expected_exit is None:
        expected_exit = 5 if execute else 0
    assert result.returncode == expected_exit, result.stdout + result.stderr
    record = json.loads(output.read_text())
    assert record["registered"]
    assert record["fixtures"] == []
    for key in ("selected", "deselected"):
        record[key] = set(record[key])
    return record


@pytest.mark.parametrize("options,enabled", [
    ([], False),
    (["--image_server_url=https://sonicstorageinternal.blob.core.windows.net/images",
      "--sonic_ops_branch=ryanzhu/ops-publish-cicd"], False),
    (["--sonic_operations_integration"], True),
])
def test_real_three_path_profile_membership(tmp_path, options, enabled):
    """Paths-only selects exactly 19; explicit consumer opt-in selects exactly 26."""
    result = collect(tmp_path, options=options)
    assert len(DEFAULT) == 19 and len(INTEGRATION) == 7
    assert result["enabled"] is enabled
    assert result["selected"] == (DEFAULT | INTEGRATION if enabled else DEFAULT)
    assert result["deselected"] == (set() if enabled else INTEGRATION)


def test_explicit_integration_nodes_cannot_start_fixtures_without_opt_in(tmp_path):
    """Even explicitly requested integration nodes are deselected before any fixture starts."""
    result = collect(tmp_path, nodes=sorted(INTEGRATION), execute=True)
    assert result["selected"] == set()
    assert result["deselected"] == INTEGRATION


def test_cached_wrapper_recovery_remains_skipped_with_integration_opt_in(tmp_path):
    """Actual pytest execution of the guarded request-only case cannot acquire DUT fixtures."""
    node = SUP + "test_wrapper_rejects_corrupted_cached_package"
    result = collect(tmp_path, options=["--sonic_operations_integration"],
                     nodes=[node], execute=True, expected_exit=0)
    assert result["selected"] == {node}
    assert result["outcomes"] == ["skipped"]


def test_profile_hook_leaves_unrelated_marked_tests_selected(tmp_path):
    """A directory-scoped conftest hook must not filter marked tests outside its suite."""
    unrelated = tmp_path / "test_unrelated.py"
    unrelated.write_text(
        "import pytest\n@pytest.mark.sonic_operations_integration\n"
        "def test_unrelated():\n    raise AssertionError('collection only')\n")
    result = collect(tmp_path, unrelated=unrelated)
    assert result["selected"] == DEFAULT | {"test_unrelated.py::test_unrelated"}
    assert result["deselected"] == INTEGRATION
