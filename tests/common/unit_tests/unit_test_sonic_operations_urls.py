"""Exercise actual package URL resolvers without DUT or integration fixtures.

Run: python -m pytest --noconftest --confcutdir=tests/common/unit_tests
     tests/common/unit_tests/unit_test_sonic_operations_urls.py -q
"""

import argparse
import importlib.util
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]
PACKAGE_DIR = ROOT / 'tests' / 'sonic_operations'
BASE = 'http://10.1.3.6/azmirrors/ACS/sonic-upgrade-packages'
PREFIX = 'pipelines/sonic-operations-packages-Official'
MODULES = ('test_package_download_nightly', 'test_cphc_package_nightly', 'test_postupgrade_package_nightly')
FILES = ('sonic-upgrade-package-1.0.0.tar', 'sonic-upgrade-package.tar.gz')
LATEST = tuple(BASE + '/' + file for file in FILES)


def _load(name):
    spec = importlib.util.spec_from_file_location('unit_urls_' + name, PACKAGE_DIR / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def modules():
    """Use real conftest registrations, helper and all three module resolvers."""
    helper = _load('sonic_operations_helper')
    with patch.dict(sys.modules, {'sonic_operations_helper': helper}):
        return SimpleNamespace(options=_load('conftest'), helper=helper,
                               tests=tuple(_load(name) for name in MODULES))


def _request(modules, arguments, tbinfo=None):
    parser = argparse.ArgumentParser()
    group = SimpleNamespace(addoption=parser.add_argument)
    modules.options.pytest_addoption(SimpleNamespace(getgroup=lambda name: group))
    options = vars(parser.parse_args(arguments))
    fixtures = {"tbinfo": {"inv_name": "str2"} if tbinfo is None else tbinfo}
    return SimpleNamespace(config=SimpleNamespace(getoption=lambda key: options[key.lstrip('-')]),
                           getfixturevalue=lambda name: fixtures[name])


def _resolve(modules, request):
    download, cphc, sup = modules.tests
    packages = download.packages.__wrapped__(request)
    return (download._package_url(request, packages['cphc']),
            download._package_url(request, packages['postupgrade']),
            cphc.package_url.__wrapped__(request), sup._tarball_url(request))


def _assert_urls(modules, request, cphc, sup):
    actual = _resolve(modules, request)
    assert actual == (cphc, sup, cphc, sup)
    for url in actual:
        for suffix in ('.md5', '.buildinfo.json'):
            assert modules.helper.sibling_url(url, suffix) == url + suffix


@pytest.mark.parametrize('branch', ['main', 'ryanzhu/ops-publish-cicd'])
def test_default_consumer_paths(modules, branch):
    """Legacy source branches cannot redirect the shared latest route."""
    request = _request(modules, ['--sonic_ops_branch', branch])
    _assert_urls(modules, request, *LATEST)
    assert all(url.count('/azmirrors/') == 1 for url in _resolve(modules, request))


def test_paths_only_consumer_defaults(modules):
    """Module paths select latest packages without a dedicated launcher or source options."""
    _assert_urls(modules, _request(modules, []), *LATEST)
    assert _request(modules, []).config.getoption("--cphc_wheel_version") is None


@pytest.mark.parametrize("testbed,host", [
    ("tbtk5-t0-7260-01", "10.1.3.6"),
    ("vms20-t0-7050cx3-1", "10.1.3.6"),
    ("testbed-bjw-can-2700-1", "10.150.22.222"),
    ("testbed-bjw-can-2700-3", "10.150.22.222"),
    ("testbed-bjw2-can-t0-4600c-1", "10.150.22.222"),
])
def test_repository_testbed_inventory_selects_all_module_sources(modules, testbed, host):
    """Use authoritative repository entries, including tbtk5 rather than a guessed name substring."""
    tbinfo = next(entry for entry in yaml.safe_load((ROOT / "ansible" / "testbed.yaml").read_text())
                  if entry["conf-name"] == testbed)
    req = _request(modules, [], tbinfo)
    base = "http://" + host + "/azmirrors/ACS/sonic-upgrade-packages/"
    _assert_urls(modules, req, *(base + file for file in FILES))
    for key, selector in (("cphc", "critical-process-health-checker"), ("postupgrade", "postupgrade_actions")):
        source = modules.helper.delivery_package_source(req, key)
        assert source["selector"] == base + selector + ".latest.buildinfo.json"
        for url in (source["selector"], source["url"], source["url"] + ".md5", source["url"] + ".buildinfo.json"):
            assert modules.helper.candidate_urls(url) == [url]
            assert modules.helper.with_sas_token(url, "never-forward") == url


@pytest.mark.parametrize("tbinfo", [
    {}, {"inv_name": ""}, {"inv_name": None}, {"inv_name": ["strtk5", "bjw"]},
    {"conf-name": "testbed-bjw-can-2700-1"},
])
def test_missing_or_ambiguous_inventory_cannot_guess_mirror(modules, tbinfo):
    """A malformed testbed record is not a region signal."""
    with pytest.raises(ValueError, match="inv_name"):
        _resolve(modules, _request(modules, [], tbinfo))


@pytest.mark.parametrize("inventory", ["strtk5", "lab", "ixia", "playground", "new-region", "notbjw"])
def test_every_non_bjw_inventory_uses_default_mirror(modules, inventory):
    """The user-defined default applies to every other inventory, not just the STR list."""
    _assert_urls(modules, _request(modules, [], {"inv_name": inventory}), *LATEST)


def test_inventory_is_authoritative_and_region_cannot_change_midrun(modules):
    """Display names are not region signals; a run cannot mix mirrored sources."""
    tbinfo = {"conf-name": "a-name-containing-bjw", "inv_name": "strtk5"}
    req = _request(modules, ["--image_server_url=http://10.150.22.222"], tbinfo)
    _assert_urls(modules, req, *LATEST)
    tbinfo["inv_name"] = "bjw"
    with pytest.raises(ValueError, match="refusing to switch regions"):
        _resolve(modules, req)


@pytest.mark.parametrize("inventory,host", [
    ("Str", "10.1.3.6"), ("strtk5a", "10.1.3.6"), ("bjw3", "10.150.22.222"),
])
def test_other_registered_regional_inventory_variants(modules, inventory, host):
    """Inventory spellings present in the repository retain the selected regional route."""
    entries = yaml.safe_load((ROOT / "ansible" / "testbed.yaml").read_text())
    tbinfo = next(entry for entry in entries if entry.get("inv_name") == inventory)
    _assert_urls(modules, _request(modules, [], tbinfo),
                 *("http://" + host + "/azmirrors/ACS/sonic-upgrade-packages/" + file for file in FILES))


@pytest.mark.parametrize("testbed,host", [
    ("tbtk5-t0-7260-01", "10.1.3.6"),
    ("testbed-bjw-can-2700-1", "10.150.22.222"),
])
def test_regional_resolution_with_real_pytest_request_and_tbinfo_fixture(tmp_path, testbed, host):
    """The real package conftest and session-scoped tbinfo fixture work without DUT fixture setup."""
    tbinfo = next(entry for entry in yaml.safe_load((ROOT / "ansible" / "testbed.yaml").read_text())
                  if entry["conf-name"] == testbed)
    probe = tmp_path / "test_region.py"
    base = "http://" + host + "/azmirrors/ACS/sonic-upgrade-packages/"
    probe.write_text(
        "from sonic_operations_helper import delivery_package_source, delivery_package_url\n"
        "def test_region(request):\n"
        "    for key in ('cphc', 'postupgrade'):\n"
        "        source = delivery_package_source(request, key)\n"
        "        assert source['url'] == " + repr(base) + " + source['filename']\n"
        "        assert source['selector'].startswith(" + repr(base) + ")\n"
        "        assert delivery_package_url(request, key) == source['url']\n")
    driver = """
import importlib.util, json, sys
from pathlib import Path
import pytest
source, data, config, test = sys.argv[1:]
sys.path.insert(0, source)
spec = importlib.util.spec_from_file_location('regional_conftest', Path(source) / 'conftest.py')
options = importlib.util.module_from_spec(spec)
spec.loader.exec_module(options)
class Testbed:
    @pytest.fixture(scope='session')
    def tbinfo(self):
        return json.loads(data)
sys.exit(pytest.main(['--noconftest', '-c', config, '-q', test,
                     '-o', 'log_format=%(message)s', '-o', 'log_cli_format=%(message)s'],
                    plugins=[options, Testbed()]))
"""
    environment = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-c", driver, str(PACKAGE_DIR), json.dumps(tbinfo),
         str(ROOT / "tests" / "pytest.ini"), str(probe)],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


@pytest.mark.parametrize("version", ["1.0.18", "1.0.19", "2.0.0rc1", "1.2.3.post1"])
def test_verified_cphc_archive_version_is_derived_from_matching_wheels(modules, version):
    """Version discovery must advance with the artifact, not a permanently fixed wheel constant."""
    members = ["installer.py"] + [
        "sonic_critical_process_checker-{}-{}-none-any.whl".format(version, tag) for tag in ("py2", "py3")]
    assert modules.helper.cphc_archive_wheel_version(members) == version
    assert modules.helper.cphc_archive_wheel_version(["./" + member for member in members]) == version


@pytest.mark.parametrize("wheels", [
    [],
    ["sonic_critical_process_checker-1.0.18-py3-none-any.whl"],
    ["sonic_critical_process_checker-1.0.18-py2-none-any.whl",
     "sonic_critical_process_checker-1.0.19-py3-none-any.whl"],
    ["sonic_critical_process_checker-1.0.18-py2-none-any.whl",
     "sonic_critical_process_checker-1.0.18-py3-none-any.whl",
     "sonic_critical_process_checker-1.0.19-py3-none-any.whl"],
    ["foreign-1.0.18-py2-none-any.whl", "foreign-1.0.18-py3-none-any.whl"],
    ["nested/sonic_critical_process_checker-1.0.18-py2-none-any.whl",
     "nested/sonic_critical_process_checker-1.0.18-py3-none-any.whl"],
])
def test_ambiguous_or_incomplete_cphc_wheel_release_is_rejected(modules, wheels):
    """Missing, conflicting or foreign wheels cannot supply an expected installer version."""
    with pytest.raises(AssertionError, match="CPHC"):
        modules.helper.cphc_archive_wheel_version(["installer.py", *wheels])


@pytest.mark.parametrize('module_index', range(3))
def test_latest_urls_override_stale_base_and_paths(modules, module_index):
    """Legacy pinned/full URL options cannot override code-owned source selection."""
    request = _request(modules, [
        '--image_server_url=https://sonicstorageinternal.blob.core.windows.net/images',
        '--sonic_ops_branch=stale', '--cphc_package_path=stale-cphc', '--sup_package_path=stale-sup',
        '--use_mirror_layout', '--cphc_package_url=' + LATEST[0], '--sup_package_url=' + LATEST[1]])
    actual = _resolve(modules, request)
    indexes = ((0, 1), (2,), (3,))[module_index]
    for index in indexes:
        url = actual[index]
        assert url == LATEST[index % 2]
        for suffix in ('', '.md5', '.buildinfo.json'):
            target = modules.helper.sibling_url(url, suffix)
            assert target == url + suffix
            for candidate in modules.helper.candidate_urls(target):
                assert candidate == target
                assert '/ACS/sonic-upgrade-packages/' in candidate
                assert '/builds/' not in candidate
                assert '/images/' not in candidate


@pytest.mark.parametrize('base', [
    'https://sonicstorageinternal.blob.core.windows.net/images',
    'https://custom.example/downloads/',
])
def test_explicit_base_and_paths_preserved(modules, base):
    """Explicit upload/custom bases and paths are ignored by the actual resolvers."""
    request = _request(modules, [
        '--image_server_url=' + base, '--sonic_ops_branch=ignored',
        '--cphc_package_path=/custom/cphc/', '--sup_package_path=/custom/sup/'])
    _assert_urls(modules, request, *LATEST)
    request = _request(modules, ['--image_server_url=' + base])
    _assert_urls(modules, request, *LATEST)
    assert modules.helper.build_package_url(base, 'custom/cphc', 'file.tar') == (
        base.rstrip('/') + '/custom/cphc/file.tar')


@pytest.mark.parametrize('base,expected_base', [
    (None, 'https://sonic.packages.trafficmanager.net'),
    ('https://sonic.packages.trafficmanager.net/azmirrors/', 'https://sonic.packages.trafficmanager.net'),
    ('http://mirror.example', 'http://mirror.example'),
    ('http://mirror.example/custom/', 'http://mirror.example/custom'),
])
def test_production_mirror_layout_preserved(modules, base, expected_base):
    """Legacy mirror layout cannot redirect sourcing; generic mirror helper is unchanged."""
    arguments = ['--use_mirror_layout']
    if base:
        arguments.append('--image_server_url=' + base)
    urls = _resolve(modules, _request(modules, arguments))
    assert urls == (LATEST[0], LATEST[1], LATEST[0], LATEST[1])
    for file in FILES:
        assert modules.helper.mirror_package_url(
            expected_base, file, modules.helper.MIRROR_CPHC_SUBPATH) == (
                expected_base + '/networkfirmware/ACS/sonic-upgrade-packages/' + file)


@pytest.mark.parametrize("module_index", range(3))
def test_exact_original_manual_arguments_are_ignored_with_warning(modules, caplog, module_index):
    """All three paths accept the original failing plan unchanged and never resolve Blob."""
    request = _request(modules, shlex.split(
        "--image_server_url=https://sonicstorageinternal.blob.core.windows.net/images "
        "--sonic_ops_branch=ryanzhu/ops-publish-cicd"))
    _assert_urls(modules, request, *LATEST)
    assert "--image_server_url" in caplog.text and "ignoring source options" in caplog.text


def test_conflicting_locations_and_sas_never_escape_to_requests_or_logs(modules, caplog):
    """Keep old options parseable without leaking legacy credentials to the frontend."""
    request = _request(modules, [
        '--cphc_package_url=https://bad.example/other.tar?sig=secret-value',
        '--sup_package_url=https://bad.example/other.tar.gz',
        '--cphc_package_path=bad', '--sup_package_path=bad',
        '--sonic_ops_branch=bad', '--use_mirror_layout', '--package_sas_token=secret-value'])
    _assert_urls(modules, request, *LATEST)
    for url in LATEST:
        for suffix in ('', '.md5', '.buildinfo.json'):
            assert modules.helper.with_sas_token(url + suffix, 'secret-value') == url + suffix
            assert modules.helper.candidate_urls(url + suffix) == [url + suffix]
    assert "secret-value" not in caplog.text
    assert "--package_sas_token" in caplog.text


@pytest.mark.parametrize("module_index", range(3))
def test_archive_version_mismatch_fails_in_each_actual_resolver(modules, module_index):
    """HWP still requires its fixed archive filename even when the wheel version advances."""
    request = _request(modules, ["--cphc_tar_version", "2.0.0"])
    download, cphc, sup = modules.tests
    with pytest.raises(ValueError, match="HWP archive filename"):
        if module_index == 0:
            download.packages.__wrapped__(request)
        elif module_index == 1:
            cphc.package_url.__wrapped__(request)
        else:
            sup._tarball_url(request)


def test_generic_helper_routes_still_support_non_delivery_callers(modules):
    """Code-owned testcase sourcing does not rewrite general URL or local mirror contracts."""
    helper = modules.helper
    url = helper.build_package_url("https://custom.example/base", "path", "package.tar")
    assert helper.candidate_urls(url)[0] == url
    assert len(helper.candidate_urls(url)) > 1
    assert helper.with_sas_token(url, "test-token") == url + "?test-token"
    assert helper.published_package_path("package", "main") == PREFIX + "/package"


def test_latest_routes_match_producer_without_historical_build_guards(modules):
    """The route is fixed, while build/commit/digest identity comes from publication metadata."""
    helper = modules.helper
    assert helper.DELIVERY_PACKAGES["cphc"]["url"] == LATEST[0]
    assert helper.DELIVERY_PACKAGES["postupgrade"]["url"] == LATEST[1]
    for key, name in (("cphc", "critical-process-health-checker"), ("postupgrade", "postupgrade_actions")):
        package = helper.DELIVERY_PACKAGES[key]
        assert package["selector"] == BASE + "/" + name + ".latest.buildinfo.json"
        assert "md5" not in package
        assert helper.candidate_urls(package["selector"]) == [package["selector"]]
        assert helper.with_sas_token(package["selector"], "secret-token") == package["selector"]
