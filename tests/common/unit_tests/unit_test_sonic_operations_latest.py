"""Fail-closed producer metadata contracts, without network or package execution."""

import importlib.util
import json
import posixpath
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pytest_ansible.results import ModuleResult


LIFECYCLE = Path(__file__).with_name("unit_test_sonic_operations_lifecycle.py")
spec = importlib.util.spec_from_file_location("latest_lifecycle", LIFECYCLE)
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
helper = lifecycle.helper


@pytest.fixture(autouse=True)
def linux_remote_paths(monkeypatch):
    """The remote hosts in this Windows-capable harness expose Linux paths."""
    monkeypatch.setattr(helper, "os", SimpleNamespace(path=posixpath))


def buildinfo(package="cphc", build="200", commit="a" * 40):
    return {
        "schemaVersion": 1, "package": helper.DELIVERY_PACKAGES[package]["filename"],
        "buildId": build, "buildNumber": "20260914.1", "branch": "main", "commit": commit,
        "publishedUtc": "2026-09-14T19:00:00Z", "md5": "b" * 32, "sha256": "c" * 64, "sizeBytes": 1024,
        "archiveVersion": "1.0.0" if package == "cphc" else None,
        "wheelVersion": "1.0.19" if package == "cphc" else None,
        "reportVersion": "1.0.0" if package == "postupgrade" else None,
    }


@pytest.mark.parametrize("package", ["cphc", "postupgrade"])
def test_valid_latest_metadata_binds_independent_package_builds(package):
    """Each package has its own build/commit; a cross-package build equality is not required."""
    info = buildinfo(package, build="201" if package == "cphc" else "199",
                     commit=("d" if package == "cphc" else "e") * 40)
    assert helper.parse_package_buildinfo(json.dumps(info), package, info["package"]) == info
    helper.require_coherent_package_metadata(info, dict(info))


@pytest.mark.parametrize("field,value", [
    ("schemaVersion", None), ("schemaVersion", True), ("schemaVersion", 2),
    ("buildId", ""), ("buildId", "wrong"), ("buildId", "0"), ("commit", "short"),
    ("md5", "HTML"), ("sha256", ""), ("sizeBytes", 0), ("sizeBytes", True), ("sizeBytes", "1024"),
    ("branch", ""), ("buildNumber", None), ("publishedUtc", "yesterday"),
    ("publishedUtc", "2026-09-14T19:00:00"), ("package", "foreign.tar"),
    ("archiveVersion", "2.0.0"), ("wheelVersion", None), ("reportVersion", "1.0.0"),
])
def test_invalid_latest_provenance_is_rejected(field, value):
    info = buildinfo()
    info[field] = value
    with pytest.raises(AssertionError):
        helper.parse_package_buildinfo(json.dumps(info), "cphc", "sonic-upgrade-package-1.0.0.tar")


@pytest.mark.parametrize("contents", ["", "<html>404</html>", "null", "[]", '{"buildId": "200"}'])
def test_missing_or_html_latest_metadata_is_not_provenance(contents):
    with pytest.raises(AssertionError):
        helper.parse_package_buildinfo(contents, "cphc", "sonic-upgrade-package-1.0.0.tar")


@pytest.mark.parametrize("field", ["buildId", "commit", "md5", "sha256", "sizeBytes", "wheelVersion", "publishedUtc"])
def test_generation_bracket_rejects_changed_metadata(field):
    before = buildinfo()
    after = dict(before)
    after[field] = "changed"
    with pytest.raises(AssertionError, match="torn latest generation"):
        helper.require_coherent_package_metadata(before, after)


def fresh_request(**options):
    req = lifecycle.request(**options)
    del req.config._sonic_operations_publications
    return req


class RecordingHost(lifecycle.Host):
    def __init__(self, package_sources=None):
        super().__init__(package_sources)
        self.requests = []

    def run(self, words, cwd):
        if words[0] == "curl":
            self.requests.append(next(word for word in words if word.startswith(("http://", "https://"))))
        return super().run(words, cwd)


@pytest.mark.parametrize("package", ["cphc", "postupgrade"])
@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("inventory,host_ip", [("strtk5", "10.1.3.6"), ("bjw", "10.150.22.222")])
def test_real_latest_fetch_checks_full_bracket_and_pins_build(package, direct, inventory, host_ip):
    """Both staging and exact consumer curl validate all five objects/observations."""
    sources = helper.BJW_DELIVERY_PACKAGES if inventory == "bjw" else helper.DELIVERY_PACKAGES
    host = RecordingHost(sources)
    req = fresh_request(tbinfo={"inv_name": inventory})
    curl = (helper.curl_like_hwproxy if package == "cphc" else helper.curl_like_wrapper) if direct else None
    with helper.dut_workspace(host, "latest-unit") as directory:
        result = helper.download_latest_package(req, host, None, package, directory, consumer_curl=curl)
        assert result["buildinfo"] == host.publications[package]
        assert helper.publication_info(req, package) == host.publications[package]
    config = sources[package]
    assert host.requests == [config["selector"], config["url"] + ".md5", config["url"],
                             config["url"] + ".buildinfo.json", config["selector"]]
    assert all(url.startswith("http://" + host_ip + "/azmirrors/ACS/sonic-upgrade-packages/") for url in host.requests)


@pytest.mark.parametrize("fault", [
    "selector_a_html", "selector_unreachable", "tar_metadata_other_build", "selector_b_other_build",
    "matching_new_tar_and_md5", "wrong_sha256", "wrong_size", "wrong_sidecar_filename",
    "unreadable_archive", "wrong_entrypoint", "md5_html", "truncated_tar",
])
def test_latest_download_rejects_incoherent_or_invalid_publication(fault):
    """Never accept mixed generations, HTML, missing scripts or malformed byte identities."""
    package = helper.DELIVERY_PACKAGES["postupgrade"]

    class BrokenHost(RecordingHost):
        def run(self, words, cwd):
            result = super().run(words, cwd)
            if words[0] == "curl":
                url = self.requests[-1]
                if url == package["selector"]:
                    if fault == "selector_a_html":
                        result["stdout"] = "<html>not found</html>"
                    elif fault == "selector_unreachable":
                        result.update(rc=28, stdout="000", stderr="timeout")
                    elif fault == "selector_b_other_build" and self.requests.count(url) == 2:
                        info = json.loads(result["stdout"])
                        info["buildId"] = "999"
                        result["stdout"] = json.dumps(info)
                if url == package["url"] + ".buildinfo.json" and fault == "tar_metadata_other_build":
                    info = json.loads(result["stdout"])
                    info["buildId"] = "999"
                    result["stdout"] = json.dumps(info)
                if url == package["url"] + ".md5":
                    dest = words[words.index("-o") + 1]
                    if fault == "wrong_sidecar_filename":
                        self.write(dest, (self.publications["postupgrade"]["md5"] + "  foreign.tar.gz").encode())
                    elif fault == "md5_html":
                        self.write(dest, b"<html>404</html>")
                if url == package["url"] and fault == "truncated_tar":
                    self.write(words[words.index("-o") + 1], self.payloads["postupgrade"][:50])
            return result

    host = BrokenHost()
    if fault == "matching_new_tar_and_md5":
        host.payloads["postupgrade"] = lifecycle.package_bytes(True) + b"new-build-bytes"
    elif fault == "wrong_sha256":
        host.publications["postupgrade"]["sha256"] = "0" * 64
    elif fault == "wrong_size":
        host.publications["postupgrade"]["sizeBytes"] += 1
    elif fault in ("unreadable_archive", "wrong_entrypoint"):
        data = b"<html>not a tar archive</html>" if fault == "unreadable_archive" else lifecycle.package_bytes()
        host.payloads["postupgrade"] = data
        host.publications["postupgrade"] = lifecycle.publication_metadata("postupgrade", data)
    with helper.dut_workspace(host, "latest-reject") as directory:
        with pytest.raises((AssertionError, RuntimeError)):
            helper.download_latest_package(fresh_request(), host, None, "postupgrade", directory,
                                           consumer_curl=helper.curl_like_wrapper)
    assert not any("timeout --signal" in command or "--install" in command for command in host.commands)
    if fault == "selector_unreachable":
        assert host.requests == [package["selector"]]


@pytest.mark.parametrize("inventory", ["strtk5", "bjw"])
def test_per_package_run_pins_reject_midrun_update_without_refetching_payload(inventory):
    """CPHC/SUP may originate from different builds, but neither may change within this pytest run."""
    sources = helper.BJW_DELIVERY_PACKAGES if inventory == "bjw" else helper.DELIVERY_PACKAGES
    host = RecordingHost(sources)
    req = fresh_request(tbinfo={"inv_name": inventory})
    with helper.dut_workspace(host, "latest-pins") as directory:
        for package in ("cphc", "postupgrade"):
            helper.download_latest_package(req, host, None, package, directory)
        assert helper.publication_info(req, "cphc")["buildId"] != helper.publication_info(req, "postupgrade")["buildId"]
        previous_count = len(host.requests)
        host.publications["cphc"]["buildId"] = "998"
        with pytest.raises(AssertionError, match="torn latest generation"):
            helper.download_latest_package(req, host, None, "cphc", directory)
        assert host.requests[previous_count:] == [sources["cphc"]["selector"]]
        # A new run can select the new release, without changing any CLI source options.
        helper.download_latest_package(fresh_request(tbinfo={"inv_name": inventory}), host, None, "cphc", directory)


def test_context_cannot_switch_regions_between_packages_even_with_equal_metadata():
    """Run-level source pinning forbids cross-lab reads before a second package is fetched."""
    host = RecordingHost(helper.BJW_DELIVERY_PACKAGES)
    tbinfo = {"inv_name": "bjw"}
    req = fresh_request(tbinfo=tbinfo)
    with helper.dut_workspace(host, "regional-pin") as directory:
        helper.download_latest_package(req, host, None, "cphc", directory)
        count = len(host.requests)
        tbinfo["inv_name"] = "strtk5"
        with pytest.raises(ValueError, match="refusing to switch regions"):
            helper.download_latest_package(req, host, None, "postupgrade", directory)
        assert len(host.requests) == count


@pytest.mark.parametrize("preinstalled", [None, "1.0.19"])
def test_cphc_new_wheel_release_installs_runs_and_restores_without_version_options(preinstalled):
    """The real fixture/test path must use metadata plus wheel contents, not old 1.0.18."""
    host = RecordingHost()
    host.installed = preinstalled
    data = lifecycle.package_bytes(wheel_version="1.0.19")
    host.payloads["cphc"] = data
    host.publications["cphc"] = lifecycle.publication_metadata("cphc", data, wheel_version="1.0.19")
    req = fresh_request()
    cphc = lifecycle.cphc
    with contextmanager(cphc.cphc_workspace.__wrapped__)(
            {"dut": host}, "dut", None, helper.DELIVERY_PACKAGES["cphc"]["url"], req) as source:
        with contextmanager(cphc.cphc_install_dir.__wrapped__)({"dut": host}, "dut", source) as directory:
            cphc.test_cphc_package_install_from_image_server(
                {"dut": host}, "dut", source, helper.DELIVERY_PACKAGES["cphc"]["url"], req, directory)
    assert host.installed == preinstalled
    assert helper.publication_info(req, "cphc")["wheelVersion"] == "1.0.19"


def test_explicit_cphc_wheel_expectation_mismatch_fails_before_download():
    host = RecordingHost()
    req = fresh_request(**{"--cphc_wheel_version": "9.9"})
    with pytest.raises(ValueError, match="wheel_version disagrees"):
        helper.select_package_publication(req, host, None, "cphc")
    assert host.requests == [helper.DELIVERY_PACKAGES["cphc"]["selector"]]
    assert not any(command.startswith("mkdir") for command in host.commands)


def test_preinstalled_other_version_is_not_overwritten_by_latest():
    """New release selection cannot remove a version for which no recovery wheel exists."""
    host = RecordingHost()
    host.installed = "0.9.0"
    with pytest.raises(pytest.skip.Exception, match="different|already installed"):
        with contextmanager(lifecycle.cphc.cphc_workspace.__wrapped__)(
                {"dut": host}, "dut", None, helper.DELIVERY_PACKAGES["cphc"]["url"], fresh_request()):
            pytest.fail("Unsafe installation must not be reached")
    assert host.installed == "0.9.0"
    assert not any(command.startswith("mkdir") or "--install" in command for command in host.commands)


def test_sup_report_version_is_derived_from_selected_release():
    host = RecordingHost()
    host.publications["postupgrade"]["reportVersion"] = "1.1.0"
    req = fresh_request()
    with lifecycle.sup_state(host) as state:
        getfixturevalue = req.getfixturevalue
        req.getfixturevalue = Mock(
            side_effect=lambda name: state if name == "postupgrade_state" else getfixturevalue(name))
        lifecycle.sup.test_postupgrade_package_runs_directly({"dut": host}, "dut", None, req)
    assert helper.publication_info(req, "postupgrade")["reportVersion"] == "1.1.0"


@pytest.mark.parametrize("inventory,host_ip", [("strtk5", "10.1.3.6"), ("bjw", "10.150.22.222")])
def test_regional_metadata_failure_never_probes_other_mirrors(inventory, host_ip):
    """Transport retries stay on the selected inventory's URL, including selector failures."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = ModuleResult(rc=28, stdout="", stderr="DUT timed out")
    runner.shell.return_value = ModuleResult(rc=7, stdout="", stderr="Runner connection refused")
    with pytest.raises(RuntimeError, match="DUT: rc=28"):
        helper.select_package_publication(fresh_request(tbinfo={"inv_name": inventory}), dut, runner, "cphc")
    expected = ("http://" + host_ip
                + "/azmirrors/ACS/sonic-upgrade-packages/critical-process-health-checker.latest.buildinfo.json")
    for host in (dut, runner):
        host.shell.assert_called_once()
        assert host.shell.call_args.args[0].endswith(expected)


@pytest.mark.parametrize("sources", [helper.DELIVERY_PACKAGES, helper.BJW_DELIVERY_PACKAGES], ids=["STR", "BJW"])
def test_provenance_logging_understands_both_code_owned_mirrors(sources):
    """The diagnostic helper validates both approved regional URLs without treating BJW as generic."""
    dut, runner = Mock(), Mock()
    info = lifecycle.publication_metadata("cphc")
    dut.shell.return_value = ModuleResult(rc=0, stdout=json.dumps(info), stderr="")
    assert json.loads(helper.log_package_provenance(
        dut, runner, sources["cphc"]["url"], sas_token="never-forward")) == info
    assert "never-forward" not in dut.shell.call_args.args[0]
    assert sources["cphc"]["url"] + ".buildinfo.json" in dut.shell.call_args.args[0]
    runner.shell.assert_not_called()


@pytest.mark.parametrize("in_suite", [False, True])
def test_selected_publication_is_recorded_in_scoped_test_results(in_suite):
    options = lifecycle.load("conftest")
    info = buildinfo()
    path = lifecycle.SOURCE / "test_cphc_package_nightly.py" if in_suite else Path(__file__)
    item = SimpleNamespace(fspath=path, config=SimpleNamespace(_sonic_operations_publications={"cphc": info}))
    result = SimpleNamespace(user_properties=[])
    outcome = Mock()
    outcome.get_result.return_value = result
    hook = options.pytest_runtest_makereport(item, None)
    next(hook)
    with pytest.raises(StopIteration):
        hook.send(outcome)
    assert result.user_properties == [
        ("sonic_operations.cphc.publication", json.dumps(info, sort_keys=True))
    ] if in_suite else result.user_properties == []


def test_metadata_failure_reports_both_dut_and_runner_dns_errors():
    """Transport diagnostics must retain both attempts, not just the last loop result."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = {"rc": 28, "stdout": "", "stderr": "DUT resolving timed out after 5000 milliseconds"}
    runner.shell.return_value = {"rc": 28, "stdout": "", "stderr": "Runner resolving timed out after 5000 milliseconds"}
    url = helper.DELIVERY_PACKAGES["cphc"]["selector"]
    with pytest.raises(RuntimeError) as failure:
        helper._read_package_metadata(dut, runner, url, "cphc")
    message = str(failure.value)
    assert "DUT:" in message and "runner:" in message
    assert message.count("rc=28") == 2
    assert dut.shell.return_value["stderr"] in message
    assert runner.shell.return_value["stderr"] in message
    dut.shell.assert_called_once()
    runner.shell.assert_called_once_with(*dut.shell.call_args.args, **dut.shell.call_args.kwargs)


def test_metadata_dut_only_dns_failure_is_not_attributed_to_runner():
    """The direct consumer path passes localhost=None, but its failed result is still the DUT's."""
    dut = Mock()
    dut.shell.return_value = {"rc": 28, "stdout": "", "stderr": "Resolving timed out after 5000 milliseconds"}
    with pytest.raises(RuntimeError) as failure:
        helper._read_package_metadata(dut, None, helper.DELIVERY_PACKAGES["postupgrade"]["selector"], "postupgrade")
    message = str(failure.value)
    assert "DUT:" in message and "rc=28" in message
    assert dut.shell.return_value["stderr"] in message
    assert "runner:" not in message


@pytest.mark.parametrize("result", [
    {"unreachable": True, "msg": "Failed to connect via ssh"},
    {"failed": True, "stderr": "Transport failed"},
    ModuleResult(unreachable=True, msg="Failed to connect via ssh"),
    ModuleResult(failed=True, stderr="Transport failed"),
    None,
])
def test_metadata_transport_missing_rc_is_explicit_not_keyerror(result):
    """Incomplete Ansible transport results are diagnosed without a KeyError or a schema claim."""
    dut = Mock()
    dut.shell.return_value = result
    with pytest.raises(RuntimeError) as failure:
        helper._read_package_metadata(dut, None, helper.DELIVERY_PACKAGES["cphc"]["selector"], "cphc")
    message = str(failure.value)
    assert "DUT:" in message and "rc=<missing>" in message
    if result is not None:
        assert result.get("stderr", result.get("msg")) in message


def test_metadata_diagnostics_redact_url_credentials_and_queries():
    """Report the transport failure without echoing credentials embedded in an error URL."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = {
        "rc": 28, "stderr": "Connection failed for https://user:secret-password@mirror.example/path?sig=secret-token"}
    runner.shell.return_value = {
        "failed": True, "msg": "Cannot download http://mirror.example/path?sig=other-secret#private-fragment"}
    with pytest.raises(RuntimeError) as failure:
        helper._read_package_metadata(dut, runner, helper.DELIVERY_PACKAGES["cphc"]["selector"], "cphc")
    message = str(failure.value)
    assert "Connection failed" in message and "Cannot download" in message
    for secret in ("secret-password", "secret-token", "other-secret", "private-fragment"):
        assert secret not in message


def test_metadata_missing_rc_can_use_same_url_runner_without_alternate_endpoint():
    """A runner may recover transport failure, but only at the identical code-owned URL."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = {"unreachable": True, "msg": "SSH transport unavailable"}
    info = lifecycle.publication_metadata("cphc")
    runner.shell.return_value = {"rc": 0, "stdout": json.dumps(info), "stderr": ""}
    assert helper._read_package_metadata(
        dut, runner, helper.DELIVERY_PACKAGES["cphc"]["selector"], "cphc") == info
    dut.shell.assert_called_once()
    runner.shell.assert_called_once_with(*dut.shell.call_args.args, **dut.shell.call_args.kwargs)


@pytest.mark.parametrize("result_type", [dict, ModuleResult])
def test_invalid_metadata_body_still_fails_before_runner_fallback(result_type):
    """A successful transfer with invalid contents cannot become a transport-retry success."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = result_type(rc=0, stdout="<html>404</html>", stderr="")
    with pytest.raises(AssertionError, match="not valid JSON"):
        helper._read_package_metadata(dut, runner, helper.DELIVERY_PACKAGES["cphc"]["selector"], "cphc")
    runner.shell.assert_not_called()


@pytest.mark.parametrize("success_host", ["DUT", "runner"])
def test_metadata_accepts_actual_pytest_ansible_module_result(success_host):
    """The production result is ModuleResult/UserDict, not a built-in dict."""
    dut, runner = Mock(), Mock()
    info = lifecycle.publication_metadata("cphc")
    success = ModuleResult(rc=0, stdout=json.dumps(info), stderr="", failed=False)
    dut.shell.return_value = success if success_host == "DUT" else ModuleResult(
        rc=28, stdout="", stderr="DUT connection timed out")
    runner.shell.return_value = success
    assert helper._read_package_metadata(
        dut, runner, helper.DELIVERY_PACKAGES["cphc"]["selector"], "cphc") == info
    assert dut.shell.call_count == 1
    assert runner.shell.call_count == (1 if success_host == "runner" else 0)


def test_actual_module_result_failures_preserve_rc_and_transport_errors():
    """Valid result wrappers carrying failed commands are not mislabeled as missing rc."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = ModuleResult(rc=28, stdout="", stderr="DUT DNS timeout")
    runner.shell.return_value = ModuleResult(rc=7, stdout="", stderr="Runner connection refused")
    with pytest.raises(RuntimeError) as failure:
        helper._read_package_metadata(dut, runner, helper.DELIVERY_PACKAGES["cphc"]["selector"], "cphc")
    message = str(failure.value)
    assert "DUT: rc=28; stderr=DUT DNS timeout" in message
    assert "runner: rc=7; stderr=Runner connection refused" in message
    assert "invalid module result" not in message


class TaggedReturnCode(int):
    """An integer subclass with the same return-code contract as framework-tagged scalars."""


def test_metadata_accepts_integer_subclass_rc_but_not_boolean_or_string_success():
    """Allow integer result wrappers without treating False or '0' as successful commands."""
    dut = Mock()
    info = lifecycle.publication_metadata("cphc")
    url = helper.DELIVERY_PACKAGES["cphc"]["selector"]
    dut.shell.return_value = ModuleResult(rc=TaggedReturnCode(0), stdout=json.dumps(info), stderr="")
    assert helper._read_package_metadata(dut, None, url, "cphc") == info
    for invalid in (False, "0"):
        dut.shell.return_value = ModuleResult(rc=invalid, stdout=json.dumps(info), stderr="")
        with pytest.raises(RuntimeError):
            helper._read_package_metadata(dut, None, url, "cphc")
