"""Local regression proofs for package lifecycle; never execute device payloads."""

import hashlib
import gzip
import argparse
import importlib.util
import inspect
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from pytest_ansible.results import ModuleResult


SOURCE = Path(__file__).resolve().parents[3] / "tests" / "sonic_operations"


def load(name):
    spec = importlib.util.spec_from_file_location("lifecycle_" + name, SOURCE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("sonic_operations_helper")
with patch.dict(sys.modules, {"sonic_operations_helper": helper}):
    cphc = load("test_cphc_package_nightly")
    sup = load("test_postupgrade_package_nightly")
    download = load("test_package_download_nightly")


def request(tbinfo=None, **overrides):
    values = {"--sup_package_url": "https://example.test/builds/123/package.tar.gz",
              "--cphc_tar_version": "1.0.0", "--cphc_wheel_version": None,
              "--package_sas_token": None, "--postupgrade_skip_execute": False}
    values.update(overrides)
    fixtures = {"tbinfo": {"inv_name": "str2"} if tbinfo is None else tbinfo}
    return SimpleNamespace(config=SimpleNamespace(
        getoption=lambda name: values.get(name),
        _sonic_operations_publications={key: publication_metadata(key) for key in helper.DELIVERY_PACKAGES}),
                           addfinalizer=Mock(), getfixturevalue=lambda name: fixtures[name])


def package_bytes(gzipped=False, wheel_version="1.0.18"):
    stream = io.BytesIO()
    names = ([sup.TARBALL.replace(".tar.gz", ""), "postupgrade_actions", "postupgrade_infra.py",
              "postupgrade_actions_data/fixture"]
             if gzipped else [cphc.INSTALLER, cphc._wheel_name(wheel_version, "py2"),
                              cphc._wheel_name(wheel_version, "py3")])
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name in names:
            entry = tarfile.TarInfo(name)
            entry.size = 7
            entry.mode = 0o755
            archive.addfile(entry, io.BytesIO(b"fixture"))
    return gzip.compress(stream.getvalue(), mtime=0) if gzipped else stream.getvalue()


def publication_metadata(key, data=None, wheel_version="1.0.18"):
    """Digest-bound producer metadata for synthetic bytes, not production payloads."""
    if data is None:
        data = package_bytes(key == "postupgrade", wheel_version)
    return {
        "schemaVersion": 1, "package": helper.DELIVERY_PACKAGES[key]["filename"],
        "buildId": "201" if key == "cphc" else "199", "buildNumber": "20260914.1",
        "branch": "main", "commit": ("a" if key == "cphc" else "b") * 40,
        "publishedUtc": "2026-09-14T19:00:00Z", "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(), "sizeBytes": len(data),
        "archiveVersion": "1.0.0" if key == "cphc" else None,
        "wheelVersion": wheel_version if key == "cphc" else None,
        "reportVersion": "1.0.0" if key == "postupgrade" else None,
    }


class Host:
    """Stateful host returning real pytest-ansible results; never execute device payloads."""

    hostname = "unit-only"
    os_version = "20250510.39"

    def __init__(self, package_sources=None):
        self.entries = {"/": (None, 0o755), "/tmp": (None, 0o1777), "/host": (None, 0o755)}
        self.commands = []
        self.installed = None
        self.summary = {"succeeded": True, "execution_error": None, "unhealthy_services": ["informational"]}
        self.clock = "2026-09-11T12:00:00Z"
        self.caller_rc = 0
        self.sup_result = None
        self.write_report = True
        self.before = lambda command: None
        self.running = False
        self.package_sources = helper.DELIVERY_PACKAGES if package_sources is None else package_sources
        self.payloads = {key: package_bytes(key == "postupgrade") for key in helper.DELIVERY_PACKAGES}
        self.publications = {key: publication_metadata(key, data) for key, data in self.payloads.items()}

    def write(self, path, data, mode=0o644):
        self.entries[path] = (data, mode)

    def stat(self, path, **kwargs):
        return ModuleResult(stat={"exists": path in self.entries, "islnk": False})

    def remove(self, path):
        for item in list(self.entries):
            if item == path or item.startswith(path + "/"):
                del self.entries[item]

    def move(self, source, target):
        if source not in self.entries:
            raise RuntimeError("Missing move source " + source)
        values = {target + key[len(source):]: value for key, value in self.entries.items()
                  if key == source or key.startswith(source + "/")}
        self.remove(source)
        self.entries.update(values)

    def shell(self, command, module_ignore_errors=False):
        self.commands.append(command)
        self.before(command)
        words = shlex.split(command)
        groups = [[]]
        for word in words:
            if word == "&&":
                groups.append([])
            else:
                groups[-1].append(word)
        cwd = "/"
        result = {"rc": 0, "stdout": "", "stderr": ""}
        for words in groups:
            if words[0] == "cd":
                cwd = words[1]
                continue
            try:
                result = self.run(words, cwd)
            except (KeyError, FileNotFoundError, tarfile.TarError, OSError) as exc:
                result = {"rc": 2, "stdout": "", "stderr": str(exc)}
            if result["rc"]:
                if not module_ignore_errors:
                    raise RuntimeError("{}: {}".format(command, result))
                break
        return ModuleResult(result)

    def run(self, words, cwd):
        result = {"rc": 0, "stdout": "", "stderr": ""}

        def path(value):
            return posixpath.normpath(posixpath.join(cwd, value))

        if words[0] == "mkdir":
            for value in words[1:]:
                if not value.startswith("-"):
                    target = path(value)
                    if target in self.entries and "-p" not in words:
                        raise RuntimeError("Directory already exists " + target)
                    self.entries[target] = (None, 0o755)
        elif words[0] == "rmdir":
            target = words[-1]
            assert not any(key.startswith(target + "/") for key in self.entries), "Directory not empty"
            self.entries.pop(target)
        elif words[0] == "rm":
            for value in words[1:]:
                if not value.startswith("-"):
                    self.remove(path(value))
        elif words[0] in ("mv", "cp"):
            operands = [word for word in words[1:] if not word.startswith("-")]
            target = path(operands[-1])
            for value in operands[:-1]:
                source = path(value)
                dest = target
                if "-T" not in words and (target.endswith("/") or self.entries.get(target, ("file",))[0] is None):
                    dest = target.rstrip("/") + "/" + posixpath.basename(source)
                if words[0] == "mv":
                    self.move(source, dest)
                else:
                    self.entries[dest] = self.entries[source]
        elif words[0] == "pip":
            if self.installed:
                result["stdout"] = "Name: sonic-critical-process-checker\nVersion: " + self.installed
            else:
                result["rc"] = 1
                result["stderr"] = "WARNING: Package(s) not found: sonic_critical_process_checker"
        elif words[:2] == ["python", cphc.INSTALLER]:
            assert cwd + "/" + cphc.INSTALLER in self.entries, "Installer absent"
            if "--install" in words:
                self.installed = helper.cphc_archive_wheel_version(
                    key[len(cwd) + 1:] for key in self.entries if key.startswith(cwd + "/"))
            elif "--validate" in words:
                result["stdout"] = "Package is installed" if self.installed else "Package is not installed"
            elif "--uninstall" in words:
                self.installed = None
                wheels = [key[len(cwd) + 1:] for key in self.entries
                          if key.startswith(cwd + "/") and key.endswith(".whl")]
                for filename in [cphc.INSTALLER, cphc._tar_name("1.0.0"), *wheels]:
                    self.remove(cwd + "/" + filename)
        elif words[0] == "date":
            assert words == ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]
            result["stdout"] = self.clock
        elif words[0] == cphc.CALLER:
            window = words[words.index("-m") + 1]
            report = cphc.CHECKER_OUTPUT_DIR + "/process_checker-" + re.sub(
                r'[\\/:* ]', '_', window.replace(",", "-")) + ".json"
            result["stdout"] = json.dumps(self.summary)
            result["rc"] = self.caller_rc
            if self.write_report:
                self.write(report, result["stdout"].encode())
        elif words[:2] == ["python", "/mock/wrapper"]:
            event = words[-1]
            self.entries[sup.EXTRACT_DIR] = (None, 0o755)
            self.write(sup.EXTRACT_DIR + "/postupgrade_actions", b"simulated")
            self.write(sup.REPORTS_DIR + "/postupgrade_actions." + event + ".json", b"{}")
        elif words[0] == "timeout" and words[-3:-1] == ["./postupgrade_actions", "-e"]:
            assert cwd == sup.EXTRACT_DIR
            assert cwd + "/postupgrade_actions" in self.entries
            assert cwd + "/postupgrade_actions_data/fixture" in self.entries
            event = words[-1]
            report = direct_sup_report(event)
            report["sonic_upgrade_summary"]["sonic_upgrade_package_version"] = \
                self.publications["postupgrade"]["reportVersion"]
            if self.sup_result:
                result, report = self.sup_result(event)
            if report is not None:
                self.write(sup.REPORTS_DIR + "/postupgrade_actions." + event + ".json", json.dumps(report).encode())
        elif words[0] == "tar":
            filename = path(words[2])
            with tarfile.open(fileobj=io.BytesIO(self.entries[filename][0])) as archive:
                if words[1] == "-xf":
                    directory = words[words.index("-C") + 1]
                    for member in archive.getmembers():
                        self.write(directory + "/" + member.name, archive.extractfile(member).read(), member.mode)
                else:
                    result["stdout"] = "\n".join(archive.getnames())
        elif words[0] in ("md5sum", "sha256sum"):
            if "-c" not in words:
                digest = hashlib.md5 if words[0] == "md5sum" else hashlib.sha256
                result["stdout"] = digest(self.entries[path(words[1])][0]).hexdigest()
        elif words[0] == "awk":
            result["stdout"] = self.entries[path(words[2])][0].decode().split()[0]
        elif words[0] == "cat":
            result["stdout"] = self.entries[path(words[1])][0].decode()
            if "awk" in words:
                result["stdout"] = result["stdout"].replace("\r", "").split()[0]
        elif words[:2] == ["ls", "-1"]:
            result["stdout"] = "\n".join(posixpath.basename(key) for key in self.entries
                                         if key.startswith(words[2] + "/"))
        elif words[0] == "test":
            result["rc"] = 0 if path(words[2]) in self.entries else 1
        elif words[0] == "dd":
            filename = path(next(word[3:] for word in words if word.startswith("of=")))
            data, mode = self.entries[filename]
            self.write(filename, b"\0" * 64 + data[64:], mode)
        elif words[:2] == ["stat", "-c"]:
            result["stdout"] = str(len(self.entries[path(words[-1])][0]))
        elif words[:2] == ["python3", "-c"]:
            if words[2] == helper._START_MIRROR:
                self.running = True
            elif words[2] == helper._MIRROR_PROCESS:
                if words[-1] == "stop":
                    self.running = False
                else:
                    assert self.running
            else:
                raise AssertionError("Unknown remote Python; do not execute " + words[2])
        elif words[0] == "echo":
            self.write(words[-1], words[1].encode())
        elif words[:2] == ["wc", "-l"]:
            self.write(words[-1], b"0")
        elif words[0] == "curl":
            if words[-1].endswith("mirror-nonce.txt"):
                result["stdout"] = next(value[0].decode() for key, value in self.entries.items()
                                        if key.endswith("/mirror-nonce.txt"))
            else:
                url = next(word for word in words if word.startswith(("http://", "https://")))
                if url.startswith(("http://127.0.0.1:8910/", "http://127.0.0.1:8911/")):
                    route = url.split("/", 3)[-1]
                    assert self.running and any(key.endswith("/www/" + route) for key in self.entries)
                    return result
                for key, package in self.package_sources.items():
                    if url in (package["selector"], package["url"] + ".buildinfo.json"):
                        result["stdout"] = json.dumps(self.publications[key])
                        break
                    if url in (package["url"], package["url"] + ".md5"):
                        data = self.payloads[key]
                        if url.endswith(".md5"):
                            data = (hashlib.md5(data).hexdigest() + "  " + package["filename"]).encode()
                        self.write(words[words.index("-o") + 1], data)
                        result["stdout"] = "200"
                        break
                else:
                    raise AssertionError("Unexpected synthetic URL: " + url)
        else:
            raise AssertionError("Unmodeled command: " + repr(words))
        return result


def seed_sup(host):
    host.entries.update({sup.BINARIES_DIR: (None, 0o750), sup.EXTRACT_DIR: (None, 0o700),
                         sup.REPORTS_DIR: (None, 0o750)})
    for path in [sup.BINARIES_DIR + "/" + sup.TARBALL, sup.BINARIES_DIR + "/" + sup.TARBALL + ".md5",
                 sup.BINARIES_DIR + "/unrelated.deb", sup.EXTRACT_DIR + "/old/script",
                 sup.REPORTS_DIR + "/unrelated.json"]:
        host.write(path, b"preexisting", 0o600)
    return host.entries.copy()


def fetch(host, runner, url, directory, filename, **kwargs):
    data = package_bytes(gzipped=filename.startswith(sup.TARBALL))
    if filename.endswith(".md5"):
        data = (hashlib.md5(data).hexdigest() + "  " + filename[:-4] + "\r\n").encode()
    target = directory + "/" + filename
    host.write(target, data)
    return target


@contextmanager
def cphc_source(host):
    with patch.object(helper, "fetch_to_dut", fetch):
        with contextmanager(cphc.cphc_workspace.__wrapped__)(
                {"dut": host}, "dut", None, "https://example.test/pinned", request()) as source:
            yield source


@contextmanager
def sup_state(host):
    with contextmanager(sup.postupgrade_state.__wrapped__)({"dut": host}, "dut") as state:
        yield state


@contextmanager
def staged(host, state, fetcher=fetch):
    with patch.object(helper, "fetch_to_dut", fetcher):
        with contextmanager(sup.staged_package.__wrapped__)(
                {"dut": host}, "dut", None, request(), state) as package:
            yield package


@pytest.mark.parametrize("preexisting", [None, "1.0.18"])
def test_cphc_ordered_install_corruption_and_both_preload_cases(preexisting):
    """Installer deletion cannot remove sources used by any subsequent case/restore."""
    host = Host()
    host.installed = preexisting
    with cphc_source(host) as source:
        archive = source + "/" + cphc._tar_name("1.0.0")
        original = host.entries[archive]
        with contextmanager(cphc.cphc_install_dir.__wrapped__)({"dut": host}, "dut", source) as scratch:
            cphc.test_cphc_package_install_from_image_server(
                {"dut": host}, "dut", source, "https://example.test/pinned", request(), scratch)
        assert host.entries[archive] == original
        cphc.test_cphc_package_rejects_corrupted_download({"dut": host}, "dut", source, request())
        mirror = helper.PackageMirror(host, "cphc", 8910)
        with patch.object(helper, "dut_eth0_ip", return_value="127.0.0.1"):
            mirror.start(source, [cphc._tar_name("1.0.0")])
        for item in mirror.served_copies(cphc._tar_name("1.0.0")):
            assert host.entries[item] == original
        with patch.object(cphc, "_preload_or_skip", return_value="/mock/preload"), \
                patch.object(mirror, "run_preload_firmware", return_value={
                    "rc": 0, "stdout": helper.PRELOAD_SUCCESS_MARKER, "stderr": ""}), \
                patch.object(mirror, "fetched_variant", return_value="unit"), \
                patch.object(mirror, "assert_rejects_corruption") as negative:
            host.write(mirror.scratch + "/" + cphc._tar_name("1.0.0"), original[0])
            host.write(mirror.scratch + "/" + cphc._tar_name("1.0.0") + ".md5", b"md5")
            cphc.test_cphc_package_downloads_via_real_preload_firmware(
                {"dut": host}, "dut", mirror, request())
            cphc.test_real_preload_firmware_rejects_corrupted_package(
                {"dut": host}, "dut", mirror, request())
            negative.assert_called_once_with("/mock/preload", cphc._tar_name("1.0.0"))
        mirror.stop()
    assert host.installed == preexisting
    assert not any("cphc-source-" in path for path in host.entries)


def test_selected_cphc_corruption_has_source_and_does_not_require_installer_case():
    """The individually selected corruption case is independent of installation."""
    host = Host()
    with cphc_source(host) as source:
        cphc.test_cphc_package_rejects_corrupted_download({"dut": host}, "dut", source, request())
    assert host.installed is None


@pytest.mark.parametrize("result", [
    {"rc": 1, "stdout": "", "stderr": "pip internal error"},
    {"rc": 127, "stdout": "", "stderr": "pip: not found"},
    {"rc": 0, "stdout": "", "stderr": ""},
    {"failed": True, "msg": "transport failed"},
])
def test_unknown_installed_state_blocks_cphc_mutation(result):
    """A failed state probe cannot be interpreted as permission to uninstall."""
    host = Mock()
    host.shell.return_value = result
    with pytest.raises(AssertionError):
        cphc._installed_version(host)
    assert not any("--uninstall" in call.args[0] for call in host.shell.call_args_list)


def test_cphc_restore_failure_errors_and_retains_verified_recovery_source():
    """A failed same-version restore is a teardown error, not a logged success."""
    host = Host()
    host.installed = "1.0.18"
    with pytest.raises(RuntimeError, match="restore failed"):
        with cphc_source(host) as source:
            host.installed = None

            def fail_restore(command):
                if "cphc-restore-" in command and "--install" in command:
                    raise RuntimeError("restore failed")
            host.before = fail_restore
    assert source + "/" + cphc._tar_name("1.0.0") in host.entries


@pytest.mark.parametrize("summary", [
    {"succeeded": False, "execution_error": ["caught runtime exception"]},
    {"succeeded": True, "execution_error": ["unexpected exception"]},
    {"succeeded": "true", "execution_error": None}, {"succeeded": True}, [], {},
])
def test_cphc_execution_errors_or_malformed_reports_cannot_pass(summary):
    """rc0 and JSON alone cannot prove executable success."""
    host = Host()
    host.summary = summary
    with cphc_source(host) as source:
        with contextmanager(cphc.cphc_install_dir.__wrapped__)({"dut": host}, "dut", source) as scratch:
            with pytest.raises(AssertionError, match="Checker"):
                cphc.test_cphc_package_install_from_image_server(
                    {"dut": host}, "dut", source, "https://example.test/pinned", request(), scratch)


def test_stale_cphc_report_cannot_pass_and_is_restored():
    """A preexisting same-window report is isolated before caller execution."""
    host = Host()
    host.write_report = False
    report = cphc.CHECKER_OUTPUT_DIR + "/process_checker-09_11_2026_11_00_00-09_11_2026_12_00_00.json"
    host.entries[cphc.CHECKER_OUTPUT_DIR] = (None, 0o755)
    host.write(report, b"original report", 0o600)
    with cphc_source(host) as source:
        with contextmanager(cphc.cphc_install_dir.__wrapped__)({"dut": host}, "dut", source) as scratch:
            with pytest.raises(RuntimeError, match="cat"):
                cphc.test_cphc_package_install_from_image_server(
                    {"dut": host}, "dut", source, "https://example.test/pinned", request(), scratch)
    assert host.entries[report] == (b"original report", 0o600)


@pytest.mark.parametrize("clock", ["2026-09-14T18:30:45Z", "2026-01-01T00:00:00Z"])
def test_cphc_smoke_window_uses_one_dut_clock_sample_and_exactly_one_hour(clock):
    """The supported -m argument ends at DUT now, never at runner now or a future timestamp."""
    host = Host()
    host.clock = clock
    with cphc_source(host) as source:
        with contextmanager(cphc.cphc_install_dir.__wrapped__)({"dut": host}, "dut", source) as scratch:
            cphc.test_cphc_package_install_from_image_server(
                {"dut": host}, "dut", source, "https://example.test/pinned", request(), scratch)
    calls = [shlex.split(command) for command in host.commands if command.startswith(cphc.CALLER)]
    assert len(calls) == 1 and calls[0][:2] == [cphc.CALLER, "-m"] and len(calls[0]) == 3
    start, end = [cphc.datetime.strptime(part, "%m/%d/%Y %H:%M:%S") for part in calls[0][2].split(",")]
    assert (end - start).total_seconds() == 3600
    assert end == cphc.datetime.strptime(clock, "%Y-%m-%dT%H:%M:%SZ")
    assert host.commands.count("date -u +%Y-%m-%dT%H:%M:%SZ") == 1


def test_cphc_nonzero_caller_cannot_pass_even_with_success_json():
    """A fresh successful JSON report cannot hide the caller's failed process outcome."""
    host = Host()
    host.caller_rc = 1
    with cphc_source(host) as source:
        with contextmanager(cphc.cphc_install_dir.__wrapped__)({"dut": host}, "dut", source) as scratch:
            with pytest.raises(AssertionError, match="failed"):
                cphc.test_cphc_package_install_from_image_server(
                    {"dut": host}, "dut", source, "https://example.test/pinned", request(), scratch)


def direct_sup_report(event):
    """Pinned postupgrade_infra.py schema: patch stages, final health stage, event GUID."""
    return {
        "sonic_upgrade_summary": {"script_name": "postupgrade_actions", "sonic_upgrade_package_version": "1.0.0",
                                  "guid": event, "fault_code": "0"},
        "sonic_upgrade_report": {
            "stages": [{"name": "patch_process_reboot_cause", "rc": "0"}, {"name": "check_device_health", "rc": "0"}],
            "health_checks": [{"name": "check_critical_service", "success": True}], "errors": [],
        },
    }


def direct_sup_request(state, **options):
    req = request(**options)
    getfixturevalue = req.getfixturevalue
    req.getfixturevalue = Mock(
        side_effect=lambda name: state if name == "postupgrade_state" else getfixturevalue(name))
    return req


def direct_curl(host, url, dest, **kwargs):
    content = package_bytes(True)
    if url.endswith(".md5"):
        content = (hashlib.md5(content).hexdigest() + "  " + sup.TARBALL).encode()
    host.write(dest, content)
    return {"rc": 0, "stdout": "", "stderr": ""}


@pytest.mark.parametrize("health_failure", [False, True])
def test_direct_sup_execution_uses_real_entrypoint_contract_and_restores_owned_paths(health_failure):
    """Real test orchestration must curl/verify/extract before bounded package invocation."""
    host = Host()
    original = seed_sup(host)

    def outcome(event):
        report = direct_sup_report(event)
        rc = 125 if health_failure else 0
        report["sonic_upgrade_summary"]["fault_code"] = str(rc)
        report["sonic_upgrade_report"]["stages"][-1]["rc"] = str(rc)
        report["sonic_upgrade_report"]["health_checks"][0]["success"] = not health_failure
        return {"rc": rc, "stdout": "not a JSON summary", "stderr": ""}, report

    host.sup_result = outcome
    with sup_state(host) as state, patch.object(sup, "curl_like_wrapper", side_effect=direct_curl) as curl:
        req = direct_sup_request(state)
        sup.test_postupgrade_package_runs_directly({"dut": host}, "dut", None, req)
        assert req.getfixturevalue.call_args_list[0].args == ("postupgrade_state",)
        assert [call.args[1] for call in curl.call_args_list] == [
            helper.DELIVERY_PACKAGES["postupgrade"]["url"] + suffix for suffix in (".md5", "")]
    assert host.entries == original
    invocation = next(command for command in host.commands if "timeout --signal=TERM" in command)
    words = shlex.split(invocation)
    assert words[:3] == ["cd", sup.EXTRACT_DIR, "&&"]
    assert words[3:-1] == [
        "timeout", "--signal=TERM", "--kill-after=30s", "1800s", "python", "./postupgrade_actions", "-e",
    ]
    assert host.commands.index(next(command for command in host.commands if command.startswith("tar -xf "))) \
        < host.commands.index(invocation)


def test_direct_sup_skip_execute_precedes_state_staging_and_all_host_calls():
    """Skip-execute must not acquire mutating fixtures or contact a DUT for the direct case."""
    req = direct_sup_request(None, **{"--postupgrade_skip_execute": True})
    with pytest.raises(pytest.skip.Exception):
        sup.test_postupgrade_package_runs_directly({}, "dut", None, req)
    req.getfixturevalue.assert_not_called()


def test_direct_sup_stale_report_is_not_execution_proof_and_is_restored():
    """The report at this exact GUID is moved aside before the new entrypoint runs."""
    host = Host()
    event = "12345678-1234-1234-1234-123456789abc"
    seed_sup(host)
    report_path = sup.REPORTS_DIR + "/postupgrade_actions." + event + ".json"
    host.write(report_path, json.dumps(direct_sup_report(event)).encode(), 0o600)
    original = host.entries.copy()
    host.sup_result = lambda event: ({"rc": 0, "stdout": "", "stderr": ""}, None)
    with sup_state(host) as state, patch.object(sup, "curl_like_wrapper", side_effect=direct_curl), \
            patch.object(sup.uuid, "uuid4", return_value=sup.uuid.UUID(event)):
        with pytest.raises(AssertionError, match="did not write"):
            sup.test_postupgrade_package_runs_directly({"dut": host}, "dut", None, direct_sup_request(state))
    assert host.entries == original


@pytest.mark.parametrize("failure", [
    "timeout", "missing_command", "missing_report", "wrong_guid", "wrong_version", "wrong_script",
    "patch_exception", "patch_error_with_rc0", "missing_final_stage", "rc_mismatch",
    "unknown_health_error", "invalid_schema",
])
def test_direct_sup_failures_never_pass_and_restore_originals(failure):
    """Timeouts, swallowed exceptions, stale/invalid reports and patch errors fail explicitly."""
    host = Host()
    original = seed_sup(host)

    def outcome(event):
        result = {"rc": 0, "stdout": "", "stderr": ""}
        report = direct_sup_report(event)
        if failure in ("timeout", "missing_command"):
            result["rc"] = 124 if failure == "timeout" else 127
        elif failure == "missing_report":
            report = None
        elif failure == "invalid_schema":
            report = {}
        elif failure in ("wrong_guid", "wrong_version", "wrong_script"):
            field = {"wrong_guid": "guid", "wrong_version": "sonic_upgrade_package_version",
                     "wrong_script": "script_name"}[failure]
            report["sonic_upgrade_summary"][field] = "wrong"
        elif failure in ("patch_exception", "patch_error_with_rc0"):
            report["sonic_upgrade_report"]["stages"][0]["rc"] = "-1" if failure == "patch_exception" else "127"
        elif failure == "missing_final_stage":
            report["sonic_upgrade_report"]["stages"].pop()
        elif failure == "rc_mismatch":
            result["rc"] = 125
        elif failure == "unknown_health_error":
            report["sonic_upgrade_report"]["errors"] = [{"message": "Unknown error"}]
        return result, report

    host.sup_result = outcome
    with sup_state(host) as state, patch.object(sup, "curl_like_wrapper", side_effect=direct_curl):
        with pytest.raises(AssertionError):
            sup.test_postupgrade_package_runs_directly({"dut": host}, "dut", None, direct_sup_request(state))
    assert host.entries == original


@pytest.mark.parametrize("failure", ["provenance", "download", "checksum"])
def test_direct_sup_source_failure_prevents_extract_and_execution(failure):
    """The new direct case cannot bypass provenance, curl failures or pinned integrity gates."""
    host = Host()
    original = seed_sup(host)

    def download_package(dut, url, dest, **kwargs):
        result = direct_curl(dut, url, dest)
        if failure == "download":
            result["rc"] = 28
        elif failure == "checksum" and not url.endswith(".md5"):
            dut.write(dest, b"corrupted")
        return result

    with sup_state(host) as state, patch.object(sup, "curl_like_wrapper", side_effect=download_package), \
            patch.object(helper, "_read_package_metadata", wraps=helper._read_package_metadata) as provenance:
        if failure == "provenance":
            provenance.side_effect = AssertionError("Wrong build provenance")
        with pytest.raises(AssertionError):
            sup.test_postupgrade_package_runs_directly({"dut": host}, "dut", None, direct_sup_request(state))
    assert host.entries == original
    assert not any(command.startswith("tar -xf ") or "timeout --signal=TERM" in command for command in host.commands)


@pytest.mark.parametrize("existing", [False, True])
def test_sup_success_restores_exact_files_modes_and_unrelated_state(existing):
    """Selected wrapper execution restores the original cached/extracted/report state."""
    host = Host()
    original = seed_sup(host) if existing else host.entries.copy()
    with sup_state(host) as state, staged(host, state) as package:
        sup.test_postupgrade_wrapper_runs_real_script(
            {"dut": host}, "dut", package, "/mock/wrapper", request(), state)
    assert host.entries == original


def test_sup_partial_download_before_yield_restores_originals():
    """Restoration is registered before the first staging mutation."""
    host = Host()
    original = seed_sup(host)

    def broken(*args, **kwargs):
        target = fetch(*args, **kwargs)
        host.write(target, b"partial")
        raise RuntimeError("download failed")

    with pytest.raises(RuntimeError, match="download failed"):
        with sup_state(host) as state, staged(host, state, broken):
            pytest.fail("Partial setup must not yield")
    assert host.entries == original


def test_sup_partial_backup_failure_restores_already_moved_originals():
    """A failure during the second backup does not lose either original."""
    host = Host()
    original = seed_sup(host)

    def fail_second(command):
        if command.startswith("mv -T -- " + sup.BINARIES_DIR + "/" + sup.TARBALL + ".md5 "):
            raise RuntimeError("backup failed")
    host.before = fail_second
    with pytest.raises(RuntimeError, match="backup failed"):
        with sup_state(host):
            pytest.fail("Failed backup must not yield")
    assert host.entries == original


def test_sup_failed_restore_retains_backup_and_reports_error():
    """Never discard the only recovery copy after a restore failure."""
    host = Host()
    seed_sup(host)
    with pytest.raises(RuntimeError, match="DUT state restoration failed"):
        with sup_state(host):
            def broken(command):
                if command.startswith("rm -rf -- " + sup.EXTRACT_DIR):
                    raise RuntimeError("restore denied")
            host.before = broken
    assert any(key.startswith(sup.EXTRACT_DIR + ".sonic-ops-") for key in host.entries)


def test_selected_sup_end_to_end_owns_all_fixed_paths():
    """The end-to-end case needs no earlier staged_package fixture to restore state."""
    host = Host()
    original = seed_sup(host)
    mirror = SimpleNamespace(scratch="/tmp/preload", run_preload_firmware=Mock(return_value={
        "rc": 0, "stdout": helper.PRELOAD_SUCCESS_MARKER, "stderr": ""}),
        fetched_variant=lambda: "unit")
    with sup_state(host) as state:
        fetch(host, None, "", mirror.scratch, sup.TARBALL)
        fetch(host, None, "", mirror.scratch, sup.TARBALL + ".md5")
        with patch.object(sup, "_preload_or_skip", return_value="/mock/preload"):
            sup.test_postupgrade_hwproxy_flow_end_to_end(
                {"dut": host}, "dut", mirror, "/mock/wrapper", request(), state)
    assert host.entries == original


@pytest.mark.parametrize("case", ["wrapper", "negative", "end_to_end"])
def test_skip_execute_never_invokes_wrapper(case):
    """Every real-wrapper path honors the execution opt-out."""
    host = Host()
    req = request(**{"--postupgrade_skip_execute": True})
    with sup_state(host) as state, staged(host, state) as package:
        with pytest.raises(pytest.skip.Exception), patch.object(sup, "_preload_or_skip", return_value="/mock/preload"):
            if case == "wrapper":
                sup.test_postupgrade_wrapper_runs_real_script(
                    {"dut": host}, "dut", package, "/mock/wrapper", req, state)
            elif case == "negative":
                sup.test_wrapper_rejects_corrupted_cached_package(req)
            else:
                sup.test_postupgrade_hwproxy_flow_end_to_end(
                    {"dut": host}, "dut", Mock(), "/mock/wrapper", req, state)
    assert not any("python /mock/wrapper" in command for command in host.commands)


def test_cached_wrapper_recovery_is_explicitly_uncovered_not_false_green():
    """Unsupported recovery must not stage files, launch a wrapper or accept rc127."""
    with pytest.raises(pytest.skip.Exception, match="controlled recovery endpoint"):
        sup.test_wrapper_rejects_corrupted_cached_package(request())
    assert list(inspect.signature(sup.test_wrapper_rejects_corrupted_cached_package).parameters) == ["request"]


def test_sup_corrupt_staging_fails_before_any_execution():
    """An isolated wrapper case cannot bypass checksum validation in its prerequisite."""
    host = Host()
    original = seed_sup(host)

    def bad_hash(*args, **kwargs):
        target = fetch(*args, **kwargs)
        if target.endswith(".md5"):
            host.write(target, b"0" * 32 + b" package.tar.gz")
        return target

    with pytest.raises(AssertionError, match="checksum mismatch"):
        with sup_state(host) as state, staged(host, state, bad_hash):
            pytest.fail("Invalid staging must not yield")
    assert host.entries == original


@pytest.mark.parametrize("point", ["copy", "spawn", "probe"])
def test_mirror_setup_exception_cleans_only_owned_process_and_files(point):
    """Failures before and after spawn cannot leak a listener or remove foreign data."""
    host = Host()
    host.write("/tmp/unrelated-mirror.pid", b"foreign")
    fetch(host, None, "", "/tmp/source", cphc._tar_name("1.0.0"))
    fetch(host, None, "", "/tmp/source", cphc._tar_name("1.0.0") + ".md5")
    original = host.entries.copy()
    mirror = helper.PackageMirror(host, "unit", 8910)

    def fail(command):
        if (point == "copy" and command.startswith("cp ")) or \
                (point == "probe" and command.startswith("curl ")):
            raise RuntimeError("setup failed")
        if point == "spawn" and helper._START_MIRROR in shlex.split(command):
            host.running = True
            raise RuntimeError("setup failed")

    host.before = fail
    with patch.object(helper, "dut_eth0_ip", return_value="127.0.0.1"):
        with pytest.raises(RuntimeError, match="setup failed"):
            mirror.start("/tmp/source", [cphc._tar_name("1.0.0")])
    assert not host.running
    assert host.entries == original


def test_explicit_missing_preload_is_an_error_not_a_skipped_or_green_negative():
    """An explicit script path must name a readable file before invoking it."""
    with pytest.raises(AssertionError, match="not readable"):
        helper.find_preload_firmware(Host(), configured="/missing/preload")


@pytest.mark.parametrize("identity", ["owned", "reused_pid", "wrong_command", "wrong_root", "dead"])
def test_mirror_stop_checks_exact_process_identity_before_signaling(identity):
    """Exercise the actual remote stop program with synthetic proc files, never real signals."""
    alive = identity != "dead"
    root = "/tmp/unique-mirror/www"

    def read(name, mode="r"):
        if name == "/identity":
            return io.StringIO(json.dumps({"pid": 1234, "start": "42"}))
        if not alive:
            raise FileNotFoundError(name)
        if name.endswith("/stat"):
            fields = ["S"] + ["0"] * 18 + ["43" if identity == "reused_pid" else "42"]
            return io.StringIO("1234 (python3) " + " ".join(fields))
        if name.endswith("/cmdline"):
            args = ["python3", "-m", "foreign" if identity == "wrong_command" else "http.server", "--directory",
                    "/tmp/foreign" if identity == "wrong_root" else root]
            return io.BytesIO(("\0".join(args) + "\0").encode())
        raise AssertionError(name)

    def signal(pid, sig):
        nonlocal alive
        assert pid == 1234
        alive = False

    with patch("builtins.open", side_effect=read), patch("os.path.exists", return_value=True), \
            patch.object(sys, "argv", ["unit", "/identity", root, "stop"]), \
            patch("os.kill", side_effect=signal) as kill:
        if identity in ("reused_pid", "wrong_command", "wrong_root"):
            with pytest.raises(RuntimeError, match="refusing"):
                exec(helper._MIRROR_PROCESS, {})
            kill.assert_not_called()
        else:
            exec(helper._MIRROR_PROCESS, {})
            assert kill.call_count == (1 if identity == "owned" else 0)


@pytest.mark.parametrize("transition", [
    "empty_then_zombie", "delayed_zombie", "cmdline_gone", "empty_then_gone",
    "zombie_after_cmdline", "signal_gone", "kill_escalation", "kill_signal_gone", "never_exits",
])
def test_mirror_stop_handles_owned_exit_interleavings(transition):
    """Run the real stop program with exit races after the initial ownership check."""
    phase = "live"
    signals = []
    empty_samples = 0
    root = "/tmp/owned-mirror/www"

    def files(name, mode="r"):
        nonlocal phase, empty_samples
        if name == "/identity":
            return io.StringIO(json.dumps({"pid": 1234, "start": "42"}))
        if phase == "gone":
            raise FileNotFoundError(name)
        if name.endswith("/stat"):
            status = "Z" if phase == "zombie" else "S"
            return io.StringIO("1234 (python3) " + " ".join([status] + ["0"] * 18 + ["42"]))
        if name.endswith("/cmdline"):
            if phase == "terminating":
                if transition == "cmdline_gone":
                    phase = "gone"
                    raise FileNotFoundError(name)
                if transition == "empty_then_gone":
                    phase = "gone"
                    return io.BytesIO(b"")
                if transition == "empty_then_zombie":
                    phase = "zombie"
                    return io.BytesIO(b"")
                if transition == "delayed_zombie":
                    empty_samples += 1
                    if empty_samples == 3:
                        phase = "zombie"
                    return io.BytesIO(b"")
                if transition == "zombie_after_cmdline":
                    phase = "zombie"
            return io.BytesIO(("\0".join(["python3", "-m", "http.server", "--directory", root]) + "\0").encode())
        raise AssertionError(name)

    def send(pid, sig):
        nonlocal phase
        assert pid == 1234
        signals.append(sig)
        if transition == "signal_gone" or (transition == "kill_signal_gone" and len(signals) == 2):
            phase = "gone"
            raise ProcessLookupError("Exited immediately before signal")
        if transition == "never_exits":
            phase = "live"
        elif transition in ("kill_escalation", "kill_signal_gone"):
            phase = "live" if len(signals) == 1 else "gone"
        else:
            phase = "terminating"

    with patch("builtins.open", side_effect=files), patch("os.path.exists", return_value=True), \
            patch.object(sys, "argv", ["unit", "/identity", root, "stop"]), \
            patch("os.kill", side_effect=send), patch("time.sleep") as sleep, patch("signal.SIGKILL", 9, create=True):
        if transition == "never_exits":
            with pytest.raises(RuntimeError, match="Owned mirror did not stop"):
                exec(helper._MIRROR_PROCESS, {})
            assert sleep.call_count == 100
        else:
            exec(helper._MIRROR_PROCESS, {})
    escalated = transition in ("kill_escalation", "kill_signal_gone", "never_exits")
    assert len(signals) == (2 if escalated else 1)
    if escalated:
        import signal
        assert signals == [signal.SIGTERM, 9]
    assert phase == "live" if transition == "never_exits" else phase in ("gone", "zombie")


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux /proc; no DUT or package payloads")
@pytest.mark.parametrize("ignore_term", [False, True])
def test_mirror_process_stops_real_owned_linux_http_server(tmp_path, ignore_term):
    """Check real loopback HTTP, TERM/KILL shutdown and repeated stop on Linux."""
    import selectors
    import signal
    from urllib.request import urlopen

    root = str(tmp_path)
    (tmp_path / "probe.txt").write_text("owned-loopback")
    command = [sys.executable, "-u", "-m", "http.server", "0",
               "--bind", "127.0.0.1", "--directory", root]
    if ignore_term:
        command = [sys.executable, "-u", "-c",
                   "import runpy,signal,sys; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                   "sys.argv.pop(1); runpy.run_module('http.server',run_name='__main__')",
                   "http.server", "0", "--bind", "127.0.0.1", "--directory", root]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=5), "Owned HTTP server did not become ready"
            startup = child.stdout.readline()
        port = re.search(r"port (\d+)", startup)
        assert port, startup
        with urlopen("http://127.0.0.1:{}/probe.txt".format(port.group(1)), timeout=5) as response:
            assert response.read() == b"owned-loopback"
        start = Path("/proc/{}/stat".format(child.pid)).read_text().rsplit(")", 1)[1].split()[19]
        identity = tmp_path / "process.json"
        identity.write_text(json.dumps({"pid": child.pid, "start": start}))
        for action in ("check", "stop", "stop"):
            result = subprocess.run([sys.executable, "-c", helper._MIRROR_PROCESS,
                                     str(identity), root, action],
                                    capture_output=True, text=True, timeout=15)
            assert result.returncode == 0, result.stderr
        assert child.wait(timeout=5) == -(signal.SIGKILL if ignore_term else signal.SIGTERM)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()


@pytest.mark.parametrize("module,fixture", [(cphc, "cphc_mirror"), (sup, "postupgrade_mirror")])
@pytest.mark.parametrize("available", [False, True])
def test_preload_prerequisite_is_checked_before_mirror_start(module, fixture, available):
    """Missing real scripts skip mirror consumers without opening a listener."""
    host = Host()
    mirror = Mock()
    with patch.object(module, "find_preload_firmware", return_value="/real/preload" if available else None), \
            patch.object(module, "PackageMirror", return_value=mirror) as factory:
        generator = getattr(module, fixture).__wrapped__({"dut": host}, "dut", "/source", request())
        if available:
            assert next(generator) is mirror
            mirror.start.assert_called_once()
            generator.close()
            mirror.stop.assert_called_once()
        else:
            with pytest.raises(pytest.skip.Exception, match="preload_firmware is not on this DUT"):
                next(generator)
            factory.assert_not_called()


@pytest.mark.parametrize("change", [
    "empty_live", "wrong_root", "wrong_command", "reused_pid", "reuse_during_cmdline", "permission_denied",
])
def test_mirror_exit_race_checks_still_refuse_live_foreign_process(change):
    """After TERM, uncertainty cannot authorize a later KILL of a live foreign process."""
    signaled = False
    reused = False
    root = "/tmp/owned-mirror/www"

    def files(name, mode="r"):
        nonlocal reused
        if name == "/identity":
            return io.StringIO(json.dumps({"pid": 1234, "start": "42"}))
        if name.endswith("/stat"):
            start = "43" if reused or (signaled and change == "reused_pid") else "42"
            return io.StringIO("1234 (python3) " + " ".join(["S"] + ["0"] * 18 + [start]))
        if name.endswith("/cmdline"):
            if change == "reuse_during_cmdline":
                reused = True
            if signaled and change == "permission_denied":
                raise PermissionError("proc access denied")
            if signaled and change == "empty_live":
                return io.BytesIO(b"")
            command = "foreign" if signaled and change == "wrong_command" else "http.server"
            directory = "/tmp/foreign" if signaled and change == "wrong_root" else root
            return io.BytesIO(("\0".join(["python3", "-m", command, "--directory", directory]) + "\0").encode())
        raise AssertionError(name)

    def send(pid, sig):
        nonlocal signaled
        signaled = True

    with patch("builtins.open", side_effect=files), patch("os.path.exists", return_value=True), \
            patch.object(sys, "argv", ["unit", "/identity", root, "stop"]), \
            patch("os.kill", side_effect=send) as kill, patch("time.sleep"):
        with pytest.raises(PermissionError if change == "permission_denied" else RuntimeError):
            exec(helper._MIRROR_PROCESS, {})
    assert kill.call_count == (0 if change == "reuse_during_cmdline" else 1)


def test_mirror_stop_missing_identity_is_idempotent():
    """Already-cleaned mirrors require no process signal."""
    with patch("os.path.exists", return_value=False), \
            patch.object(sys, "argv", ["unit", "/identity", "/tmp/owned", "stop"]), patch("os.kill") as kill:
        with pytest.raises(SystemExit) as result:
            exec(helper._MIRROR_PROCESS, {})
    assert result.value.code == 0
    kill.assert_not_called()


def test_mirror_start_identity_write_failure_stops_its_child():
    """A spawn/identity-recording partial failure must not orphan the spawned child."""
    child = Mock(pid=1234)

    def files(name, mode="r"):
        if name == "/identity":
            raise OSError("identity write failed")
        if name == "/log":
            return io.BytesIO()
        if name == "/proc/1234/stat":
            return io.StringIO("1234 (python3) " + " ".join(["S"] + ["0"] * 18 + ["42"]))
        raise AssertionError(name)

    with patch("builtins.open", side_effect=files), patch("subprocess.Popen", return_value=child), \
            patch.object(sys, "argv", ["unit", "/root", "/log", "/identity", "8910", "127.0.0.1"]):
        with pytest.raises(OSError, match="identity write failed"):
            exec(helper._START_MIRROR, {})
    child.terminate.assert_called_once()
    child.wait.assert_called_once_with(timeout=5)


def test_mirror_cleanup_refusal_retains_identity_and_does_not_delete_owned_evidence():
    """Ambiguous process ownership surfaces an error instead of deleting evidence."""
    host = Host()
    mirror = helper.PackageMirror(host, "unit", 8910)
    mirror.created = True
    host.write(mirror.pid_file, b"identity")
    with patch.object(mirror, "_process", side_effect=RuntimeError("identity changed")):
        with pytest.raises(RuntimeError, match="identity changed"):
            mirror.stop()
    assert mirror.pid_file in host.entries
    assert not any(command.startswith("rm ") for command in host.commands)


def test_sup_source_download_failure_cleans_unique_workspace_only():
    """Mirror input setup failures cannot clear a preexisting similarly named workspace."""
    host = Host()
    host.write(sup.POSTUPGRADE_WORKSPACE + "/user", b"keep")
    original = host.entries.copy()

    def broken(*args, **kwargs):
        fetch(*args, **kwargs)
        raise RuntimeError("source failed")

    with patch.object(helper, "fetch_to_dut", broken):
        with pytest.raises(RuntimeError, match="source failed"):
            with contextmanager(sup.postupgrade_workspace.__wrapped__)(
                    {"dut": host}, "dut", None, request()):
                pytest.fail("Failed source must not yield")
    assert host.entries == original


@pytest.mark.parametrize("copy_fails", [False, True])
def test_runner_download_staging_is_unique_and_cleaned_even_on_copy_failure(copy_fails):
    """Fallback download never overwrites a shared basename or leaves a copy-failure partial."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = {"rc": 28, "stdout": "000", "stderr": "timeout"}
    runner.shell.return_value = {"rc": 0, "stdout": "200", "stderr": ""}
    if copy_fails:
        dut.copy.side_effect = RuntimeError("copy failed")
    with patch.object(helper, "candidate_urls", return_value=["https://example.test/package.tar"]):
        if copy_fails:
            with pytest.raises(RuntimeError, match="copy failed"):
                helper.fetch_to_dut(dut, runner, "https://example.test/package.tar", "/tmp/owned", "package.tar")
        else:
            helper.fetch_to_dut(dut, runner, "https://example.test/package.tar", "/tmp/owned", "package.tar")
    source = dut.copy.call_args.kwargs["src"]
    assert "sonic-ops-" in source and source != "/tmp/package.tar"
    assert runner.shell.call_args.args[0] == "rm -f -- " + shlex.quote(source)


@pytest.mark.parametrize("inventory,host_ip", [("strtk5", "10.1.3.6"), ("bjw", "10.150.22.222")])
@pytest.mark.parametrize("arguments", [
    [],
    ["--image_server_url=https://sonicstorageinternal.blob.core.windows.net/images",
     "--sonic_ops_branch=ryanzhu/ops-publish-cicd"],
    ["--cphc_package_url=https://wrong.example/cphc", "--sup_package_url=https://wrong.example/sup",
     "--use_mirror_layout", "--package_sas_token=never-forward-me"],
    ["--image_server_url=https://sonic.packages.trafficmanager.net/azmirrors",
     "--cphc_package_url=https://sonic.packages.trafficmanager.net/azmirrors/ACS/"
     "sonic-upgrade-packages/sonic-upgrade-package-1.0.0.tar",
     "--sup_package_url=https://sonic.packages.trafficmanager.net/azmirrors/ACS/"
     "sonic-upgrade-packages/sonic-upgrade-package.tar.gz"],
])
def test_actual_three_fixture_download_paths_are_latest_and_anonymous(arguments, inventory, host_ip, caplog):
    """All six source surfaces use metadata-bracketed latest URLs even for stale plans."""
    options = load("conftest")
    parser = argparse.ArgumentParser()
    options.pytest_addoption(SimpleNamespace(getgroup=lambda name: SimpleNamespace(addoption=parser.add_argument)))
    values = vars(parser.parse_args(arguments))
    req = SimpleNamespace(
        config=SimpleNamespace(getoption=lambda key: values[key.lstrip("-")]),
        getfixturevalue=lambda name: {"tbinfo": {"inv_name": inventory}}[name])

    class DownloadHost(Host):
        def __init__(self):
            super().__init__(helper.BJW_DELIVERY_PACKAGES if inventory == "bjw" else helper.DELIVERY_PACKAGES)
            self.urls = []

        def run(self, words, cwd):
            if words[0] == "curl":
                url = next(word for word in words if word.startswith(("http://", "https://")))
                if url.startswith("http://127.0.0.1:8911/"):
                    return super().run(words, cwd)
                self.urls.append(url)
            return super().run(words, cwd)

    host = DownloadHost()
    runner = Mock()
    runner.shell.side_effect = AssertionError("Unexpected runner request")
    with patch.object(helper, "os", SimpleNamespace(path=posixpath)):
        packages = download.packages.__wrapped__(req)
        for package in packages.values():
            download.test_package_downloads_with_curl({"dut": host}, "dut", req, package)
        with contextmanager(download.staged.__wrapped__)({"dut": host}, "dut", runner, req, packages):
            pass
        source_url = cphc.package_url.__wrapped__(req)
        with contextmanager(cphc.cphc_workspace.__wrapped__)(
                {"dut": host}, "dut", runner, source_url, req):
            pass
        with sup_state(host) as state:
            with contextmanager(sup.staged_package.__wrapped__)(
                    {"dut": host}, "dut", runner, req, state):
                pass
        with sup_state(host) as state:
            getfixturevalue = req.getfixturevalue
            req.getfixturevalue = Mock(
                side_effect=lambda name: state if name == "postupgrade_state" else getfixturevalue(name))
            sup.test_postupgrade_package_runs_directly({"dut": host}, "dut", runner, req)
        with contextmanager(sup.postupgrade_workspace.__wrapped__)(
                {"dut": host}, "dut", runner, req) as source:
            mirror = helper.PackageMirror(host, "source-proof", 8911)
            with patch.object(helper, "dut_eth0_ip", return_value="127.0.0.1"):
                mirror.start(source, [sup.TARBALL],
                             package_metadata={sup.TARBALL: helper.publication_info(req, "postupgrade")})
            for served in mirror.served_copies(sup.TARBALL):
                assert host.entries[served][0] == package_bytes(True)
            mirror.stop()
    expected = {package["url"] + suffix for package in host.package_sources.values()
                for suffix in ("", ".md5", ".buildinfo.json")} | {
                    package["selector"] for package in host.package_sources.values()}
    assert set(host.urls) == expected
    assert all(url.startswith("http://" + host_ip + "/azmirrors/ACS/sonic-upgrade-packages/") for url in host.urls)
    assert len(host.urls) == 40
    for offset in range(0, len(host.urls), 5):
        selector, md5, tarball, info, selector_after = host.urls[offset:offset + 5]
        assert selector == selector_after
        assert md5 == tarball + ".md5" and info == tarball + ".buildinfo.json"
    assert req.config._sonic_operations_publications == host.publications
    assert "never-forward-me" not in caplog.text
    assert not any("never-forward-me" in command or "blob.core" in command for command in host.commands)
    assert not any("sonic.packages.trafficmanager.net" in command for command in host.commands)


@pytest.mark.parametrize("sources", [helper.DELIVERY_PACKAGES, helper.BJW_DELIVERY_PACKAGES], ids=["STR", "BJW"])
def test_pinned_fetch_failure_does_not_try_any_alternate_endpoint(sources):
    """DUT/runner retries must use the same exact URL, never Blob or regional fallback."""
    dut, runner = Mock(), Mock()
    dut.shell.return_value = runner.shell.return_value = ModuleResult(rc=28, stdout="000", stderr="timeout")
    url = sources["cphc"]["url"]
    with pytest.raises(RuntimeError, match="Could not download"):
        helper.fetch_to_dut(dut, runner, url, "/tmp/owned", "package.tar", sas_token="hidden-token")
    requests = [call.args[0] for host in (dut, runner) for call in host.shell.call_args_list
                if call.args[0].startswith("curl")]
    assert len(requests) == 2
    assert all(shlex.split(command)[-1] == url for command in requests)


@pytest.mark.parametrize("provenance", [
    {"buildId": "different", "commit": "a" * 40},
    {"buildId": "201", "commit": "different"},
])
def test_pinned_provenance_mismatch_fails_without_silent_fallback(provenance):
    """An accessible sidecar for a different publication cannot identify this build."""
    host = Mock()
    host.shell.return_value = {"rc": 0, "stdout": json.dumps(provenance), "stderr": ""}
    with pytest.raises(AssertionError, match="buildinfo"):
        helper.log_package_provenance(host, Mock(), helper.DELIVERY_PACKAGES["cphc"]["url"])


def test_matching_tar_and_sidecar_from_another_build_are_rejected():
    """Self-consistent replacement bytes cannot pass the selected buildinfo hash constraint."""
    host = Host()
    fetch(host, None, "", "/tmp/verify", sup.TARBALL)
    fetch(host, None, "", "/tmp/verify", sup.TARBALL + ".md5")
    metadata = publication_metadata("postupgrade")
    metadata["md5"] = "0" * 32
    with pytest.raises(AssertionError, match="selected buildinfo"):
        helper.require_package_integrity(
            host, "/tmp/verify/" + sup.TARBALL, "/tmp/verify/" + sup.TARBALL + ".md5", metadata)


@pytest.mark.parametrize("status", [127, 124, 126, 137])
def test_preload_negative_rejects_infrastructure_exit_even_after_good_control(status):
    """A valid baseline does not make a later missing-command/timeout a corruption pass."""
    host = Host()
    mirror = helper.PackageMirror(host, "negative", 8910)
    for directory in mirror.docroots():
        fetch(host, None, "", directory, sup.TARBALL)
        fetch(host, None, "", directory, sup.TARBALL + ".md5")
    original = host.entries.copy()
    with patch.object(mirror, "assert_valid_download"), \
            patch.object(mirror, "run_preload_firmware", return_value={"rc": status, "stdout": "", "stderr": "failed"}):
        with pytest.raises(AssertionError, match="could not run"):
            mirror.assert_rejects_corruption("/mock/preload", sup.TARBALL)
    assert host.entries == original


@pytest.mark.parametrize("subpath", ["", "sonic-upgrade-packages/"])
def test_preload_corruption_requires_observed_fetch_and_reversible_controls(subpath):
    """Both shipped layouts use good/corrupt/good controls without a fixed rejection code."""
    host = Host()
    mirror = helper.PackageMirror(host, "negative", 8910)
    for directory in mirror.docroots():
        fetch(host, None, "", directory, sup.TARBALL)
        fetch(host, None, "", directory, sup.TARBALL + ".md5")
    original = host.entries.copy()
    log = "\n".join('127.0.0.1 - - [time] "GET /networkfirmware/ACS/{}{}{} HTTP/1.1" 200 -'.format(
        subpath, sup.TARBALL, suffix) for suffix in ("", ".md5"))
    with patch.object(mirror, "assert_valid_download") as valid, \
            patch.object(mirror, "run_preload_firmware", return_value={"rc": 2, "stdout": "", "stderr": "rejected"}), \
            patch.object(mirror, "_requests", return_value=log):
        mirror.assert_rejects_corruption("/mock/preload", sup.TARBALL)
        assert valid.call_count == 2
    assert host.entries == original


def test_preload_missing_or_failed_http_request_is_not_integrity_rejection():
    """No fetched corrupt bytes means there is no evidence of an integrity rejection."""
    host = Host()
    mirror = helper.PackageMirror(host, "negative", 8910)
    for directory in mirror.docroots():
        fetch(host, None, "", directory, sup.TARBALL)
        fetch(host, None, "", directory, sup.TARBALL + ".md5")
    with patch.object(mirror, "assert_valid_download"), \
            patch.object(mirror, "run_preload_firmware", return_value={"rc": 2, "stdout": "", "stderr": ""}), \
            patch.object(mirror, "_requests", return_value='"GET /not-found HTTP/1.1" 404 -'):
        with pytest.raises(AssertionError, match="No successful fetch"):
            mirror.assert_rejects_corruption("/mock/preload", sup.TARBALL)


@pytest.mark.parametrize("http_status", [200, 404])
def test_real_curl_checks_returned_bytes_not_just_nonempty_body(tmp_path, http_status):
    """Real consumer curl accepts404; the external package integrity gate rejects it."""
    curl = shutil.which("curl.exe" if os.name == "nt" else "curl")
    if not curl:
        pytest.skip("Local curl unavailable")
    data = package_bytes(gzipped=True)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (hashlib.md5(data).hexdigest() + "  " + sup.TARBALL + "\r\n").encode() \
                if self.path.endswith(".md5") else data
            if http_status == 404:
                body = b"<html>not found</html>"
            self.send_response(http_status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class CurlHost(Host):
        def run(self, words, cwd):
            if words[0] == "curl" and "-o" in words:
                output = tmp_path / Path(words[words.index("-o") + 1]).name
                destination = words[words.index("-o") + 1]
                words[words.index("-o") + 1] = str(output)
                run = subprocess.run([curl, *words[1:]], capture_output=True, text=True, timeout=5)
                self.write(destination, output.read_bytes())
                return {"rc": run.returncode, "stdout": run.stdout, "stderr": run.stderr}
            return super().run(words, cwd)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = CurlHost()
        pkg = SimpleNamespace(key="postupgrade", filename=sup.TARBALL,
                              curl=helper.curl_like_wrapper, consumer="wrapper")
        url = "http://127.0.0.1:{}/{}".format(server.server_port, sup.TARBALL)
        with patch.dict(helper.DELIVERY_PACKAGES["postupgrade"],
                        {"url": url, "selector": url + ".latest.buildinfo.json"}):
            if http_status == 404:
                with pytest.raises(AssertionError, match="Invalid MD5 sidecar"):
                    download.test_package_downloads_with_curl({"dut": host}, "dut", request(), pkg)
            else:
                download.test_package_downloads_with_curl({"dut": host}, "dut", request(), pkg)
        assert not any("package-curl-" in key for key in host.entries)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
