"""Exercise saithrift package replacement without a DUT or Ansible dependencies."""

import ast
import glob
import logging
import os
from pathlib import Path
import shlex
import shutil
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "test_pretest.py"
SYSTEM_SITE = "/usr/lib/python3/dist-packages"
VENV_SITE = "/root/env-python3/lib/python3.13/site-packages"


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def update_saithrift():
    """Execute the actual pretest function using the repository's AST test pattern."""
    tree = ast.parse(MODULE_PATH.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "test_update_saithrift_ptf")
    namespace = dict(
        os=os, logging=logging, shlex=shlex, pytest=pytest, pytest_assert=_assert,
        logger=logging.getLogger(__name__), time=Mock(), is_msft_url=lambda url: False,
    )
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["test_update_saithrift_ptf"]


class PackageHost:
    """Model dpkg-owned files separately from copies left in PTF site-packages."""

    def __init__(self, root, layout="egg", minor="3.11", venv=True, client="switch_sai_thrift"):
        self.root = root
        self.venv = venv
        self.client = client
        self.pending = (layout, minor, "first")
        self.owned_directory = None
        self.package_files = []
        self.copies = []
        self.removals = []
        self.commands = []
        self.purelib_error = False
        self.copy_error = False

    def local(self, remote):
        return self.root / remote.lstrip("/")

    def get_url(self, **kwargs):
        return {"failed": False, "msg": "OK"}

    def install(self):
        if self.owned_directory is not None:
            shutil.rmtree(self.local(self.owned_directory))
        layout, minor, revision = self.pending
        if layout == "empty":
            self.owned_directory = None
            self.package_files = []
            return
        if layout == "egg":
            directory = "{}/saithrift-0.9-py3.{}.egg/{}".format(SYSTEM_SITE, minor.split(".")[1], self.client)
        elif layout == "py2":
            directory = "/usr/lib/python2.7/dist-packages/saithrift-0.9-py2.7.egg/{}".format(self.client)
        else:
            directory = "{}/{}".format(SYSTEM_SITE, self.client)
        self.owned_directory = directory
        self.local(directory).mkdir(parents=True, exist_ok=True)
        self.local(directory + "/__init__.py").write_text("REVISION = {!r}\n".format(revision))
        self.package_files = [directory, directory + "/__init__.py"]

    def shell(self, command, module_ignore_errors=False):
        self.commands.append(command)
        args = shlex.split(command)
        if args[:2] == ["rm", "-f"]:
            return {"stdout": "", "rc": 0}
        if args[:2] == ["dpkg", "-i"]:
            self.install()
            return {"stdout": "", "rc": 0}
        if args[:2] == ["dpkg-deb", "--field"]:
            return {"stdout": "python-saithrift", "rc": 0}
        if args[:2] == ["dpkg", "-L"]:
            return {"stdout": "\n".join(self.package_files), "stdout_lines": self.package_files, "rc": 0}
        if args[:2] == ["ls", "-d"]:
            matches = glob.glob(str(self.local(args[2])))
            path = "/" + str(Path(matches[0]).relative_to(self.root)) if matches else ""
            return {"stdout": path, "rc": 0 if matches else 2}
        if "sysconfig.get_paths()" in command:
            if self.purelib_error:
                if module_ignore_errors:
                    return {"stdout": "", "rc": 1}
                raise RuntimeError("PTF interpreter failed")
            if not self.venv and command.startswith("/root/env-python3/bin/python"):
                return {"stdout": "", "rc": 127}
            return {"stdout": VENV_SITE if self.venv else SYSTEM_SITE, "rc": 0}
        if args[:2] == ["rm", "-rf"]:
            target = args[-1]
            assert Path(target).name in ("switch_sai_thrift", "sai_thrift")
            self.removals.append(target)
            path = self.local(target)
            if path.exists():
                shutil.rmtree(path)
            return {"stdout": "", "rc": 0}
        raise AssertionError("Unexpected remote command: {}".format(command))

    def copy(self, src, dest, remote_src):
        assert remote_src
        if self.copy_error:
            raise RuntimeError("PTF copy failed")
        self.copies.append((src, dest))
        target = self.local(dest) / Path(src).name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.local(src), target)


def run_update(update_saithrift, host, url="https://vendor.example/python-saithrift_0.9.4_amd64.deb"):
    request = Mock()
    request.config.getoption.return_value = url
    update_saithrift(request, host, {}, "unused")


@pytest.mark.parametrize("layout,minor", [("egg", "3.11"), ("egg", "3.13"), ("flat", "3.13")])
def test_client_is_refreshed_in_private_venv(update_saithrift, tmp_path, layout, minor):
    """Both existing egg packages and the new flat package populate the private venv."""
    host = PackageHost(tmp_path, layout, minor)
    run_update(update_saithrift, host)
    assert host.local(VENV_SITE + "/switch_sai_thrift/__init__.py").read_text() == "REVISION = 'first'\n"


@pytest.mark.parametrize("first,second", [("egg", "flat"), ("flat", "egg"), ("egg", "egg")])
def test_replacement_uses_latest_package(update_saithrift, tmp_path, first, second):
    """A new package must replace the previous venv copy in either layout direction."""
    host = PackageHost(tmp_path, first)
    run_update(update_saithrift, host)
    host.pending = (second, "3.13", "replacement")
    run_update(update_saithrift, host)
    assert host.local(VENV_SITE + "/switch_sai_thrift/__init__.py").read_text() == "REVISION = 'replacement'\n"


def test_unmanaged_flat_copy_cannot_override_installed_egg(update_saithrift, tmp_path):
    """Use the installed package's manifest rather than a stale system directory."""
    host = PackageHost(tmp_path)
    stale = host.local(SYSTEM_SITE + "/switch_sai_thrift")
    stale.mkdir(parents=True)
    (stale / "__init__.py").write_text("REVISION = 'stale'\n")
    run_update(update_saithrift, host)
    assert host.local(VENV_SITE + "/switch_sai_thrift/__init__.py").read_text() == "REVISION = 'first'\n"


def test_flat_system_install_is_not_deleted_without_venv(update_saithrift, tmp_path):
    """When source and destination coincide, leave the dpkg-installed client intact."""
    host = PackageHost(tmp_path, "flat", venv=False)
    run_update(update_saithrift, host)
    assert host.local(SYSTEM_SITE + "/switch_sai_thrift/__init__.py").is_file()
    assert host.copies == []
    assert host.removals == []


def test_legacy_system_python_path_is_preserved(update_saithrift, tmp_path):
    """Older PTF images without a venv still receive the client in system site-packages."""
    host = PackageHost(tmp_path, venv=False)
    run_update(update_saithrift, host)
    assert host.local(SYSTEM_SITE + "/switch_sai_thrift/__init__.py").read_text() == "REVISION = 'first'\n"


@pytest.mark.parametrize("layout", ["egg", "flat"])
def test_sai_v2_client_is_refreshed(update_saithrift, tmp_path, layout):
    """The other SAI-defined Python namespace also survives the flat-layout transition."""
    host = PackageHost(tmp_path, layout, client="sai_thrift")
    run_update(update_saithrift, host)
    assert host.local(VENV_SITE + "/sai_thrift/__init__.py").read_text() == "REVISION = 'first'\n"


def test_no_url_still_skips_update(update_saithrift, tmp_path):
    """Keep the optional pretest behavior for pipelines that do not request a package."""
    host = PackageHost(tmp_path)
    with pytest.raises(pytest.skip.Exception):
        run_update(update_saithrift, host, url=None)
    assert host.commands == []


def test_empty_package_cannot_report_success(update_saithrift, tmp_path):
    """A package without a client must fail instead of retaining an old venv copy."""
    host = PackageHost(tmp_path, "empty")
    with pytest.raises(AssertionError, match="client"):
        run_update(update_saithrift, host)


def test_python2_system_package_remains_supported(update_saithrift, tmp_path):
    """Do not force the legacy mixed PTF image's Python 2 package into Python 3."""
    host = PackageHost(tmp_path, "py2", venv=False)
    run_update(update_saithrift, host)
    assert host.local(host.owned_directory + "/__init__.py").is_file()
    assert host.copies == []


def test_broken_venv_cannot_fall_back_to_system(update_saithrift, tmp_path):
    """A real interpreter failure must propagate, not appear as a missing venv."""
    host = PackageHost(tmp_path)
    host.purelib_error = True
    with pytest.raises(RuntimeError, match="interpreter"):
        run_update(update_saithrift, host)


def test_copy_failure_is_not_hidden(update_saithrift, tmp_path):
    """An unsuccessful refresh must not leave a success-shaped pretest result."""
    host = PackageHost(tmp_path)
    host.copy_error = True
    with pytest.raises(RuntimeError, match="copy"):
        run_update(update_saithrift, host)
