"""Offline regression tests for image-upgrade configuration selection."""

import fnmatch
import importlib.util
import io
import posixpath
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest


class ModuleExit(BaseException):
    """Match Ansible's non-returning exit_json/fail_json behavior."""

    def __init__(self, **result):
        self.result = result


class FakeAnsibleModule:
    def __init__(self):
        self.params = {}
        self.commands = []
        self.command_failure = None

    def run_command(self, command, **kwargs):
        self.commands.append(command)
        if self.command_failure and self.command_failure in command:
            return 1, "", "command failed"
        return 0, "", ""

    def fail_json(self, **kwargs):
        raise ModuleExit(failed=True, **kwargs)

    def exit_json(self, **kwargs):
        raise ModuleExit(**kwargs)


@pytest.fixture
def upgrade(monkeypatch):
    """Import the actual module with only its Ansible boundary replaced."""
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = Mock()
    debug = types.ModuleType("ansible.module_utils.debug_utils")
    debug.config_module_logging = Mock()
    monkeypatch.setitem(sys.modules, "ansible", types.ModuleType("ansible"))
    monkeypatch.setitem(sys.modules, "ansible.module_utils", types.ModuleType("ansible.module_utils"))
    monkeypatch.setitem(sys.modules, basic.__name__, basic)
    monkeypatch.setitem(sys.modules, debug.__name__, debug)
    sonic = types.ModuleType("sonic_py_common")
    sonic.device_info = types.SimpleNamespace(is_smartswitch=Mock(return_value=False))
    monkeypatch.setitem(sys.modules, sonic.__name__, sonic)
    spec = importlib.util.spec_from_file_location(
        "reduce_and_add_sonic_images", Path(__file__).with_name("reduce_and_add_sonic_images.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.device_info = sonic.device_info
    return module


@pytest.fixture
def saved_files(upgrade, monkeypatch):
    """Keep DUT filesystem access entirely in memory, including staged copies."""
    files = {}
    for directory in ("/etc/sonic", "/host/old_config"):
        files[directory + "/config_db.json"] = '{"DEVICE_METADATA": {"localhost": {"hostname": "saved"}}}'
        files[directory + "/golden_config_db.json"] = '{"PORT": {}}'
        files[directory + "/minigraph.xml"] = "<DeviceMiniGraph><Hostname>stale</Hostname></DeviceMiniGraph>"

    def open_config(filename, mode="r"):
        if filename not in files:
            raise FileNotFoundError(filename)
        if "b" in mode:
            return io.BytesIO(files[filename].encode("utf-8"))
        return io.StringIO(files[filename])

    monkeypatch.setattr(upgrade, "open", open_config, raising=False)
    monkeypatch.setattr(upgrade, "path", types.SimpleNamespace(join=posixpath.join, exists=lambda p: p in files))
    monkeypatch.setattr(upgrade, "glob", lambda pattern: sorted(fnmatch.filter(files, pattern)))
    return files


@pytest.fixture
def installer(upgrade, saved_files, monkeypatch):
    """Prevent disk, memory, download and image-inspection operations."""
    monkeypatch.setattr(upgrade, "get_disk_free_size", Mock(return_value=4096))
    monkeypatch.setattr(upgrade, "get_memory_sizes", Mock(return_value=(4096, 2048)))
    monkeypatch.setattr(upgrade, "download_new_sonic_image", Mock())
    monkeypatch.setattr(upgrade, "get_sonic_image_size", Mock())
    return FakeAnsibleModule()


def json_removals(module):
    return [command for command in module.commands if command.startswith("rm ") and "config_db" in command]


@pytest.mark.parametrize("is_smartswitch", [False, True])
@pytest.mark.parametrize("xml", ["stale", None])
def test_default_keeps_both_json_files(upgrade, installer, saved_files, is_smartswitch, xml):
    """Stale, malformed or absent XML must never override the default JSON."""
    upgrade.device_info.is_smartswitch.return_value = is_smartswitch
    for directory in ("/etc/sonic", "/host/old_config"):
        if xml is None:
            del saved_files[directory + "/minigraph.xml"]
        else:
            saved_files[directory + "/minigraph.xml"] = xml
    before = saved_files.copy()
    upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin")
    assert not json_removals(installer)
    assert saved_files == before
    upgrade.device_info.is_smartswitch.assert_not_called()


@pytest.mark.parametrize("image_path", ["/host/image.bin", "/tmp/tmpfs/image.bin"])
def test_explicit_minigraph_removes_json_after_install(upgrade, installer, saved_files, image_path):
    """Both installation branches apply explicit minigraph only after success."""
    upgrade.install_new_sonic_image(installer, None, save_as=image_path, config_source="minigraph")
    removal = "rm -f /host/old_config/config_db.json /host/old_config/golden_config_db.json"
    assert json_removals(installer) == [removal]
    commands = installer.commands
    install_index = next(i for i, command in enumerate(commands)
                         if command.startswith("sonic_installer install ") and "--help" not in command)
    validation_index = commands.index("sonic-cfggen -m /host/old_config/minigraph.xml --print-data > /dev/null")
    assert install_index < validation_index < commands.index(removal)


@pytest.mark.parametrize("source,filename,content", [
    ("config_db", "config_db.json", None),
    ("config_db", "config_db.json", "{invalid"),
    ("config_db", "config_db.json", "[]"),
    ("config_db", "golden_config_db.json", "{invalid"),
    ("config_db", "config_db0.json", "{invalid"),
    ("minigraph", "minigraph.xml", None),
    ("minigraph", "minigraph.xml", "<invalid"),
])
@pytest.mark.parametrize("directory", ["/etc/sonic", "/host/old_config"])
def test_invalid_selected_config_fails(upgrade, installer, saved_files, source, filename, content, directory):
    """Missing or malformed selected files fail rather than choosing the other source."""
    filename = directory + "/" + filename
    if content is None:
        saved_files.pop(filename)
    else:
        saved_files[filename] = content
    with pytest.raises(ModuleExit) as error:
        upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin", config_source=source)
    assert error.value.result["failed"]
    assert filename in error.value.result["msg"]
    assert not json_removals(installer)
    if directory == "/etc/sonic":
        assert not installer.commands
        upgrade.download_new_sonic_image.assert_not_called()


def test_golden_config_is_optional(upgrade, installer, saved_files):
    """A normal saved config need not have a golden override."""
    for directory in ("/etc/sonic", "/host/old_config"):
        del saved_files[directory + "/golden_config_db.json"]
    upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin")
    assert not json_removals(installer)


@pytest.mark.parametrize("failure", ["smartswitch", "missing_detector", "import_error", "detection_error"])
def test_minigraph_fails_closed(upgrade, installer, monkeypatch, failure):
    """Unsupported or unknown SmartSwitch status never permits JSON deletion."""
    expected_error = ModuleExit
    if failure == "smartswitch":
        upgrade.device_info.is_smartswitch.return_value = True
    elif failure == "missing_detector":
        del upgrade.device_info.is_smartswitch
    elif failure == "import_error":
        monkeypatch.setitem(sys.modules, "sonic_py_common", None)
    else:
        upgrade.device_info.is_smartswitch.side_effect = RuntimeError("detection failed")
        expected_error = RuntimeError
    with pytest.raises(expected_error):
        upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin", config_source="minigraph")
    assert not installer.commands
    upgrade.download_new_sonic_image.assert_not_called()


@pytest.mark.parametrize("image_path", ["/host/image.bin", "/tmp/tmpfs/image.bin"])
def test_install_failure_never_selects_minigraph(upgrade, installer, image_path):
    """A failed installer cannot be reported as successful or discard saved JSON."""
    installer.command_failure = "sonic_installer install " + image_path
    with pytest.raises(ModuleExit) as error:
        upgrade.install_new_sonic_image(installer, None, save_as=image_path, config_source="minigraph")
    assert "Image installation failed" in error.value.result["msg"]
    assert not json_removals(installer)


@pytest.mark.parametrize("directory", ["/etc/sonic", "/host/old_config"])
def test_cfggen_failure_does_not_delete_json(upgrade, installer, directory):
    """Well-formed but unusable minigraph fails before destructive selection."""
    installer.command_failure = "sonic-cfggen -m " + directory
    with pytest.raises(ModuleExit) as error:
        upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin", config_source="minigraph")
    assert "validating selected minigraph" in error.value.result["msg"]
    assert not json_removals(installer)


def test_removal_failure_is_reported(upgrade, installer):
    """Failure to select the requested source must not claim upgrade success."""
    installer.command_failure = "rm -f /host/old_config/config_db.json"
    with pytest.raises(ModuleExit) as error:
        upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin", config_source="minigraph")
    assert "selecting minigraph" in error.value.result["msg"]


@pytest.mark.parametrize("source", ["config_db", "minigraph"])
@pytest.mark.parametrize("image", ["url", "local", None])
def test_main_policy_and_cleanup(upgrade, monkeypatch, source, image):
    """The module exposes the safe default and does not validate cleanup-only calls."""
    module = FakeAnsibleModule()
    spec = {}

    def make_module(argument_spec, **kwargs):
        spec.update(argument_spec)
        module.params = {key: value.get("default") for key, value in argument_spec.items()}
        module.params["config_source"] = source
        if image == "url":
            module.params["new_image_url"] = "https://example.com/sonic.bin"
        elif image == "local":
            module.params["save_as"] = "/host/image.bin"
        return module

    monkeypatch.setattr(upgrade, "AnsibleModule", make_module)
    for name in ("work_around_for_reboot", "work_around_for_slow_disks", "reduce_installed_sonic_images",
                 "free_up_disk_space", "free_up_memory_space", "setup_swap_if_necessary",
                 "install_new_sonic_image", "validate_config_source"):
        monkeypatch.setattr(upgrade, name, Mock())
    with pytest.raises(ModuleExit) as result:
        upgrade.main()
    assert not result.value.result.get("failed")
    assert spec["config_source"]["default"] == "config_db"
    assert spec["config_source"]["choices"] == ["config_db", "minigraph"]
    if image:
        assert upgrade.install_new_sonic_image.call_args.kwargs["config_source"] == source
    else:
        upgrade.install_new_sonic_image.assert_not_called()
        upgrade.validate_config_source.assert_not_called()
        upgrade.reduce_installed_sonic_images.assert_called_once_with(module)


def test_invalid_policy_does_not_install(upgrade, installer):
    """Direct Python calls cannot bypass the module's argument choices."""
    with pytest.raises(ModuleExit) as error:
        upgrade.install_new_sonic_image(installer, "https://example.com/sonic.bin", config_source="automatic")
    assert "Unsupported config_source" in error.value.result["msg"]
    assert not installer.commands
