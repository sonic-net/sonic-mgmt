"""Unit tests for saved configuration preservation during SONiC image installation."""

import importlib.util
import os
import sys
import types
from unittest.mock import Mock

import pytest


PRESERVE_CASES = [
    pytest.param({}, False, id="default"),
    pytest.param({"preserve_config_db": False}, False, id="explicit-false"),
    pytest.param({"preserve_config_db": True}, True, id="explicit-true"),
]


class ModuleExit(BaseException):
    """Represent Ansible's exit_json/fail_json termination without real process exit."""


@pytest.fixture
def image_module(monkeypatch):
    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = object
    debug_utils = types.ModuleType("ansible.module_utils.debug_utils")
    debug_utils.config_module_logging = lambda _: None

    with monkeypatch.context() as imports:
        for name, module in {
            "ansible": ansible,
            "ansible.module_utils": module_utils,
            "ansible.module_utils.basic": basic,
            "ansible.module_utils.debug_utils": debug_utils,
        }.items():
            imports.setitem(sys.modules, name, module)

        module_path = os.path.join(os.path.dirname(__file__), "reduce_and_add_sonic_images.py")
        spec = importlib.util.spec_from_file_location("reduce_and_add_sonic_images", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    monkeypatch.setattr(module, "get_memory_sizes", lambda _: (4096, 2048))
    monkeypatch.setattr(module, "download_new_sonic_image", Mock())
    monkeypatch.setattr(module, "get_sonic_image_size", Mock())
    return module


@pytest.mark.parametrize("options, preserve", PRESERVE_CASES)
@pytest.mark.parametrize("install_source", ["host-url", "tmpfs-url", "host-local"])
@pytest.mark.parametrize("device_type", ["ordinary", "smartswitch", "missing-helper", "failing-helper"])
@pytest.mark.parametrize("has_minigraph", [True, False])
@pytest.mark.parametrize("json_files", [
    ("config_db.json", "golden_config_db.json"),
    ("config_db.json",),
    ("golden_config_db.json",),
    (),
])
def test_install_configuration_policy(
        image_module, monkeypatch, tmp_path, install_source, device_type, has_minigraph, json_files, options, preserve):
    """Preserve JSON only on opt-in or legacy exemptions, leaving minigraph untouched."""
    old_config = tmp_path / "old_config"
    old_config.mkdir()
    for name in json_files:
        (old_config / name).write_text('{"DEVICE_METADATA": {"localhost": {"hostname": "saved"}}}')
    if has_minigraph:
        (old_config / "minigraph.xml").write_text("<Minigraph />")
    original_config = {item.name: item.read_bytes() for item in old_config.iterdir()}

    sonic_py_common = types.ModuleType("sonic_py_common")
    device_info = types.ModuleType("sonic_py_common.device_info")
    is_smartswitch = Mock(return_value=device_type == "smartswitch")
    if device_type == "failing-helper":
        is_smartswitch.side_effect = RuntimeError("Device detection unavailable")
    if device_type != "missing-helper":
        device_info.is_smartswitch = is_smartswitch
    sonic_py_common.device_info = device_info
    monkeypatch.setitem(sys.modules, "sonic_py_common", sonic_py_common)
    monkeypatch.setitem(sys.modules, "sonic_py_common.device_info", device_info)
    monkeypatch.setattr(image_module, "path", types.SimpleNamespace(
        exists=lambda name: (old_config / name.rsplit("/", 1)[-1]).exists()))

    use_tmpfs = install_source == "tmpfs-url"
    monkeypatch.setattr(image_module, "get_disk_free_size",
                        lambda _, partition: 1800 if use_tmpfs and partition == "/host" else 4096)
    image_path = "/tmp/tmpfs/downloaded-sonic-image" if use_tmpfs else "/host/downloaded-sonic-image"
    image_url = None if install_source == "host-local" else "https://example.com/sonic.bin"
    save_as = image_path if install_source == "host-local" else None

    def run_command(command, **kwargs):
        if command.startswith("rm -f /host/old_config/"):
            backup = old_config / command.rsplit("/", 1)[-1]
            if backup.exists():
                backup.unlink()
        if command == "sonic_installer install --help":
            return 0, "--skip-package-migration --skip-platform-check --skip_migration", ""
        return 0, "", ""

    module = Mock()
    module.run_command.side_effect = run_command
    image_module.install_new_sonic_image(module, image_url, save_as=save_as, **options)

    delete_json = not preserve and has_minigraph and device_type != "smartswitch"
    if delete_json:
        for name in json_files:
            del original_config[name]
    assert {item.name: item.read_bytes() for item in old_config.iterdir()} == original_config
    expected_commands = [] if save_as else ["rm -f /host/downloaded-sonic-image"]
    expected_commands.append("sonic_installer install --help")
    if use_tmpfs:
        expected_commands.extend([
            "mkdir -p /tmp/tmpfs",
            "umount /tmp/tmpfs",
            "mount -t tmpfs -o size=1300M tmpfs /tmp/tmpfs",
        ])
    expected_commands.append("sonic_installer install {} --skip-package-migration  -y".format(image_path))
    if use_tmpfs:
        expected_commands.extend(["sync", "umount /tmp/tmpfs", "rm -rf /tmp/tmpfs"])
    else:
        expected_commands.append("rm -f {}".format(image_path))
    if delete_json:
        expected_commands.extend([
            "rm -f /host/old_config/config_db.json",
            "rm -f /host/old_config/golden_config_db.json",
        ])
    assert [call[0][0] for call in module.run_command.call_args_list] == expected_commands
    module.fail_json.assert_not_called()
    image_module.download_new_sonic_image.assert_called_once_with(module, image_url, image_path)
    image_module.get_sonic_image_size.assert_called_once_with(module)
    if not preserve and has_minigraph and device_type != "missing-helper":
        is_smartswitch.assert_called_once_with()
    else:
        is_smartswitch.assert_not_called()


@pytest.mark.parametrize("options, preserve", PRESERVE_CASES)
@pytest.mark.parametrize("save_as", ["/host/downloaded-sonic-image", "/tmp/tmpfs/downloaded-sonic-image"])
def test_install_failure_retains_cleanup_and_stops_before_config_policy(
        image_module, monkeypatch, options, preserve, save_as):
    """Failed installations still clean up their image and never process saved config."""
    monkeypatch.setattr(image_module, "get_disk_free_size", lambda *_: 4096)
    monkeypatch.setattr(image_module, "path", Mock())
    module = Mock()
    module.fail_json.side_effect = ModuleExit
    module.run_command.side_effect = lambda command, **kwargs: (
        (1, "", "install failed") if command.startswith("sonic_installer install /") else (0, "", ""))

    with pytest.raises(ModuleExit):
        image_module.install_new_sonic_image(module, None, save_as=save_as, **options)

    commands = [call[0][0] for call in module.run_command.call_args_list]
    if save_as.startswith("/tmp/tmpfs"):
        assert commands[-3:] == ["sync", "umount /tmp/tmpfs", "rm -rf /tmp/tmpfs"]
    else:
        assert commands[-1] == "rm -f {}".format(save_as)
    assert not any("old_config" in command for command in commands)
    image_module.path.exists.assert_not_called()
    image_module.get_sonic_image_size.assert_not_called()
    module.fail_json.assert_called_once_with(msg="Image installation failed: rc=1, out=, err=install failed")


@pytest.mark.parametrize("options, preserve", PRESERVE_CASES)
@pytest.mark.parametrize("image_args", [
    pytest.param({}, id="cleanup-only"),
    pytest.param({"new_image_url": "https://example.com/sonic.bin"}, id="url"),
    pytest.param({"save_as": "/host/downloaded-sonic-image"}, id="local"),
])
def test_module_option_defaults_and_dispatch(image_module, monkeypatch, options, preserve, image_args):
    """Ansible defaults to legacy policy, forwards opt-in, and leaves cleanup-only unchanged."""
    module = Mock()
    module.exit_json.side_effect = ModuleExit

    def make_module(argument_spec, **kwargs):
        assert argument_spec["preserve_config_db"] == {"required": False, "type": "bool", "default": False}
        module.params = {name: spec["default"] for name, spec in argument_spec.items()}
        module.params.update(image_args, **options)
        return module

    monkeypatch.setattr(image_module, "AnsibleModule", make_module)
    for name in (
            "work_around_for_reboot", "work_around_for_slow_disks", "reduce_installed_sonic_images",
            "free_up_disk_space", "free_up_memory_space", "setup_swap_if_necessary", "install_new_sonic_image"):
        monkeypatch.setattr(image_module, name, Mock())

    with pytest.raises(ModuleExit):
        image_module.main()

    image_module.reduce_installed_sonic_images.assert_called_once_with(module)
    image_module.free_up_disk_space.assert_called_once_with(module, 8)
    if image_args:
        image_module.install_new_sonic_image.assert_called_once_with(
            module, image_args.get("new_image_url"), image_args.get("save_as"), 1600, False,
            preserve_config_db=preserve)
        assert image_module.results["current_stage"] == "complete"
    else:
        image_module.install_new_sonic_image.assert_not_called()
        image_module.work_around_for_reboot.assert_not_called()
        image_module.work_around_for_slow_disks.assert_not_called()
        image_module.free_up_memory_space.assert_not_called()
        image_module.setup_swap_if_necessary.assert_not_called()
    module.fail_json.assert_not_called()
    module.exit_json.assert_called_once_with(ansible_facts=image_module.results)
