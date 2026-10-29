"""Unit tests for upgrade_dpu_sonic_image.py."""

import importlib.util
import os
import sys
import threading
import types

import pytest


class ModuleExit(Exception):
    """Represent Ansible module exit_json/fail_json calls in unit tests."""

    def __init__(self, results):
        super(ModuleExit, self).__init__(results.get("msg"))
        self.results = results


class FakeAnsibleModule(object):
    def __init__(self, command_results=None):
        self.command_results = list(command_results or [])
        self.commands = []

    def run_command(self, command, **kwargs):
        self.commands.append(command)
        return self.command_results.pop(0)

    def fail_json(self, **kwargs):
        raise ModuleExit(kwargs)

    def exit_json(self, **kwargs):
        raise ModuleExit(kwargs)


def _load_upgrade_module():
    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = object
    smartswitch_utils = types.ModuleType("ansible.module_utils.smartswitch_utils")
    smartswitch_utils.smartswitch_hwsku_config = {}
    debug_utils = types.ModuleType("ansible.module_utils.debug_utils")
    debug_utils.config_module_logging = lambda _: None

    saved_modules = {}
    fake_modules = {
        "ansible": ansible,
        "ansible.module_utils": module_utils,
        "ansible.module_utils.basic": basic,
        "ansible.module_utils.smartswitch_utils": smartswitch_utils,
        "ansible.module_utils.debug_utils": debug_utils,
    }
    for name, module in fake_modules.items():
        saved_modules[name] = sys.modules.get(name)
        sys.modules[name] = module

    try:
        module_path = os.path.join(os.path.dirname(__file__), "upgrade_dpu_sonic_image.py")
        spec = importlib.util.spec_from_file_location("upgrade_dpu_sonic_image", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, module in saved_modules.items():
            if module is None:
                del sys.modules[name]
            else:
                sys.modules[name] = module


upgrade_module = _load_upgrade_module()


def make_upgrade(command_results=None, dpu_num=3, target_dpu_index=-1):
    upgrade = upgrade_module.UpgradeDpuSonicImageModule.__new__(
        upgrade_module.UpgradeDpuSonicImageModule)
    upgrade.module = FakeAnsibleModule(command_results)
    upgrade.messages = []
    upgrade._log_lock = threading.Lock()
    upgrade._cli_lock = threading.Lock()
    upgrade.dpu_num = dpu_num
    upgrade.target_dpu_index = target_dpu_index
    return upgrade


def test_get_installed_images_normalizes_leading_slash():
    """Image names should not retain the leading slash emitted by some installers."""
    upgrade = make_upgrade([
        (True, "Current: /SONiC-OS-20251110.34\nNext: SONiC-OS-20251110.34\n", ""),
    ])
    upgrade.execute_command = lambda *args, **kwargs: upgrade.module.command_results.pop(0)

    assert upgrade.get_installed_images(object(), "169.254.200.1") == (
        True, "SONiC-OS-20251110.34", "SONiC-OS-20251110.34")


def test_prepare_image_for_reboot_maps_uboot_image_to_physical_slot():
    """U-Boot selection must use the physical slot rather than the compact image list."""
    upgrade = make_upgrade()
    commands = []
    results = iter([
        (True, "NONE\nSONiC-OS-20260510.10\n", ""),
        (True, "", ""),
        (True, "", ""),
        (True, "", ""),
        (True, "run sonic_image_2\n", ""),
    ])
    upgrade.execute_command = lambda _, __, command: commands.append(command) or next(results)

    assert upgrade.prepare_image_for_reboot(
        object(), "169.254.200.1", "SONiC-OS-20260510.10") is True
    assert commands[1:] == [
        "sudo fw_setenv boot_next 'run sonic_image_2'",
        "sudo fw_setenv boot_once 'run sonic_image_2'",
        "sudo sync",
        "fw_printenv -n boot_next",
    ]


@pytest.mark.parametrize("results", [
    [(False, "", "slot read failed")],
    [(True, "NONE\nSONiC-OS-20260510.10\n", ""), (False, "", "boot_next failed")],
    [(True, "NONE\nSONiC-OS-20260510.10\n", ""), (True, "", ""), (False, "", "boot_once failed")],
    [(True, "NONE\nSONiC-OS-20260510.10\n", ""), (True, "", ""), (True, "", ""),
     (False, "", "sync failed")],
])
def test_prepare_image_for_reboot_rejects_command_failure(results):
    """Any boot-selection command failure must prevent a reboot."""
    upgrade = make_upgrade()
    command_results = iter(results)
    upgrade.execute_command = lambda *args: next(command_results)

    assert upgrade.prepare_image_for_reboot(
        object(), "169.254.200.1", "SONiC-OS-20260510.10") is False


@pytest.mark.parametrize("slot_output", [
    "NONE\nNONE\n",
    "SONiC-OS-20260510.10\nSONiC-OS-20260510.10\n",
])
def test_prepare_image_for_reboot_rejects_missing_or_duplicate_uboot_slot(slot_output):
    """An ambiguous U-Boot slot mapping must prevent the chassis power cycle."""
    upgrade = make_upgrade()
    upgrade.execute_command = lambda *args: (True, slot_output, "")

    assert upgrade.prepare_image_for_reboot(
        object(), "169.254.200.1", "SONiC-OS-20260510.10") is False


def test_prepare_image_for_reboot_uses_installer_on_non_uboot_platform():
    """Non-U-Boot platforms should retain the sonic-installer selection path."""
    upgrade = make_upgrade()
    commands = []
    results = iter([
        (True, "__NOT_UBOOT__\n", ""),
        (True, "", ""),
        (True, "", ""),
        (True, "", ""),
    ])
    upgrade.execute_command = lambda _, __, command: commands.append(command) or next(results)
    upgrade.get_installed_images = lambda *_: (
        True, "SONiC-OS-20251110.34", "SONiC-OS-20260510.10")

    assert upgrade.prepare_image_for_reboot(
        object(), "169.254.200.1", "SONiC-OS-20260510.10") is True
    assert commands[1:] == [
        "sudo sonic-installer set-default SONiC-OS-20260510.10",
        "sudo sonic-installer set-next-boot SONiC-OS-20260510.10",
        "sudo sync",
    ]


def test_get_admin_up_dpu_indices_skips_admin_down_dpus():
    """Only DPUs with admin_status=up should remain upgrade targets."""
    upgrade = make_upgrade([
        (0, "up\n", ""),
        (0, "down\n", ""),
        (0, "UP\n", ""),
    ])

    admin_up, skipped = upgrade.get_admin_up_dpu_indices([0, 1, 2])

    assert admin_up == [0, 2]
    assert skipped == [1]
    assert upgrade.module.commands == [
        'sonic-db-cli CONFIG_DB HGET "CHASSIS_MODULE|DPU0" admin_status',
        'sonic-db-cli CONFIG_DB HGET "CHASSIS_MODULE|DPU1" admin_status',
        'sonic-db-cli CONFIG_DB HGET "CHASSIS_MODULE|DPU2" admin_status',
    ]


@pytest.mark.parametrize("command_result, expected_message", [
    ((1, "", "database unavailable"), "Failed to read admin status for DPU0"),
    ((0, "", ""), "Invalid or missing admin status '' for DPU0"),
])
def test_get_admin_up_dpu_indices_rejects_unreadable_status(command_result, expected_message):
    """Unreadable admin state should fail rather than accidentally upgrade a DPU."""
    upgrade = make_upgrade([command_result], dpu_num=1)

    with pytest.raises(ModuleExit, match=expected_message):
        upgrade.get_admin_up_dpu_indices([0])


def test_upgrade_dpus_does_not_download_when_all_targets_are_admin_down():
    """An all-admin-down target set should complete without downloading an image."""
    upgrade = make_upgrade([
        (0, "down\n", ""),
        (0, "down\n", ""),
    ], dpu_num=2)
    upgrade.download_image_on_npu = lambda: pytest.fail("image should not be downloaded")

    assert upgrade.upgrade_dpus() == (0, 0, [0, 1])


def test_run_reports_admin_down_target_as_unchanged():
    """A specifically targeted admin-down DPU should be skipped without changes."""
    upgrade = make_upgrade([(0, "down\n", "")], dpu_num=2, target_dpu_index=1)
    upgrade.download_image_on_npu = lambda: pytest.fail("image should not be downloaded")

    with pytest.raises(ModuleExit) as exc:
        upgrade.run()

    assert exc.value.results["changed"] is False
    assert exc.value.results["success_count"] == 0
    assert exc.value.results["failure_count"] == 0
    assert exc.value.results["total_dpus"] == 0
    assert exc.value.results["skipped_dpus"] == [1]
    assert exc.value.results["msg"] == (
        "No admin-up DPUs to upgrade (skipped 1 admin-down DPU(s))")
