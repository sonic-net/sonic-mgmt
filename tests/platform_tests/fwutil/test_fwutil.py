import re
import pytest
import os
import json
from fwutil_common import call_fwutil, show_firmware, upload_platform, find_pattern

pytestmark = [
    pytest.mark.topology("any")
]

DEVICES_PATH = "/usr/share/sonic/device"


def test_fwutil_show(duthost):
    """Tests that fwutil show has all components defined for platform"""
    duthost.fetch(dest=os.path.join("firmware", "platform_components_backup.json"),
                  src=os.path.join(DEVICES_PATH, duthost.facts["platform"], "platform_components.json"),
                  flat=True)
    with open(os.path.join("firmware", "platform_components_backup.json")) as f:
        platform_comp = json.load(f)

    versions = show_firmware(duthost)
    chassis = list(versions["chassis"].keys())[0]

    show_fw_comp_set = set(versions["chassis"][chassis]["component"].keys())
    platform_comp_set = set(platform_comp["chassis"][chassis]["component"].keys())
    assert show_fw_comp_set == platform_comp_set


def test_fwutil_install_file(request, duthost, localhost, pdu_controller, component, fw_pkg):
    """Tests manually installing firmware to a component from a file."""
    call_fwutil(request,
                duthost,
                localhost,
                pdu_controller,
                fw_pkg,
                component=component,
                basepath=os.path.join(DEVICES_PATH, duthost.facts['platform']))


def test_fwutil_install_url(request, duthost, localhost, pdu_controller, component, fw_pkg, host_firmware):
    """Tests manually installing firmware to a component from a URL."""
    call_fwutil(request,
                duthost,
                localhost,
                pdu_controller,
                fw_pkg,
                component=component,
                basepath=host_firmware)


def test_fwutil_install_bad_name(duthost):
    """Tests that fwutil install validates component names correctly."""
    out = duthost.command("fwutil install chassis component BAD fw BAD.pkg", module_ignore_errors=True)
    pattern = re.compile(r'.*Invalid value for "<component_name>"*.')
    assert find_pattern(out['stderr_lines'], pattern)


def test_fwutil_install_bad_path(duthost, component):
    """Tests that fwutil install validates firmware paths correctly."""
    out = duthost.command(f"fwutil install chassis component {component} fw BAD.pkg",
                          module_ignore_errors=True)
    pattern = re.compile(r'.*Error: Invalid value for "<fw_path>"*.')
    assert find_pattern(out['stderr_lines'], pattern)


def test_fwutil_update_current(request, duthost, localhost, pdu_controller, component, fw_pkg):
    """Tests updating firmware from current image using fwutil update"""
    call_fwutil(request,
                duthost,
                localhost,
                pdu_controller,
                fw_pkg,
                component=component)


def test_fwutil_update_next(request, duthost, localhost, pdu_controller, component, next_image, fw_pkg):
    """Tests updating firmware from the "next" image using fwutil update"""
    call_fwutil(request,
                duthost,
                localhost,
                pdu_controller,
                fw_pkg,
                component=component,
                next_image=next_image)


def test_fwutil_update_bad_config(duthost, component):
    """Tests that fwutil update validates the platform_components.json schema correctly."""
    versions = show_firmware(duthost)
    chassis = list(versions["chassis"].keys())[0]  # Only one chassis

    # Test fwutil update with config file without chassis section
    with open("platform_components.json", "w") as f:
        json.dump({}, f, indent=4)
    upload_platform(duthost, {})
    out_empty_json = duthost.command(f"fwutil update chassis component {component} fw -y",
                                     module_ignore_errors=True)
    pattern_bad_platform = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid platform schema*.')
    found_bad_platform = find_pattern(out_empty_json['stdout_lines'], pattern_bad_platform)
    assert found_bad_platform

    # Test fwutil update with config file without component section
    with open("platform_components.json", "w") as f:
        json.dump({"chassis": {chassis: {}}}, f, indent=4)
    upload_platform(duthost, {})
    out_empty_chassis = duthost.command(f"fwutil update chassis component {component} fw -y", module_ignore_errors=True)
    pattern_bad_chassis = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid chassis schema*.')
    found_bad_chassis = find_pattern(out_empty_chassis['stdout_lines'], pattern_bad_chassis)
    assert found_bad_chassis

    # Test fwutil update with config file with version of type dict
    with open("platform_components.json", "w") as f:
        json.dump({"chassis": {chassis: {"component": {component: {"version": {"version": "ver"}}}}}},
                  f,
                  indent=4)
    upload_platform(duthost, {})
    out_bad_version = duthost.command("fwutil update chassis component {} fw -y".format(component),
                                      module_ignore_errors=True)
    pattern_bad_component = re.compile(r'.*Error: Failed to parse "platform_components.json": '
                                       r'invalid component schema*.')
    found_bad_component = find_pattern(out_bad_version['stdout_lines'], pattern_bad_component)
    assert found_bad_component


@pytest.mark.parametrize("reboot_type", ["none", "cold"])
def test_fwutil_auto(request, duthost, localhost, pdu_controller, fw_pkg, reboot_type):
    """Tests fwutil update all command ability to properly select firmware for install based on boot type."""
    call_fwutil(request,
                duthost,
                localhost,
                pdu_controller,
                fw_pkg,
                boot=reboot_type)
