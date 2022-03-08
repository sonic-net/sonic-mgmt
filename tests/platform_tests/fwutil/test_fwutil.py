import re
import pytest
import os
import json

from fwutil_common import call_fwutil, show_firmware, upload_platform, find_pattern

DEVICES_PATH="/usr/share/sonic/device"

def test_fwutil_show(duthost):
    """Tests that fwutil show has all components defined for platform"""
    platform_comp = {}
    duthost.fetch(dest=os.path.join("firmware", "platform_components_backup.json"),
            src=os.path.join(DEVICES_PATH, duthost.facts["platform"], "platform_components.json"),
            flat=True)
    with open(os.path.join("firmware", "platform_components_backup.json")) as f:
        platform_comp = json.load(f)

    versions = show_firmware(duthost)
    chassis = versions["chassis"].keys()[0]

    show_fw_comp_set = set(versions["chassis"][chassis]["component"].keys())
    platform_comp_set = set(platform_comp["chassis"][chassis]["component"].keys())
    comp = show_fw_comp_set == platform_comp_set

    assert comp

def test_fwutil_install_file(duthost, localhost, pdu_controller, fw_pkg, random_component):
    """Tests manually installing firmware to a component from a file."""
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg,
            component=random_component,
            basepath=os.path.join(DEVICES_PATH, duthost.facts['platform']))

def test_fwutil_install_url(duthost, localhost, pdu_controller, fw_pkg, random_component, host_firmware):
    """Tests manually installing firmware to a component from a URL."""
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg,
            component=random_component,
            basepath=host_firmware)

def test_fwutil_install_bad_name(duthost, fw_pkg):
    """Tests that fwutil install validates component names correctly."""
    out = duthost.command("fwutil install chassis component BAD fw BAD.pkg", module_ignore_errors=True)
    pattern = re.compile(r'.*Invalid value for "<component_name>"*.')
    found = find_pattern(out['stderr_lines'], pattern)
    assert found

def test_fwutil_install_bad_path(duthost, fw_pkg, random_component):
    """Tests that fwutil install validates firmware paths correctly."""
    out = duthost.command("fwutil install chassis component {} fw BAD.pkg".format(random_component), module_ignore_errors=True)
    pattern = re.compile(r'.*Error: Invalid value for "<fw_path>"*.')
    found = find_pattern(out['stderr_lines'], pattern)
    assert found

def test_fwutil_update_current(duthost, localhost, pdu_controller, fw_pkg, random_component):
    """Tests updating firmware from current image using fwutil update"""
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg,
            component=random_component)

def test_fwutil_update_next(duthost, localhost, pdu_controller, fw_pkg, random_component, next_image):
    """Tests updating firmware from the "next" image using fwutil update"""
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg,
            component=random_component,
            next_image=next_image)

def test_fwutil_update_bad_config(duthost, fw_pkg, random_component):
    """Tests that fwutil update validates the platform_components.json schema correctly."""
    versions = show_firmware(duthost)
    chassis = versions["chassis"].keys()[0] # Only one chassis

    # Test fwutil update with config file without chassis section
    with open("platform_components.json", "w") as f:
        json.dump({}, f, indent=4)
    upload_platform(duthost, {})
    out_empty_json = duthost.command("fwutil update chassis component {} fw -y".format(random_component), module_ignore_errors=True)
    pattern_bad_platform = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid platform schema*.')
    found_bad_platform = find_pattern(out_empty_json['stdout_lines'], pattern_bad_platform)
    assert found_bad_platform

    # Test fwutil update with config file without component section
    with open("platform_components.json", "w") as f:
        json.dump({"chassis":{chassis:{}}}, f, indent=4)
    upload_platform(duthost, {})
    out_empty_chassis = duthost.command("fwutil update chassis component {} fw -y".format(random_component), module_ignore_errors=True)
    pattern_bad_chassis = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid chassis schema*.')
    found_bad_chassis = find_pattern(out_empty_chassis['stdout_lines'], pattern_bad_chassis)
    assert found_bad_chassis

    # Test fwutil update with config file with version of type dict
    with open("platform_components.json", "w") as f:
        json.dump({"chassis":{chassis:{"component":{random_component:{"version":{"version":"ver"}}}}}}
                , f, indent=4)
    upload_platform(duthost, {})
    out_bad_version = duthost.command("fwutil update chassis component {} fw -y".format(random_component), module_ignore_errors=True)
    pattern_bad_component = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid component schema*.')
    found_bad_component = find_pattern(out_bad_version['stdout_lines'], pattern_bad_component)
    assert found_bad_component


@pytest.mark.parametrize("reboot_type", ["none", "cold"])
def test_fwutil_auto(duthost, localhost, pdu_controller, fw_pkg, reboot_type):
    """Tests fwutil update all command ability to properly select firmware for install based on boot type."""
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg,
            boot=reboot_type)

