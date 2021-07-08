import re
import pytest
import os
import json

from fwutil_common import call_fwutil, show_firmware, upload_platform

DEVICES_PATH="/usr/share/sonic/device"

def test_fwutil_show(duthost):
    # Test that command returns without error
    assert show_firmware(duthost)

def test_fwutil_install_file(duthost, localhost, pdu_controller, fw_pkg, random_component):
    assert call_fwutil(duthost, 
            localhost, 
            pdu_controller, 
            fw_pkg, 
            component=random_component, 
            basepath=os.path.join(DEVICES_PATH, duthost.facts['platform']))

def test_fwutil_install_url(duthost, localhost, pdu_controller, fw_pkg, random_component, host_firmware):
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg, 
            component=random_component, 
            basepath=host_firmware)

def test_fwutil_install_bad_name(duthost, fw_pkg):
    out = duthost.command("fwutil install chassis component BAD fw BAD.pkg", module_ignore_errors=True)
    found = False
    pattern = re.compile(r'.*Invalid value for "<component_name>"*.')
    for line in out['stderr_lines']:
        if pattern.match(line):
            found = True
            break
    assert found

def test_fwutil_install_bad_path(duthost, fw_pkg, random_component):
    # Test fwutil with bad filepath to firmware
    out = duthost.command("fwutil install chassis component {} fw BAD.pkg".format(random_component), module_ignore_errors=True)
    found = False
    pattern = re.compile(r'.*Error: Invalid value for "<fw_path>"*.')
    for line in out['stderr_lines']:
        if pattern.match(line):
            found = True
            break
    assert found

def test_fwutil_update_current(duthost, localhost, pdu_controller, fw_pkg, random_component):
    assert call_fwutil(duthost,
            localhost,
            pdu_controller,
            fw_pkg, 
            component=random_component)

def test_fwutil_update_next(duthost, localhost, pdu_controller, fw_pkg, random_component, next_image):
    assert call_fwutil(duthost, 
            localhost,
            pdu_controller,
            fw_pkg, 
            component=random_component, 
            next_image=next_image)

def test_fwutil_update_bad_config(duthost, fw_pkg, random_component):
    versions = show_firmware(duthost)
    chassis = versions["chassis"].keys()[0] # Only one chassis

    # Test fwutil update with config file without chassis section
    
    with open("platform_components.json", "w") as f:
        json.dump({}, f, indent=4)
    upload_platform(duthost, {})
    found = False
    out = duthost.command("fwutil update chassis component {} fw -y".format(random_component), module_ignore_errors=True)
    pattern = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid platform schema*.')
    for line in out["stdout_lines"]:
        if pattern.match(line):
            found = True
            break
    assert found

    # Test fwutil update with config file without component section
    with open("platform_components.json", "w") as f:
        json.dump({"chassis":{chassis:{}}}, f, indent=4)
    upload_platform(duthost, {})
    found = False
    out = duthost.command("fwutil update chassis component {} fw -y".format(random_component), module_ignore_errors=True)
    pattern = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid chassis schema*.')
    for line in out["stdout_lines"]:
        if pattern.match(line):
            found = True
            break
    assert found

    # Test fwutil update with config file with version of type dict
    with open("platform_components.json", "w") as f:
        json.dump({"chassis":{chassis:{"component":{random_component:{"version":{"version":"ver"}}}}}}
                , f, indent=4)
    upload_platform(duthost, {})
    found = False
    out = duthost.command("fwutil update chassis component {} fw -y".format(random_component), module_ignore_errors=True)
    pattern = re.compile(r'.*Error: Failed to parse "platform_components.json": invalid component schema*.')
    for line in out["stdout_lines"]:
        if pattern.match(line):
            found = True
            break
    assert found

@pytest.mark.skip(reason="Command not yet merged into sonic-utilites")
@pytest.mark.parametrize("reboot_type", ["none", "warm", "fast", "cold", "power off"])
def test_fwutil_auto(duthost, localhost, pdu_controller, fw_pkg, reboot_type):
    assert call_fwutil(duthost, 
            localhost,
            pdu_controller,
            fw_pkg, 
            reboot=reboot_type)

