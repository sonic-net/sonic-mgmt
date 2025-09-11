import json
import re
from tests.common.reboot import reboot
from tests.common.utilities import wait_until


def is_cisco_device(dut):
    return dut.facts["asic_type"] == "cisco-8000"


def is_model_json_format(duthost):
    model_json_platforms = ['x86_64-8102_64h_o-r0']
    return duthost.facts['platform'] in model_json_platforms


def get_markings_config_file(duthost):
    """
        Get the config file where the ECN markings are enabled or disabled.
    """
    if duthost.facts["asic_type"] != "cisco-8000":
        raise RuntimeError("This is applicable only to cisco platforms.")
    platform = duthost.facts['platform']
    hwsku = duthost.facts['hwsku']
    if is_model_json_format(duthost):
        match = re.search(r"\-([^-_]+)_", platform)
        if match:
            model = match.group(1)
        else:
            raise RuntimeError("Couldn't get the model from platform:{}".format(platform))
    else:
        model = "serdes"
    config_file = "/usr/share/sonic/device/{}/{}/{}.json".format(platform, hwsku, model)
    return config_file


def get_markings_dut(duthost, key_list=['ecn_dequeue_marking', 'ecn_latency_marking', 'voq_allocation_mode']):
    """
        Get the ecn marking values from the duthost.
    """
    config_file = get_markings_config_file(duthost)
    dest_file = "/tmp/"
    contents = duthost.fetch(src=config_file, dest=dest_file)
    local_file = contents['dest']
    with open(local_file) as fd:
        json_contents = json.load(fd)
    markings_dict = {}
    # Getting markings from first device.
    device = json_contents['devices'][0]
    for key in key_list:
        markings_dict[key] = device['device_property'][key]
    return markings_dict


def setup_markings_dut(duthost, localhost, **kwargs):
    """
        Setup dequeue or latency depending on arguments.
        Applicable to cisco-8000 Platforms only.
    """
    config_file = get_markings_config_file(duthost)
    dest_file = "/tmp/"
    contents = duthost.fetch(src=config_file, dest=dest_file)
    local_file = contents['dest']
    with open(local_file) as fd:
        json_contents = json.load(fd)
    reboot_required = False
    for device in json_contents['devices']:
        for k, v in list(kwargs.items()):
            if device['device_property'][k] != v:
                reboot_required = True
                device['device_property'][k] = v
    if reboot_required:
        duthost.copy(content=json.dumps(json_contents, sort_keys=True, indent=4), dest=config_file)
        reboot(duthost, localhost)


def check_dshell_ready(duthost):
    show_command = "sudo show platform npu rx cgm_global"
    err_msg = "debug shell server for asic 0 is not running"
    output = duthost.command(show_command)['stdout']
    if err_msg in output:
        return False
    return True


def run_dshell_command(duthost, command):
    if not wait_until(300, 20, 0, check_dshell_ready, duthost):
        raise RuntimeError("Debug shell is not ready on {}".format(duthost.hostname))
    return duthost.shell(command)


def copy_dshell_script_cisco_8000(dut, asic, dshell_script, script_name):
    if dut.facts['asic_type'] != "cisco-8000":
        raise RuntimeError("This function should have been called only for cisco-8000.")

    script_path = "/tmp/{}".format(script_name)
    dut.copy(content=dshell_script, dest=script_path)
    if dut.sonichost.is_multi_asic:
        dest = f"syncd{asic}"
    else:
        dest = "syncd"
    dut.docker_copy_to_all_asics(
        container_name=dest,
        src=script_path,
        dst="/")


def copy_set_voq_watchdog_script_cisco_8000(dut, asic="", enable=True):
    dshell_script = '''
from common import d0
def set_voq_watchdog(enable):
    d0.set_bool_property(sdk.la_device_property_e_VOQ_WATCHDOG_ENABLED, enable)
set_voq_watchdog({})
'''.format(enable)

    copy_dshell_script_cisco_8000(dut, asic, dshell_script, script_name="set_voq_watchdog.py")
