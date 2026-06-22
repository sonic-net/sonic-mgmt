import json
import re
from tests.common.reboot import reboot
from tests.common.utilities import wait_until


# =============================================================================
# Cisco 8000 Constants
# =============================================================================
CISCO_ASIC_TYPE = "cisco-8000"

# Platform prefixes for conditional_mark and other test infrastructure.
CISCO_8122_PREFIX = "x86_64-8122"        # Matches both GR2 (x86_64-8122_*) and GR2X (x86_64-8122x*)
CISCO_8122_GR2_PREFIX = "x86_64-8122_"   # GR2 only (note trailing underscore)
CISCO_8122_GR2X_PREFIX = "x86_64-8122x"  # GR2X only (note 'x' suffix)

# Legacy aliases (kept for backward compatibility)
GR2X_PLATFORM_PREFIX = CISCO_8122_GR2X_PREFIX
GR2X_HWSKU_PREFIX = "Cisco-8122X"


def is_cisco_device(dut):
    return dut.facts["asic_type"] == CISCO_ASIC_TYPE


def is_model_json_format(duthost):
    model_json_platforms = ['x86_64-8102_64h_o-r0']
    return duthost.facts['platform'] in model_json_platforms


def get_markings_config_file(duthost):
    """
        Get the config file where the ECN markings are enabled or disabled.
    """
    if duthost.facts["asic_type"] != CISCO_ASIC_TYPE:
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


def copy_dshell_script_cisco_8000(dut, asic, dshell_script, script_name):
    if dut.facts['asic_type'] != CISCO_ASIC_TYPE:
        raise RuntimeError("This function should have been called only for cisco-8000.")

    script_path = "/tmp/{}".format(script_name)
    dut.copy(content=dshell_script, dest=script_path)
    if dut.sonichost.is_multi_asic:
        dest = f"syncd{asic}"
    else:
        dest = "syncd"
    dut.shell(f"docker cp {script_path} {dest}:/")  # noqa: E231


def copy_set_voq_watchdog_script_cisco_8000(dut, asic="", enable=True):
    dshell_script = '''
from common import d0
def set_voq_watchdog(enable):
    d0.set_bool_property(sdk.la_device_property_e_VOQ_WATCHDOG_ENABLED, enable)
set_voq_watchdog({})
'''.format(enable)

    copy_dshell_script_cisco_8000(dut, asic, dshell_script, script_name="set_voq_watchdog.py")


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


def get_voq_quant_thresholds(duthost, interface, traffic_class):
    """
        Return the quantized VOQ congestion thresholds (in bytes) for a given
        interface and traffic class on a Cisco-8000 device.

        Runs the "show platform npu voq thresholds" serviceability command and
        parses its JSON output, returning the "cong_level_to_bytes" list. These
        are the exact watermark values the hardware will report as queue
        occupancy crosses each successive congestion level.

        Args:
            duthost: The DUT host handle.
            interface (str): The egress interface name (e.g. "Ethernet8").
            traffic_class (int): The traffic class / queue index.

        Returns:
            list[int]: The congestion-level thresholds in bytes, ordered from
                lowest to highest.
    """
    if duthost.facts["asic_type"] != "cisco-8000":
        raise RuntimeError("VOQ quantized thresholds are only available on cisco-8000 platforms.")
    cmd = "show platform npu voq thresholds -i {} -t {} -d".format(interface, traffic_class)
    output = duthost.shell(cmd)["stdout"]
    data = json.loads(output)
    return [int(value) for value in data["cong_level_to_bytes"]]
