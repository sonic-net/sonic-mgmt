import json
import re
from tests.common.reboot import reboot


def is_cisco_device(dut):
    return dut.facts["asic_type"] == "cisco-8000"


def get_markings_config_file(duthost):
    """
        Get the config file where the ECN markings are enabled or disabled.
    """
    platform = duthost.facts['platform']
    if platform != 'x86_64-8102_64h_o-r0':
        raise RuntimeError("This is applicable only to cisco platforms.")

    hwsku = duthost.facts['hwsku']
    match = re.search(r"\-([^-_]+)_", platform)
    if match:
        model = match.group(1)
    else:
        raise RuntimeError("Couldn't get the model from platform:{}".format(platform))
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
        for k,v in kwargs.iteritems():
            if device['device_property'][k] != v:
                reboot_required = True
                device['device_property'][k] = v
    if reboot_required:
        duthost.copy(content=json.dumps(json_contents, sort_keys=True, indent=4), dest=config_file)
        reboot(duthost, localhost)
