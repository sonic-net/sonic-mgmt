import json
import re
from tests.common.reboot import reboot


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
    if is_model_json_format(duthost):
        required_entry = None
        for i in range(len(json_contents['devices'])):
            try:
                 json_contents['devices'][i].get('id')
                 required_entry = i
            except KeyError:
                 continue

        if required_entry is None:
            raise RuntimeError("Couldnot find the required entry(id) in the config file:{}".format(config_file))
        for key in key_list:
            markings_dict[key] = json_contents['devices'][i][key]
    else:
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
    if is_model_json_format(duthost):
        required_entry = None
        for i in range(len(json_contents['devices'])):
            try:
                 json_contents['devices'][i].get('id')
                 required_entry = i
            except KeyError:
                 continue

        if required_entry is None:
            raise RuntimeError("Couldnot find the required entry(id) in the config file:{}".format(config_file))
        for k,v in kwargs.iteritems():
            if json_contents['devices'][required_entry][k] != v:
                reboot_required = True
                json_contents['devices'][required_entry][k] = v
    else:
        for device in json_contents['devices']:
            for k,v in kwargs.iteritems():
                if device['device_property'][k] != v:
                    reboot_required = True
                    device['device_property'][k] = v
    if reboot_required:
        duthost.copy(content=json.dumps(json_contents, sort_keys=True, indent=4), dest=config_file)
        reboot(duthost, localhost)
