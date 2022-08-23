import json
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
    match = re.search("\-([^-_]+)_", platform)
    if match:
       model = match.group(1)
    else:
       raise RuntimeError("Couldn't get the model from platform:{}".format(platform))
    config_file = "/usr/share/sonic/device/{}/{}/{}.json".format(platform, hwsku, model)
    return config_file

def get_ecn_markings_dut(duthost, key_list=['ecn_dequeue_marking', 'ecn_latency_marking', 'voq_allocation_mode']):
    """
        Get the ecn marking values from the duthost.
    """
    config_file = get_markings_config_file(duthost)
    dest_file = "/tmp/"
    contents = duthost.fetch(src=config_file, dest = dest_file)
    local_file = contents['dest']
    with open(local_file) as fd:
        json_contents = json.load(fd)
    required_entry = None
    for i in range(len(json_contents['devices'])):
        try:
             json_contents['devices'][i].get('id')
             required_entry = i
        except KeyError:
             continue

    if required_entry is None:
        raise RuntimeError("Couldnot find the required entry(id) in the config file:{}".format(config_file))
    original_values = {}
    for key in key_list:
        original_values[key] = json_contents['devices'][i][key]
    return original_values

def setup_ecn_markings_dut(duthost, localhost, **kwargs):
    """
        Setup dequeue or latency depending on arguments.
        Applicable to cisco-8000 Platforms only.
    """
    config_file = get_markings_config_file(duthost)
    dest_file = "/tmp/"
    contents = duthost.fetch(src=config_file, dest = dest_file)
    local_file = contents['dest']
    with open(local_file) as fd:
        json_contents = json.load(fd)
    required_entry = None
    for i in range(len(json_contents['devices'])):
        try:
             json_contents['devices'][i].get('id')
             required_entry = i
        except KeyError:
             continue

    if required_entry is None:
        raise RuntimeError("Couldnot find the required entry(id) in the config file:{}".format(config_file))
    reboot_required = False
    for k,v in kwargs.iteritems():
        if json_contents['devices'][required_entry][k] != v:
            reboot_required = True
            json_contents['devices'][required_entry][k] = v

    if reboot_required:
        duthost.copy(content=json.dumps(json_contents, sort_keys=True, indent=4), dest=config_file)
        reboot(duthost, localhost)
