import json
from tests.common.reboot import reboot

def is_cisco_device(dut):
    return dut.facts["asic_type"] == "cisco-8000"

def get_markings_config_file(duthost):
    """
        Get the config file where the ECN markings are enabled or disabled.
    """
    asic_type = duthost.facts['asic_type']
    if asic_type != "cisco-8000":
        raise RuntimeError("This is applicable only to cisco platforms.")

    platform = duthost.facts['platform']
    hwsku = duthost.facts['hwsku']
    match = re.search("\-([^-_]+)_", platform)
    if match:
       model = match.group(1)
    else:
       raise RuntimeError("Couldn't get the model from platform:{}".format(platform))
    config_files = []
    if platform in ['x86_64-88_lc0_36fh_mo-r0']:
        for asic in [0, 1, 2]:
            config_files.append("/usr/share/sonic/device/{}/{}/{}/silicon_one.json".format(platform, hwsku, asic))
    else:
        config_files.append("/usr/share/sonic/device/{}/{}/{}.json".format(platform, hwsku, model))
    return config_files

def get_markings_dut(duthost, key_list=['ecn_dequeue_marking', 'ecn_latency_marking', 'voq_allocation_mode']):
    """
        Get the ecn marking values from the duthost.
    """
    config_files = get_markings_config_file(duthost)
    if len(config_files) == 1:

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

    else:
        original_values = {}
        asic_index = 0
        for config_file in config_files:
            str_asic_index = str(asic_index)
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

            original_values[str_asic_index] = {}
            for key in key_list:
                original_values[str_asic_index][key] = json_contents['devices'][required_entry]['device_property'][key]
            asic_index += 1
    return original_values

def setup_markings_dut(duthost, localhost, **kwargs):
    """
        Setup dequeue or latency depending on arguments.
        Applicable to cisco-8000 Platforms only.
    """
    config_files = get_markings_config_file(duthost)
    if len(config_files) == 1:
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
    else:
        asic_index = 0
        for config_file in config_files:
            str_asic_index = str(asic_index)
            dest_file = "/tmp/"
            contents = duthost.fetch(src=config_file, dest = dest_file)
            local_file = contents['dest']
            with open(local_file) as fd:
                json_contents[str_asic_index] = json.load(fd)
            required_entry = None
            for i in range(len(json_contents[str_asic_index]['devices'])):
                try:
                     json_contents[str_asic_index]['devices'][i].get('id')
                     required_entry = i
                except KeyError:
                     continue

            if required_entry is None:
                raise RuntimeError("Couldnot find the required entry(id) in the config file:{}".format(config_file))
            reboot_required = False
            for k,v in kwargs.iteritems():
                if json_contents[str_asic_index]['devices'][required_entry]['device_property'][k] != v:
                    reboot_required = True
                    json_contents[str_asic_index]['devices'][required_entry]['device_property'][k] = v
    
        if reboot_required:
            index = 0
            for _ in keys(json_contents): 
                str_index = str(index)
                duthost.copy(content=json.dumps(json_contents[str_index], sort_keys=True, indent=4), dest=config_file[index])
                index+=1
            reboot(duthost, localhost)
