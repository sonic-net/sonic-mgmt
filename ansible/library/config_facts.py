#!/usr/bin/env python
import json
from collections import defaultdict
from natsort import natsorted

DOCUMENTATION = '''
---
module: config_facts
version_added: "1.0"
author: Mykola Faryma (mykolaf@mellanox.com)
short_description: Retrive configuration facts for a device.
description:
    - Retrieve configuration facts for a device, the facts will be
      inserted to the ansible_facts key.
    - The data can be pulled from redis (running config) or /etc/sonic/config_db.json (persistent config)
options:
    host:
        description:
            - Set to target switch (normally {{inventory_hostname}})
        required: true
    source:
        description:
            - Set to "running" for running config, or "persistent" for persistent config from /etc/sonic/config_db.json
'''

PERSISTENT_CONFIG_PATH = "/etc/sonic/config_db{}.json"
TABLE_NAME_SEPARATOR = '|'

def format_config(json_data):
    """Format config data. 
    Returns:
        Config data in a dictionary form of TABLE, KEY, [ ENTRY ], FV
    Example:
    {
    "VLAN_MEMBER": {
        "Vlan1000|Ethernet2": {
            "tagging_mode": "untagged"
        },
        "Vlan1000|Ethernet4": {
            "tagging_mode": "untagged"
        }
    }
    Is converted into 
     'VLAN_MEMBER': {'Vlan1000': {'Ethernet10': {'tagging_mode': 'untagged'},
                                  'Ethernet12': {'tagging_mode': 'untagged'}
                    }
    """
    res = {}
    for table, item in json_data.items():
        data = {}
        for key, entry in item.items():
            try:
                (key_l1, key_l2)= key.split(TABLE_NAME_SEPARATOR, 1)
                data.setdefault(key_l1, {})[key_l2] = entry
            except ValueError:
                # This is a single level key
                data.setdefault(key, entry)

        res.setdefault(table, data)

    return res


def create_maps(config):
    """ Create a map of SONiC port name to physical port index """
    port_index_map = {}
    port_name_to_alias_map = {}
    port_alias_to_name_map = {}

    if 'PORT' in config:
        port_name_list = config["PORT"].keys()
        port_name_list_sorted = natsorted(port_name_list)

        for idx, val in enumerate(port_name_list_sorted):
            port_index_map[val] = idx

        port_name_to_alias_map = { name : v['alias'] if 'alias' in v else '' for name, v in config["PORT"].iteritems()}

        # Create inverse mapping between port name and alias
        port_alias_to_name_map = {v: k for k, v in port_name_to_alias_map.iteritems()}

    return {
    'port_name_to_alias_map' : port_name_to_alias_map,
    'port_alias_to_name_map' : port_alias_to_name_map,
    'port_index_map' : port_index_map
    }


def get_running_config(module, namespace):
    cmd = "sonic-cfggen -d --print-data"
    if namespace:
        cmd += " -n {}".format(namespace)
    rt, out, err = module.run_command(cmd)
    if rt != 0:
        module.fail_json(msg="Failed to dump running config! {}".format(err))
    json_info = json.loads(out)
    return json_info


def get_facts(config):
    """ Create the facts dict """

    Tree = lambda: defaultdict(Tree)

    results = Tree()

    results.update(format_config(config))

    results.update(create_maps(config))

    return results

def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            source=dict(required=True, choices=["running", "persistent"]),
            filename=dict(),
            namespace=dict(default=None),
        ),
        supports_check_mode=True
    )

    m_args = module.params
    try:
        config = {}
        namespace = m_args['namespace']
        if m_args["source"] == "persistent":
            if 'filename' in m_args and m_args['filename'] is not None:
                cfg_file_path = "%s" % m_args['filename']
            else:
                if namespace is not None:
                    asic_index = namespace.split("asic")[1]
                    cfg_file_path = PERSISTENT_CONFIG_PATH.format(asic_index)
                else:
                    cfg_file_path = PERSISTENT_CONFIG_PATH.format("")
            with open(cfg_file_path, "r") as f:
                config = json.load(f)
        elif m_args["source"] == "running":    
            config = get_running_config(module, namespace)
        results = get_facts(config)
        module.exit_json(ansible_facts=results)
    except Exception as e:
        module.fail_json(msg=e.message)


from ansible.module_utils.basic import AnsibleModule

if __name__ == "__main__":
    main()
