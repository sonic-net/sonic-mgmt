#!/usr/bin/env python

from ansible.module_utils.basic import AnsibleModule
import traceback
import re


def set_autoneg(vm_topo_config, hwsku, port_name, autoneg_value):
    if 'autoneg_interfaces' not in vm_topo_config:
        vm_topo_config['autoneg_interfaces'] = {}
    autoneg_interfaces = vm_topo_config['autoneg_interfaces']
    if 'intfs' not in autoneg_interfaces:
        autoneg_interfaces['intfs'] = []
    intfs = autoneg_interfaces['intfs']
    if_index = re.search(r"(\d+)", port_name)
    if_index = int(if_index.group(1))
    if hwsku == "Mellanox-SN5600-C256S1":
        port_id = str(int(if_index / 8 + 1))
        line_id = chr(ord('a') + int(if_index % 8))
        if_index = port_id + line_id
    if autoneg_value == "on":
        if if_index not in intfs:
            intfs.append(if_index)
    elif autoneg_value == "off":
        if if_index in intfs:
            autoneg_interfaces['intfs'] = [i for i in intfs if i != if_index]


def update_autoneg(module, hwsku, vm_topo_config, device_conn):
    for port, attribute in device_conn.items():
        if port in device_conn:
            attribute = device_conn[port]
            if "autoneg" in attribute:
                autoneg_value = attribute["autoneg"]
        if autoneg_value:
            module.warn("Add port %s to autoneg list" % port)
            set_autoneg(vm_topo_config, hwsku, port, autoneg_value)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hwsku=dict(required=True, default=None),
            vm_topo_config=dict(required=True, type=dict),
            device_conn=dict(required=True, type=dict)
        )
    )

    hwsku = module.params['hwsku']
    vm_topo_config = module.params['vm_topo_config']
    device_conn = module.params['device_conn']

    update_autoneg(module, hwsku, vm_topo_config, device_conn)

    try:
        module.exit_json(ansible_facts={'vm_topo_config': vm_topo_config})
    except Exception as detail:
        module.fail_json(msg="ERROR: %s, TRACEBACK: %s" %
                         (repr(detail), traceback.format_exc()))
    module.exit_json(
        ansible_facts=dict()
    )


if __name__ == "__main__":
    main()
