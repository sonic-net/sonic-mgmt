#!/usr/bin/env python


from ansible.module_utils.basic import *
from collections import defaultdict

def main():
    module = AnsibleModule(
        argument_spec=dict(
            data=dict(required=False, type='dict', default=None),),
    supports_check_mode=False)

    m_args = module.params
    results = {}
    data = m_args['data']

    data_struct = dict()
    i = 1
    device_type = ""
    for key in data:
        if key == 'eth0':
            continue
        host_ip = data[key]['chassis']['mgmt-ip']

        if host_ip not in data_struct:
            data_struct = {host_ip:{}}
            data_struct[host_ip]['nei_interfaces'] = {}
            data_struct[host_ip]['nei_device_type'] = {}
        if 'Arista' in data[key]['chassis']['descr']:
            device_type = 'Arista'
        elif 'Nexus' in data[key]['chassis']['descr']:
            device_type = 'Nexus'
        interface = data[key]['port']['ifname']
        data_struct[host_ip]['nei_interfaces'][str(i)] = interface
        data_struct[host_ip]['nei_device_type'] = device_type
        i = i + 1

    results['ansible_interface_up_down_data_struct_facts'] = data_struct
    module.exit_json(ansible_facts=results)

main()
