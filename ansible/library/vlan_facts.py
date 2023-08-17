#!/usr/bin/env python
# This ansible module is for gathering VLAN related facts from SONiC device.

from ansible.module_utils.basic import AnsibleModule
from collections import defaultdict


DOCUMENTATION = '''
---
module: vlan_facts
version_added: "1.0"
author: Bing Wang (bingwang@microsoft.com)
short_description: Retrive VLAN facts from a device.
description:
    - Retrieve VLAN facts for a device, the facts will be
      inserted to the ansible_facts key.
options:
    N/A
'''

EXAMPLES = '''
# Gather VLAN facts
- name: Gathering VLAN facts from the device
  vlan_facts:
  {
      "vlan1000": {
          "name": "vlan1000",
          "vlanid": "1000",
          "members": [
              "Ethernet0": {
                  "tagging_mode": "untagged"
              },
              "Ethernet2": {
                  "tagging_mode": "untagged"
              }
          ],
          "interfaces": [
              {
                "addr": "192.168.0.1",
                "prefixlen": 21
                },
                {
                "prefixlen": 64,
                "addr": "fc02:1000::1",
                }
            ]
      }
  }
'''


def get_all_vlan(module, config):
    """
    @summary:  Read all running vlan with sonic-cfggen.
    @param module: The AnsibleModule object
    @param config: The retrieved vlan config
    @return: None
    """
    rc, stdout, stderr = module.run_command(
        'sonic-cfggen -d --var-json \"VLAN\"')
    if rc != 0:
        module.fail_json(msg='Failed to get DUT running config, rc=%s, stdout=%s, stderr=%s' % (
            rc, stdout, stderr))

    try:
        vlan_config = module.from_json(stdout)
        for k, v in vlan_config.items():
            config[k] = {
                'name': k,
                'vlanid': v['vlanid']
            }
    except Exception as e:
        module.fail_json(
            msg='Failed to parse config from output of "sonic-cfggen -d --var-json VLAN", err=' + str(e))


def get_vlan_interfaces(module, config):
    """
    @summary:  Read all running vlan interface IP with sonic-cfggen.
    @param module: The AnsibleModule object
    @param config: The retrieved vlan config
    @return: None
    """
    rc, stdout, stderr = module.run_command(
        'sonic-cfggen -d --var-json \"VLAN_INTERFACE\"')
    if rc != 0:
        module.fail_json(msg='Failed to get DUT running config, rc=%s, stdout=%s, stderr=%s' % (
            rc, stdout, stderr))

    try:
        vlan_config = module.from_json(stdout)
        for k, v in vlan_config.items():
            vlan_ip = k.split('|')
            if len(vlan_ip) != 2:
                continue
            vlan = vlan_ip[0]
            if 'interfaces' not in config[vlan]:
                config[vlan]['interfaces'] = []
            ip_prefix = vlan_ip[1].split('/')
            config[vlan]['interfaces'].append(
                {
                    "addr": ip_prefix[0],
                    "prefixlen": 32 if len(ip_prefix) < 2 else int(ip_prefix[1])
                }
            )

    except Exception as e:
        module.fail_json(
            msg='Failed to parse config from output of "sonic-cfggen -d --var-json VLAN_INTERFACE", err=' + str(e))


def get_vlan_members(module, config):
    """
    @summary:  Read all running vlan members with sonic-cfggen.
    @param module: The AnsibleModule object
    @param config: The retrieved vlan config
    @return: None
    """
    rc, stdout, stderr = module.run_command(
        'sonic-cfggen -d --var-json \"VLAN_MEMBER\"')
    if rc != 0:
        module.fail_json(msg='Failed to get DUT running config, rc=%s, stdout=%s, stderr=%s' % (
            rc, stdout, stderr))

    try:
        vlan_config = module.from_json(stdout)
        for k, v in vlan_config.items():
            vlan_intf = k.split('|')
            if len(vlan_intf) < 2:
                continue
            if 'members' not in config[vlan_intf[0]]:
                config[vlan_intf[0]]['members'] = {}
            config[vlan_intf[0]]['members'].update(
                {vlan_intf[1]: {"tagging_mode": v['tagging_mode']}}
            )

    except Exception as e:
        module.fail_json(
            msg='Failed to parse config from output of "sonic-cfggen -d --var-json VLAN_MEMBER", err=' + str(e))


def main():

    module = AnsibleModule(argument_spec=dict())

    vlan_config = defaultdict(dict)

    get_all_vlan(module, vlan_config)
    get_vlan_interfaces(module, vlan_config)
    get_vlan_members(module, vlan_config)

    module.exit_json(ansible_facts={'ansible_vlan_facts': vlan_config})


if __name__ == '__main__':
    main()
