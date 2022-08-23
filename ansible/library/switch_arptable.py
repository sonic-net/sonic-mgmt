#!/usr/bin/python

from ansible.module_utils.basic import *
import re

DOCUMENTATION = '''
---
module: switch_arptble
version_added: "1.9"
short description:
    Ansible module to retrieves arp table from SONiC switch
description:
    gathing arp information using "/sbin/ip neigh" command
    parsing the result of the shell command
    return ansible_facts for arptable
        - arptable groups in v4 and v6
        - for each entry:
            key: IP address (either V4 or V6)
            values:
                interface: interface name
                state: STALE | REACHABLE | FAILED | DELAY
                macaddress: 'None'  for failed
                            '00:00:00:01:02:03' for actual learned mac
option:
    None
'''

EXAMPLES = '''
    switch_arptable:
'''

RETURN = '''
return: ansible_facts:
    arptable{
        "v4":{
            "10.10.1.3":{
                "interface": "Ethernet68"
                "state": "STALE"
                "macaddress": "00:00:00:01:02:03"
                },
            "10.10.1.4":
                 "interface": "Ethernet4"
                "state": "REACHABLE"
                "macaddress": "00:85:00:00:0a:70"
            }
        "v6":{
            "fc00::6e": {
                "interface": "Ethernet68"
                "state": "STALE"
                "macaddress": "00:00:00:01:02:03"
                }
             },
    }
 '''

SAMPLE_COMMAND_DATA = '''
fc00::5a dev Ethernet88 lladdr 52:54:00:56:3b:f0 router DELAY
fc00::32 dev Ethernet48 lladdr 52:54:00:f7:42:72 router STALE
fc00::4e dev Ethernet76  FAILED
fe80::5054:ff:fe96:9857 dev Ethernet16 lladdr 52:54:00:96:98:57 router STALE
fc00::52 dev Ethernet80 lladdr 52:54:00:1d:5e:ba router REACHABLE
10.0.0.43 dev Ethernet84 lladdr 52:54:00:34:51:ee REACHABLE
10.0.0.55 dev Ethernet108 lladdr 52:54:00:58:2d:4c REACHABLE
10.0.0.61 dev Ethernet120 lladdr 52:54:00:b2:46:15 REACHABLE
10.0.0.13 dev PortChannel24 lladdr 52:54:00:4e:a8:f4 STALE
'''


def parse_arptable(output):
    v4host = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    v6host = re.compile('[0-9a-fA-F:]+::[0-9a-fA-F:]+')
    v4tbl = dict()
    v6tbl = dict()
    for line in output.split('\n'):
        fields = line.split()
        if len(fields) != 0:
            if v4host.match(fields[0]):
                if len(fields) == 4:
                    v4tbl[fields[0]] = {'interface': fields[2], 'state':fields[3], 'macaddress': 'None'}
                else:
                    v4tbl[fields[0]] = {'interface': fields[2], 'state':fields[-1], 'macaddress': fields[4]}
            if v6host.match(fields[0]):
                if len(fields) == 4:
                    v6tbl[fields[0]] = {'interface': fields[2], 'state':fields[3], 'macaddress': 'None'}
                else:
                    v6tbl[fields[0]] = {'interface': fields[2], 'state':fields[-1], 'macaddress': fields[4]}
    arps = {'v4':v4tbl, 'v6':v6tbl}
    return arps


def main():
    module = AnsibleModule(
        argument_spec=dict(
            namespace=dict(required=False, default=None),
        ),
        supports_check_mode=False)

    m_args = module.params
    try:
        namespace = m_args['namespace']
        if namespace:
            cmd = "sudo ip -n {} neigh".format(namespace)
        else:
            cmd = "ip neigh"
        rt, out, err = module.run_command(cmd)
        if rt != 0:
            module.fail_json(msg="Command 'ip neigh' failed rc=%d, out=%s, err=%s" %(rt, out, err))
            return
        arp_tbl = parse_arptable(out)
        module.exit_json(changed=False, ansible_facts={'arptable':arp_tbl})
    except Exception as e:
        err_msg = "Parse ip neigh table failed! " + str(e)
        module.fail_json(msg=err_msg)

if __name__ == "__main__":
    main()
