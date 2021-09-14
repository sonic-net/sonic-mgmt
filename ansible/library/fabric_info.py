#!/usr/bin/env python

import ipaddress

DOCUMENTATION = '''
module: fabric_info.py
short_description:   Find SONiC Fabric ASIC inforamtion if applicable for the DUT
Description:
        When the testbed has Fabric ASICs, this module helps to collect that information
        which helps in generating the minigraph
    Input:
        num_fabric_asic asics_host_basepfx asics_host_basepfx6

    Return Ansible_facts:
    fabric_info:  SONiC Fabric ASIC information

'''

EXAMPLES = '''
    - name: get Fabric ASIC info
      fabric_info: num_fabric_asic=1 asics_host_basepfx="10.1.0.1/32" asics_host_basepfx="FC00:1::1/128"
'''

RETURN = '''
      ansible_facts{
        fabric_info: [{'asicname': 'ASIC0', 'ip_prefix': '10.1.0.1/32', 'ip6_prefix': 'FC00:1::1/128'},
                      {'asicname': 'ASIC1', 'ip_prefix': '10.1.0.2/32', 'ip6_prefix': 'FC00:1::2/128'}]
      }
'''

def main():
    module = AnsibleModule(
        argument_spec=dict(
            num_fabric_asic=dict(type='str', required=True),
            asics_host_basepfx=dict(type='str', required=False),
            asics_host_basepfx6=dict(type='str', required=False)
        ),
        supports_check_mode=True
    )
    m_args = module.params
    try:
        fabric_info = []
        # num_fabric_asic may not be present for fixed systems which have no Fabric ASIC.
        # Then return empty fabric_info
        if 'num_fabric_asic' not in m_args or int(m_args['num_fabric_asic']) < 1:
           module.exit_json(ansible_facts={'fabric_info': fabric_info})
           return
        num_fabric_asic = int( m_args[ 'num_fabric_asic' ] )
        v4pfx = str( m_args[ 'asics_host_basepfx' ] ).split("/")
        v6pfx = str( m_args[ 'asics_host_basepfx6' ] ).split("/")
        v4base = int( ipaddress.IPv4Address(unicode(v4pfx[0])) )
        v6base = int( ipaddress.IPv6Address(unicode(v6pfx[0])) )
        for asic_id in range(num_fabric_asic):
            key = "ASIC%d" % asic_id
            next_v4addr = str( ipaddress.IPv4Address(v4base + asic_id) )
            next_v6addr = str( ipaddress.IPv6Address(v6base + asic_id) )
            data = { 'asicname': key,
                     'ip_prefix': next_v4addr + "/" + v4pfx[-1],
                     'ip6_prefix': next_v6addr + "/" + v6pfx[-1] }
            fabric_info.append( data )
        module.exit_json(ansible_facts={'fabric_info': fabric_info})
    except (IOError, OSError) as e:
        fail_msg = "IO error" + str(e)
        module.fail_json(msg=fail_msg)
    except Exception as e:
        fail_msg = "failed to find the correct fabric asic info " + str(e)
        module.fail_json(msg=fail_msg)

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
