#!/usr/bin/env python

from ansible.module_utils.basic import AnsibleModule
import json


DOCUMENTATION = '''
module: gather_sysports.py
Ansible_version_added:  2.0.0.2
short_description:   Gather the system ports info of a SONiC chassis if there are sysports json data files in /tmp
Description:
        System ports info is critical for SONiC VOQ chassis. We need to gather the system ports info from all the devices in the chassis.
        Then this info will be used to generate configuration files for the chassis.
    Input:
        duts

    Return Ansible_facts:
    all_sysports:  SONiC chassis system ports info

'''

EXAMPLES = '''
    - name: get chassis system ports info
      gather_sysports: duts="{{ansible_play_batch}}"
'''

RETURN = '''
      ansible_facts{
        all_sysports: [...]
      }
'''

def main():
    module = AnsibleModule(
        argument_spec=dict(
            duts=dict(required=True, type='list')
        ),
        supports_check_mode=True
    )
    duts = module.params['duts']
    all_sysports = []
    for dut in duts:
        try:
            with open("/tmp/{}_sysports.json".format(dut), 'r') as sysports_file:
                sysports = json.load(sysports_file)
                all_sysports.extend(sysports)
        except (IOError, OSError) as e:
            fail_msg = "IO error" + str(e)
            module.fail_json(msg=fail_msg)
        except Exception as e:
            fail_msg = "failed to find the correct sysports file for {}".format(dut)
            module.fail_json(msg=fail_msg)

    module.exit_json(ansible_facts={'all_sysports': all_sysports})

if __name__ == "__main__":
    main()
