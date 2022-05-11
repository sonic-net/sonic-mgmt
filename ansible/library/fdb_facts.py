#!/usr/bin/python

DOCUMENTATION = '''
module:         fdb_facts
version_added:  "1.0"
short_description: Retrieve fdb from DUT by 'show mac' command
description:
    - Retrieve fdb from DUT by 'show mac' command
    - The retrieved MAC will be returned as a dict
'''

EXAMPLES = '''
- name: Get fdb facts from DUT
  fdb_facts:
'''

# Example of the output
'''
The input:
$ fdbshow 
  No.    Vlan  MacAddress         Port        Type
-----  ------  -----------------  ----------  -------
    1    1000  24:8A:07:4C:F5:06  Ethernet24  Dynamic

The output:
{
    '24:8A:07:4C:F5:06': 
        [
            {
                'vlan': '1000',
                'type': 'Dynamic',
                'port': 'Ethernet24'
            }
        ]
}

'''

class FdbModule(object):
    def __init__(self):
        self.module = AnsibleModule(argument_spec=dict())

    def run(self):
        """
            Main method of the class
        """
        cmd = 'show mac'
        try:
            rc, out, err = self.module.run_command(cmd, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(msg=str(e))

        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, self.out, err))
        ret = {}
        # Parse output of 'show mac'
        for line in out.split('\n'):
            d = line.split()
            if len(d) != 5:
                continue
            # Skip if the first column is not a number
            if not d[0].strip().isdigit():
                continue
            mac = d[2].strip()
            val = {
                    'vlan': int(d[1].strip()) if d[1] != "" else 0,
                    'port': d[3].strip(),
                    'type': d[4].strip()
                }
            ret[mac] = ret.get(mac, [])
            ret[mac].append(val)

        self.module.exit_json(ansible_facts=ret)

def main():
    bgp = FdbModule()
    bgp.run()

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()

