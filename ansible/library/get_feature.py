#!/usr/bin/python
try:
    from ansible.module_utils.parse_utils import parse_tabular_output
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.parse_utils import parse_tabular_output

DOCUMENTATION = '''
module:         get_feature
author:         Yutong Zhang (yutongzhang@microsoft.com)
short_description: Retrieve features status from DUT by 'show feature status' or 'show features' command 
description:
    - Retrieve features status from DUT by 'show feature status' or 'show features' command
    - The retrieved features status will be returned as a dict 
'''

EXAMPLES = '''
- name: Get feature status from DUT
  get_feature:
'''

# Example of the output
'''
The input:
$ show feature status
Feature         State            AutoRestart     SetOwner
--------------  ---------------  --------------  ----------
bgp             enabled          enabled
database        always_enabled   always_enabled

The output:
{
    'bgp': 'enabled',
    'database': 'always_enabled'
}
'''

class FeatureModule(object):
    def __init__(self):
        self.module = AnsibleModule(argument_spec=dict())

    def run(self):
        """
            Main method of the class
        """

        command_list = ['show feature status', 'show features']
        try:
            for cmd in command_list:
                rc, out, err = self.module.run_command(cmd, executable='/bin/bash')
                if rc == 0:
                    break
        except Exception as e:
            self.module.fail_json(msg=str(e))

        ret = {}
        ret["feature_status"] = {}

        for state in result:
            ret["feature_status"][state["feature"]] = state["state"]

        self.module.exit_json(ansible_facts=ret)

def main():
    feature = FeatureModule()
    feature.run()

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
