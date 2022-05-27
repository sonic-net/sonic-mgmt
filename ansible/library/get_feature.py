#!/usr/bin/python

DOCUMENTATION = '''
module:         get_feature
version_added:  "1.0"
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
        for cmd in command_list:
            try:
                rc, out, err = self.module.run_command(cmd, executable='/bin/bash', use_unsafe_shell=True)
            except Exception as e:
                self.module.fail_json(msg=str(e))

            if rc != 0:
                self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" % (rc, self.out, err))
            else:
                break

        ret = {}
        ret["feature_status"] = {}
        # Parse output of 'show feature status' or 'show features'
        for line in out.split('\n')[2:]:
            d = line.split()
            if len(d) < 2:
                continue
            feature = d[0].strip()
            ret["feature_status"][feature] = ret.get(feature, "")
            ret["feature_status"][feature] = d[1].strip()

        self.module.exit_json(ansible_facts=ret)

def main():
    feature = FeatureModule()
    feature.run()

from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()





