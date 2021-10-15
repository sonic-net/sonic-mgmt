#!/usr/bin/python
import subprocess
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module: sonic_release
version_added: "0.1"
author: Ashok Daparthi (ashok.daparthi@dell.com)
short_description: Retrive os release facts from device
description:
    - Retrieve sonic release facts for a device, the facts will be
      inserted to the ansible_facts key.
'''

EXAMPLES = '''
# Gather sonic release facts
 - name: Gather sonic release
   sonic_release:

'''
def main():

    module = AnsibleModule(argument_spec=dict())
    """
    Gets the SONiC OS version that is running on this device.
    """
    sonic_release = None
    sonic_qos_db_fv_reference_with_table = false
    try:
        process = subprocess.Popen(['sonic-cfggen', '-y', '/etc/sonic/sonic_version.yml', '-v', 'release'],
                stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        self.stdout, stderr = process.communicate()
        ret_code = process.returncode
    except Exception as e:
        module.fail_json(msg=str(e))
    else:
        if ret_code != 0:
             module.fail_json(msg=stderr)
        else:
             sonic_release = self.stdout.split('.')[0].strip()
    """
    Check for QOS DB format for Field Value refered with tables or not.
    """
    old_format_release_list = ["201811", "201911", "202012", "202106"]
    if any(release == sonic_release for release in old_format_release_list):
        sonic_qos_db_fv_reference_with_table = true

    module.exit_json(ansible_facts={'sonic_release': sonic_release, 'sonic_qos_db_fv_reference_with_table': sonic_qos_db_fv_reference_with_table})

if __name__ == '__main__':
    main()
