#!/usr/bin/env python
# This ansible module is for gathering basic facts from DUT of specified testbed.
#
# Example output:
try:
    from ansible.module_utils.parse_utils import parse_tabular_output
except ImportError:
    # Add parent dir for using outside Ansible
    import sys
    sys.path.append('..')
    from module_utils.parse_utils import parse_tabular_output

from ansible.module_utils.basic import *


DOCUMENTATION = '''
---
module: dut_basic_facts
author: Xin Wang (xiwang5@microsoft.com)
short_description: Retrive basic facts from DUT.
description:
    - Retrive basic facts from DUT. This module should only be applied to a SONiC device.
options:
    N/A
'''

EXAMPLES = '''
# Gather DUT basic facts
- name: Gathering DUT basic facts
  dut_basic_facts:
'''

from sonic_py_common import device_info


def main():

    module = AnsibleModule(argument_spec=dict(), supports_check_mode=False)

    results = {}

    try:
        results['platform'], results['hwsku'] = device_info.get_platform_and_hwsku()
        results['is_multi_asic'] = device_info.is_multi_npu()
        results['num_asic'] = device_info.get_num_npus()
        results.update(device_info.get_sonic_version_info())
        results['kernel_version'] = results['kernel_version'].split('-')[0]
        results['is_supervisor'] = False
        if hasattr(device_info, 'is_supervisor'):
            results['is_supervisor'] = device_info.is_supervisor()

        # In case a image does not have /etc/sonic/sonic_release, guess release from 'build_version'
        if 'release' not in results or not results['release'] or results['release'] == 'none':
            if 'build_version' in results:
                if '201811' in results['build_version']:
                    results['release'] = '201811'
                elif '201911' in results['build_version']:
                    results['release'] = '201911'
                elif 'master' in results['build_version']:
                    results['release'] = 'master'
                else:
                    results['release'] = 'unknown'

        # get dut feature status
        command_list = ['show feature status', 'show features']
        try:
            for cmd in command_list:
                rc, out, err = module.run_command(cmd, executable='/bin/bash', use_unsafe_shell=True)
                if rc == 0:
                    break
        except Exception as e:
            module.fail_json(msg=str(e))

        result = parse_tabular_output(out.split('\n'))

        results["feature_status"] = {}

        for state in result:
            results["feature_status"][state["feature"]] = state["state"]

        module.exit_json(ansible_facts={'dut_basic_facts': results})
    except Exception as e:
        module.fail_json(msg='Gather DUT facts failed, exception: {}'.format(repr(e)))

if __name__ == '__main__':
    main()
