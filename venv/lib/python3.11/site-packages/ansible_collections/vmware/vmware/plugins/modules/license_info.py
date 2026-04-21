#!/usr/bin/python

# Copyright: (c) 2024, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
module: license_info
short_description: Fetch VMware vCenter license keys
description:
- Fetch vCenter, ESXi server license keys.
author:
- Ansible Cloud Team (@ansible-collections)
requirements:
- Python SDK for the VMware vSphere Management API
attributes:
  check_mode:
    description: The check_mode support.
    support: full
extends_documentation_fragment:
- vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Fetch vCenter license
  vmware.vmware.license_info:
    hostname: '{{ vcenter_hostname }}'
    username: '{{ vcenter_username }}'
    password: '{{ vcenter_password }}'
'''

RETURN = r'''
licenses:
    description: List of license keys.
    returned: always
    type: list
    sample:
    - f600d-21ae3-5592b-249e0-cc341
    - 143cc-0e942-b2955-3ea12-d006f
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)


class VcenterLicenseMgr(ModulePyvmomiBase):
    def __init__(self, module):
        super(VcenterLicenseMgr, self).__init__(module)

    def list_keys(self, licenses):
        keys = []
        for item in licenses:
            if item.used is None:
                continue
            keys.append(item.licenseKey)
        return keys


def main():
    module = AnsibleModule(
        argument_spec=base_argument_spec(),
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
    )

    pyv = VcenterLicenseMgr(module)
    if not pyv.is_vcenter():
        module.fail_json(msg="vcenter_license is meant for vCenter, hostname %s "
                             "is not vCenter server." % module.params.get('hostname'))

    lm = pyv.content.licenseManager
    result['licenses'] = pyv.list_keys(lm.licenses)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
