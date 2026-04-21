#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Red Hat, Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_nic_info
short_description: Retrieve information about one or more oVirt/RHV virtual machine network interfaces
version_added: "1.0.0"
author: "oVirt Developers (@oVirt)"
description:
    - "Retrieve information about one or more oVirt/RHV virtual machine network interfaces."
    - This module was called C(ovirt_nic_facts) before Ansible 2.9, returning C(ansible_facts).
      Note that the M(ovirt.ovirt.ovirt_nic_info) module no longer returns C(ansible_facts)!
notes:
    - "This module returns a variable C(ovirt_nics), which
       contains a list of NICs. You need to register the result with
       the I(register) keyword to use it."
options:
    vm:
        description:
            - "Name of the VM where NIC is attached."
            - You must provide either C(vm) parameter or C(template) parameter.
        type: str
    template:
        description:
            - "Name of the template where NIC is attached."
            - You must provide either C(vm) parameter or C(template) parameter.
        type: str
        version_added: 1.2.0
    name:
        description:
            - "Name of the NIC, can be used as glob expression."
        type: str
    follow:
        description:
            - List of linked entities, which should be fetched along with the main entity.
            - This parameter replaces usage of C(fetch_nested) and C(nested_attributes).
            - "All follow parameters can be found at following url: https://ovirt.github.io/ovirt-engine-api-model/master/#types/nic/links_summary"
        type: list
        version_added: 1.5.0
        elements: str
        aliases: ['follows']
        default: []
extends_documentation_fragment: ovirt.ovirt.ovirt_info
'''

EXAMPLES = '''
# Examples don't contain auth parameter for simplicity,
# look at ovirt_auth module to see how to reuse authentication:

# Gather information about all NICs which names start with C(eth) for VM named C(centos7):
- ovirt.ovirt.ovirt_nic_info:
    vm: centos7
    name: eth*
  register: result
- ansible.builtin.debug:
    msg: "{{ result.ovirt_nics }}"
'''

RETURN = '''
ovirt_nics:
    description: "List of dictionaries describing the network interfaces. NIC attributes are mapped to dictionary keys,
                  all NICs attributes can be found at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/nic."
    returned: On success.
    type: list
'''

import fnmatch
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import (
    check_sdk,
    create_connection,
    get_dict_of_struct,
    ovirt_info_full_argument_spec,
    search_by_name,
)


def main():
    argument_spec = ovirt_info_full_argument_spec(
        vm=dict(default=None),
        template=dict(default=None),
        name=dict(default=None),
    )
    module = AnsibleModule(
        argument_spec,
        required_one_of=[['vm', 'template']],
        supports_check_mode=True,
    )
    check_sdk(module)
    if module.params['fetch_nested'] or module.params['nested_attributes']:
        module.deprecate(
            "The 'fetch_nested' and 'nested_attributes' are deprecated please use 'follow' parameter",
            version='4.0.0',
            collection_name='ovirt.ovirt'
        )

    try:
        auth = module.params.pop('auth')
        connection = create_connection(auth)

        if module.params.get('vm'):
            # Locate the VM, where we will manage NICs:
            entity_name = module.params.get('vm')
            collection_service = connection.system_service().vms_service()
        elif module.params.get('template'):
            entity_name = module.params.get('template')
            collection_service = connection.system_service().templates_service()
        entity = search_by_name(collection_service, entity_name)
        if entity is None:
            raise Exception("VM/Template '%s' was not found." % entity_name)

        nics_service = collection_service.service(entity.id).nics_service()
        if module.params['name']:
            nics = [
                e for e in nics_service.list(follow=",".join(module.params['follow']))
                if fnmatch.fnmatch(e.name, module.params['name'])
            ]
        else:
            nics = nics_service.list(follow=",".join(module.params['follow']))

        result = dict(
            ovirt_nics=[
                get_dict_of_struct(
                    struct=c,
                    connection=connection,
                    fetch_nested=module.params.get('fetch_nested'),
                    attributes=module.params.get('nested_attributes'),
                ) for c in nics
            ],
        )
        module.exit_json(changed=False, **result)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == '__main__':
    main()
