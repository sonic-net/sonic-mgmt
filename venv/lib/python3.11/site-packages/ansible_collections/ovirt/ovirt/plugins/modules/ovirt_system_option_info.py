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
module: ovirt_system_option_info
short_description: Retrieve information about one oVirt/RHV system options.
version_added: "1.3.0"
author: "oVirt Developers (@oVirt)"
description:
    - "Retrieve information about one oVirt/RHV system options."
notes:
    - "This module returns a variable C(ovirt_system_option_info), which
       contains a dict of system option. You need to register the result with
       the I(register) keyword to use it."
options:
    name:
        description:
            - "Name of system option."
        type: str
    version:
        description:
            - "The version of the option."
        type: str
    follow:
        description:
            - List of linked entities, which should be fetched along with the main entity.
            - This parameter replaces usage of C(fetch_nested) and C(nested_attributes).
            - "All follow parameters can be found at following url: https://ovirt.github.io/ovirt-engine-api-model/master/#types/system_option/links_summary"
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

- ovirt.ovirt.ovirt_system_option_info:
    name: "ServerCPUList"
    version: "4.4"
  register: result
- ansible.builtin.debug:
    msg: "{{ result.ovirt_system_option }}"
'''

RETURN = '''
ovirt_system_option:
    description: "Dictionary describing the system option. Option attributes are mapped to dictionary keys,
                  all option attributes can be found at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/system_option."
    returned: On success.
    type: dict
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import (
    check_sdk,
    create_connection,
    get_dict_of_struct,
    ovirt_info_full_argument_spec,
)


def main():
    argument_spec = ovirt_info_full_argument_spec(
        name=dict(default=None),
        version=dict(default=None),
    )
    module = AnsibleModule(
        argument_spec,
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
        options_service = connection.system_service().options_service()
        option_service = options_service.option_service(module.params.get('name'))

        try:
            option = option_service.get(version=module.params.get('version'))
        except Exception as e:
            if str(e) == "HTTP response code is 404.":
                raise ValueError("Could not find the option with name '{0}'".format(module.params.get('name')))
            raise Exception("Unexpected error: '{0}'".format(e))

        result = dict(
            ovirt_system_option=get_dict_of_struct(
                struct=option,
                connection=connection,
                fetch_nested=module.params.get('fetch_nested'),
                attributes=module.params.get('nested_attributes'),
            ),
        )
        module.exit_json(changed=False, **result)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == '__main__':
    main()
