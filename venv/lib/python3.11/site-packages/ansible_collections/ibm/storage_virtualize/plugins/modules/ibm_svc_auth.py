#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_auth
short_description: This module generates an authentication token for a user on IBM Storage Virtualize family system
description:
  - Ansible interface to generate the authentication token.
    The token is used to make REST API calls to the storage system.
version_added: "1.5.0"
options:
  clustername:
    description:
    - The hostname or management IP of the Storage Virtualize system.
    type: str
    required: true
  domain:
    description:
    - Domain for the Storage Virtualize system.
    - Valid when hostname is used for the parameter I(clustername).
    type: str
  username:
    description:
    - REST API username for the Storage Virtualize system.
    - This parameter is required in this module to generate the token.
    type: str
  password:
    description:
    - REST API password for the Storage Virtualize system.
    - This parameter is required in this module to generate the token.
    type: str
  token:
    description:
    - The authentication token to verify a user on the Storage Virtualize system.
    - This field is not required for ibm_svc_auth module.
    type: str
  validate_certs:
    description:
    - Validates certification.
    default: false
    type: bool
  log_path:
    description:
    - Path of debug log file.
    type: str
author:
    - Shilpi Jain(@Shilpi-J)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Obtain an authentication token
  register: result
  ibm.storage_virtualize.ibm_svc_auth:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
- name: Create a volume
  ibm.storage_virtualize.ibm_svc_manage_volume:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    token: "{{ result.token }}"
    name: volume0
    state: present
    pool: Pool0
    size: "4294967296"
    unit: b
'''

RETURN = '''
token:
    description: Authentication token for a user.
    returned: success
    type: str
    version_added: 1.5.0
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCauth(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=None
        )


def main():
    v = IBMSVCauth()
    try:
        if v.restapi.token is not None:
            msg = "Authentication token generated"
            v.module.exit_json(msg=msg, token=v.restapi.token)
        else:
            msg = "Authentication token is not generated"
            v.module.fail_json(msg=msg, token=v.restapi.token)
    except Exception as e:
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
