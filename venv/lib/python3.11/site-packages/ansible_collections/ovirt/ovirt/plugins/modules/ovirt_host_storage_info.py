#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_host_storage_info
short_description: Retrieve information about one or more oVirt/RHV HostStorages (applicable only for block storage)
version_added: "1.0.0"
author: "oVirt Developers (@oVirt)"
description:
    - "Retrieve information about one or more oVirt/RHV HostStorages (applicable only for block storage)."
    - This module was called C(ovirt_host_storage_facts) before Ansible 2.9, returning C(ansible_facts).
      Note that the M(ovirt.ovirt.ovirt_host_storage_info) module no longer returns C(ansible_facts)!
options:
    host:
        description:
            - "Host to get device list from."
        required: true
        type: str
    iscsi:
        description:
            - "Dictionary with values for iSCSI storage type:"
        suboptions:
            address:
                description:
                  - "Address of the iSCSI storage server."
            target:
                description:
                  - "The target IQN for the storage device."
            username:
                description:
                  - "A CHAP user name for logging into a target."
            password:
                description:
                  - "A CHAP password for logging into a target."
            portal:
                description:
                  - "The portal being used to connect with iscsi."
        type: dict
    fcp:
        description:
            - "Dictionary with values for fibre channel storage type:"
        suboptions:
            address:
                description:
                  - "Address of the fibre channel storage server."
            port:
                description:
                  - "Port of the fibre channel storage server."
            lun_id:
                description:
                  - "LUN id."
        type: dict
    follow:
        description:
            - List of linked entities, which should be fetched along with the main entity.
            - This parameter replaces usage of C(fetch_nested) and C(nested_attributes).
            - "All follow parameters can be found at following url: https://ovirt.github.io/ovirt-engine-api-model/master/#types/host_storage/links_summary"
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

# Gather information about HostStorages with specified target and address:
- ovirt.ovirt.ovirt_host_storage_info:
    host: myhost
    iscsi:
      target: iqn.2016-08-09.domain-01:nickname
      address: 10.34.63.204
  register: result
- ansible.builtin.debug:
    msg: "{{ result.ovirt_host_storages }}"

- name: Gather information about all storages
  ovirt.ovirt.ovirt_host_storage_info:
    host: myhost

- name: Gather information about all iscsi storages
  ovirt.ovirt.ovirt_host_storage_info:
    host: myhost
    iscsi: {}

- name: Gather information about all fcp storages
  ovirt.ovirt.ovirt_host_storage_info:
    host: myhost
    fcp: {}
'''

RETURN = '''
ovirt_host_storages:
    description: "List of dictionaries describing the HostStorage. HostStorage attributes are mapped to dictionary keys,
                  all HostStorage attributes can be found at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/host_storage."
    returned: On success.
    type: list
'''

import traceback

try:
    import ovirtsdk4.types as otypes
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import (
    check_sdk,
    create_connection,
    get_dict_of_struct,
    ovirt_info_full_argument_spec,
    get_id_by_name,
)


def _login(host_service, iscsi):
    host_service.iscsi_login(
        iscsi=otypes.IscsiDetails(
            username=iscsi.get('username'),
            password=iscsi.get('password'),
            address=iscsi.get('address'),
            target=iscsi.get('target'),
            portal=iscsi.get('portal')
        ),
    )


def main():
    argument_spec = ovirt_info_full_argument_spec(
        host=dict(required=True),
        iscsi=dict(default=None, type='dict'),
        fcp=dict(default=None, type='dict'),
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

        # Get Host
        hosts_service = connection.system_service().hosts_service()
        host_id = get_id_by_name(hosts_service, module.params['host'])
        host_service = hosts_service.host_service(host_id)

        if module.params.get('iscsi'):
            # Login
            _login(host_service, module.params.get('iscsi'))

        # Get LUNs exposed from the specified target
        host_storages = host_service.storage_service().list(follow=",".join(module.params['follow']))
        if module.params.get('iscsi') is not None:
            host_storages = list(filter(lambda x: x.type == otypes.StorageType.ISCSI, host_storages))
            if 'target' in module.params.get('iscsi'):
                host_storages = list(filter(lambda x: module.params.get('iscsi').get('target') == x.logical_units[0].target, host_storages))
        elif module.params.get('fcp') is not None:
            host_storages = list(filter(lambda x: x.type == otypes.StorageType.FCP, host_storages))

        result = dict(
            ovirt_host_storages=[
                get_dict_of_struct(
                    struct=c,
                    connection=connection,
                    fetch_nested=module.params.get('fetch_nested'),
                    attributes=module.params.get('nested_attributes'),
                ) for c in host_storages
            ],
        )
        module.exit_json(changed=False, **result)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == '__main__':
    main()
