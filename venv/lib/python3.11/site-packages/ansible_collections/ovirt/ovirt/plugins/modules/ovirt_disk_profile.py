#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_disk_profile
short_description: "Module to manage storage domain disk profiles in ovirt"
author: "oVirt Developers (@oVirt)"
description:
    - "Module to manage storage domain disk profiles in ovirt."
options:
    id:
        description:
            - "ID of the disk profile to manage. Either C(id) or C(name) is required."
        type: str
    name:
        description:
            - "Name of the disk profile to manage. Either C(id) or C(name)/C(alias) is required."
        type: str
    description:
        description:
            - "Description of the disk profile."
        type: str
    comment:
        description:
            - "Comment of the disk profile."
        type: str
    storage_domain:
        description:
            - "Name of the storage domain where the disk profile should be created."
        type: str
    data_center:
        description:
            - "Name of the data center where the qos entry has been created."
        type: str
    qos:
        description:
            - "Name of the QoS entry on the disk profile. If not passed defaults to ovirt HE default"
        type: str
    state:
        description:
            - "Should the disk profile be present/absent."
        choices: ['present', 'absent']
        default: 'present'
        type: str
extends_documentation_fragment: ovirt.ovirt.ovirt
'''

EXAMPLES = '''
- name: Create a new disk profile on storage_domain_01 using the test_qos QoS in the Default datacenter
  ovirt.ovirt.ovirt_disk_profile:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_disk_profile"
    state: "present"
    storage_domain: "storage_domain_01"
    qos: "test_qos"

- name: Create a new disk profile on storage_domain_01 in the Default datacenter using the HE default qos
  ovirt.ovirt.ovirt_disk_profile:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_disk_profile"
    state: "present"
    storage_domain: "storage_domain_01"

- name: Remove the test_qos disk profile
  ovirt.ovirt.ovirt_disk_profile:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_disk_profile"
    state: "absent"
    storage_domain: "storage_domain_01"
    qos: "test_qos"
'''

RETURN = '''
id:
    description: "ID of the managed disk profile"
    returned: "On success if disk profile is found."
    type: str
    sample: 7de90f31-222c-436c-a1ca-7e655bd5b60c
disk_profile:
    description: "Dictionary of all the disk profile attributes. Disk profile attributes can be found on your oVirt/RHV instance
                  at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/disk_profile."
    returned: "On success if disk profile is found."
    type: dict
'''
try:
    import ovirtsdk4.types as otypes
except ImportError:
    pass

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import (
    BaseModule,
    check_sdk,
    create_connection,
    ovirt_full_argument_spec,
    get_id_by_name,
    get_entity
)


class DiskProfileModule(BaseModule):

    def _get_qos(self):
        """
        Gets the QoS entry if exists

        :return: otypes.QoS or None
        """
        dc_name = self._module.params.get('data_center')
        dcs_service = self._connection.system_service().data_centers_service()
        qos_service = dcs_service.data_center_service(get_id_by_name(dcs_service, dc_name)).qoss_service()
        return get_entity(qos_service.qos_service(get_id_by_name(qos_service, self._module.params.get('qos'))))

    def _get_storage_domain(self):
        """
        Gets the storage domain

        :return: otypes.StorageDomain or None
        """
        storage_domain_name = self._module.params.get('storage_domain')
        storage_domains_service = self._connection.system_service().storage_domains_service()
        return get_entity(storage_domains_service.storage_domain_service(get_id_by_name(storage_domains_service, storage_domain_name)))

    def build_entity(self):
        """
        Abstract method from BaseModule called from create() and remove()

        Builds the disk profile from the given params

        :return: otypes.DiskProfile
        """
        qos = self._get_qos()
        storage_domain = self._get_storage_domain()

        if qos is None:
            raise Exception(
                "The qos: {0} does not exist in data center: {1}".format(self._module.params.get('qos'), self._module.params.get('data_center'))
            )
        if storage_domain is None:
            raise Exception(
                "The storage domain: {0} does not exist.".format(self._module.params.get('storage_domain'))
            )
        return otypes.DiskProfile(
            name=self._module.params.get('name') if self._module.params.get('name') else None,
            id=self._module.params.get('id') if self._module.params.get('id') else None,
            comment=self._module.params.get('comment'),
            description=self._module.params.get('description'),
            qos=qos,
            storage_domain=storage_domain,
        )


def main():
    argument_spec = ovirt_full_argument_spec(
        state=dict(
            choices=['present', 'absent'],
            default='present',
        ),
        id=dict(default=None),
        name=dict(default=None),
        comment=dict(default=None),
        storage_domain=dict(default=None),
        data_center=dict(default=None),
        qos=dict(default=None),
        description=dict(default=None)
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[['id', 'name']],
    )

    check_sdk(module)

    try:
        auth = module.params.pop('auth')
        connection = create_connection(auth)

        disk_profiles_service = connection.system_service().disk_profiles_service()

        disk_profile_module = DiskProfileModule(
            connection=connection,
            module=module,
            service=disk_profiles_service,
        )
        state = module.params.get('state')
        if state == 'present':
            ret = disk_profile_module.create()
        elif state == 'absent':
            ret = disk_profile_module.remove()

        module.exit_json(**ret)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == "__main__":
    main()
