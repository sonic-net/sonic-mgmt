#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_datacenter
short_description: Module to manage data centers in oVirt/RHV
version_added: "1.0.0"
author: "oVirt Developers (@oVirt)"
description:
    - "Module to manage data centers in oVirt/RHV"
options:
    id:
        description:
            - "ID of the datacenter to manage."
        type: str
    name:
        description:
            - "Name of the data center to manage."
        required: true
        type: str
    state:
        description:
            - "Should the data center be present or absent."
        choices: ['present', 'absent']
        default: present
        type: str
    description:
        description:
            - "Description of the data center."
        type: str
    comment:
        description:
            - "Comment of the data center."
        type: str
    local:
        description:
            - "I(True) if the data center should be local, I(False) if should be shared."
            - "Default value is set by engine."
        type: bool
    compatibility_version:
        description:
            - "Compatibility version of the data center."
        type: str
    quota_mode:
        description:
            - "Quota mode of the data center. One of I(disabled), I(audit) or I(enabled)"
        choices: ['disabled', 'audit', 'enabled']
        type: str
    mac_pool:
        description:
            - "MAC pool to be used by this datacenter."
            - "IMPORTANT: This option is deprecated in oVirt/RHV 4.1. You should
               use C(mac_pool) in C(ovirt_clusters) module, as MAC pools are
               set per cluster since 4.1."
        type: str
    force:
        description:
            - "This parameter can be used only when removing a data center.
              If I(True) data center will be forcibly removed, even though it
              contains some clusters. Default value is I(False), which means
              that only empty data center can be removed."
        type: bool
    iscsi_bonds:
        description:
            - "List of iscsi bonds, which should be created in datacenter."
        suboptions:
            name:
                description:
                    - "Name of the iscsi bond."
                type: str
            networks:
                description:
                    - "List of network names in bond."
                type: list
                elements: str
            storage_domains:
                description:
                    - "List of storage domain names and it will automatically get all storage_connections in the domain."
                type: list
                default: []
                elements: str
            storage_connections:
                description:
                    - "List of storage_connection IDs. Used when you want to use specific storage connection instead of all in storage domain."
                type: list
                default: []
                elements: str
        type: list
        elements: dict

extends_documentation_fragment: ovirt.ovirt.ovirt
'''

EXAMPLES = '''
# Examples don't contain auth parameter for simplicity,
# look at ovirt_auth module to see how to reuse authentication:

# Create datacenter
- ovirt.ovirt.ovirt_datacenter:
    name: mydatacenter
    local: true
    compatibility_version: 4.0
    quota_mode: enabled

# Remove datacenter
- ovirt.ovirt.ovirt_datacenter:
    state: absent
    name: mydatacenter

# Change Datacenter Name
- ovirt.ovirt.ovirt_datacenter:
    id: 00000000-0000-0000-0000-000000000000
    name: "new_datacenter_name"

# Create datacenter with iscsi bond
- ovirt.ovirt.ovirt_datacenter:
    name: mydatacenter
    iscsi_bonds:
      - name: bond1
        networks:
          - network1
          - network2
        storage_domains:
          - storage1
      - name: bond2
        networks:
          - network3
        storage_connections:
          - cf780201-6a4f-43c1-a019-e65c4220ab73

# Remove all iscsi bonds
- ovirt.ovirt.ovirt_datacenter:
    name: mydatacenter
    iscsi_bonds: []
'''

RETURN = '''
id:
    description: "ID of the managed datacenter"
    returned: "On success if datacenter is found."
    type: str
    sample: 7de90f31-222c-436c-a1ca-7e655bd5b60c
data_center:
    description: "Dictionary of all the datacenter attributes. Datacenter attributes can be found on your oVirt/RHV instance
                  at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/datacenter."
    returned: "On success if datacenter is found."
    type: dict
'''

import traceback

try:
    import ovirtsdk4.types as otypes
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ovirt.ovirt.plugins.module_utils.ovirt import (
    BaseModule,
    check_sdk,
    check_params,
    create_connection,
    equal,
    ovirt_full_argument_spec,
    search_by_name,
    get_id_by_name
)


class DatacentersModule(BaseModule):

    def __get_major(self, full_version):
        if full_version is None:
            return None
        if isinstance(full_version, otypes.Version):
            return full_version.major
        return int(full_version.split('.')[0])

    def __get_minor(self, full_version):
        if full_version is None:
            return None
        if isinstance(full_version, otypes.Version):
            return full_version.minor
        return int(full_version.split('.')[1])

    def _get_mac_pool(self):
        mac_pool = None
        if self._module.params.get('mac_pool'):
            mac_pool = search_by_name(
                self._connection.system_service().mac_pools_service(),
                self._module.params.get('mac_pool'),
            )
        return mac_pool

    def build_entity(self):
        return otypes.DataCenter(
            name=self._module.params['name'],
            id=self._module.params['id'],
            comment=self._module.params['comment'],
            description=self._module.params['description'],
            mac_pool=otypes.MacPool(
                id=getattr(self._get_mac_pool(), 'id', None),
            ) if self._module.params.get('mac_pool') else None,
            quota_mode=otypes.QuotaModeType(
                self._module.params['quota_mode']
            ) if self._module.params['quota_mode'] else None,
            local=self._module.params['local'],
            version=otypes.Version(
                major=self.__get_major(self._module.params['compatibility_version']),
                minor=self.__get_minor(self._module.params['compatibility_version']),
            ) if self._module.params['compatibility_version'] else None,
        )

    def update_check(self, entity):
        minor = self.__get_minor(self._module.params.get('compatibility_version'))
        major = self.__get_major(self._module.params.get('compatibility_version'))
        return (
            equal(getattr(self._get_mac_pool(), 'id', None), getattr(entity.mac_pool, 'id', None)) and
            equal(self._module.params.get('comment'), entity.comment) and
            equal(self._module.params.get('description'), entity.description) and
            equal(self._module.params.get('name'), entity.name) and
            equal(self._module.params.get('quota_mode'), str(entity.quota_mode)) and
            equal(self._module.params.get('local'), entity.local) and
            equal(minor, self.__get_minor(entity.version)) and
            equal(major, self.__get_major(entity.version))
        )


def get_storage_connections(iscsi_bond, connection):
    resp = []
    for storage_domain_name in iscsi_bond.get('storage_domains', []):
        storage_domains_service = connection.system_service().storage_domains_service()
        storage_domain = storage_domains_service.storage_domain_service(
            get_id_by_name(storage_domains_service, storage_domain_name)).get()
        resp.extend(connection.follow_link(storage_domain.storage_connections))

    for storage_connection_id in iscsi_bond.get('storage_connections', []):
        resp.append(connection.system_service().storage_connections_service(
        ).storage_connection_service(storage_connection_id).get())
    return resp


def serialize_iscsi_bond(iscsi_bonds):
    return [{"name": bond.name,
             "networks": [net.name for net in bond.networks],
             "storage_connections": [connection.address for connection in bond.storage_connections]} for bond in iscsi_bonds]


def main():
    argument_spec = ovirt_full_argument_spec(
        state=dict(
            choices=['present', 'absent'],
            default='present',
        ),
        name=dict(required=True),
        description=dict(default=None),
        local=dict(type='bool'),
        id=dict(default=None),
        compatibility_version=dict(default=None),
        quota_mode=dict(choices=['disabled', 'audit', 'enabled']),
        comment=dict(default=None),
        mac_pool=dict(default=None),
        force=dict(default=None, type='bool'),
        iscsi_bonds=dict(type='list', default=None, elements='dict'),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    check_sdk(module)
    check_params(module)

    try:
        auth = module.params.pop('auth')
        connection = create_connection(auth)
        data_centers_service = connection.system_service().data_centers_service()
        data_centers_module = DatacentersModule(
            connection=connection,
            module=module,
            service=data_centers_service,
        )

        state = module.params['state']
        if state == 'present':
            ret = data_centers_module.create()
            if module.params.get('iscsi_bonds') is not None:
                iscsi_bonds_service = data_centers_service.data_center_service(
                    ret.get('id')).iscsi_bonds_service()
                before_iscsi_bonds = iscsi_bonds_service.list()
                networks_service = connection.system_service().networks_service()
                # Remove existing bonds
                for bond in iscsi_bonds_service.list():
                    iscsi_bonds_service.iscsi_bond_service(bond.id).remove()
                # Create new bond
                for new_bond in module.params.get('iscsi_bonds'):
                    iscsi_bond = otypes.IscsiBond(
                        name=new_bond.get('name'),
                        data_center=data_centers_service.data_center_service(
                            ret.get('id')).get(),
                        storage_connections=get_storage_connections(
                            new_bond, connection),
                        networks=[search_by_name(networks_service, network_name)
                                  for network_name in new_bond.get('networks')],
                    )
                    iscsi_bonds_service.add(iscsi_bond)
                ret['changed'] = ret['changed'] or serialize_iscsi_bond(
                    before_iscsi_bonds) != serialize_iscsi_bond(iscsi_bonds_service.list())
        elif state == 'absent':
            ret = data_centers_module.remove(force=module.params['force'])

        module.exit_json(**ret)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == "__main__":
    main()
