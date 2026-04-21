#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: ovirt_qos
short_description: "Module to manage QoS entries in ovirt"
author: "oVirt Developers (@oVirt)"
description:
    - "Module to manage QoS entries in ovirt."
    - "Doesn't support updating a QoS that exists"
    - "Only works with storage QoS entries atm"
options:
    id:
        description:
            - "ID of the QoS to manage. Either C(id) or C(name) is required."
        type: str
    name:
        description:
            - "Name of QoS to manage. Either C(id) or C(name)/C(alias) is required."
        type: str
    description:
        description:
            - "Description of the QoS."
        type: str
    data_center:
        description:
            - "Name of the data center where the QoS entry should be created."
        type: str
    max_iops:
        description:
            - "The max number of read/write iops. If passed you can't pass a value for C(read_iops) or C(write_iops)"
            - "If no value is given it will default to the HE value, assuming C(read_iops) or C(write_iops) hasn't been set"
        type: int
    write_iops:
        description:
            - "The max number of write iops. If passed you can't pass a value for C(max_iops)"
            - "If no value is given it will default to the HE value, assuming C(max_iops) hasn't been set"
        type: int
    read_iops:
        description:
            - "The max number of read iops. If passed you can't pass a value for C(max_iops)"
            - "If no value is given it will default to the HE value, assuming C(max_iops) hasn't been set"
        type: int
    max_throughput:
        description:
            - "The max number of read/write throughput. If passed you can't pass a value for C(read_throughput) or C(write_throughput)"
            - "If no value is given it will default to the HE value, assuming C(read_throughput) or C(write_throughput) hasn't been set"
        type: int
    write_throughput:
        description:
            - "The max number of write throughput. If passed you can't pass a value for C(max_throughput)"
            - "If no value is given it will default to the HE value, assuming C(max_throughput) hasn't been set"
        type: int
    read_throughput:
        description:
            - "The max number of read throughput. If passed you can't pass a value for C(max_throughput)"
            - "If no value is given it will default to the HE value, assuming C(max_throughput) hasn't been set"
        type: int
    cpu_limit:
        description:
            - "The maximum processing capability in %."
            - "Used to configure computing resources."
        type: int
    inbound_average:
        description:
            - "The desired average inbound bit rate in Mbps (Megabits per sec)."
            - "Used to configure virtual machines networks. If defined, C(inbound_peak) and C(inbound_burst) also has to be set."
            - "See link:https://libvirt.org/formatnetwork.html#elementQoS[Libvirt-QOS] for further details."
        type: int
    inbound_peak:
        description:
            - "The maximum inbound rate in Mbps (Megabits per sec)."
            - "Used to configure virtual machines networks. If defined, C(inbound_average) and C(inbound_burst) also has to be set."
            - "See link:https://libvirt.org/formatnetwork.html#elementQoS[Libvirt-QOS] for further details."
        type: int
    inbound_burst:
        description:
            - "The amount of data that can be delivered in a single burst, in MB."
            - "Used to configure virtual machine networks. If defined, C(inbound_average) and C(inbound_peak) must also be set."
            - "See link:https://libvirt.org/formatnetwork.html#elementQoS[Libvirt-QOS] for further details."
        type: int
    outbound_average:
        description:
            - "The desired average outbound bit rate in Mbps (Megabits per sec)."
            - "Used to configure virtual machines networks. If defined, C(outbound_peak) and C(outbound_burst) also has to be set."
            - "See link:https://libvirt.org/formatnetwork.html#elementQoS[Libvirt-QOS] for further details."
        type: int
    outbound_peak:
        description:
            - "The maximum outbound rate in Mbps (Megabits per sec)."
            - "Used to configure virtual machines networks. If defined, C(outbound_average) and C(outbound_burst) also has to be set."
            - "See link:https://libvirt.org/formatnetwork.html#elementQoS[Libvirt-QOS] for further details."
        type: int
    outbound_burst:
        description:
            - "The amount of data that can be sent in a single burst, in MB."
            - "Used to configure virtual machine networks. If defined, C(outbound_average) and C(outbound_peak) must also be set."
            - "See link:https://libvirt.org/formatnetwork.html#elementQoS[Libvirt-QOS] for further details."
        type: int
    outbound_average_linkshare:
        description:
            - "Weighted share."
            - "Used to configure host networks. Signifies how much of the logical link's capacity a specific network should be
              allocated, relative to the other networks attached to the same logical link. The exact share depends on the sum
              of shares of all networks on that link. By default this is a number in the range 1-100."
        type: int
    outbound_average_upperlimit:
        description:
            - "The maximum bandwidth to be used by a network in Mbps (Megabits per sec)."
            - "Used to configure host networks. If C(outboundAverageUpperlimit) and
              C(outbound_average_realtime) are provided, the C(outbound_averageUpperlimit) must not be lower than the C(outbound_average_realtime)."
        type: int
    outbound_average_realtime:
        description:
            - "The committed rate in Mbps (Megabits per sec)."
            - "Used to configure host networks. The minimum bandwidth required by a network. The committed rate requested is not
               guaranteed and will vary depending on the network infrastructure and the committed rate requested by other
               networks on the same logical link."
        type: int
    type:
        description:
            - "The type of QoS."
        choices: ['storage', 'cpu', 'network', 'hostnetwork']
        type: str
    state:
        description:
            - "Should the QoS be present/absent."
        choices: ['present', 'absent']
        default: 'present'
        type: str
extends_documentation_fragment: ovirt.ovirt.ovirt
'''

EXAMPLES = '''
- name: Create a new storage QoS with default values for max_iops and max_throughput
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_qos_01"
    state: "present"
    type: "storage"

- name: Create a new storage QoS with default values for max_iops and read_throughput but 100 for write throughput
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_qos_01"
    state: "present"
    type: "storage"
    write_throughput: 100

- name: Create a new storage QoS with default values for write_iops and max_throughput but 100 for read iops
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_qos_01"
    state: "present"
    type: "storage"
    read_iops: 100

- name: Create a new storage QoS with 100 max_iops and 200 max_throughput
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_qos_01"
    state: "present"
    type: "storage"
    max_iops: 100
    max_throughput: 100

- name: Remove a storage QoS
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    data_center: "Default"
    name: "test_qos_01"
    state: "absent"
    type: "storage"

- name: Add a network QoS
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    name: "myqos"
    data_center: "Default"
    state: "present"
    type: "network"
    inbound_average: 10
    inbound_peak: 10
    inbound_burst: 10
    outbound_average: 10
    outbound_peak: 10
    outbound_burst: 10

- name: Add a hostnetwork QoS
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    name: "myqos"
    data_center: "Default"
    state: "present"
    type: "hostnetwork"
    outbound_average_linkshare: 10
    outbound_average_upperlimit: 100
    outbound_average_realtime: 50

- name: Add a hostnetwork QoS
  ovirt.ovirt.ovirt_qos:
    auth: "{{ ovirt_auth }}"
    name: "myqos"
    data_center: "Default"
    state: "present"
    type: "cpu"
    cpu_limit: 10
'''

RETURN = '''
id:
    description: "ID of the managed QoS"
    returned: "On success if QoS is found."
    type: str
    sample: 7de90f31-222c-436c-a1ca-7e655bd5b60c
qos:
    description: "Dictionary of all the QoS attributes. QoS attributes can be found on your ovirt instance
                  at following url: http://ovirt.github.io/ovirt-engine-api-model/master/#types/qos."
    returned: "On success if QoS is found."
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
    get_id_by_name
)


class QosModule(BaseModule):

    def _get_qos_type(self, type):
        if type == 'storage':
            return otypes.QosType.STORAGE
        elif type == 'network':
            return otypes.QosType.NETWORK
        elif type == 'hostnetwork':
            return otypes.QosType.HOSTNETWORK
        elif type == 'cpu':
            return otypes.QosType.CPU
        return None

    def build_entity(self):
        """
        Abstract method from BaseModule called from create() and remove()

        Builds the QoS from the given params

        :return: otypes.QoS
        """
        return otypes.Qos(
            name=self.param('name'),
            id=self.param('id'),
            type=self._get_qos_type(self.param('type')),
            description=self.param('description'),
            max_iops=self.param('max_iops'),
            max_read_iops=self.param('read_iops'),
            max_read_throughput=self.param('read_throughput'),
            max_throughput=self.param('max_throughput'),
            max_write_iops=self.param('write_iops'),
            cpu_limit=self.param('cpu_limit'),
            inbound_average=self.param('inbound_average'),
            inbound_peak=self.param('inbound_peak'),
            inbound_burst=self.param('inbound_burst'),
            outbound_average=self.param('outbound_average'),
            outbound_peak=self.param('outbound_peak'),
            outbound_burst=self.param('outbound_burst'),
            outbound_average_linkshare=self.param('outbound_average_linkshare'),
            outbound_average_upperlimit=self.param('outbound_average_upperlimit'),
            outbound_average_realtime=self.param('outbound_average_realtime'),
        )


def _get_qoss_service(connection, dc_name):
    """
    Gets the qoss_service from the data_center provided

    :returns: ovirt.services.QossService or None
    """
    dcs_service = connection.system_service().data_centers_service()
    return dcs_service.data_center_service(get_id_by_name(dcs_service, dc_name)).qoss_service()


def main():
    argument_spec = ovirt_full_argument_spec(
        state=dict(
            choices=['present', 'absent'],
            default='present',
        ),
        id=dict(default=None),
        name=dict(default=None),
        description=dict(default=None),
        data_center=dict(default=None),
        max_iops=dict(default=None, type='int'),
        read_iops=dict(default=None, type='int'),
        write_iops=dict(default=None, type='int'),
        max_throughput=dict(default=None, type='int'),
        read_throughput=dict(default=None, type='int'),
        write_throughput=dict(default=None, type='int'),
        cpu_limit=dict(default=None, type='int'),
        inbound_average=dict(default=None, type='int'),
        inbound_peak=dict(default=None, type='int'),
        inbound_burst=dict(default=None, type='int'),
        outbound_average=dict(default=None, type='int'),
        outbound_peak=dict(default=None, type='int'),
        outbound_burst=dict(default=None, type='int'),
        outbound_average_linkshare=dict(default=None, type='int'),
        outbound_average_upperlimit=dict(default=None, type='int'),
        outbound_average_realtime=dict(default=None, type='int'),
        type=dict(
            choices=['storage', 'cpu', 'network', 'hostnetwork'],
            default=None,
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[['id', 'name']],
        mutually_exclusive=[
            ['max_iops', 'read_iops'],
            ['max_iops', 'write_iops'],
            ['max_throughput', 'read_throughput'],
            ['max_throughput', 'write_throughput']
        ],
        required_together=[
            ['inbound_average', 'inbound_peak', 'inbound_burst'],
            ['outbound_average', 'outbound_peak', 'outbound_burst'],
        ]
    )

    check_sdk(module)

    try:
        auth = module.params.pop('auth')
        connection = create_connection(auth)
        qoss_service = _get_qoss_service(connection, module.params.get('data_center'))

        qos_module = QosModule(
            connection=connection,
            module=module,
            service=qoss_service,
        )

        if module.params.get('state') == 'present':
            ret = qos_module.create()
        elif module.params.get('state') == 'absent':
            ret = qos_module.remove()

        module.exit_json(**ret)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())
    finally:
        connection.close(logout=auth.get('token') is None)


if __name__ == "__main__":
    main()
