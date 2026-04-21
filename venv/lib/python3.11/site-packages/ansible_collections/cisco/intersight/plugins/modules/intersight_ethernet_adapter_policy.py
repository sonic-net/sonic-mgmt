#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: intersight_ethernet_adapter_policy
short_description: Ethernet Adapter Policy configuration for Cisco Intersight
description:
  - Manages Ethernet Adapter Policy configuration on Cisco Intersight.
  - Configure virtual ethernet interface settings including advanced features like RDMA, QoS, and offload capabilities.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/EthAdapterPolicy/get/).
extends_documentation_fragment: intersight
options:
  state:
    description:
      - If C(present), will verify the resource is present and will create if needed.
      - If C(absent), will verify the resource is absent and will delete if needed.
    type: str
    choices: [present, absent]
    default: present
  organization:
    description:
      - The name of the Organization this resource is assigned to.
      - Profiles, Policies, and Pools that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Ethernet Adapter Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Ethernet Adapter Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  vxlan_enabled:
    description:
      - Status of the Virtual Extensible LAN Protocol on the virtual ethernet interface.
    type: bool
    default: false
  nvgre_enabled:
    description:
      - Status of the Network Virtualization using Generic Routing Encapsulation on the virtual ethernet interface.
    type: bool
    default: false
  arfs_enabled:
    description:
      - Status of Accelerated Receive Flow Steering on the virtual ethernet interface.
    type: bool
    default: false
  ptp_enabled:
    description:
      - Status of Precision Time Protocol (PTP) on the virtual ethernet interface.
      - PTP can be enabled only on one vNIC on an adapter.
    type: bool
    default: false
  advanced_filter:
    description:
      - Enables advanced filtering on the interface.
    type: bool
    default: false
  interrupt_scaling:
    description:
      - Enables Interrupt Scaling on the interface.
    type: bool
    default: false
  geneve_enabled:
    description:
      - GENEVE offload protocol allows you to create logical networks that span physical network boundaries.
      - Cannot be enabled simultaneously with ARFS.
    type: bool
    default: false
  etherchannel_pinning_enabled:
    description:
      - Enables EtherChannel Pinning to combine multiple physical links between two network switches into a single logical link.
      - Transmit Queue Count should be at least 2 to enable ether channel pinning.
    type: bool
    default: false
  roce_enabled:
    description:
      - If enabled sets RDMA over Converged Ethernet (RoCE) on this virtual interface.
      - Cannot be enabled simultaneously with NVGRE.
    type: bool
    default: false
  roce_queue_pairs:
    description:
      - The number of queue pairs per adapter. Recommended value = integer power of 2.
      - Only applicable when roce_enabled is true.
    type: int
    default: 256
  roce_memory_regions:
    description:
      - The number of memory regions per adapter. Recommended value = integer power of 2.
      - Only applicable when roce_enabled is true.
    type: int
    default: 131072
  roce_resource_groups:
    description:
      - The number of resource groups per adapter. Recommended value = be an integer power of 2 greater than or equal to the number of CPU cores.
      - Only applicable when roce_enabled is true.
    type: int
    default: 2
  roce_version:
    description:
      - Configure RDMA over Converged Ethernet (RoCE) version on the virtual interface.
      - Only RoCEv1 is supported on Cisco VIC 13xx series adapters and only RoCEv2 is supported on Cisco VIC 14xx series adapters.
      - Only applicable when roce_enabled is true.
    type: int
    choices: [1, 2]
    default: 1
  roce_class_of_service:
    description:
      - The Class of Service for RoCE on this virtual interface.
      - Only applicable when roce_enabled is true.
    type: int
    choices: [1, 2, 4, 5, 6]
    default: 5
  interrupt_count:
    description:
      - The number of interrupt resources to allocate. Typical value is be equal to the number of completion queue resources.
    type: int
    default: 8
  interrupt_mode:
    description:
      - Preferred driver interrupt mode.
      - MSIx - Message Signaled Interrupts (MSI) with the optional extension (recommended).
      - MSI - MSI only.
      - INTx - PCI INTx interrupts.
    type: str
    choices: ['MSIx', 'MSI', 'INTx']
    default: 'MSIx'
  interrupt_coalescing_time:
    description:
      - The time to wait between interrupts or the idle period that must be encountered before an interrupt is sent.
      - To turn off interrupt coalescing, enter 0 (zero) in this field.
    type: int
    default: 125
  interrupt_coalescing_type:
    description:
      - Interrupt Coalescing Type.
      - MIN - The system waits for the time specified in the Coalescing Time field before sending another interrupt event.
      - IDLE - The system does not send an interrupt until there is a period of no activity
        lasting at least as long as the time specified in the Coalescing Time field.
    type: str
    choices: ['MIN', 'IDLE']
    default: 'MIN'
  rx_queue_count:
    description:
      - The number of receive queue resources to allocate.
    type: int
    default: 4
  rx_ring_size:
    description:
      - The number of descriptors in each receive queue.
    type: int
    default: 512
  tx_queue_count:
    description:
      - The number of transmit queue resources to allocate.
    type: int
    default: 1
  tx_ring_size:
    description:
      - The number of descriptors in each transmit queue.
    type: int
    default: 256
  completion_queue_count:
    description:
      - The number of completion queue resources to allocate.
      - In general, the number of completion queue resources to allocate is equal to the number of transmit queue resources
        plus the number of receive queue resources.
    type: int
    default: 5
  completion_ring_size:
    description:
      - The number of descriptors in each completion queue.
    type: int
    default: 1
  uplink_failback_timeout:
    description:
      - Uplink Failback Timeout in seconds when uplink failover is enabled for a vNIC.
      - After a vNIC has started using its secondary interface, this setting controls how long
        the primary interface must be available before the system resumes using the primary
        interface for the vNIC.
    type: int
    default: 5
  tcp_tx_checksum:
    description:
      - When enabled, the CPU sends all packets to the hardware so that the checksum can be calculated.
    type: bool
    default: true
  tcp_rx_checksum:
    description:
      - When enabled, the CPU sends all packet checksums to the hardware for validation.
    type: bool
    default: true
  tcp_large_send:
    description:
      - Enables the CPU to send large packets to the hardware for segmentation.
    type: bool
    default: true
  tcp_large_receive:
    description:
      - Enables the reassembly of segmented packets in hardware before sending them to the CPU.
    type: bool
    default: true
  rss_enabled:
    description:
      - Receive Side Scaling allows the incoming traffic to be spread across multiple CPU cores.
    type: bool
    default: true
  rss_ipv4_hash:
    description:
      - When enabled, the IPv4 address is used for traffic distribution.
    type: bool
    default: true
  rss_ipv6_hash:
    description:
      - When enabled, the IPv6 address is used for traffic distribution.
    type: bool
    default: false
  rss_ipv6_ext_hash:
    description:
      - When enabled, the IPv6 extensions are used for traffic distribution.
    type: bool
    default: true
  rss_tcp_ipv4_hash:
    description:
      - When enabled, both the IPv4 address and TCP port number are used for traffic distribution.
    type: bool
    default: true
  rss_tcp_ipv6_hash:
    description:
      - When enabled, both the IPv6 address and TCP port number are used for traffic distribution.
    type: bool
    default: false
  rss_tcp_ipv6_ext_hash:
    description:
      - When enabled, both the IPv6 extensions and TCP port number are used for traffic distribution.
    type: bool
    default: true
  rss_udp_ipv4_hash:
    description:
      - When enabled, both the IPv4 address and UDP port number are used for traffic distribution.
    type: bool
    default: false
  rss_udp_ipv6_hash:
    description:
      - When enabled, both the IPv6 address and UDP port number are used for traffic distribution.
    type: bool
    default: false
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a basic Ethernet Adapter Policy
  cisco.intersight.intersight_ethernet_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "basic-ethernet-adapter-policy"
    description: "Basic Ethernet adapter policy with default settings"
    tags:
      - Key: "Environment"
        Value: "Production"

- name: Create an Ethernet Adapter Policy with VXLAN and advanced features
  cisco.intersight.intersight_ethernet_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "advanced-ethernet-adapter-policy"
    description: "Advanced Ethernet adapter policy with VXLAN and PTP"
    vxlan_enabled: true
    ptp_enabled: true
    advanced_filter: true
    interrupt_scaling: true
    interrupt_count: 16
    rx_queue_count: 8
    tx_queue_count: 4
    completion_queue_count: 12
    tags:
      - Key: "Environment"
        Value: "Production"
      - Key: "Feature"
        Value: "Advanced"

- name: Create an Ethernet Adapter Policy with RoCE enabled
  cisco.intersight.intersight_ethernet_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "roce-ethernet-adapter-policy"
    description: "Ethernet adapter policy with RoCE v2 enabled"
    roce_enabled: true
    roce_queue_pairs: 256
    roce_memory_regions: 131072
    roce_resource_groups: 2
    roce_version: 2
    roce_class_of_service: 5
    tags:
      - Key: "Protocol"
        Value: "RoCE"

- name: Create an Ethernet Adapter Policy with EtherChannel pinning
  cisco.intersight.intersight_ethernet_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "etherchannel-adapter-policy"
    description: "Ethernet adapter policy with EtherChannel pinning"
    etherchannel_pinning_enabled: true
    tx_queue_count: 2
    completion_queue_count: 6
    tags:
      - Key: "Feature"
        Value: "EtherChannel"

- name: Create an Ethernet Adapter Policy with custom RSS settings
  cisco.intersight.intersight_ethernet_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "custom-rss-adapter-policy"
    description: "Ethernet adapter policy with custom RSS configuration"
    rss_enabled: true
    rss_ipv4_hash: true
    rss_ipv6_hash: false
    rss_tcp_ipv4_hash: false
    rss_tcp_ipv6_hash: false
    rss_udp_ipv4_hash: true
    rss_udp_ipv6_hash: true
    tags:
      - Key: "Feature"
        Value: "CustomRSS"

- name: Delete an Ethernet Adapter Policy
  cisco.intersight.intersight_ethernet_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-ethernet-adapter-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    {
        "Moid": "6889f3e8f654d9f7013baae4",
        "ObjectType": "vnic.EthAdapterPolicy",
        "Name": "basic-ethernet-adapter-policy",
        "Description": "Basic Ethernet adapter policy with default settings",
        "AdvancedFilter": false,
        "ArfsSettings": {
            "Enabled": false
        },
        "VxlanSettings": {
            "Enabled": false
        },
        "NvgreSettings": {
            "Enabled": false
        },
        "PtpSettings": {
            "Enabled": false
        },
        "RoceSettings": {
            "Enabled": false
        },
        "InterruptSettings": {
            "Count": 8,
            "Mode": "MSIx",
            "CoalescingTime": 125,
            "CoalescingType": "MIN"
        },
        "RxQueueSettings": {
            "Count": 4,
            "RingSize": 512
        },
        "TxQueueSettings": {
            "Count": 1,
            "RingSize": 256
        },
        "CompletionQueueSettings": {
            "Count": 5,
            "RingSize": 1
        },
        "TcpOffloadSettings": {
            "TxChecksum": true,
            "RxChecksum": true,
            "LargeSend": true,
            "LargeReceive": true
        },
        "RssSettings": true,
        "RssHashSettings": {
            "Ipv4Hash": true,
            "Ipv6Hash": true,
            "Ipv6ExtHash": false,
            "TcpIpv4Hash": true,
            "TcpIpv6Hash": true,
            "TcpIpv6ExtHash": false,
            "UdpIpv4Hash": false,
            "UdpIpv6Hash": false
        }
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_configuration(module):
    """
    Validate configuration according to Intersight constraints.
    """
    # Constraint 1: Cannot enable RDMA over Converged Ethernet and NVGRE simultaneously
    if module.params['roce_enabled'] and module.params['nvgre_enabled']:
        module.fail_json(
            msg="Cannot enable RDMA over Converged Ethernet and NVGRE simultaneously."
        )

    # Constraint 2: Cannot enable 'GENEVE Offload' and 'Accelerated Receive Flow Steering (ARFS)' simultaneously
    if module.params['geneve_enabled'] and module.params['arfs_enabled']:
        module.fail_json(
            msg="Cannot enable 'GENEVE Offload' and 'Accelerated Receive Flow Steering (ARFS)' simultaneously."
        )

    # Constraint 3: Cannot enable ether channel pinning with transmit queue count less than 2
    if module.params['etherchannel_pinning_enabled'] and module.params['tx_queue_count'] < 2:
        module.fail_json(
            msg="Cannot enable ether channel pinning with transmit queue count less than 2. "
                "Current tx_queue_count is {}. Set tx_queue_count to at least 2.".format(
                    module.params['tx_queue_count']
                )
        )

    # Validate ranges
    if not (1 <= module.params['interrupt_count'] <= 1024):
        module.fail_json(msg="interrupt_count must be between 1 and 1024")

    if not (0 <= module.params['interrupt_coalescing_time'] <= 65535):
        module.fail_json(msg="interrupt_coalescing_time must be between 0 and 65535")

    if not (1 <= module.params['rx_queue_count'] <= 1000):
        module.fail_json(msg="rx_queue_count must be between 1 and 1000")

    if not (64 <= module.params['rx_ring_size'] <= 16384):
        module.fail_json(msg="rx_ring_size must be between 64 and 16384")

    if not (1 <= module.params['tx_queue_count'] <= 1000):
        module.fail_json(msg="tx_queue_count must be between 1 and 1000")

    if not (64 <= module.params['tx_ring_size'] <= 16384):
        module.fail_json(msg="tx_ring_size must be between 64 and 16384")

    if not (1 <= module.params['completion_queue_count'] <= 2000):
        module.fail_json(msg="completion_queue_count must be between 1 and 2000")

    if not (1 <= module.params['completion_ring_size'] <= 256):
        module.fail_json(msg="completion_ring_size must be between 1 and 256")

    if not (0 <= module.params['uplink_failback_timeout'] <= 600):
        module.fail_json(msg="uplink_failback_timeout must be between 0 and 600")

    # RoCE specific validations
    if module.params['roce_enabled']:
        if not (1 <= module.params['roce_queue_pairs'] <= 8192):
            module.fail_json(msg="roce_queue_pairs must be between 1 and 8192")

        if not (1 <= module.params['roce_memory_regions'] <= 524288):
            module.fail_json(msg="roce_memory_regions must be between 1 and 524288")

        if not (1 <= module.params['roce_resource_groups'] <= 128):
            module.fail_json(msg="roce_resource_groups must be between 1 and 128")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        # VXLAN, NVGRE, ARFS, PTP settings
        vxlan_enabled=dict(type='bool', default=False),
        nvgre_enabled=dict(type='bool', default=False),
        arfs_enabled=dict(type='bool', default=False),
        ptp_enabled=dict(type='bool', default=False),
        # Advanced features
        advanced_filter=dict(type='bool', default=False),
        interrupt_scaling=dict(type='bool', default=False),
        geneve_enabled=dict(type='bool', default=False),
        etherchannel_pinning_enabled=dict(type='bool', default=False),
        # RoCE settings
        roce_enabled=dict(type='bool', default=False),
        roce_queue_pairs=dict(type='int', default=256),
        roce_memory_regions=dict(type='int', default=131072),
        roce_resource_groups=dict(type='int', default=2),
        roce_version=dict(type='int', choices=[1, 2], default=1),
        roce_class_of_service=dict(type='int', choices=[1, 2, 4, 5, 6], default=5),
        # Interrupt settings
        interrupt_count=dict(type='int', default=8),
        interrupt_mode=dict(type='str', choices=['MSIx', 'MSI', 'INTx'], default='MSIx'),
        interrupt_coalescing_time=dict(type='int', default=125),
        interrupt_coalescing_type=dict(type='str', choices=['MIN', 'IDLE'], default='MIN'),
        # Queue settings
        rx_queue_count=dict(type='int', default=4),
        rx_ring_size=dict(type='int', default=512),
        tx_queue_count=dict(type='int', default=1),
        tx_ring_size=dict(type='int', default=256),
        # Completion
        completion_queue_count=dict(type='int', default=5),
        completion_ring_size=dict(type='int', default=1),
        uplink_failback_timeout=dict(type='int', default=5),
        # TCP offload settings
        tcp_tx_checksum=dict(type='bool', default=True),
        tcp_rx_checksum=dict(type='bool', default=True),
        tcp_large_send=dict(type='bool', default=True),
        tcp_large_receive=dict(type='bool', default=True),
        # RSS settings
        rss_enabled=dict(type='bool', default=True),
        rss_ipv4_hash=dict(type='bool', default=True),
        rss_ipv6_hash=dict(type='bool', default=False),
        rss_ipv6_ext_hash=dict(type='bool', default=True),
        rss_tcp_ipv4_hash=dict(type='bool', default=True),
        rss_tcp_ipv6_hash=dict(type='bool', default=False),
        rss_tcp_ipv6_ext_hash=dict(type='bool', default=True),
        rss_udp_ipv4_hash=dict(type='bool', default=False),
        rss_udp_ipv6_hash=dict(type='bool', default=False),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    validate_configuration(module)
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/vnic/EthAdapterPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Build the API body with all the settings
        intersight.api_body.update({
            'VxlanSettings': {
                'Enabled': module.params['vxlan_enabled']
            },
            'NvgreSettings': {
                'Enabled': module.params['nvgre_enabled']
            },
            'ArfsSettings': {
                'Enabled': module.params['arfs_enabled']
            },
            'PtpSettings': {
                'Enabled': module.params['ptp_enabled']
            },
            'AdvancedFilter': module.params['advanced_filter'],
            'InterruptScaling': module.params['interrupt_scaling'],
            'GeneveEnabled': module.params['geneve_enabled'],
            'EtherChannelPinningEnabled': module.params['etherchannel_pinning_enabled'],
            'RoceSettings': {
                'Enabled': module.params['roce_enabled']
            },
            'InterruptSettings': {
                'Count': module.params['interrupt_count'],
                'Mode': module.params['interrupt_mode'],
                'CoalescingTime': module.params['interrupt_coalescing_time'],
                'CoalescingType': module.params['interrupt_coalescing_type']
            },
            'RxQueueSettings': {
                'Count': module.params['rx_queue_count'],
                'RingSize': module.params['rx_ring_size']
            },
            'TxQueueSettings': {
                'Count': module.params['tx_queue_count'],
                'RingSize': module.params['tx_ring_size']
            },
            'CompletionQueueSettings': {
                'Count': module.params['completion_queue_count'],
                'RingSize': module.params['completion_ring_size']
            },
            'UplinkFailbackTimeout': module.params['uplink_failback_timeout'],
            'TcpOffloadSettings': {
                'TxChecksum': module.params['tcp_tx_checksum'],
                'RxChecksum': module.params['tcp_rx_checksum'],
                'LargeSend': module.params['tcp_large_send'],
                'LargeReceive': module.params['tcp_large_receive']
            },
            'RssSettings': module.params['rss_enabled'],
            'RssHashSettings': {
                'Ipv4Hash': module.params['rss_ipv4_hash'],
                'Ipv6Hash': module.params['rss_ipv6_hash'],
                'Ipv6ExtHash': module.params['rss_ipv6_ext_hash'],
                'TcpIpv4Hash': module.params['rss_tcp_ipv4_hash'],
                'TcpIpv6Hash': module.params['rss_tcp_ipv6_hash'],
                'TcpIpv6ExtHash': module.params['rss_tcp_ipv6_ext_hash'],
                'UdpIpv4Hash': module.params['rss_udp_ipv4_hash'],
                'UdpIpv6Hash': module.params['rss_udp_ipv6_hash']
            }
        })

        # Add RoCE-specific settings only when RoCE is enabled
        if module.params['roce_enabled']:
            intersight.api_body['RoceSettings'].update({
                'QueuePairs': module.params['roce_queue_pairs'],
                'MemoryRegions': module.params['roce_memory_regions'],
                'ResourceGroups': module.params['roce_resource_groups'],
                'Version': module.params['roce_version'],
                'ClassOfService': module.params['roce_class_of_service']
            })

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
