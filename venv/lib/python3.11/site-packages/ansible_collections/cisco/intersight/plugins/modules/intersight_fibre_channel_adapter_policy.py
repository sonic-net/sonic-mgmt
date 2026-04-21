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
module: intersight_fibre_channel_adapter_policy
short_description: Manage Fibre Channel Adapter Policies for Cisco Intersight
description:
  - Create, update, and delete Fibre Channel Adapter Policies on Cisco Intersight.
  - Fibre Channel Adapter policies configure FC adapter settings for Fibre Channel virtual interfaces.
  - These policies control error recovery, timeouts, retry counts, interrupt modes, queue settings, and LUN configurations.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs/vnic/FcAdapterPolicies/get/).
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
      - Policies created within a Custom Organization are applicable only to devices in the same Organization.
      - Use 'default' for the default organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the Fibre Channel Adapter Policy.
      - Must be unique within the organization.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Fibre Channel Adapter Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  error_recovery_enabled:
    description:
      - Enables Fibre Channel Error recovery.
    type: bool
    default: false
  port_down_timeout:
    description:
      - The number of milliseconds a remote Fibre Channel port should be offline before informing the SCSI upper layer.
      - This determines when the port is considered unavailable.
      - For a server with a VIC adapter running ESXi, the recommended value is 10000.
      - For a server with a port used to boot a Windows OS from the SAN, the recommended value is 5000 milliseconds.
    type: int
    default: 10000
  io_retry_timeout:
    description:
      - The number of seconds the adapter waits before aborting the pending command.
      - After timeout, it resends the same IO request.
    type: int
    default: 5
  link_down_timeout:
    description:
      - The number of milliseconds the port should actually be down before it is marked down.
      - After this timeout, fabric connectivity is considered lost.
    type: int
    default: 30000
  port_down_io_retry_count:
    description:
      - The number of times an I/O request to a port is retried because the port is busy.
      - After this count, the system decides the port is unavailable.
    type: int
    default: 8
  error_detection_timeout:
    description:
      - Error Detection Timeout, also referred to as EDTOV, is the number of milliseconds to wait.
      - This is the time before the system assumes that an error has occurred.
    type: int
    default: 2000
  resource_allocation_timeout:
    description:
      - Resource Allocation Timeout, also referred to as RATOV, is the number of milliseconds to wait.
      - This is the time before the system assumes that a resource cannot be properly allocated.
    type: int
    default: 10000
  flogi_retries:
    description:
      - The number of times that the system tries to log in to the fabric after the first failure.
    type: int
    default: 8
  flogi_timeout:
    description:
      - The number of milliseconds that the system waits before it tries to log in again.
    type: int
    default: 4000
  plogi_retries:
    description:
      - The number of times that the system tries to log in to a port after the first failure.
    type: int
    default: 8
  plogi_timeout:
    description:
      - The number of milliseconds that the system waits before it tries to log in again.
    type: int
    default: 20000
  interrupt_mode:
    description:
      - The preferred driver interrupt mode.
      - MSIx is the recommended option.
    type: str
    choices: [MSIx, MSI, INTx]
    default: MSIx
  io_throttle_count:
    description:
      - The maximum number of data or control I/O operations that can be pending for the virtual interface at one time.
      - If this value is exceeded, the additional I/O operations wait in the queue.
      - They wait until the number of pending I/O operations decreases and the additional operations can be processed.
    type: int
    default: 512
  lun_count:
    description:
      - The maximum number of LUNs that the Fibre Channel driver will export or show.
      - The maximum number of LUNs is usually controlled by the operating system running on the server.
      - Lun Count value can exceed 1024 only for vHBA of type 'FC Initiator' and on servers having supported firmware version.
    type: int
    default: 1024
  lun_queue_depth:
    description:
      - The number of commands that the HBA can send and receive in a single transmission per LUN.
    type: int
    default: 20
  rx_ring_size:
    description:
      - The number of descriptors in each receive queue.
      - The maximum value for Receive queue is 2048.
    type: int
    default: 64
  tx_ring_size:
    description:
      - The number of descriptors in each transmit queue.
      - The maximum value for Transmit queue is 128.
    type: int
    default: 64
  scsi_io_queue_count:
    description:
      - The number of SCSI I/O queue resources the system should allocate.
    type: int
    default: 1
  scsi_io_ring_size:
    description:
      - The number of descriptors in each SCSI I/O queue.
    type: int
    default: 512
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create Fibre Channel Adapter Policy with default settings
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-adapter-default"
    description: "Fibre Channel Adapter policy with default values"
    state: present

- name: Create Fibre Channel Adapter Policy with custom error recovery settings
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-adapter-error-recovery"
    description: "FC Adapter policy with error recovery enabled"
    error_recovery_enabled: true
    port_down_timeout: 5000
    io_retry_timeout: 8
    link_down_timeout: 20000
    port_down_io_retry_count: 10
    tags:
      - Key: Environment
        Value: Production
    state: present

- name: Create Fibre Channel Adapter Policy with custom queue settings
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-adapter-high-performance"
    description: "FC Adapter policy with optimized queue settings"
    io_throttle_count: 1024
    lun_count: 4096
    lun_queue_depth: 254
    rx_ring_size: 128
    tx_ring_size: 128
    scsi_io_queue_count: 8
    scsi_io_ring_size: 512
    state: present

- name: Create Fibre Channel Adapter Policy with custom timeout settings
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "Engineering"
    name: "fc-adapter-custom-timeouts"
    description: "FC Adapter policy with custom timeout values"
    error_detection_timeout: 5000
    resource_allocation_timeout: 15000
    flogi_retries: 12
    flogi_timeout: 8000
    plogi_retries: 12
    plogi_timeout: 30000
    state: present

- name: Create Fibre Channel Adapter Policy with MSI interrupt mode
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-adapter-msi-mode"
    description: "FC Adapter policy with MSI interrupt mode"
    interrupt_mode: MSI
    state: present

- name: Update Fibre Channel Adapter Policy description
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-adapter-default"
    description: "Updated FC Adapter policy description"
    state: present

- name: Delete Fibre Channel Adapter Policy
  cisco.intersight.intersight_fibre_channel_adapter_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: "default"
    name: "fc-adapter-default"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "fc-adapter-default",
        "ObjectType": "vnic.FcAdapterPolicy",
        "Moid": "1234567890abcdef12345678",
        "Description": "Fibre Channel Adapter policy with default values",
        "ErrorRecoverySettings": {
            "Enabled": false,
            "PortDownTimeout": 10000,
            "LinkDownTimeout": 30000,
            "IoRetryTimeout": 5,
            "IoRetryCount": 8
        },
        "ErrorDetectionTimeout": 2000,
        "ResourceAllocationTimeout": 10000,
        "FlogiSettings": {
            "Retries": 8,
            "Timeout": 4000
        },
        "PlogiSettings": {
            "Retries": 8,
            "Timeout": 20000
        },
        "InterruptSettings": {
            "Mode": "MSIx"
        },
        "IoThrottleCount": 512,
        "LunCount": 1024,
        "LunQueueDepth": 20,
        "RxQueueSettings": {
            "RingSize": 64
        },
        "TxQueueSettings": {
            "RingSize": 64
        },
        "ScsiQueueSettings": {
            "Count": 1,
            "RingSize": 512
        },
        "Organization": {
            "Moid": "abcdef1234567890abcdef12",
            "ObjectType": "organization.Organization"
        },
        "Tags": [
            {
                "Key": "Environment",
                "Value": "Production"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec


def validate_parameters(module):
    """
    Validate module parameters for Fibre Channel Adapter policy configuration.
    """
    if module.params['state'] != 'present':
        return
    # Validate port_down_timeout range (0-240000)
    port_down_timeout = module.params.get('port_down_timeout')
    if port_down_timeout is not None and (port_down_timeout < 0 or port_down_timeout > 240000):
        module.fail_json(msg="Parameter 'port_down_timeout' must be between 0 and 240000")
    # Validate io_retry_timeout range (1-59)
    io_retry_timeout = module.params.get('io_retry_timeout')
    if io_retry_timeout is not None and (io_retry_timeout < 1 or io_retry_timeout > 59):
        module.fail_json(msg="Parameter 'io_retry_timeout' must be between 1 and 59")
    # Validate link_down_timeout range (0-240000)
    link_down_timeout = module.params.get('link_down_timeout')
    if link_down_timeout is not None and (link_down_timeout < 0 or link_down_timeout > 240000):
        module.fail_json(msg="Parameter 'link_down_timeout' must be between 0 and 240000")
    # Validate port_down_io_retry_count range (0-255)
    port_down_io_retry_count = module.params.get('port_down_io_retry_count')
    if port_down_io_retry_count is not None and (port_down_io_retry_count < 0 or port_down_io_retry_count > 255):
        module.fail_json(msg="Parameter 'port_down_io_retry_count' must be between 0 and 255")
    # Validate error_detection_timeout range (1000-100000)
    error_detection_timeout = module.params.get('error_detection_timeout')
    if error_detection_timeout is not None and (error_detection_timeout < 1000 or error_detection_timeout > 100000):
        module.fail_json(msg="Parameter 'error_detection_timeout' must be between 1000 and 100000")
    # Validate resource_allocation_timeout range (5000-100000)
    resource_allocation_timeout = module.params.get('resource_allocation_timeout')
    if resource_allocation_timeout is not None and (resource_allocation_timeout < 5000 or resource_allocation_timeout > 100000):
        module.fail_json(msg="Parameter 'resource_allocation_timeout' must be between 5000 and 100000")
    # Validate flogi_retries range (0-4294967295)
    flogi_retries = module.params.get('flogi_retries')
    if flogi_retries is not None and (flogi_retries < 0 or flogi_retries > 4294967295):
        module.fail_json(msg="Parameter 'flogi_retries' must be between 0 and 4294967295")
    # Validate flogi_timeout range (1000-255000)
    flogi_timeout = module.params.get('flogi_timeout')
    if flogi_timeout is not None and (flogi_timeout < 1000 or flogi_timeout > 255000):
        module.fail_json(msg="Parameter 'flogi_timeout' must be between 1000 and 255000")
    # Validate plogi_retries range (0-255)
    plogi_retries = module.params.get('plogi_retries')
    if plogi_retries is not None and (plogi_retries < 0 or plogi_retries > 255):
        module.fail_json(msg="Parameter 'plogi_retries' must be between 0 and 255")
    # Validate plogi_timeout range (1000-255000)
    plogi_timeout = module.params.get('plogi_timeout')
    if plogi_timeout is not None and (plogi_timeout < 1000 or plogi_timeout > 255000):
        module.fail_json(msg="Parameter 'plogi_timeout' must be between 1000 and 255000")
    # Validate io_throttle_count range (1-1024)
    io_throttle_count = module.params.get('io_throttle_count')
    if io_throttle_count is not None and (io_throttle_count < 1 or io_throttle_count > 1024):
        module.fail_json(msg="Parameter 'io_throttle_count' must be between 1 and 1024")
    # Validate lun_count range (1-4096)
    lun_count = module.params.get('lun_count')
    if lun_count is not None and (lun_count < 1 or lun_count > 4096):
        module.fail_json(msg="Parameter 'lun_count' must be between 1 and 4096")
    # Validate lun_queue_depth range (1-254)
    lun_queue_depth = module.params.get('lun_queue_depth')
    if lun_queue_depth is not None and (lun_queue_depth < 1 or lun_queue_depth > 254):
        module.fail_json(msg="Parameter 'lun_queue_depth' must be between 1 and 254")
    # Validate rx_ring_size (>= 64)
    rx_ring_size = module.params.get('rx_ring_size')
    if rx_ring_size is not None and rx_ring_size < 64:
        module.fail_json(msg="Parameter 'rx_ring_size' must be at least 64")
    # Validate tx_ring_size (>= 64)
    tx_ring_size = module.params.get('tx_ring_size')
    if tx_ring_size is not None and tx_ring_size < 64:
        module.fail_json(msg="Parameter 'tx_ring_size' must be at least 64")
    # Validate scsi_io_queue_count range (1-245)
    scsi_io_queue_count = module.params.get('scsi_io_queue_count')
    if scsi_io_queue_count is not None and (scsi_io_queue_count < 1 or scsi_io_queue_count > 245):
        module.fail_json(msg="Parameter 'scsi_io_queue_count' must be between 1 and 245")
    # Validate scsi_io_ring_size range (64-512)
    scsi_io_ring_size = module.params.get('scsi_io_ring_size')
    if scsi_io_ring_size is not None and (scsi_io_ring_size < 64 or scsi_io_ring_size > 512):
        module.fail_json(msg="Parameter 'scsi_io_ring_size' must be between 64 and 512")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        error_recovery_enabled=dict(type='bool', default=False),
        port_down_timeout=dict(type='int', default=10000),
        io_retry_timeout=dict(type='int', default=5),
        link_down_timeout=dict(type='int', default=30000),
        port_down_io_retry_count=dict(type='int', default=8),
        error_detection_timeout=dict(type='int', default=2000),
        resource_allocation_timeout=dict(type='int', default=10000),
        flogi_retries=dict(type='int', default=8),
        flogi_timeout=dict(type='int', default=4000),
        plogi_retries=dict(type='int', default=8),
        plogi_timeout=dict(type='int', default=20000),
        interrupt_mode=dict(type='str', choices=['MSIx', 'MSI', 'INTx'], default='MSIx'),
        io_throttle_count=dict(type='int', default=512),
        lun_count=dict(type='int', default=1024),
        lun_queue_depth=dict(type='int', default=20),
        rx_ring_size=dict(type='int', default=64),
        tx_ring_size=dict(type='int', default=64),
        scsi_io_queue_count=dict(type='int', default=1),
        scsi_io_ring_size=dict(type='int', default=512),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Validate module parameters
    validate_parameters(module)

    # Resource path used to configure policy
    resource_path = '/vnic/FcAdapterPolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': module.params['organization'],
        },
        'Name': module.params['name'],
    }

    if module.params['state'] == 'present':
        intersight.api_body['ErrorRecoverySettings'] = {
            'Enabled': module.params['error_recovery_enabled'],
            'PortDownTimeout': module.params['port_down_timeout'],
            'LinkDownTimeout': module.params['link_down_timeout'],
            'IoRetryTimeout': module.params['io_retry_timeout'],
            'IoRetryCount': module.params['port_down_io_retry_count'],
        }
        intersight.api_body['ErrorDetectionTimeout'] = module.params['error_detection_timeout']
        intersight.api_body['ResourceAllocationTimeout'] = module.params['resource_allocation_timeout']
        intersight.api_body['FlogiSettings'] = {
            'Retries': module.params['flogi_retries'],
            'Timeout': module.params['flogi_timeout'],
        }
        intersight.api_body['PlogiSettings'] = {
            'Retries': module.params['plogi_retries'],
            'Timeout': module.params['plogi_timeout'],
        }
        intersight.api_body['InterruptSettings'] = {
            'Mode': module.params['interrupt_mode'],
        }
        intersight.api_body['IoThrottleCount'] = module.params['io_throttle_count']
        intersight.api_body['LunCount'] = module.params['lun_count']
        intersight.api_body['LunQueueDepth'] = module.params['lun_queue_depth']
        intersight.api_body['RxQueueSettings'] = {
            'RingSize': module.params['rx_ring_size'],
        }
        intersight.api_body['TxQueueSettings'] = {
            'RingSize': module.params['tx_ring_size'],
        }
        intersight.api_body['ScsiQueueSettings'] = {
            'Count': module.params['scsi_io_queue_count'],
            'RingSize': module.params['scsi_io_ring_size'],
        }
        intersight.set_tags_and_description()
    intersight.configure_policy_or_profile(resource_path=resource_path)
    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
