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
module: intersight_storage_policy
short_description: Storage Policy configuration for Cisco Intersight
description:
  - Manages Storage Policy configuration on Cisco Intersight.
  - A policy to configure storage settings and virtual drive configurations for Cisco Intersight managed servers.
  - For more information see L(Cisco Intersight,https://intersight.com/apidocs).
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
      - The name assigned to the Storage Policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  description:
    description:
      - The user-defined description for the Storage Policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
    default: []
  use_jbod_for_vd_creation:
    description:
      - Disks in JBOD State are used to create virtual drives.
      - This setting must be disabled if Default Drive State is set to JBOD.
    type: bool
    default: false
  unused_disks_state:
    description:
      - State to which drives, not used in this policy, are to be moved.
      - NoChange will not change the drive state.
      - No Change must be selected if Default Drive State is set to JBOD or RAID0.
    type: str
    choices: ['NoChange', 'UnconfiguredGood', 'Jbod']
    default: 'NoChange'
  default_drive_mode:
    description:
      - All unconfigured drives will move to the selected state on deployment.
      - Newly inserted drives will move to the selected state.
      - Select UnconfiguredGood option to retain the existing configuration.
      - Select Jbod to move the unconfigured drives to JBOD state.
      - Select RAID0 to create a RAID0 virtual drive on each of the unconfigured drives.
    type: str
    choices: ['UnconfiguredGood', 'Jbod', 'RAID0']
    default: 'UnconfiguredGood'
  secure_jbods:
    description:
      - JBOD drives specified in this slot range will be encrypted.
      - Allowed values are 'ALL', or a comma or hyphen separated number range.
      - Sample format is ALL or 1, 3 or 4-6, 8.
      - Setting the value to 'ALL' will encrypt all the unused UnconfigureGood/JBOD disks.
      - 'Slot format examples: "1,4,5", "2", "1-5", "1,2,6-8"'
    type: str
  m2_virtual_drive_config:
    description:
      - M.2 RAID virtual drive configuration.
    type: dict
    suboptions:
      enable:
        description:
          - Enable M.2 virtual drive configuration.
        type: bool
        default: false
      controller_slot:
        description:
          - Slot of the M.2 RAID controller for virtual drive creation.
          - Select 'MSTOR-RAID-1' to create virtual drive on the M.2 RAID controller in the first slot.
          - Select 'MSTOR-RAID-2' for second slot.
          - Select 'MSTOR-RAID-1,MSTOR-RAID-2' for both slots or either slot.
        type: str
        choices: ['MSTOR-RAID-2', 'MSTOR-RAID-1', 'MSTOR-RAID-1,MSTOR-RAID-2']
        default: 'MSTOR-RAID-1'
      name:
        description:
          - The name of the virtual drive.
          - The name can be between 1 and 15 alphanumeric characters.
          - Spaces or any special characters other than - (hyphen) and _ (underscore) are not allowed.
        type: str
        default: 'MStorBootVd'
  raid0_drive_config:
    description:
      - MRAID/RAID Single Drive RAID0 Configuration.
    type: dict
    suboptions:
      enable:
        description:
          - Enable RAID0 drive configuration.
        type: bool
        default: false
      drive_slots:
        description:
          - The set of drive slots where RAID0 virtual drives must be created.
          - If not specified, it will not be added.
          - 'Slot format examples: "1,4,5", "2", "1-5", "1,2,6-8"'
        type: str
      strip_size:
        description:
          - Desired strip size in KiB.
        type: int
        choices: [64, 128, 256, 512, 1024]
        default: 64
      access_policy:
        description:
          - Access policy that host has on this virtual drive.
        type: str
        choices: ['Default', 'ReadWrite', 'ReadOnly', 'Blocked']
        default: 'Default'
      read_policy:
        description:
          - Read ahead mode to be used to read data from this virtual drive.
        type: str
        choices: ['Default', 'ReadAhead', 'NoReadAhead']
        default: 'Default'
      write_policy:
        description:
          - Write mode to be used to write data to this virtual drive.
        type: str
        choices: ['Default', 'WriteThrough', 'WriteBackGoodBbu', 'AlwaysWriteBack']
        default: 'Default'
      disk_cache:
        description:
          - Disk cache policy for the virtual drive.
        type: str
        choices: ['Default', 'NoChange', 'Enable', 'Disable']
        default: 'Default'
  controller_attached_nvme_slots:
    description:
      - Only U.3 NVMe drives need to be specified, entered slots will be moved to controller attached mode.
      - Allowed slots are 1-9, 21-24, 101-104.
      - Allowed value is a comma or hyphen separated number ranges.
      - 'Slot format examples: "1,4,5", "2", "1-5", "1,2,6-8"'
    type: str
  direct_attached_nvme_slots:
    description:
      - Only U.3 NVMe drives need to be specified, entered slots will be moved to Direct attached mode.
      - Allowed slots are 1-9, 21-24, 101-104.
      - Allowed value is a comma or hyphen separated number ranges.
      - 'Slot format examples: "1,4,5", "2", "1-5", "1,2,6-8"'
    type: str
  drive_groups:
    description:
      - List of drive groups to be created and attached to the storage policy.
      - Each drive group can contain multiple virtual drives.
      - Leave empty to create a policy without drive groups for manual configuration later.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - The name of the drive group.
          - The name can be between 1 and 64 alphanumeric characters.
        type: str
        required: true
      raid_level:
        description:
          - The supported RAID level for the disk group.
        type: str
        choices: ['Raid0', 'Raid1', 'Raid5', 'Raid6', 'Raid10', 'Raid50', 'Raid60']
        default: 'Raid0'
      secure_drive_group:
        description:
          - Enables/disables the drive security on all the drives used in this policy.
          - This flag just enables the drive security and only after Remote/Manual key setting configured, the actual security will be applied.
        type: bool
        default: false
      dedicated_hot_spares:
        description:
          - A collection of drives to be used as hot spares for this Drive Group.
          - Not applicable for RAID0.
          - 'Slot format examples: "1,4,5", "2", "1-5", "1,2,6-8"'
        type: str
      span_groups:
        description:
          - List of span groups for the drive group.
          - Each span group contains drive slots.
          - Required field - must be provided for all drive groups.
          - Single span group for RAID0, RAID1, RAID5, RAID6.
          - Multiple span groups (2-8) for RAID10, RAID50, RAID60.
        type: list
        elements: dict
        required: true
        suboptions:
          slots:
            description:
              - Drive slots for this span group.
              - 'Slot format examples: "1,4,5", "2", "1-5", "1,2,6-8"'
            type: str
            required: true
      virtual_drives:
        description:
          - List of virtual drives to be created in this drive group.
        type: list
        elements: dict
        suboptions:
          name:
            description:
              - The name of the virtual drive.
              - The name can be between 1 and 15 alphanumeric characters.
              - Spaces or any special characters other than - (hyphen) and _ (underscore) are not allowed.
            type: str
            required: true
          size:
            description:
              - Virtual drive size in MebiBytes.
              - Size is mandatory field except when the Expand to Available option is enabled.
            type: int
          expand_to_available:
            description:
              - Whether to expand the virtual drive to use all available space.
            type: bool
            default: false
          boot_drive:
            description:
              - Whether this virtual drive is a boot drive.
            type: bool
            default: false
          strip_size:
            description:
              - Desired strip size in KiB.
            type: int
            choices: [64, 128, 256, 512, 1024]
            default: 64
          access_policy:
            description:
              - Access policy that host has on this virtual drive.
            type: str
            choices: ['Default', 'ReadWrite', 'ReadOnly', 'Blocked']
            default: 'Default'
          read_policy:
            description:
              - Read ahead mode to be used to read data from this virtual drive.
            type: str
            choices: ['Default', 'ReadAhead', 'NoReadAhead']
            default: 'Default'
          write_policy:
            description:
              - Write mode to be used to write data to this virtual drive.
            type: str
            choices: ['Default', 'WriteThrough', 'WriteBackGoodBbu', 'AlwaysWriteBack']
            default: 'Default'
          disk_cache:
            description:
              - Disk cache policy for the virtual drive.
            type: str
            choices: ['Default', 'NoChange', 'Enable', 'Disable']
            default: 'Default'
      state:
        description:
          - Whether to create/update or delete the drive group.
        type: str
        choices: ['present', 'absent']
        default: present
author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Create a basic storage policy
  cisco.intersight.intersight_storage_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "basic-storage-policy"
    description: "Basic storage policy configuration"
    tags:
      - Key: "Environment"
        Value: "Production"

- name: Create storage policy with M.2 virtual drive enabled
  cisco.intersight.intersight_storage_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "m2-enabled-storage-policy"
    description: "Storage policy with M.2 virtual drive"
    m2_virtual_drive_config:
      enable: true
      controller_slot: "MSTOR-RAID-1"
      name: "MStorBootVd"
    tags:
      - Key: "Site"
        Value: "Datacenter1"

- name: Create storage policy with RAID0 configuration
  cisco.intersight.intersight_storage_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "raid0-storage-policy"
    description: "Storage policy with RAID0 configuration"
    use_jbod_for_vd_creation: true
    default_drive_mode: "RAID0"
    secure_jbods: "1"
    raid0_drive_config:
      enable: true
      strip_size: 128
      access_policy: "ReadWrite"
      read_policy: "ReadAhead"
      write_policy: "WriteBackGoodBbu"
      disk_cache: "Enable"
    controller_attached_nvme_slots: "2"
    direct_attached_nvme_slots: "3"

- name: Create storage policy with drive groups
  cisco.intersight.intersight_storage_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "drive-group-storage-policy"
    description: "Storage policy with drive groups"
    m2_virtual_drive_config:
      enable: false
    raid0_drive_config:
      enable: false
    drive_groups:
      - name: "raid0-group"
        raid_level: "Raid0"
        secure_drive_group: false
        span_groups:
          - slots: "1,2"
        virtual_drives:
          - name: "raid0-vd"
            size: 1024
            expand_to_available: false
            boot_drive: true
            strip_size: 128
            access_policy: "ReadWrite"
            read_policy: "ReadAhead"
            write_policy: "WriteBackGoodBbu"
            disk_cache: "Enable"
      - name: "raid1-group"
        raid_level: "Raid1"
        secure_drive_group: true
        dedicated_hot_spares: "3,4"
        span_groups:
          - slots: "5,6"
        virtual_drives:
          - name: "raid1-vd"
            size: 0
            expand_to_available: true
            boot_drive: false
            strip_size: 64
            access_policy: "Default"
            read_policy: "Default"
            write_policy: "Default"
            disk_cache: "Default"

- name: Create storage policy with nested RAID drive groups
  cisco.intersight.intersight_storage_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "nested-raid-storage-policy"
    description: "Storage policy with nested RAID configurations"
    m2_virtual_drive_config:
      enable: false
    raid0_drive_config:
      enable: false
    drive_groups:
      - name: "raid60-group"
        raid_level: "Raid60"
        secure_drive_group: false
        dedicated_hot_spares: "33,34,35,36"
        span_groups:
          - slots: "1,2,3,4"
          - slots: "5,6,7,8"
          - slots: "9,10,11,12"
          - slots: "13,14,15,16"
          - slots: "17,18,19,20"
          - slots: "21,22,23,24"
          - slots: "25,26,27,28"
          - slots: "29,30,31,32"
        virtual_drives:
          - name: "raid60-vd1"
            size: 1024
            expand_to_available: false
            boot_drive: true
            strip_size: 64
            access_policy: "ReadWrite"
            read_policy: "Default"
            write_policy: "Default"
            disk_cache: "Default"
          - name: "raid60-vd2"
            size: 1024
            expand_to_available: false
            boot_drive: false
            strip_size: 64
            access_policy: "ReadWrite"
            read_policy: "Default"
            write_policy: "Default"
            disk_cache: "Default"

- name: Delete a storage policy
  cisco.intersight.intersight_storage_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    name: "old-storage-policy"
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "basic-storage-policy",
        "UseJbodForVdCreation": true,
        "UnusedDisksState": "NoChange",
        "DefaultDriveMode": "UnconfiguredGood",
        "M2VirtualDrive": {
            "Enable": false,
            "ControllerSlot": "MSTOR-RAID-1",
            "Name": "MStorBootVd"
        },
        "Raid0Drive": {
            "Enable": false,
            "VirtualDrivePolicy": {
                "StripSize": 64,
                "AccessPolicy": "Default",
                "ReadPolicy": "Default",
                "WritePolicy": "Default",
                "DriveCache": "Default"
            }
        },
        "ObjectType": "storage.StoragePolicy",
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


# Virtual drive policy specification
VIRTUAL_DRIVE_POLICY_SPEC = {
    'strip_size': dict(type='int', choices=[64, 128, 256, 512, 1024], default=64),
    'access_policy': dict(type='str', choices=['Default', 'ReadWrite', 'ReadOnly', 'Blocked'], default='Default'),
    'read_policy': dict(type='str', choices=['Default', 'ReadAhead', 'NoReadAhead'], default='Default'),
    'write_policy': dict(type='str', choices=['Default', 'WriteThrough', 'WriteBackGoodBbu', 'AlwaysWriteBack'], default='Default'),
    'disk_cache': dict(type='str', choices=['Default', 'NoChange', 'Enable', 'Disable'], default='Default')
}


def build_virtual_drive_policy(virtual_drive_config):
    """
    Build VirtualDrivePolicy from virtual drive configuration.
    Args:
        virtual_drive_config: Dictionary containing virtual drive policy parameters
    Returns:
        Dictionary representing VirtualDrivePolicy
    """
    return {
        'StripSize': virtual_drive_config.get('strip_size', 64),
        'AccessPolicy': virtual_drive_config.get('access_policy', 'Default'),
        'ReadPolicy': virtual_drive_config.get('read_policy', 'Default'),
        'WritePolicy': virtual_drive_config.get('write_policy', 'Default'),
        'DriveCache': virtual_drive_config.get('disk_cache', 'Default')
    }


def validate_input(module):
    """
    Validate input parameters for the storage policy module.
    """
    # Validate UseJbodForVdCreation vs DefaultDriveMode compatibility
    use_jbod = module.params.get('use_jbod_for_vd_creation')
    default_drive_mode = module.params.get('default_drive_mode')
    unused_disks_state = module.params.get('unused_disks_state')

    # UseJbodForVdCreation must be disabled if DefaultDriveMode is JBOD
    if default_drive_mode == 'Jbod' and use_jbod:
        module.fail_json(msg="use_jbod_for_vd_creation must be disabled when default_drive_mode is set to 'Jbod'")

    # UnusedDisksState must be NoChange if DefaultDriveMode is JBOD or RAID0
    if default_drive_mode in ['Jbod', 'RAID0'] and unused_disks_state != 'NoChange':
        module.fail_json(msg="unused_disks_state must be set to 'NoChange' when default_drive_mode is 'Jbod' or 'RAID0'")

    # Validate M.2 virtual drive configuration
    m2_config = module.params.get('m2_virtual_drive_config')
    if m2_config and m2_config.get('enable'):
        if not m2_config.get('controller_slot'):
            module.fail_json(msg="controller_slot is required when M.2 virtual drive is enabled")
        if not m2_config.get('name'):
            module.fail_json(msg="name is required when M.2 virtual drive is enabled")

        # Validate name format
        name = m2_config.get('name')
        if len(name) > 15 or len(name) < 1:
            module.fail_json(msg="M.2 virtual drive name must be between 1 and 15 characters")

    # Validate drive groups configuration
    drive_groups = module.params.get('drive_groups', [])
    if drive_groups:
        for drive_group in drive_groups:
            # Validate drive group name
            name = drive_group.get('name', '')
            if len(name) > 64 or len(name) < 1:
                module.fail_json(msg="Drive group name must be between 1 and 64 characters")

            # Validate dedicated hot spares for RAID0
            raid_level = drive_group.get('raid_level')
            dedicated_hot_spares = drive_group.get('dedicated_hot_spares')
            if raid_level == 'Raid0' and dedicated_hot_spares:
                module.fail_json(msg="Dedicated hot spares are not applicable for RAID0")

            # Validate span groups requirements based on RAID level
            span_groups = drive_group.get('span_groups', [])
            if not span_groups:
                module.fail_json(msg="span_groups is required for drive groups")

            # Validate span group count based on RAID level
            span_count = len(span_groups)
            if raid_level in ['Raid10', 'Raid50', 'Raid60']:
                if span_count > 8:
                    module.fail_json(msg=f"RAID level {raid_level} supports maximum 8 span groups, got {span_count}")
                if span_count < 2:
                    module.fail_json(msg=f"RAID level {raid_level} requires minimum 2 span groups, got {span_count}")
            elif raid_level in ['Raid0', 'Raid1', 'Raid5', 'Raid6']:
                if span_count != 1:
                    module.fail_json(msg=f"RAID level {raid_level} requires exactly 1 span group, got {span_count}")

            # Validate virtual drives
            virtual_drives = drive_group.get('virtual_drives', [])
            for virtual_drive in virtual_drives:
                # Validate virtual drive name
                vd_name = virtual_drive.get('name', '')
                if len(vd_name) > 15 or len(vd_name) < 1:
                    module.fail_json(msg="Virtual drive name must be between 1 and 15 characters")

                # Validate size requirement
                size = virtual_drive.get('size')
                expand_to_available = virtual_drive.get('expand_to_available', False)
                if not expand_to_available and not size:
                    module.fail_json(msg="Virtual drive size is mandatory except when expand_to_available is enabled")


def main():
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict', default=[]),
        use_jbod_for_vd_creation=dict(type='bool', default=False),
        unused_disks_state=dict(type='str', choices=['NoChange', 'UnconfiguredGood', 'Jbod'], default='NoChange'),
        default_drive_mode=dict(type='str', choices=['UnconfiguredGood', 'Jbod', 'RAID0'], default='UnconfiguredGood'),
        secure_jbods=dict(type='str'),
        m2_virtual_drive_config=dict(
            type='dict',
            required=False,
            options=dict(
                enable=dict(type='bool', default=False),
                controller_slot=dict(type='str',
                                     choices=['MSTOR-RAID-2', 'MSTOR-RAID-1', 'MSTOR-RAID-1,MSTOR-RAID-2'],
                                     default='MSTOR-RAID-1'),
                name=dict(type='str', default='MStorBootVd')
            ),
        ),
        raid0_drive_config=dict(
            type='dict',
            required=False,
            options=dict(
                enable=dict(type='bool', default=False),
                drive_slots=dict(type='str'),
                strip_size=VIRTUAL_DRIVE_POLICY_SPEC['strip_size'],
                access_policy=VIRTUAL_DRIVE_POLICY_SPEC['access_policy'],
                read_policy=VIRTUAL_DRIVE_POLICY_SPEC['read_policy'],
                write_policy=VIRTUAL_DRIVE_POLICY_SPEC['write_policy'],
                disk_cache=VIRTUAL_DRIVE_POLICY_SPEC['disk_cache']
            ),
        ),
        controller_attached_nvme_slots=dict(type='str'),
        direct_attached_nvme_slots=dict(type='str'),
        drive_groups=dict(
            type='list',
            elements='dict',
            options=dict(
                name=dict(type='str', required=True),
                raid_level=dict(type='str', choices=['Raid0', 'Raid1', 'Raid5', 'Raid6', 'Raid10', 'Raid50', 'Raid60'], default='Raid0'),
                secure_drive_group=dict(type='bool', default=False),
                dedicated_hot_spares=dict(type='str'),
                span_groups=dict(
                    type='list',
                    elements='dict',
                    required=True,
                    options=dict(
                        slots=dict(type='str', required=True)
                    )
                ),
                virtual_drives=dict(
                    type='list',
                    elements='dict',
                    options=dict(
                        name=dict(type='str', required=True),
                        size=dict(type='int'),
                        expand_to_available=dict(type='bool', default=False),
                        boot_drive=dict(type='bool', default=False),
                        strip_size=VIRTUAL_DRIVE_POLICY_SPEC['strip_size'],
                        access_policy=VIRTUAL_DRIVE_POLICY_SPEC['access_policy'],
                        read_policy=VIRTUAL_DRIVE_POLICY_SPEC['read_policy'],
                        write_policy=VIRTUAL_DRIVE_POLICY_SPEC['write_policy'],
                        disk_cache=VIRTUAL_DRIVE_POLICY_SPEC['disk_cache']
                    )
                ),
                state=dict(type='str', choices=['present', 'absent'], default='present')
            )
        ),
    )

    required_if = [
        ['state', 'present', ['m2_virtual_drive_config', 'raid0_drive_config']],
    ]

    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    if module.params['state'] == 'present':
        validate_input(module)

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/storage/StoragePolicies'

    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        intersight.set_tags_and_description()

        # Set basic storage configuration
        intersight.api_body['UseJbodForVdCreation'] = intersight.module.params['use_jbod_for_vd_creation']
        intersight.api_body['UnusedDisksState'] = intersight.module.params['unused_disks_state']
        intersight.api_body['DefaultDriveMode'] = intersight.module.params['default_drive_mode']

        # Set secure JBODs if specified
        if module.params['secure_jbods']:
            intersight.api_body['SecureJbods'] = module.params['secure_jbods']

        # Set M.2 virtual drive configuration
        m2_config = module.params.get('m2_virtual_drive_config', {})
        intersight.api_body['M2VirtualDrive'] = {
            'Enable': m2_config.get('enable', False)
        }
        if m2_config.get('enable'):
            intersight.api_body['M2VirtualDrive']['ControllerSlot'] = m2_config.get('controller_slot', 'MSTOR-RAID-1')
            intersight.api_body['M2VirtualDrive']['Name'] = m2_config.get('name', 'MStorBootVd')

        # Set RAID0 drive configuration
        raid0_config = module.params.get('raid0_drive_config', {})
        intersight.api_body['Raid0Drive'] = {
            'Enable': raid0_config.get('enable', False)
        }
        if raid0_config.get('enable'):
            if raid0_config.get('drive_slots'):
                intersight.api_body['Raid0Drive']['DriveSlots'] = raid0_config['drive_slots']

            # Set virtual drive policy using the common function
            intersight.api_body['Raid0Drive']['VirtualDrivePolicy'] = build_virtual_drive_policy(raid0_config)

        # Set NVMe slot configurations
        if module.params['controller_attached_nvme_slots']:
            intersight.api_body['ControllerAttachedNvmeSlots'] = module.params['controller_attached_nvme_slots']

        if module.params['direct_attached_nvme_slots']:
            intersight.api_body['DirectAttachedNvmeSlots'] = module.params['direct_attached_nvme_slots']

    intersight.configure_policy_or_profile(resource_path)

    # Save the storage policy response
    storage_policy_response = intersight.result['api_response']
    storage_policy_moid = None
    if module.params['state'] == 'present' and storage_policy_response:
        storage_policy_moid = storage_policy_response.get('Moid')

    # Process drive groups if provided
    drive_groups_response = []
    if module.params['state'] == 'present' and module.params['drive_groups']:
        for drive_group_config in module.params['drive_groups']:
            # Build drive group API body
            drive_group_api_body = {
                'Name': drive_group_config['name'],
                'RaidLevel': drive_group_config['raid_level'],
                'SecureDriveGroup': drive_group_config.get('secure_drive_group', False),
                'Type': 0,  # Manual drive group
                'StoragePolicy': storage_policy_moid
            }

            # Build ManualDriveGroup
            manual_drive_group = {}

            # Add dedicated hot spares if specified (not for RAID0)
            dedicated_hot_spares = drive_group_config.get('dedicated_hot_spares')
            if dedicated_hot_spares and drive_group_config['raid_level'] != 'Raid0':
                manual_drive_group['DedicatedHotSpares'] = dedicated_hot_spares

            # Build span groups (required field)
            span_groups = drive_group_config.get('span_groups', [])
            # Transform lowercase 'slots' to uppercase 'Slots' for API
            api_span_groups = []
            for span_group in span_groups:
                api_span_groups.append({'Slots': span_group['slots']})
            manual_drive_group['SpanGroups'] = api_span_groups

            drive_group_api_body['ManualDriveGroup'] = manual_drive_group

            # Build virtual drives
            virtual_drives = []
            for virtual_drive_config in drive_group_config.get('virtual_drives', []):
                virtual_drive = {
                    'Name': virtual_drive_config['name'],
                    'ExpandToAvailable': virtual_drive_config.get('expand_to_available', False),
                    'BootDrive': virtual_drive_config.get('boot_drive', False),
                    'VirtualDrivePolicy': build_virtual_drive_policy(virtual_drive_config)
                }

                # Add size if specified and not expanding to available
                if not virtual_drive_config.get('expand_to_available', False):
                    virtual_drive['Size'] = virtual_drive_config.get('size', 0)

                virtual_drives.append(virtual_drive)

            drive_group_api_body['VirtualDrives'] = virtual_drives

            # Create the drive group
            resource_path = '/storage/DriveGroups'
            intersight.api_body = drive_group_api_body
            # Filter by both DriveGroup name AND StoragePolicy to avoid affecting DriveGroups in other policies
            custom_filter = f"Name eq '{drive_group_config['name']}' and StoragePolicy.Moid eq '{storage_policy_moid}'"
            intersight.configure_secondary_resource(
                resource_path=resource_path,
                state=drive_group_config.get('state', 'present'),
                custom_filter=custom_filter
            )

            # Save the drive group response
            drive_groups_response.append(intersight.result['api_response'])

    # Combine storage policy and drive groups in the main response
    if storage_policy_response:
        storage_policy_response['DriveGroups'] = drive_groups_response
        intersight.result['api_response'] = storage_policy_response

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
