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
module: intersight_system_qos_policy
short_description: System QoS policy configuration for Cisco Intersight
description:
  - System QoS policy configuration for Cisco Intersight.
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
      - Profiles and Policies that are created within a Custom Organization are applicable only to devices in the same Organization.
    type: str
    default: default
  name:
    description:
      - The name assigned to the System QoS policy.
      - The name must be between 1 and 62 alphanumeric characters, allowing special characters :-_.
    type: str
    required: true
  tags:
    description:
      - List of tags in Key:<user-defined key> Value:<user-defined value> format.
    type: list
    elements: dict
  description:
    description:
      - The user-defined description of the System QoS policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  classes:
    description:
      - List of QoS classes configured in the policy.
      - System includes predefined classes (Bronze, Silver, Gold, Platinum, Best Effort, FC).
      - Best Effort and FC classes are always enabled and have restrictions on modifiable parameters.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Name of the QoS class.
          - Valid class names are Bronze, Silver, Gold, Platinum, Best Effort, FC.
        type: str
        required: true
        choices: [Bronze, Silver, Gold, Platinum, "Best Effort", FC]
      admin_state:
        description:
          - Administrative state of the QoS class.
          - Best Effort and FC classes are always enabled.
          - Bronze, Silver, Gold, and Platinum classes are disabled by default when not specified.
          - If not specified, appropriate class defaults will be applied automatically.
        type: str
        choices: [Enabled, Disabled]
      cos:
        description:
          - Class of service received by the traffic tagged with this QoS.
          - Valid range is 0-6.
          - FC class defaults to 3.
          - Bronze defaults to 1, Silver to 2, Gold to 4, Platinum to 5.
          - If not specified, appropriate class defaults will be applied automatically.
        type: int
      mtu:
        description:
          - Maximum transmission unit (MTU) is the largest size packet or frame, that can be sent in a packet- or frame-based network such as the Internet.
          - Valid range is 1500-9216.
          - Normal (default) maps to 1500, FC maps to 2240
          - FC class defaults to 2240, others default to 1500.
          - If not specified, appropriate class defaults will be applied automatically.
        type: int
      packet_drop:
        description:
          - If enabled, this QoS class will allow packet drops within an acceptable limit.
          - FC class defaults to false (no packet drop).
          - All other classes default to true (packet drop enabled).
          - If not specified, appropriate class defaults will be applied automatically.
        type: bool
      weight:
        description:
          - The weight of the QoS Class controls the distribution of bandwidth between QoS Classes.
          - Valid range is 0-10.
          - Bronze defaults to 7, Silver to 8, Gold to 9, Platinum to 10, Best Effort and FC to 5.
          - If not specified, appropriate class defaults will be applied automatically.
        type: int

author:
  - Ron Gershburg (@rgershbu)
'''

EXAMPLES = r'''
- name: Configure System QoS Policy with default classes
  cisco.intersight.intersight_system_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-system-qos
    description: System QoS policy for lab use
    tags:
      - Key: Site
        Value: RCDN
    classes:
      - name: Bronze
        admin_state: Enabled
        weight: 7
      - name: Silver
        admin_state: Enabled
        weight: 8
      - name: Gold
        admin_state: Enabled
        weight: 9
      - name: Platinum
        admin_state: Enabled
        weight: 10
      - name: 'Best Effort'
        weight: 5
      - name: FC
        weight: 5

- name: Configure System QoS Policy with custom settings
  cisco.intersight.intersight_system_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: custom-system-qos
    description: Custom System QoS policy
    classes:
      - name: Bronze
        admin_state: Enabled
        cos: 1
        mtu: 1500
        packet_drop: true
        weight: 7
      - name: Gold
        admin_state: Enabled
        cos: 4
        mtu: 1500
        packet_drop: true
        weight: 9
      - name: 'Best Effort'
        mtu: 1500
        weight: 6
      - name: FC
        weight: 8

- name: Delete System QoS Policy
  cisco.intersight.intersight_system_qos_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-system-qos
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "Name": "lab-system-qos"
    "Description": "System QoS policy for lab use"
    "Organization": {
        "ObjectType": "organization.Organization",
        "Moid": "675450ee69726530014753e2"
    }
    "Classes": [
        {
             "Name": "Bronze",
             "AdminState": "Enabled",
             "Cos": 1,
             "Mtu": 1500,
             "PacketDrop": true,
             "Weight": 7,
             "MulticastOptimize": false
        }
    ]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec

ALLOWED_CLASSES = ['Bronze', 'Silver', 'Gold', 'Platinum', 'Best Effort', 'FC']


def get_qos_class_defaults(class_name):
    """
    Get default values for QoS classes based on the class name.
    """
    defaults = {
        'Bronze': {
            'admin_state': 'Disabled',
            'cos': 1,
            'mtu': 1500,
            'packet_drop': True,
            'weight': 7
        },
        'Silver': {
            'admin_state': 'Disabled',
            'cos': 2,
            'mtu': 1500,
            'packet_drop': True,
            'weight': 8
        },
        'Gold': {
            'admin_state': 'Disabled',
            'cos': 4,
            'mtu': 1500,
            'packet_drop': True,
            'weight': 9
        },
        'Platinum': {
            'admin_state': 'Disabled',
            'cos': 5,
            'mtu': 1500,
            'packet_drop': True,
            'weight': 10
        },
        'Best Effort': {
            'admin_state': 'Enabled',
            'cos': 255,
            'mtu': 1500,
            'packet_drop': True,
            'weight': 5
        },
        'FC': {
            'admin_state': 'Enabled',
            'cos': 3,
            'mtu': 2240,
            'packet_drop': False,
            'weight': 5
        }
    }
    return defaults.get(class_name, {})


def validate_qos_class(qos_class, module):
    """
    Validate QoS class configuration and apply restrictions.
    """
    class_name = qos_class.get('name')
    if not class_name:
        module.fail_json(msg="QoS class name is required")

    # Apply restrictions for FC class
    if class_name == 'FC':
        if qos_class.get('admin_state') and qos_class['admin_state'] != 'Enabled':
            module.fail_json(msg="FC class must always be enabled")
        if qos_class.get('cos') and qos_class['cos'] != 3:
            module.fail_json(msg="FC class CoS must be 3")
        if qos_class.get('packet_drop') and qos_class['packet_drop']:
            module.fail_json(msg="FC class packet drop must be false")
        if qos_class.get('mtu') and qos_class['mtu'] != 2240:
            module.fail_json(msg="FC class MTU must be 2240")

    # Apply restrictions for Best Effort class
    if class_name == 'Best Effort':
        if qos_class.get('admin_state') and qos_class['admin_state'] != 'Enabled':
            module.fail_json(msg="Best Effort class must always be enabled")
        if qos_class.get('packet_drop') and not qos_class['packet_drop']:
            module.fail_json(msg="Best Effort class packet drop must be true")
        if qos_class.get('cos'):
            module.fail_json(msg="Best Effort class CoS cannot be modified by user")

    # Validate CoS values (Best Effort is handled above)
    if qos_class.get('cos') and class_name != 'Best Effort':
        cos_value = qos_class['cos']
        if cos_value < 0 or cos_value > 6:
            module.fail_json(msg="CoS value must be between 0-6")

    # Validate weight values
    if qos_class.get('weight'):
        weight_value = qos_class['weight']
        if weight_value < 0 or weight_value > 10:
            module.fail_json(msg="Weight value must be between 0-10")

    # Validate MTU values
    if qos_class.get('mtu'):
        mtu_value = qos_class['mtu']
        if mtu_value < 1500 or mtu_value > 9216:
            module.fail_json(msg="MTU value must be between 1500-9216")


def format_qos_classes(classes, module):
    """
    Format QoS classes for API submission, applying defaults and validations.
    """
    if not classes:
        # Return default configuration with all 6 classes
        default_classes = []
        for class_name in ALLOWED_CLASSES:
            defaults = get_qos_class_defaults(class_name)
            default_classes.append({
                'Name': class_name,
                'AdminState': defaults['admin_state'],
                'Cos': defaults['cos'],
                'Mtu': defaults['mtu'],
                'PacketDrop': defaults['packet_drop'],
                'Weight': defaults['weight'],
                'MulticastOptimize': False  # Always false, not user-configurable
            })
        return default_classes

    formatted_classes = []
    provided_class_names = [cls.get('name') for cls in classes]

    # Process provided classes
    for qos_class in classes:
        validate_qos_class(qos_class, module)
        class_name = qos_class['name']
        defaults = get_qos_class_defaults(class_name)

        formatted_class = {
            'Name': class_name,
            'AdminState': qos_class.get('admin_state') if qos_class.get('admin_state') else defaults['admin_state'],
            'Cos': qos_class.get('cos') if qos_class.get('cos') else defaults['cos'],
            'Mtu': qos_class.get('mtu') if qos_class.get('mtu') else defaults['mtu'],
            'PacketDrop': qos_class.get('packet_drop') if qos_class.get('packet_drop') else defaults['packet_drop'],
            'Weight': qos_class.get('weight') if qos_class.get('weight') else defaults['weight'],
            'MulticastOptimize': False  # Always false, not user-configurable
        }
        formatted_classes.append(formatted_class)

    # Add missing classes with defaults
    for class_name in ALLOWED_CLASSES:
        if class_name not in provided_class_names:
            defaults = get_qos_class_defaults(class_name)
            formatted_classes.append({
                'Name': class_name,
                'AdminState': defaults['admin_state'],
                'Cos': defaults['cos'],
                'Mtu': defaults['mtu'],
                'PacketDrop': defaults['packet_drop'],
                'Weight': defaults['weight'],
                'MulticastOptimize': False  # Always false, not user-configurable
            })

    return formatted_classes


def main():
    class_spec = dict(
        name=dict(type='str', required=True, choices=ALLOWED_CLASSES),
        admin_state=dict(type='str', choices=['Enabled', 'Disabled']),
        cos=dict(type='int'),
        mtu=dict(type='int'),
        packet_drop=dict(type='bool'),
        weight=dict(type='int')
    )

    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        classes=dict(type='list', elements='dict', options=class_spec)
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''

    # Resource path used to configure policy
    resource_path = '/fabric/SystemQosPolicies'
    # Define API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization']
        },
        'Name': intersight.module.params['name']
    }

    if module.params['state'] == 'present':
        # Format QoS classes with validation and defaults
        formatted_classes = format_qos_classes(module.params.get('classes'), module)
        intersight.api_body['Classes'] = formatted_classes
        intersight.set_tags_and_description()

    intersight.configure_policy_or_profile(resource_path=resource_path)

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
