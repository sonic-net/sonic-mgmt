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
module: intersight_virtual_media_policy
short_description: Virtual Media policy configuration for Cisco Intersight
description:
  - Virtual Media policy configuration for Cisco Intersight.
  - Used to configure Virtual Media image mappings on Cisco Intersight managed devices.
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
      - The name assigned to the NTP policy.
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
      - The user-defined description of the NTP policy.
      - Description can contain letters(a-z, A-Z), numbers(0-9), hyphen(-), period(.), colon(:), or an underscore(_).
    type: str
    aliases: [descr]
  enable:
    description:
      - Enable or disable virtual media.
    type: bool
    default: true
  encryption:
    description:
      - If enabled, allows encryption of all Virtual Media communications
    type: bool
    default: false
  low_power_usb:
    description:
      - If enabled, the virtual drives appear on the boot selection menu after mapping the image and rebooting the host.
    type: bool
    default: true
  cdd_virtual_media:
    description:
      - CDD Virtual Media image mapping options.
    type: dict
    suboptions:
      enable:
        description:
          - Enable or disable CDD image mapping.
        type: bool
        default: true
      mount_type:
        description:
          - Type (protocol) of network share used by the remote_hostname.
          - Ensure that the remote_hostname's communication port for the mount type that you choose is accessible from the managed endpoint.
          - For CIFS as your mount type, ensure port 445 (which is its communication port) on the remote_hostname is accessible.
          - For HTTP, ensure port 80 is accessible.
          - For HTTPS, ensure port 443 is accessible.
          - For NFS, ensure port 2049 is accessible.
        type: str
        choices: [nfs,cifs,http,https]
        required: true
      volume:
        description:
          - A user defined name of the image mounted for mapping.
        type: str
        required: true
      remote_hostname:
        description:
          - Hostname or IP address of the server hosting the virtual media image.
        type: str
        required: true
      remote_path:
        description:
          - Filepath (not including the filename) of the remote image.
          - Ex. mnt/SHARE/ISOS
        type: str
        required: true
      remote_file:
        description:
          - Filename of the remote image.
          - Ex. custom_image.iso
        type: str
        required: true
      username:
        description:
          - The username for the specified Mount Type, if required.
        type: str
      password:
        description:
          - The password for the selected username, if required.
        type: str
      mount_options:
        description:
          - Mount options for the Virtual Media mapping.
          - For NFS, supported options are ro, rw, nolock, noexec, soft, port=VALUE, timeo=VALUE, retry=VALUE
          - For CIFS, supported options are soft, nounix, noserverino, guest
        type: str
        required: false
      authentication_protocol:
        description:
          - Authentication Protocol for CIFS Mount Type
        type: str
        default: none
        required: false
  hdd_virtual_media:
    description:
      - HDD Virtual Media image mapping options.
    type: dict
    suboptions:
      enable:
        description:
          - Enable or disable HDD image mapping.
        type: bool
        default: true
      mount_type:
        description:
          - Type (protocol) of network share used by the remote_hostname.
          - Ensure that the remote_hostname's communication port for the mount type that you choose is accessible from the managed endpoint.
          - For CIFS as your mount type, ensure port 445 (which is its communication port) on the remote_hostname is accessible.
          - For HTTP, ensure port 80 is accessible.
          - For HTTPS, ensure port 443 is accessible.
          - For NFS, ensure port 2049 is accessible.
        type: str
        choices: [nfs,cifs,http,https]
        required: true
      volume:
        description:
          - A user defined name of the image mounted for mapping.
        type: str
        required: true
      remote_hostname:
        description:
          - Hostname or IP address of the server hosting the virtual media image.
        type: str
        required: true
      remote_path:
        description:
          - Filepath (not including the filename) of the remote image.
          - Ex. mnt/SHARE/ISOS
        type: str
        required: true
      remote_file:
        description:
          - Filename of the remote image.
          - Ex. custom_image.iso
        type: str
        required: true
      username:
        description:
          - The username for the specified Mount Type, if required.
        type: str
      password:
        description:
          - The password for the selected username, if required.
        type: str
      mount_options:
        description:
          - Mount options for the Virtual Media mapping.
          - For NFS, supported options are ro, rw, nolock, noexec, soft, port=VALUE, timeo=VALUE, retry=VALUE
          - For CIFS, supported options are soft, nounix, noserverino, guest
        type: str
        required: false
      authentication_protocol:
        description:
          - Authentication Protocol for CIFS Mount Type
        type: str
        default: none
        required: false
author:
  - David Soper (@dsoper2)
  - Sid Nath (@SidNath21)
'''

EXAMPLES = r'''
- name: Configure Virtual Media Policy
  cisco.intersight.intersight_virtual_media_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-vmedia
    description: Virutal Media policy for lab use
    tags:
      - Key: Site
        Value: RCDN
    cdd_virtual_media:
      mount_type: nfs
      volume: nfs-cdd
      remote_hostname: 172.28.224.77
      remote_path: mnt/SHARE/ISOS/CENTOS
      remote_file: CentOS7.iso
    hdd_virtual_media:
      mount_type: nfs
      volume: nfs-hdd
      remote_hostname: 172.28.224.77
      remote_path: mnt/SHARE/ISOS/CENTOS
      remote_file: CentOS7.iso

- name: Delete Virtual Media Policy
  cisco.intersight.intersight_virtual_media_policy:
    api_private_key: "{{ api_private_key }}"
    api_key_id: "{{ api_key_id }}"
    organization: DevNet
    name: lab-vmedia
    state: absent
'''

RETURN = r'''
api_response:
  description: The API response output returned by the specified resource.
  returned: always
  type: dict
  sample:
    "api_response": {
        "Name": "lab-ntp",
        "ObjectType": "ntp.Policy",
        "Tags": [
            {
                "Key": "Site",
                "Value": "RCDN"
            }
        ]
    }
'''


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.intersight.plugins.module_utils.intersight import IntersightModule, intersight_argument_spec, compare_values


def main():
    path = '/vmedia/Policies'
    virtual_media_mapping = dict(
        enable=dict(type='bool', default=True),
        mount_type=dict(type='str', choices=['nfs', 'cifs', 'http', 'https'], required=True),
        volume=dict(type='str', required=True),
        remote_hostname=dict(type='str', required=True),
        remote_path=dict(type='str', required=True),
        remote_file=dict(type='str', required=True),
        mount_options=dict(type='str'),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
        authentication_protocol=dict(type='str', default='none'),
    )
    argument_spec = intersight_argument_spec.copy()
    argument_spec.update(
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        organization=dict(type='str', default='default'),
        name=dict(type='str', required=True),
        description=dict(type='str', aliases=['descr']),
        tags=dict(type='list', elements='dict'),
        enable=dict(type='bool', default=True),
        encryption=dict(type='bool', default=False),
        low_power_usb=dict(type='bool', default=True),
        cdd_virtual_media=dict(type='dict', options=virtual_media_mapping),
        hdd_virtual_media=dict(type='dict', options=virtual_media_mapping),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    intersight = IntersightModule(module)
    intersight.result['api_response'] = {}
    intersight.result['trace_id'] = ''
    # Defined API body used in compares or create
    intersight.api_body = {
        'Organization': {
            'Name': intersight.module.params['organization'],
        },
        'Name': intersight.module.params['name'],
        'Tags': intersight.module.params['tags'],
        'Description': intersight.module.params['description'],
        'Enabled': intersight.module.params['enable'],
        "Encryption": intersight.module.params['encryption'],
        "LowPowerUsb": intersight.module.params['low_power_usb'],
        'Mappings': [],
    }

    if intersight.module.params.get('cdd_virtual_media'):
        intersight.api_body['Mappings'].append(
            {
                "ClassId": "vmedia.Mapping",
                "ObjectType": "vmedia.Mapping",
                "AuthenticationProtocol": intersight.module.params['cdd_virtual_media']['authentication_protocol'],
                "DeviceType": "cdd",
                "HostName": intersight.module.params['cdd_virtual_media']['remote_hostname'],
                "Password": intersight.module.params['cdd_virtual_media']['password'],
                "IsPasswordSet": intersight.module.params['cdd_virtual_media']['password'] != '',
                "MountOptions": intersight.module.params['cdd_virtual_media']['mount_options'],
                "MountProtocol": intersight.module.params['cdd_virtual_media']['mount_type'],
                "RemoteFile": intersight.module.params['cdd_virtual_media']['remote_file'],
                "RemotePath": intersight.module.params['cdd_virtual_media']['remote_path'],
                "Username": intersight.module.params['cdd_virtual_media']['username'],
                "VolumeName": intersight.module.params['cdd_virtual_media']['volume'],
            }
        )
    if intersight.module.params.get('hdd_virtual_media'):
        intersight.api_body['Mappings'].append(
            {
                "ClassId": "vmedia.Mapping",
                "ObjectType": "vmedia.Mapping",
                "AuthenticationProtocol": intersight.module.params['hdd_virtual_media']['authentication_protocol'],
                "DeviceType": "hdd",
                "HostName": intersight.module.params['hdd_virtual_media']['remote_hostname'],
                "Password": intersight.module.params['hdd_virtual_media']['password'],
                "IsPasswordSet": intersight.module.params['hdd_virtual_media']['password'] != '',
                "MountOptions": intersight.module.params['hdd_virtual_media']['mount_options'],
                "MountProtocol": intersight.module.params['hdd_virtual_media']['mount_type'],
                "RemoteFile": intersight.module.params['hdd_virtual_media']['remote_file'],
                "RemotePath": intersight.module.params['hdd_virtual_media']['remote_path'],
                "Username": intersight.module.params['hdd_virtual_media']['username'],
                "VolumeName": intersight.module.params['hdd_virtual_media']['volume'],
            }
        )

    organization_moid = None
    # GET Organization Moid
    intersight.get_resource(
        resource_path='/organization/Organizations',
        query_params={
            '$filter': "Name eq '" + intersight.module.params['organization'] + "'",
            '$select': 'Moid',
        },
    )
    if intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        organization_moid = intersight.result['api_response']['Moid']

    intersight.result['api_response'] = {}
    # get the current state of the resource
    filter_str = "Name eq '" + intersight.module.params['name'] + "'"
    filter_str += "and Organization.Moid eq '" + organization_moid + "'"
    intersight.get_resource(
        resource_path=path,
        query_params={
            '$filter': filter_str,
            '$expand': 'Organization',
        },
    )

    moid = None
    resource_values_match = False
    if intersight.result['api_response'].get('Moid'):
        # resource exists and moid was returned
        moid = intersight.result['api_response']['Moid']
        if module.params['state'] == 'present':
            resource_values_match = compare_values(intersight.api_body, intersight.result['api_response'])
        else:  # state == 'absent'
            intersight.delete_resource(
                moid=moid,
                resource_path=path,
            )
            moid = None

    if module.params['state'] == 'present' and not resource_values_match:
        # remove read-only Organization key
        intersight.api_body.pop('Organization')
        if not moid:
            # Organization must be set, but can't be changed after initial POST
            intersight.api_body['Organization'] = {
                'Moid': organization_moid,
            }
        intersight.configure_resource(
            moid=moid,
            resource_path=path,
            body=intersight.api_body,
            query_params={
                '$filter': filter_str,
            },
        )

    module.exit_json(**intersight.result)


if __name__ == '__main__':
    main()
