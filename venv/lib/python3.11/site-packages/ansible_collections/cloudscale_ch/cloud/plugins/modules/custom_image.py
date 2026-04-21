#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, Ciril Troxler <ciril.troxler@cloudscale.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: custom_image
short_description: Manage custom images on the cloudscale.ch IaaS service
description:
  - Import, modify and delete custom images.
notes:
  - To import a new custom-image the I(url) and I(name) options are required.
author:
  - Ciril Troxler (@ctx)
  - Gaudenz Steinlin (@gaudenz)
version_added: 2.2.0
options:
  url:
    description:
      - The URL used to download the image.
    type: str
  force_retry:
    description:
      - Retry the image import even if a failed import using the same name and
        URL already exists. This is necessary to recover from download errors.
    default: false
    type: bool
  name:
    description:
      - The human readable name of the custom image. Either name or UUID must
        be present to change an existing image.
    type: str
  uuid:
    description:
      - The unique identifier of the custom image import. Either name or UUID
        must be present to change an existing image.
    type: str
  slug:
    description:
      - A string identifying the custom image for use within the API.
    type: str
  user_data_handling:
    description:
      - How user_data will be handled when creating a server. There are
        currently two options, "pass-through" and "extend-cloud-config".
    type: str
    choices: [ pass-through, extend-cloud-config ]
  zones:
    description:
      - Specify zones in which the custom image will be available (e.g. C(lpg1)
        or C(rma1)).
    type: list
    elements: str
  source_format:
    description:
      - The file format of the image referenced in the url.
    type: str
    choices: [ raw, qcow2 ]
    default: raw
  firmware_type:
    description:
      - The firmware type that will be used for servers created
        with this image.
    type: str
    choices: [ bios, uefi ]
    default: bios
  tags:
    description:
      - The tags assigned to the custom image.
    type: dict
  state:
    description: State of the coustom image.
    choices: [ present, absent ]
    default: present
    type: str
extends_documentation_fragment: cloudscale_ch.cloud.api_parameters
'''

EXAMPLES = r'''
- name: Import custom image
  cloudscale_ch.cloud.custom_image:
    name: "My Custom Image"
    url: https://ubuntu.com/downloads/hirsute.img
    slug: my-custom-image
    user_data_handling: extend-cloud-config
    zones: lpg1
    tags:
      project: luna
    state: present
  register: my_custom_image

- name: Wait until import succeeded
  cloudscale_ch.cloud.custom_image:
    uuid: "{{ my_custom_image.uuid }}"
  retries: 15
  delay: 5
  register: image
  until: image.import_status == 'success'
  failed_when: image.import_status == 'failed'

- name: Import custom image and wait until import succeeded
  cloudscale_ch.cloud.custom_image:
    name: "My Custom Image"
    url: https://ubuntu.com/downloads/hirsute.img
    slug: my-custom-image
    user_data_handling: extend-cloud-config
    zones: lpg1
    tags:
      project: luna
    state: present
  retries: 15
  delay: 5
  register: image
  until: image.import_status == 'success'
  failed_when: image.import_status == 'failed'

- name: Import custom image with UEFI firmware type
  cloudscale_ch.cloud.custom_image:
    name: "My Custom UEFI Image"
    url: https://ubuntu.com/downloads/hirsute.img
    slug: my-custom-uefi-image
    user_data_handling: extend-cloud-config
    zones: lpg1
    firmware_type: uefi
    tags:
      project: luna
    state: present
  register: my_custom_image

- name: Update custom image
  cloudscale_ch.cloud.custom_image:
    name: "My Custom Image"
    slug: my-custom-image
    user_data_handling: extend-cloud-config
    tags:
      project: luna
    state: present

- name: Delete custom image
  cloudscale_ch.cloud.custom_image:
    uuid: '{{ my_custom_image.uuid }}'
    state: absent

- name: List all custom images
  uri:
    url: 'https://api.cloudscale.ch/v1/custom-images'
    headers:
      Authorization: 'Bearer {{ query("env", "CLOUDSCALE_API_TOKEN") }}'
    status_code: 200
  register: image_list
- name: Search the image list for all images with name 'My Custom Image'
  set_fact:
    my_custom_images: '{{ image_list.json | selectattr("name","search", "My Custom Image" ) }}'
'''

RETURN = r'''
href:
  description: The API URL to get details about this resource.
  returned: success when state == present
  type: str
  sample: https://api.cloudscale.ch/v1/custom-imges/11111111-1864-4608-853a-0771b6885a3a
uuid:
  description: The unique identifier of the custom image.
  returned: success
  type: str
  sample: 11111111-1864-4608-853a-0771b6885a3a
name:
  description: The human readable name of the custom image.
  returned: success
  type: str
  sample: alan
created_at:
  description: The creation date and time of the resource.
  returned: success
  type: str
  sample: "2020-05-29T13:18:42.511407Z"
slug:
  description: A string identifying the custom image for use within the API.
  returned: success
  type: str
  sample: foo
checksums:
  description: The checksums of the custom image as key and value pairs. The
    algorithm (e.g. sha256) name is in the key and the checksum in the value.
    The set of algorithms used might change in the future.
  returned: success
  type: dict
  sample: {
    "md5": "5b3a1f21cde154cfb522b582f44f1a87",
    "sha256": "5b03bcbd00b687e08791694e47d235a487c294e58ca3b1af704120123aa3f4e6"
  }
user_data_handling:
  description: How user_data will be handled when creating a server. There are
    currently two options, "pass-through" and "extend-cloud-config".
  returned: success
  type: str
  sample: "pass-through"
tags:
  description: Tags assosiated with the custom image.
  returned: success
  type: dict
  sample: { 'project': 'my project' }
import_status:
  description: Shows the progress of an import. Values are one of
    "started", "in_progress", "success" or "failed".
  returned: success
  type: str
  sample: "in_progress"
error_message:
  description: Error message in case of a failed import.
  returned: success
  type: str
  sample: "Expected HTTP 200, got HTTP 403"
state:
  description: The current status of the custom image.
  returned: success
  type: str
  sample: present
'''


from ansible.module_utils.basic import (
    AnsibleModule,
)
from ansible.module_utils.urls import (
    fetch_url
)
from ..module_utils.api import (
    AnsibleCloudscaleBase,
    cloudscale_argument_spec,
)
from ansible.module_utils._text import (
    to_text
)


class AnsibleCloudscaleCustomImage(AnsibleCloudscaleBase):

    def _transform_import_to_image(self, imp):
        # Create a stub image from the import
        img = imp.get('custom_image', {})
        return {
            'href': img.get('href'),
            'uuid': imp['uuid'],
            'name': img.get('name'),
            'created_at': None,
            'size_gb': None,
            'checksums': None,
            'tags': imp['tags'],
            'url': imp['url'],
            'import_status': imp['status'],
            'error_message': imp.get('error_message', ''),
            # Even failed image imports are reported as present. This then
            # represents a failed import resource.
            'state': 'present',
            # These fields are not present on the import, assume they are
            # unchanged from the module parameters
            'user_data_handling': self._module.params['user_data_handling'],
            'zones': self._module.params['zones'],
            'slug': self._module.params['slug'],
            'firmware_type': self._module.params['firmware_type'],
        }

    # This method can be replaced by calling AnsibleCloudscaleBase._get form
    # AnsibleCloudscaleCustomImage._get once the API bug is fixed.
    def _get_url(self, url):

        response, info = fetch_url(self._module,
                                   url,
                                   headers=self._auth_header,
                                   method='GET',
                                   timeout=self._module.params['api_timeout'])

        if info['status'] == 200:
            response = self._module.from_json(
                to_text(response.read(),
                        errors='surrogate_or_strict'),
            )
        elif info['status'] == 404:
            # Return None to be compatible with AnsibleCloudscaleBase._get
            response = None
        elif info['status'] == 500 and url.startswith(self._api_url + self.resource_name + '/import/'):
            # Workaround a bug in the cloudscale.ch API which wrongly returns
            # 500 instead of 404
            response = None
        else:
            self._module.fail_json(
                msg='Failure while calling the cloudscale.ch API with GET for '
                '"%s"' % url,
                fetch_url_info=info,
            )

        return response

    def _get(self, api_call):

        # Split api_call into components
        api_url, call_uuid = api_call.split(self.resource_name)

        # If the api_call does not contain the API URL
        if not api_url:
            api_url = self._api_url

        # Fetch image(s) from the regular API endpoint
        response = self._get_url(api_url + self.resource_name + call_uuid) or []

        # Additionally fetch image(s) from the image import API endpoint
        response_import = self._get_url(
            api_url + self.resource_name + '/import' + call_uuid,
        ) or []

        # No image was found
        if call_uuid and response == [] and response_import == []:
            return None

        # Convert single image responses (call with UUID) into a list
        if call_uuid and response:
            response = [response]
        if call_uuid and response_import:
            response_import = [response_import]

        # Transform lists into UUID keyed dicts
        response = dict([(i['uuid'], i) for i in response])
        response_import = dict([(i['uuid'], i) for i in response_import])

        # Filter the import list so that successfull and in_progress imports
        # shadow failed imports
        response_import_filtered = dict([(k, v) for k, v
                                         in response_import.items()
                                         if v['status'] in ('success',
                                                            'in_progress')])
        # Only add failed imports if no import with the same name exists
        # Only add the last failed import in the list (there is no timestamp on
        # imports)
        import_names = set([v['custom_image']['name'] for k, v
                           in response_import_filtered.items()])
        for k, v in reversed(list(response_import.items())):
            name = v['custom_image']['name']
            if (v['status'] == 'failed' and name not in import_names):
                import_names.add(name)
                response_import_filtered[k] = v

        # Merge import list into image list
        for uuid, imp in response_import_filtered.items():
            if uuid in response:
                # Merge addtional fields only present on the import
                response[uuid].update(
                    url=imp['url'],
                    import_status=imp['status'],
                    error_message=imp.get('error_message', ''),
                )
            else:
                response[uuid] = self._transform_import_to_image(imp)

        if not call_uuid:
            return response.values()
        else:
            return next(iter(response.values()))

    def _post(self, api_call, data=None):
        # Only new image imports are supported, no direct POST call to image
        # resources are supported by the API
        if not api_call.endswith('custom-images'):
            self._module.fail_json(msg="Error: Bad api_call URL.")
        # Custom image imports use a different endpoint
        api_call += '/import'

        if self._module.params['url']:
            return self._transform_import_to_image(
                self._post_or_patch("%s" % api_call, 'POST', data),
            )
        else:
            self._module.fail_json(msg="Cannot import a new image without url.")

    def present(self):
        resource = self.query()

        # If the module passes the firmware_type argument,
        # and the module argument and API response are not the same for
        # argument firmware_type.
        if (resource.get('firmware_type') is not None
                and resource.get('firmware_type') !=
                self._module.params['firmware_type']):
            # Custom error if the module tries to change the firmware_type.
            msg = "Cannot change firmware type of an existing custom image"
            self._module.fail_json(msg)

        if resource['state'] == "absent":
            resource = self.create(resource)
        else:
            # If this is a failed upload and the URL changed or the "force_retry"
            # parameter is used, create a new image import.
            if (resource.get('import_status') == 'failed'
                and (resource['url'] != self._module.params['url']
                     or self._module.params['force_retry'])):
                resource = self.create(resource)
            else:
                resource = self.update(resource)

        return self.get_result(resource)


def main():
    argument_spec = cloudscale_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str'),
        slug=dict(type='str'),
        url=dict(type='str'),
        force_retry=dict(type='bool', default=False),
        user_data_handling=dict(type='str',
                                choices=('pass-through',
                                         'extend-cloud-config')),
        uuid=dict(type='str'),
        firmware_type=dict(type='str',
                           choices=('bios',
                                    'uefi'),
                           default=('bios')),
        tags=dict(type='dict'),
        state=dict(type='str', default='present',
                   choices=('present', 'absent')),
        zones=dict(type='list', elements='str'),
        source_format=dict(type='str', default='raw',
                           choices=('raw', 'qcow2')),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(('name', 'uuid'),),
        supports_check_mode=True,
    )

    cloudscale_custom_image = AnsibleCloudscaleCustomImage(
        module,
        resource_name='custom-images',
        resource_key_uuid='uuid',
        resource_key_name='name',
        resource_create_param_keys=[
            'name',
            'slug',
            'url',
            'user_data_handling',
            'firmware_type',
            'tags',
            'zones',
            'source_format',
        ],
        resource_update_param_keys=[
            'name',
            'slug',
            'user_data_handling',
            'firmware_type',
            'tags',
        ],
    )

    if module.params['state'] == "absent":
        result = cloudscale_custom_image.absent()
    else:
        result = cloudscale_custom_image.present()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
