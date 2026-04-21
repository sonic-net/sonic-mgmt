#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt
# or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

################################################################################
# Documentation
################################################################################


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ["preview"], 'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_parameter_manager
description:
- Access and Update Google Cloud Parameter Manager objects
- Create new parameters.
- Create new parameters with format.
- Create new parameters with labels.
- Create new parameters with format and labels.
- Add/Remove parameter version.
- Remove parameter.
short_description: Access and Update Google Cloud Parameter Manager objects
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 3.7
- requests >= 2.32.3
- google-auth >= 2.39.0
options:
  project:
    description:
    - The Google Cloud Platform project to use. Defaults to OS env variable
      GCP_PROJECT if not present
    type: str
  auth_kind:
    description:
    - The type of credential used.
    type: str
    required: true
    choices:
    - application
    - machineaccount
    - serviceaccount
    - accesstoken
  service_account_contents:
    description:
    - The contents of a Service Account JSON file, either in a dictionary or as a
      JSON string that represents it.
    type: jsonarg
  service_account_file:
    description:
    - The path of a Service Account JSON file if serviceaccount is selected as type.
    type: path
  service_account_email:
    description:
    - An optional service account email address if machineaccount is selected and
      the user does not wish to use the default email.
    type: str
  access_token:
    description:
    - An OAuth2 access token if credential type is accesstoken.
    type: str
  scopes:
    description:
    - Array of scopes to be used
    type: list
    elements: str
  env_type:
    description:
    - Specifies which Ansible environment you're running this module within.
    - This should not be set unless you know what you're doing.
    - This only alters the User Agent string for any API requests.
    type: str
  name:
    description:
    - Name of the parameter to be used
    type: str
    required: true
    aliases:
    - key
    - parameter
    - parameter_id
  format:
    description:
    - Format of the parameter to be used.
    type: str
    default: UNFORMATTED
    choices:
    - UNFORMATTED
    - JSON
    - YAML
  location:
    description:
    - Location of the parameter to be used
    type: str
    default: global
  version:
    description:
    - Name of the parameter to be used
    type: str
    required: false
    aliases:
    - version_id
    - parameter_version_id
  value:
    description:
    - The parameter value that the parameter should have
    - this will be set upon create
    - If the parameter value is not this, a new version will be added with this value
    type: str
  state:
    description:
    - whether the parameter should exist
    default: present
    choices:
    - absent
    - present
    type: str
  return_value:
    description:
    - if true, the value of the parameter will be returned unencrypted to Ansible
    - if false, no value will be returned or decrypted
    type: bool
    default: true
  labels:
    description:
    - A set of key-value pairs to assign as labels to a parameter
    - only used in creation
    - Note that the "value" piece of a label must contain only readable chars
    type: dict
    default: {}
'''

EXAMPLES = '''
- name: Create a new parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Create a new parameter with version
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    value: super_parameter
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Create a new structured parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    format: JSON
    value: '{"key":"value"}'
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Create a parameter with labels
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    value: super_parameter
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json
    labels:
      key_name: "ansible_rox"

- name: Create a structured parameter with labels
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    format: JSON
    value: '{"key":"value"}'
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json
    labels:
      key_name: "ansible_rox"

- name: Ensure the parameter exists, fail otherwise and return the value
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: present

- name: Ensure parameter exists but don't return the value
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: present
    return_value: false

- name: Add a new version of a parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    value: updated super parameter
    state: present

- name: Delete version 1 of a parameter (but not the parameter itself)
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    state: absent

- name: Delete parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: absent

- name: Create a new regional parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Create a new regional parameter with version
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    value: super_parameter
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Create a new structured regional parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    format: JSON
    value: '{"key":"value"}'
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Create a regional parameter with labels
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    value: super_parameter
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json
    labels:
      key_name: "ansible_rox"

- name: Create a structured regional parameter with labels
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    format: JSON
    value: '{"key":"value"}'
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json
    labels:
      key_name: "ansible_rox"

- name: Ensure the regional parameter exists, fail otherwise and return the value
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: present

- name: Ensure regional parameter exists but don't return the value
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: present
    return_value: false

- name: Add a new version of a regional parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    value: updated super parameter
    state: present

- name: Delete version 1 of a regional parameter (but not the regional parameter itself)
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    version: version_key
    state: absent

- name: Delete parameter
  google.cloud.gcp_parameter_manager:
    name: parameter_key
    state: absent
'''

RETURN = '''
resources:
  description: List of resources
  returned: always
  type: complex
  contains:
    name:
      description:
      - The name of the parameter
      returned: success
      type: str
    location:
      description:
      - The location of the regional parameter
      returned: success
      type: str
    version:
      description:
      - the version of the parameter returned
      returned: success
      type: str
    url:
      description:
      - the Google Cloud URL used to make the request
      returned: success
      type: str
    status_code:
      description:
      - the HTTP status code of the response to Google Cloud
      returned: success
      type: str
    msg:
      description:
      - A message indicating what was done (or not done)
      returned: success, failure
      type: str
    value:
      description:
      - The decrypted parameter data value, please use care with this
      returned: success
      type: str
    payload:
      description:
      - The base 64 parameter payload
      returned: success
      type: dict
'''


################################################################################
# Imports
################################################################################

from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    navigate_hash,
    GcpSession,
    GcpModule
)

# for decoding and validating parameters
import json
import base64


def get_auth(module):
    return GcpSession(module, 'parameter-manager')


def make_url_prefix(module):
    if module.params.get('location') is not None and module.params.get('location') != 'global':
        return "https://parametermanager.{location}.rep.googleapis.com/v1/projects/{project}/locations/{location}/"
    return "https://parametermanager.googleapis.com/v1/projects/{project}/locations/global/"


def self_parameter_link(module):
    return (make_url_prefix(module) + "parameters/{name}").format(**module.params)


def self_parameter_version_link(module):
    return (make_url_prefix(module) + "parameters/{name}/versions/{version}").format(**module.params)


def self_parameter_list_link(module):
    return (make_url_prefix(module) + "parameters").format(**module.params)


def self_parameter_version_list_link(module):
    return (make_url_prefix(module) + "parameters/{name}/versions").format(**module.params)


def check_parameter_exist(module, allow_not_found=True):
    auth = get_auth(module)
    param_list = list_parameters(module)
    if param_list is None:
        return None

    link = self_parameter_link(module)
    access_obj = return_if_object(module, auth.get(link), allow_not_found)
    if access_obj is None:
        return None
    return access_obj


def check_parameter_version_exist(module, allow_not_found=True):
    auth = get_auth(module)
    version_list = list_parameter_versions(module)
    if version_list is None:
        return None

    link = self_parameter_version_link(module)
    access_obj = return_if_object(module, auth.get(link), allow_not_found)
    if access_obj is None:
        return None
    return access_obj


def create_parameter(module):
    # build the payload
    payload = dict()
    if module.params.get('format'):
        payload['format'] = module.params.get('format')
    if module.params.get('labels'):
        payload['labels'] = module.params.get('labels')

    url = (make_url_prefix(module) + "parameters?parameter_id={name}").format(**module.params)
    auth = get_auth(module)
    # validate create
    return return_if_object(module, auth.post(url, payload), False)


def create_parameter_version(module):
    # build the payload
    b64_value = base64.b64encode(module.params.get('value').encode("utf-8")).decode("utf-8")
    payload = {
        u'payload': {
            u'data': b64_value
        }
    }
    auth = get_auth(module)
    url = (make_url_prefix(module) + "parameters/{name}/versions?parameter_version_id={version}").format(**module.params)
    # validate create
    return return_if_object(module, auth.post(url, payload), False)


def list_parameters(module):
    url = self_parameter_list_link(module)
    auth = get_auth(module)
    return return_if_object(module, auth.get(url), True)


def list_parameter_versions(module):
    # filter by only enabled parameter version
    url = self_parameter_version_list_link(module)
    auth = get_auth(module)
    return return_if_object(module, auth.get(url), True)


def delete_parameter(module):
    auth = get_auth(module)
    url = self_parameter_link(module)
    return return_if_object(module, auth.delete(url), True)


def delete_parameter_version(module):
    auth = get_auth(module)
    url = self_parameter_version_link(module)
    return return_if_object(module, auth.delete(url), True)


def return_if_object(module, response, allow_not_found=False):
    # If not found, return nothing.
    if allow_not_found and response.status_code == 404:
        return None

    if response.status_code == 409:
        module.params['info'] = "exists already"
        return None

    # probably a code error
    if response.status_code == 400:
        module.fail_json(msg="unexpected REST failure: %s" % response.json()['error'])

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
        result['url'] = response.request.url
        result['status_code'] = response.status_code
        if "name" in result:
            result['location'] = result['name'].split("/")[3]
            result['name'] = result['name'].split("/")[5]
            if len(result['name'].split("/")) == 8:
                result['version'] = result['name'].split("/")[-1]

        # base64 decode the value
        if "payload" in result and "data" in result['payload']:
            result['value'] = base64.b64decode(result['payload']['data']).decode("utf-8")

    except getattr(json.decoder, 'JSONDecodeError', ValueError):
        module.fail_json(msg="Invalid JSON response with error: %s" % response.text)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def main():
    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str', aliases=['key', 'parameter', 'parameter_id']),
            version=dict(required=False, type='str', aliases=['version_id', 'parameter_version_id']),
            location=dict(required=False, type='str', default='global'),
            value=dict(required=False, type='str'),
            format=dict(required=False, type='str', default='UNFORMATTED', choices=['UNFORMATTED', 'JSON', 'YAML']),
            return_value=dict(required=False, type='bool', default=True),
            labels=dict(required=False, type='dict', default=dict())
        )
    )

    try :
        if module.params.get('scopes') is None:
            module.params['scopes'] = ["https://www.googleapis.com/auth/cloud-platform"]

        if module.params.get('project') is None:
            module.fail_json(msg="The project is required. Please specify the Google Cloud project to use.")

        state = module.params.get('state')
        changed = False
        fetch = check_parameter_exist(module, allow_not_found=True)
        fetch_version = None
        if fetch:
            fetch_version = check_parameter_version_exist(module, allow_not_found=True)

        if state == 'present':
            # if parameter not exist
            if not fetch:
                # doesn't exist, must create
                if module.params.get('version') and module.params.get('value'):
                    # create a new parameter
                    fetch = create_parameter(module)
                    fetch = create_parameter_version(module)
                    changed = True
                # specified present and verison is provided but value is not provided
                elif module.params.get('version') and module.params.get('value') is None:
                    module.fail_json(
                        msg="parameter '{name}' not present in '{project}' and no value for the parameter version is provided".format(**module.params)
                    )
                # specified present and verison is not provided
                # that no parameter could be created without a version
                elif module.params.get('value'):
                    module.fail_json(msg="parameter '{name}' not present in '{project}' and no version for the parameter is provided".format(**module.params))
                # specified present but no value
                # that no parameter version could be created without a value to encrypt
                else:
                    fetch = create_parameter(module)
                    changed = True

            elif not fetch_version:
                # doesn't exist, must create
                if module.params.get('version') and module.params.get('value'):
                    fetch = create_parameter_version(module)
                    changed = True
                # specified present and verison is provided but value is not provided
                elif module.params.get('version') and module.params.get('value') is None:
                    module.fail_json(msg="parameter '{name}' present in '{project}' and no value for the parameter version is provided".format(**module.params))
                # specified present and verison is not provided
                # that no parameter could be created without a version
                elif module.params.get('value'):
                    module.fail_json(msg="parameter '{name}' present in '{project}' and no version for the parameter is provided".format(**module.params))
                # specified present but no value
                # that no parameter could be created without a value to encrypt
                else:
                    module.fail_json(
                        msg="parameter '{name}' present in '{project}' and no value and version for the parameter is provided".format(**module.params)
                    )

            else:
                # parameter and parameter version both exist
                # check if the value is the same
                # if not, delete the version and create new one
                # if the value is the same, do nothing
                if "value" in fetch_version and module.params.get('value', '') is not None:
                    if fetch_version['value'] != module.params.get('value'):
                        fetch['msg'] = 'values not identical, but parameter version name is same'
                        # Delete existing version and create new one
                        fetch = delete_parameter_version(module)
                        fetch = create_parameter_version(module)
                        changed = True
                    else:
                        module.exit_json(msg="parameter '{name}' is already exist and value is the same".format(**module.params))
                elif module.params.get('value', '') is None:
                    module.fail_json(msg="parameter '{name}' present in '{project}' and no value for the parameter version is provided".format(**module.params))

        else:
            if fetch is None:
                fetch = {}
                module.exit_json(msg="parameter {name} is not exist".format(**module.params))

            if fetch_version is None and module.params.get('version'):
                fetch = {}
                module.exit_json(msg="parameter version {version} is not exist".format(**module.params))

            if module.params.get('version'):
                version = delete_parameter_version(module)
                if version is not None:
                    fetch = version
                    changed = True
                else:
                    module.exit_json(msg="parameter version {version} is already deleted".format(**module.params))
            else:
                versions = list_parameter_versions(module)
                if versions is not None:
                    version = versions.get('parameterVersions', None)
                    if version is None:
                        param = delete_parameter(module)
                        if param is not None:
                            changed = True
                            fetch = param
                        else:
                            module.exit_json(msg="parameter {name} is already deleted".format(**module.params))
                    else:
                        module.fail_json(msg="parameter {name} has nested version resources".format(**module.params))
                else:
                    module.exit_json(msg="parameter {name} is not exist".format(**module.params))

        # # pop value data if return_value == false
        if module.params.get('return_value') is False:
            if "value" in fetch:
                fetch.pop('value')
            if "payload" in fetch:
                fetch.pop('payload')
            if "msg" in fetch:
                fetch['msg'] = "{} | not returning parameter value since 'return_value' is set to false".format(fetch['msg'])
            else:
                fetch['msg'] = "not returning parameter value since 'return_value' is set to false"

        fetch['changed'] = changed
        fetch['name'] = module.params.get('name')
    except Exception as e:
        module.fail_json(msg=str(e))

    module.exit_json(**fetch)


if __name__ == "__main__":
    main()
