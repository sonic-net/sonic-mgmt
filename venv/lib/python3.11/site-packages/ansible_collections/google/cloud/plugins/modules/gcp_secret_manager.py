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
module: gcp_secret_manager
description:
- Access secrets stored in Google Secrets Manager.
- Create new secrets.
- Create new secret values.
- Add/remove versions of secrets.
- Please note that other features like etags, replication, annontation expected to be managed outside of Ansible.
- Deals with regional secrets if location option is defined.
short_description: Access and Update Google Cloud Secrets Manager objects
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  project:
    description:
    - The Google Cloud Platform project to use.
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
    - Name of the secret to be used
    type: str
    required: true
    aliases:
    - key
    - secret
    - secret_id
  location:
    description:
    - If provided, it defines the location of the regional secret.
    type: str
  value:
    description:
    - The secret value that the secret should have
    - this will be set upon create
    - If the secret value is not this, a new version will be added with this value
    type: str
  state:
    description:
    - whether the secret should exist
    default: present
    choices:
    - absent
    - present
    type: str
  return_value:
    description:
    - if true, the value of the secret will be returned unencrypted to Ansible
    - if false, no value will be returned or decrypted
    type: bool
    default: true
  version:
    description:
    - A version label to apply to the secret
    - Default is "latest" which is the newest version of the secret
    - The special "all" is also acceptable on delete (which will delete all versions of a secret)
    type: str
    default: latest
  labels:
    description:
    - A set of key-value pairs to assign as labels to asecret
    - only used in creation
    - Note that the "value" piece of a label must contain only readable chars
    type: dict
    default: {}
notes:
- 'API Reference: U(https://cloud.google.com/secret-manager/docs/reference/rests)'
- 'Official Documentation: U(https://cloud.google.com/secret-manager/docs/overview)'
- for authentication, you can set service_account_file using the C(GCP_SERVICE_ACCOUNT_FILE)
  env variable.
- for authentication, you can set service_account_contents using the C(GCP_SERVICE_ACCOUNT_CONTENTS)
  env variable.
- For authentication, you can set service_account_email using the C(GCP_SERVICE_ACCOUNT_EMAIL)
  env variable.
- For authentication, you can set auth_kind using the C(GCP_AUTH_KIND) env variable.
- For authentication, you can set scopes using the C(GCP_SCOPES) env variable.
- Environment variables values will only be used if the playbook values are not set.
- The I(service_account_email) and I(service_account_file) options are mutually exclusive.
'''

EXAMPLES = '''
- name: Create a new secret
  google.cloud.gcp_secret_manager:
    name: secret_key
    value: super_secret
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Ensure the secretexists, fail otherwise and return the value
  google.cloud.gcp_secret_manager:
    name: secret_key
    state: present

- name: Ensure secret exists but don't return the value
  google.cloud.gcp_secret_manager:
    name: secret_key
    state: present
    return_value: false

- name: Add a new version of a secret
  google.cloud.gcp_secret_manager:
    name: secret_key
    value: updated super secret
    state: present

- name: Delete version 1 of a secret (but not the secret itself)
  google.cloud.gcp_secret_manager:
    name: secret_key
    version: 1
    state: absent

- name: Delete all versions of a secret
  google.cloud.gcp_secret_manager:
    name: secret_key
    version: all
    state: absent

- name: Create a secret with labels
  google.cloud.gcp_secret_manager:
    name: secret_key
    value: super_secret
    labels:
      key_name: "ansible_rox"

- name: Create a new regional secret
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    value: super_secret
    state: present
    auth_kind: serviceaccount
    service_account_file: service_account_creds.json

- name: Ensure the regional secret exists, fail otherwise and return the value
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    state: present

- name: Ensure regional secret exists but don't return the value
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    state: present
    return_value: false

- name: Add a new version of a regional secret
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    value: updated super secret
    state: present

- name: Delete version 1 of a regional secret (but not the secret itself)
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    version: 1
    state: absent

- name: Delete all versions of a regional secret
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    version: all
    state: absent

- name: Create a regional secret with labels
  google.cloud.gcp_secret_manager:
    name: secret_key
    location: us-central1
    value: super_secret
    labels:
      key_name: "ansible_rox"
'''

RETURN = '''
resources:
  description: List of resources
  returned: always
  type: complex
  contains:
    name:
      description:
      - The name of the secret
      returned: success
      type: str
    location:
      description:
      - The location of the regional secret.
      returned: success
      type: str
    version:
      description:
      - The version number of the secret returned
      returned: success
      type: str
    url:
      description:
      - The Google Cloud URL used to make the request
      returned: success
      type: str
    status_code:
      description:
      - The HTTP status code of the response to Google Cloud
      returned: success
      type: str
    msg:
      description:
      - A message indicating what was done (or not done)
      returned: success, failure
      type: str
    value:
      description:
      - The decrypted secret value, please use care with this
      returned: success
      type: str
    payload:
      description:
      - The base 64 secret payload including CRC for validation
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

# for decoding and validating secrets
import json
import base64
import copy


def get_auth(module):
    return GcpSession(module, 'secret-manager')


def make_url_prefix(module):
    if module.params['location']:
        return "https://secretmanager.{location}.rep.googleapis.com/v1/projects/{project}/locations/{location}/"
    return "https://secretmanager.googleapis.com/v1/projects/{project}/"


def self_access_link(module):
    return (make_url_prefix(module) + "secrets/{name}/versions/{calc_version}:access").format(**module.params)


def self_get_link(module):
    return (make_url_prefix(module) + "secrets/{name}/versions/{calc_version}").format(**module.params)


def self_update_link(module):
    return (make_url_prefix(module) + "secrets/{name}/versions/{calc_version:version}").format(**module.params)


def self_list_link(module):
    return (make_url_prefix(module) + "secrets/{name}/versions?filter=state:ENABLED").format(**module.params)


def self_delete_link(module):
    return (make_url_prefix(module) + "secrets/{name}").format(**module.params)


def fetch_resource(module, allow_not_found=True):
    auth = get_auth(module)
    # set version to the latest version because
    # we can't be sure that "latest" is always going
    # to be set if secret versions get disabled
    # see https://issuetracker.google.com/issues/286489671
    if module.params['version'] == "latest" or module.params['version'] == 'all':
        version_list = list_secret_versions(module)
        latest_version = None
        if version_list is None:
            return None

        if "versions" in version_list:
            versions_numbers = []
            for version in version_list['versions']:
                versions_numbers.append(version['name'].split('/')[-1])
            latest_version = sorted(versions_numbers, key=int)[-1]
            module.params['calc_version'] = latest_version
        else:
            # if this occurs, there are no available secret versions
            # handle the corner case that we tried to delete
            # a secret version that doesn't exist
            if module.params['state'] == "absent":
                return {"action": "delete_secret"}

    link = self_access_link(module)
    access_obj = return_if_object(module, auth.get(link), allow_not_found)
    if access_obj is None:
        return None
    link = self_get_link(module)
    get_obj = return_if_object(module, auth.get(link), allow_not_found)
    if get_obj is None:
        return None
    return merge_dicts(get_obj, access_obj)


def merge_dicts(x, y):
    z = copy.deepcopy(x)
    z.update(y)
    return z


# create secret is a create call + an add version call
def create_secret(module):
    # build the payload
    payload = {"replication": {"automatic": {}}}
    if module.params['location']:
        payload = dict()
    if module.params['labels']:
        payload['labels'] = module.params['labels']

    url = (make_url_prefix(module) + "secrets").format(**module.params)
    auth = get_auth(module)
    post_response = auth.post(url, body=payload, params={'secretId': module.params['name']})
    # validate create
    module.raise_for_status(post_response)
    return update_secret(module)


def update_secret(module):
    # build the payload
    b64_value = base64.b64encode(module.params['value'].encode("utf-8")).decode("utf-8")
    payload = {
        u'payload': {
            u'data': b64_value
        }
    }
    auth = get_auth(module)
    url = (make_url_prefix(module) + "secrets/{name}:addVersion").format(**module.params)
    return return_if_object(module, auth.post(url, payload), False)


def list_secret_versions(module):
    # filter by only enabled secrets
    url = self_list_link(module)
    auth = get_auth(module)
    return return_if_object(module, auth.get(url), True)


# technically we're destroying the version
def delete_secret(module, destroy_all=False):
    # delete secret does not take "latest" as a default version
    # get the latest version if it doesn't exist in the request
    version = module.params['version']
    auth = get_auth(module)
    if version.lower() == "all" or destroy_all:
        url = self_delete_link(module)
        return return_if_object(module, auth.delete(url))
    else:
        url = self_get_link(module) + ":destroy"
        return return_if_object(module, auth.post(url, {}), False)


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
            result['version'] = result['name'].split("/")[-1]
            if 'locations' in result['name'].split("/"):
                result['location'] = result['name'].split("/")[3]
                result['name'] = result['name'].split("/")[5]
            else:
                result['name'] = result['name'].split("/")[3]

        # base64 decode the value
        if "payload" in result and "data" in result['payload']:
            result['value'] = base64.b64decode(result['payload']['data']).decode("utf-8")

    except getattr(json.decoder, 'JSONDecodeError', ValueError):
        module.fail_json(msg="Invalid JSON response with error: %s" % response.text)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def main():
    # limited support for parameters described in the "Secret" resource
    # in order to simplify and deploy primary use cases
    # expectation is customers needing to support additional capabilities
    # in the SecretPayload will do so outside of Ansible.
    # ref: https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets#Secret
    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            name=dict(required=True, type='str', aliases=['key', 'secret', 'secret_id']),
            location=dict(required=False, type='str'),
            value=dict(required=False, type='str'),
            version=dict(required=False, type='str', default='latest'),
            return_value=dict(required=False, type='bool', default=True),
            labels=dict(required=False, type='dict', default=dict())
        )
    )

    if not module.params['scopes']:
        module.params['scopes'] = ["https://www.googleapis.com/auth/cloud-platform"]

    module.params['calc_version'] = module.params['version']

    state = module.params['state']
    fetch = fetch_resource(module, allow_not_found=True)
    changed = False

    # nothing came back, so the secret doesn't exist
    if not fetch:
        # doesn't exist, must create
        if module.params.get('value') and state == 'present':
            # create a new secret
            fetch = create_secret(module)
            changed = True
        # specified present but no value
        # fail, let the user know
        # that no secret could be created without a value to encrypt
        elif state == 'present':
            module.fail_json(msg="secret '{name}' not present in '{project}' and no value for the secret is provided".format(**module.params))

        # secret is absent, success
        else:
            fetch = {"msg": "secret '{name}' in project '{project}' not present".format(**module.params)}

    else:
        # delete the secret version (latest if no version is specified)
        if state == "absent":
            # delete the secret
            fetch = delete_secret(module, ("action" in fetch))
            fetch['msg'] = "Secret Destroyed, it may take time to propagate"
            changed = True

        # check to see if the values are the same, and update if neede
        if "value" in fetch and module.params.get('value') is not None:
            # Update secret
            if fetch['value'] != module.params['value']:
                update_secret(module)
                changed = True
            else:
                fetch['msg'] = "values identical, no need to update secret"

        # pop value data if return_value == false
        if module.params['return_value'] is False:
            fetch.pop('value')
            fetch.pop('payload')
            if "msg" in fetch:
                fetch['msg'] = "{} | not returning secret value since 'return_value is set to false".format(fetch['msg'])
            else:
                fetch['msg'] = "not returning secret value since 'return_value is set to false"

    fetch['changed'] = changed
    fetch['name'] = module.params['name']

    module.exit_json(**fetch)


if __name__ == "__main__":
    main()
