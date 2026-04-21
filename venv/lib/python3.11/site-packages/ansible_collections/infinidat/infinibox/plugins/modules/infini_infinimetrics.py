#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position,too-many-locals

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""This module creates or modifies Infinibox registrations on Infinimetrics."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_infinimetrics
version_added: 2.16.0
short_description: Create (present state) or remove (absent state) an Infinibox registration on an Infinimetrics.
description:
    - Create (present state) or remove (absent state) an Infinibox registration on an Infinimetrics.
author: David Ohlemacher (@ohlemacher)
options:
  ibox_serial:
    description:
      - Infinibox serial number.
    type: str
    required: true
  ibox_url:
    description: Infinibox DNS resolvable hostname or IPv4 address.
    type: str
    required: false
  ibox_readonly_user:
    description:
      - Read only Infinibox user name.
    type: str
    required: false
  ibox_readonly_password:
    description:
      - Read only Infinibox user password.
    type: str
    required: false
  imx_system:
    description:
      - Infinimetrics hostname or IPv4 Address.
    type: str
    required: true
  imx_user:
    description:
      - Infinimetrics user name.
    type: str
    required: true
  imx_password:
    description:
      - Infinimetrics user password.
    type: str
    required: true
  state:
    description:
      - Registers the Infinibox with Infinimetrics, when using state present.
      - For state absent, the Infinibox is disabled on Infinimetrics and will no longer appear on the Infinimetrics UI.
      - State search_iboxes returns a json dictionary of information for Infiniboxes registered with the Infinimetrics.
      - Existing Infinibox data is not purged from Infinimetrics.
      - Purging may be executed using the Infinimetrics CLI tool.
    type: str
    required: false
    default: present
    choices: [ "present", "absent", "search_iboxes" ]
extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Register IBOX with Infinimetrics
  infini_infinimetrics:
    infinimetrics_system: infinimetrics
    state: present
    user: admin
    password: secret
    system: ibox001

- name: Deregister IBOX from Infinimetrics
  infini_infinimetrics:
    infinimetrics_system: infinimetrics
    state: absent
    user: admin
    password: secret
    system: ibox001
"""

# RETURN = r''' # '''

import re
import traceback

from ansible.module_utils.basic import missing_required_lib

try:
    import requests
except ImportError:
    HAS_REQUESTS = False
    HAS_REQUESTS_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_REQUESTS = True
    HAS_REQUESTS_IMPORT_ERROR = None

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    api_wrapper,
    get_system,
    infinibox_argument_spec,
)


def find_csrfmiddleware_token(response):
    """Search for csrfmiddlewaretoken in the response lines. Return token or None."""
    token = None
    for line_bytes in response.iter_lines():
        line = str(line_bytes)
        # Example of line searched for:
        # <input type="hidden" name="csrfmiddlewaretoken" value="VUe6...m5Nl7y">'
        result = re.search(r'"csrfmiddlewaretoken" value="(\w+)"', line)
        if result:
            token = result.group(1)
            break
    return token


@api_wrapper
def imx_login(module, imx_session):
    """ Log into an IMX (GET and POST) using credentials. """
    imx_system = module.params.get('imx_system')
    path = f"https://{imx_system}/auth/login/"

    # Get a token
    get_response = imx_session.get(path, data=None, verify=False)
    status_code = get_response.status_code
    if status_code not in [200]:
        text = get_response.text
        msg = f"Cannot log into Infinimetrics {imx_system}. Status code: {status_code}. Text returned: {text}"
        module.fail_json(msg=msg)

    token = find_csrfmiddleware_token(get_response)

    # Use POST provide token
    data = {
        'csrfmiddlewaretoken': token,
        'password': module.params.get('imx_password', None),
        'username': module.params.get('imx_user', None),
    }
    headers = {
        'referer': f'https://{module.params.get("imx_system")}',
    }
    response = imx_session.post(path, headers=headers, data=data, verify=False)
    if response.status_code not in [200, 201]:
        msg = f"Cannot log into Infinimetrics {imx_system}. Status code: {response.status_code}. Text returned: {response.text}"
        module.fail_json(msg=msg)


@api_wrapper
def imx_system_add(module, imx_session):
    """ Add an Infinibox to an Infinimetrics using an imx_session """
    imx_system = module.params.get('imx_system')
    ibox_readonly_user = module.params.get('ibox_readonly_user')
    ibox_readonly_password = module.params.get('ibox_readonly_password')
    ibox_serial = module.params.get('ibox_serial')
    ibox_url = module.params.get('ibox_url')
    path = f"https://{imx_system}/system/add/"
    headers = {
        'referer': f'https://{imx_system}/',
    }

    # Use GET to get a token
    get_response = imx_session.get(path, headers=headers, verify=False)
    status_code = get_response.status_code
    if status_code not in [200]:
        text = get_response.text
        msg = f"Cannot add Infinibox {ibox_url} to Infinimetrics {imx_system}. Status code: {status_code}. Text returned: {text}"
        module.fail_json(msg=msg)

    get_token = find_csrfmiddleware_token(get_response)

    # Use POST provide token
    data = {
        'api_url': ibox_url,
        'api_username': ibox_readonly_user,
        'api_password': ibox_readonly_password,
        'csrfmiddlewaretoken': get_token,
    }
    response = imx_session.post(path, headers=headers, data=data, verify=False)
    status_code = response.status_code
    text = response.text
    if status_code not in [200, 201]:
        msg = f"Cannot add Infinibox {ibox_url} to Infinimetrics {imx_system}. Status code: {status_code}. Text returned: {text}"
        module.fail_json(msg=msg)

    # Check that the IBOX was added or was previously added.
    # Search for one of:
    #   - 'The system is already monitored'
    #   - add_progress url
    if ("The system is already" not in response.text or "monitored" not in response.text) \
            and (f"/system/{ibox_serial}/add_progress" not in response.text):
        msg = f"Cannot add Infinibox {ibox_url} to Infinimetrics {imx_system}. Status code: {status_code}. Text returned: {text}"
        module.fail_json(msg=msg)

    if "add_progress" in response.text:
        return True  # Just added now
    return False  # Previously added


@api_wrapper
def imx_system_delete(module, imx_session):
    """ Remove an Infinibox from an Infinimetrics using an imx_session """
    imx_system = module.params.get('imx_system')
    serial = module.params.get('ibox_serial')
    ibox_url = module.params.get('ibox_url')
    path = f"https://{imx_system}/system/{serial}/edit/"
    headers = {
        'referer': f'https://{imx_system}/',
    }

    # Use GET to get a token
    get_response = imx_session.get(path, headers=headers, verify=False)
    status_code = get_response.status_code
    if status_code not in [200]:
        text = get_response.text
        msg = f"Cannot remove Infinibox {ibox_url} from Infinimetrics {imx_system}. Status code: {status_code}. Text returned: {text}"
        module.fail_json(msg=msg)

    get_token = find_csrfmiddleware_token(get_response)

    path = f"https://{imx_system}/system/{serial}/remove/"
    headers = {
        'X-CSRFToken': get_token,
        'referer': f'https://{imx_system}/',
    }
    response = imx_session.delete(path, headers=headers, verify=False)

    # Check that the IBOX was removed or was previously removed
    # In response.return_code, search for 200
    status_code = response.status_code
    if status_code not in [200, 201]:
        text = response.text
        msg = f"Cannot remove Infinibox {serial} from infinimetrics {imx_system}. Status code: {status_code}, Text returned: {text}"
        module.fail_json(msg=msg)


@api_wrapper
def imx_system_search_iboxes(module, imx_session):
    """Search for iboxes registered with an Infinimetrics using an imx_session """
    imx_system = module.params.get('imx_system')
    path = f"https://{imx_system}/api/rest/systems?page_size=1000"
    headers = None

    get_response = imx_session.get(path, headers=headers, verify=False)
    status_code = get_response.status_code
    if status_code not in [200]:
        text = get_response.text
        msg = f"Cannot search for Infiniboxes registered with Infinimetrics {imx_system}. Status code: {status_code}. Text returned: {text}"
        module.fail_json(msg=msg)
    return get_response.json()


def handle_present(module):
    """ Handle the present state parameter """
    imx_system = module.params.get('imx_system')
    ibox_url = module.params.get('ibox_url')

    imx_session = requests.session()
    imx_login(module, imx_session)
    is_newly_added = imx_system_add(module, imx_session)

    if is_newly_added:
        msg = f"Infinibox {ibox_url} added to Infinimetrics {imx_system}"
        changed = True
    else:
        msg = f"Infinibox {ibox_url} previously added to Infinimetrics {imx_system}"
        changed = False

    result = dict(changed=changed, msg=msg)
    module.exit_json(**result)


def handle_absent(module):
    """ Handle the absent state parameter. """
    imx_system = module.params.get('imx_system')
    serial = module.params.get('ibox_serial')

    imx_session = requests.session()
    imx_login(module, imx_session)
    imx_system_delete(module, imx_session)
    result = dict(
        changed=True,
        msg=f"Infinibox serial {serial} has been removed from Infinimetrics {imx_system}"
    )
    module.exit_json(**result)


def handle_search_iboxes(module):
    """ Handle the search state parameter. Use to find IBOXs. """
    imx_system = module.params.get('imx_system')

    imx_session = requests.session()
    imx_login(module, imx_session)
    ibox_json = imx_system_search_iboxes(module, imx_session)
    result = dict(
        changed=False,
        msg=f"Successfully searched Infinimetrics {imx_system} for registered Infiniboxes",
        ibox_json = ibox_json,
    )
    module.exit_json(**result)


def execute_state(module):
    """Handle states"""
    state = module.params["state"]
    try:
        if state == "present":
            handle_present(module)
            system = get_system(module)
            system.logout()
        elif state == "absent":
            handle_absent(module)
        elif state == "search_iboxes":
            handle_search_iboxes(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        pass


def verify_params(module, req_params):
    """ Verify that required params are provided """
    missing_req_params = []
    for req_param in req_params:
        if not module.params[req_param]:
            missing_req_params.append(req_param)
    if missing_req_params:
        state = module.params["state"]
        msg = f"Cannot handle state {state} due to missing parameters: {missing_req_params}"
        module.fail_json(msg=msg)


def check_options(module):  # pylint: disable=too-many-branches
    """ Check option logic """
    state = module.params['state']

    if state == 'present':
        req_params = ["ibox_url", "ibox_readonly_user", "ibox_readonly_password", "ibox_serial"]
        verify_params(module, req_params)
    elif state == 'absent':
        req_params = ["ibox_serial"]
        verify_params(module, req_params)
    elif state == 'search_iboxes':
        pass
    else:
        module.fail_json(msg=f'Internal handler error. Invalid state: {state}')


def main():
    """ Main """
    # This module does not use infinibox_argument_spec() from infinibox.py
    argument_spec = dict(
        stay_logged_in=dict(required=False, type=bool, default=False),
        stay_logged_in_minutes=dict(required=False, type=int, default=5),
    )
    argument_spec.update(
        dict(
            ibox_serial=dict(required=False),
            ibox_url=dict(required=False, default=None),
            ibox_readonly_user=dict(required=False, default=None),
            ibox_readonly_password=dict(required=False, no_log=True, default=None),
            imx_system=dict(required=True),
            imx_user=dict(required=True),
            imx_password=dict(required=True, no_log=True),
            state=dict(default="present", choices=["present", "absent", "search_iboxes"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(
            msg=missing_required_lib('requests'),
            exception=HAS_REQUESTS_IMPORT_ERROR,
        )

    check_options(module)

    execute_state(module)


if __name__ == "__main__":
    main()
