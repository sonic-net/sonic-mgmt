#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Manage SSO """

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_sso
version_added: 2.16.0
short_description: Configures or queries SSO on Infinibox
description:
    - This module configures (present state) or gets information about (absent state) SSO on Infinibox
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Sets a name to reference the SSO by.
    required: true
    type: str
  issuer:
    description:
      - URI of the SSO issuer.
    required: false
    type: str
  sign_on_url:
    description:
      - URL for sign on.
    type: str
    required: false
  signed_assertion:
    description:
      - Signed assertion
    type: bool
    required: false
    default: false
  signed_response:
    description:
      - Signed response
    required: false
    type: bool
    default: false
  signing_certificate:
    description:
      - Signing certificate content.
    type: str
    required: false
  enabled:
    description:
      - Determines if the SSO is enabled.
    required: false
    default: true
    type: bool
  state:
    description:
      - Creates/Modifies the SSO, when using state present.
      - For state absent, the SSO is removed.
      - State stat shows the existing SSO's details.
    type: str
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
extends_documentation_fragment:
    - infinibox
"""

EXAMPLES = r"""
- name: Configure SSO
  infini_sso:
    name: OKTA
    enabled: true
    issuer: "http://www.okta.com/eykRra384o32rrTs"
    sign_on_url: "https://infinidat.okta.com/app/infinidat_psus/exkra32oyyU6KCUCk2p7/sso/saml"
    state: present
    user: admin
    password: secret
    system: ibox001

- name: Stat SSO
  infini_sso:
    name: OKTA
    state: stat
    user: admin
    password: secret
    system: ibox001

- name: Clear SSO configuration
  infini_sso:
    state: absent
    user: admin
    password: secret
    system: ibox001
"""

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    api_wrapper,
    merge_two_dicts,
    get_system,
    infinibox_argument_spec,
)

try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def find_sso(module, name):
    """ Find a SSO using its name """
    path = f"config/sso/idps?name={name}"

    try:
        system = get_system(module)
        sso_result = system.api.get(path=path).get_result()
    except APICommandFailed as err:
        msg = f"Cannot find SSO identity provider {name}: {err}"
        module.fail_json(msg=msg)

    return sso_result


def handle_stat(module):
    """ Handle the stat state """
    name = module.params["name"]
    sso_result = find_sso(module, name)
    if not sso_result:
        msg = f"SSO identity provider {name} not found. Cannot stat."
        module.fail_json(msg=msg)

    result = dict(
        changed=False,
        msg=f"SSO identity provider {name} stat found"
    )

    result = merge_two_dicts(result, sso_result[0])
    result['signing_certificate'] = "redacted"
    module.exit_json(**result)


def handle_present(module):  # pylint: disable=too-many-locals
    """ Handle the present state """
    enabled = module.params['enabled']
    issuer = module.params['issuer']
    sign_on_url = module.params['sign_on_url']
    signed_assertion = module.params['signed_assertion']
    signed_response = module.params['signed_response']
    signing_certificate = module.params['signing_certificate']
    name = module.params['name']

    existing_sso = find_sso(module, name)
    if existing_sso:
        existing_sso_id = existing_sso[0]['id']
        delete_sso(module, existing_sso_id)

    path = "config/sso/idps"
    data = {
        "enabled": enabled,
        "issuer": issuer,
        "name": name,
        "sign_on_url": sign_on_url,
        "signed_assertion": signed_assertion,
        "signed_response": signed_response,
        "signing_certificate": signing_certificate,
    }

    try:
        system = get_system(module)
        sso_result = system.api.post(path=path, data=data).get_result()
    except APICommandFailed as err:
        msg = f"Cannot configure SSO identity provider named {name}: {err}"
        module.fail_json(msg=msg)

    if not existing_sso:
        msg = f"SSO identity provider named {name} successfully configured"
    else:
        msg = f"SSO identity provider named {name} successfully removed and recreated with updated parameters"
    result = dict(
        changed=True,
        msg=msg,
    )
    result = merge_two_dicts(result, sso_result)
    result['signing_certificate'] = "redacted"

    module.exit_json(**result)


def delete_sso(module, sso_id):
    """ Delete a SSO. Reference its ID. """
    path = f"config/sso/idps/{sso_id}"
    name = module.params["name"]
    try:
        system = get_system(module)
        sso_result = system.api.delete(path=path).get_result()
    except APICommandFailed as err:
        msg = f"Cannot delete SSO identity provider {name}: {err}"
        module.fail_json(msg=msg)
    return sso_result


def handle_absent(module):
    """ Handle the absent state """
    name = module.params["name"]
    found_sso = find_sso(module, name)
    if not found_sso:
        result = dict(
            changed=False,
            msg=f"SSO {name} already not found"
        )
        module.exit_json(**result)

    sso_id = found_sso[0]['id']
    sso_result = delete_sso(module, sso_id)

    if not sso_result:
        msg = f"SSO identity provider named {name} with ID {sso_id} not found. Cannot delete."
        module.fail_json(msg=msg)

    result = dict(
        changed=True,
        msg=f"SSO identity provider named {name} deleted"
    )

    result = merge_two_dicts(result, sso_result)
    result['signing_certificate'] = "redacted"
    module.exit_json(**result)


def execute_state(module):
    """Handle states"""
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """Verify module options are sane"""
    signing_certificate = module.params["signing_certificate"]
    sign_on_url = module.params["sign_on_url"]
    state = module.params["state"]
    is_failed = False
    msg = ""
    if state in ["present"]:
        if not sign_on_url:
            msg += "A sign_on_url parameter must be provided. "
            is_failed = True
        if not signing_certificate:
            msg += "A signing_certificate parameter must be provided. "
            is_failed = True
    if is_failed:
        module.fail_json(msg=msg)


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            enabled=dict(required=False, type="bool", default=True),
            issuer=dict(required=False, default=None),
            name=dict(required=True),
            sign_on_url=dict(required=False, default=None),
            signed_assertion=dict(required=False, type="bool", default=False),
            signed_response=dict(required=False, type="bool", default=False),
            signing_certificate=dict(required=False, default=None, no_log=True),
            state=dict(default="present", choices=["stat", "present", "absent"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    check_options(module)
    execute_state(module)


if __name__ == "__main__":
    main()
