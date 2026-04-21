#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)


__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "certified",
}

DOCUMENTATION = """
---
module: cyberark_authentication
short_description: CyberArk Authentication using PAS Web Services SDK.
author:
    - Edward Nunez (@enunez-cyberark)
    - Cyberark Bizdev (@cyberark-bizdev)
version_added: '1.0.0'
description:
    - Authenticates to CyberArk Vault using Privileged Account Security
      Web Services SDK and creates a session fact that can be used by other
      modules. It returns an Ansible fact called I(cyberark_session). Every
      module can use this fact as C(cyberark_session) parameter.
options:
    state:
        default: present
        choices: [present, absent]
        description:
            - Specifies if an authentication logon/logoff and a
              cyberark_session should be added/removed.
        type: str
    username:
        description:
            - The name of the user who will logon to the Vault.
        type: str
    password:
        description:
            - The password of the user.
        type: str
    new_password:
        description:
            - The new password of the user. This parameter is optional,
              and enables you to change a password.
        type: str
    api_base_url:
        description:
            - A string containing the base URL of the server hosting
              CyberArk's Privileged Account Security Web Services SDK.
        type: str
    validate_certs:
        type: bool
        default: 'true'
        description:
            - If C(false), SSL certificates will not be validated.  This
              should only set to C(false) used on personally controlled
              sites using self-signed certificates.
    use_ldap_authentication:
        type: bool
        default: 'false'
        description:
            - Whether or not LDAP will be used.
    use_windows_authentication:
        type: bool
        default: 'false'
        description:
            - Whether or not Windows will be used.
    use_cyberark_authentication:
        type: bool
        default: 'false'
        description:
            - Whether or not LDAP will be used.
    use_radius_authentication:
        type: bool
        default: 'false'
        description:
            - Whether or not users will be authenticated via a RADIUS
              server. Valid values are true/false.
    connection_number:
        type: int
        description:
            - To support multiple connections for same user specify
            - different value for this parameter.
    concurrentSession:
        type: bool
        default: false
        description:
            - Whether or not to allow concurrent sessions for the same user.
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the
              different values to perform actions on a logged-on CyberArk
              session.
        type: dict
    timeout:
        description:
            - Allows you set a timeout for when your authenticating to Cyberark
        default: 10
        type: int
"""

EXAMPLES = """
- name: Logon - use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    use_shared_logon_authentication: true

- name: Logon - Not use_shared_logon_authentication
  cyberark_authentication:
    api_base_url: "{{ web_services_base_url }}"
    username: "{{ password_object.password }}"
    password: "{{ password_object.passprops.username }}"
    use_shared_logon_authentication: false

- name: Logoff from CyberArk Vault
  cyberark_authentication:
    state: absent
    cyberark_session: "{{ cyberark_session }}"
"""

RETURN = """
cyberark_session:
    description: Authentication facts.
    returned: success
    type: complex
    contains:
        api_base_url:
            description:
                - Base URL for API calls. Returned in the cyberark_session,
                  so it can be used in subsequent calls.
            type: str
            returned: always
        token:
            description:
                - The token that identifies the session, encoded in BASE 64.
            type: str
            returned: always
        use_shared_logon_authentication:
            description:
                - Whether or not Shared Logon Authentication was used to
                  establish the session.
            type: bool
            returned: always
        validate_certs:
            description: Whether or not SSL certificates should be validated.
            type: bool
            returned: always
"""

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.http_client import HTTPException
import json


def processAuthentication(module):

    # Getting parameters from module

    api_base_url = module.params["api_base_url"]
    validate_certs = module.params["validate_certs"]
    username = module.params["username"]
    password = module.params["password"]
    new_password = module.params["new_password"]

    use_radius = module.params["use_radius_authentication"]
    use_ldap = module.params["use_ldap_authentication"]
    use_windows = module.params["use_windows_authentication"]
    use_cyberark = module.params["use_cyberark_authentication"]

    # connection_number = module.params["connection_number"]
    state = module.params["state"]
    cyberark_session = module.params["cyberark_session"]

    concurrentSession = module.params["concurrentSession"]

    timeout = module.params["timeout"]

    # if in check mode it will not perform password changes
    if module.check_mode and new_password is not None:
        new_password = None

    # Defining initial values for open_url call
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
    }

    payload = ""

    if state == "present":  # Logon Action

        # Different end_points based on the use of desired method of auth

        if use_ldap:
            end_point = "/PasswordVault/API/Auth/LDAP/Logon"

        elif use_radius:
            end_point = "/PasswordVault/API/Auth/radius/Logon"

        elif use_windows:
            end_point = "/PasswordVault/API/auth/Windows/Logon"

        else:
            use_cyberark = True
            end_point = "/PasswordVault/API/Auth/CyberArk/Logon"

        # The payload will contain username, password
        # and optionally use_radius_authentication and new_password
        payload_dict = {"username": username, "password": password}

        if new_password is not None and use_cyberark:
            payload_dict["newPassword"] = new_password

        # COMMENT: I dont know what this is for and the old api seems like it didnt have this field
        # if connection_number is not None:
        #     payload_dict["connectionNumber"] = connection_number

        if concurrentSession:
            payload_dict["concurrentSession"] = True

        payload = json.dumps(payload_dict)

    else:  # Logoff Action

        # Get values from cyberark_session already established
        api_base_url = cyberark_session["api_base_url"]
        validate_certs = cyberark_session["validate_certs"]

        headers["Authorization"] = cyberark_session["token"]

        # All off the logoff with the same endpoint
        end_point = "/PasswordVault/API/Auth/Logoff"

    result = None
    changed = False
    response = None

    try:

        response = open_url(
            api_base_url + end_point,
            method="POST",
            headers=headers,
            data=payload,
            validate_certs=validate_certs,
            timeout=timeout,
        )

    except (HTTPError, HTTPException) as http_exception:

        module.fail_json(
            msg=(
                "Error while performing authentication."
                "Please validate parameters provided, and ability to logon to "
                "CyberArk.\n*** end_point=%s%s\n ==> %s"
            )
            % (api_base_url, end_point, to_text(http_exception)),
            headers=headers,
            status_code=http_exception.code,
        )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing authentication."
                "\n*** end_point=%s%s\n%s"
                % (api_base_url, end_point, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )

    if response.getcode() == 200:  # Success

        if state == "present":  # Logon Action

            # Result token from REST Api uses a different key based
            # the use of shared logon authentication
            token = ""
            try:
                token = str(json.loads(response.read()))

                # the new one just returns a token
                # if use:
                #     token = json.loads(response.read())["LogonResult"]
                # else:
                #     token = json.loads(response.read())["CyberArkLogonResult"]
            except Exception as e:
                module.fail_json(
                    msg="Error obtaining token\n%s" % (to_text(e)),
                    payload=payload,
                    headers=headers,
                    status_code=-1,
                )

            # Preparing result of the module
            result = {
                "cyberark_session": {
                    "token": token,
                    "api_base_url": api_base_url,
                    "validate_certs": validate_certs,
                }
            }

            if new_password is not None:
                # Only marks change if new_password was received resulting
                # in a password change
                changed = True

        else:  # Logoff Action clears cyberark_session

            result = {"cyberark_session": {}}

        return (changed, result, response.getcode())

    else:
        module.fail_json(msg="error in end_point=>" + end_point, headers=headers)


def main():

    fields = {
        "api_base_url": {"type": "str"},
        "validate_certs": {"type": "bool", "default": "true"},
        "username": {"type": "str"},
        "password": {"type": "str", "no_log": True},
        "new_password": {"type": "str", "no_log": True},
        "use_radius_authentication": {"default": False, "type": "bool"},
        "use_windows_authentication": {"default": False, "type": "bool"},
        "use_ldap_authentication": {"default": False, "type": "bool"},
        "use_cyberark_authentication": {"default": False, "type": "bool"},
        "concurrentSession": {"default": False, "type": "bool"},
        "connection_number": {"type": "int"},
        "state": {
            "type": "str",
            "choices": ["present", "absent"],
            "default": "present",
        },
        "cyberark_session": {"type": "dict"},
        "timeout": {"default": 10, "type": "int"},
    }

    # cyberark and radius -> mutually_exclusive is cyberark and ldap
    # ldap and radius
    # windows has to be by itself

    mutually_exclusive = [
        [
            "use_windows_authentication",
            "use_ldap_authentication",
            "use_cyberark_authentication",
            "use_radius_authentication",
        ],
        ["use_radius_authentication", "new_password"],
        ["use_windows_authentication", "new_password"],
        ["use_ldap_authentication", "new_password"],
        ["api_base_url", "cyberark_session"],
    ]

    required_if = [
        ("state", "present", ["api_base_url"]),
        ("state", "absent", ["cyberark_session"]),
    ]

    required_together = [["username", "password"]]

    module = AnsibleModule(
        argument_spec=fields,
        mutually_exclusive=mutually_exclusive,
        required_if=required_if,
        required_together=required_together,
        supports_check_mode=True,
    )

    (changed, result, status_code) = processAuthentication(module)

    module.exit_json(changed=changed, ansible_facts=result, status_code=status_code)


if __name__ == "__main__":
    main()
