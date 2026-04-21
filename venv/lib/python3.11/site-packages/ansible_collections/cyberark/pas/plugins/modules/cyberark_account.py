#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)


__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cyberark_account
short_description: Module for CyberArk Account object creation, deletion,
    modification, and password retrieval using PAS Web Services SDK.
author:
    - CyberArk BizDev (@cyberark-bizdev)
    - Edward Nunez (@enunez-cyberark)
    - James Stutes (@jimmyjamcabd)
version_added: '1.0.0'
description:
    - Creates a URI for adding, deleting, modifying, and retrieving a privileged credential
      within the Cyberark Vault.  The request uses the Privileged Account
      Security Web Services SDK.


options:
    state:
        description:
            - Assert the desired state of the account C(present) to create or
              update and account object. Set to C(absent) for deletion of an
              account object. Set to C(retrieve) to get the account object including the password.
        required: false
        default: present
        choices: [present, absent, retrieve]
        type: str
    logging_level:
        description:
            - Parameter used to define the level of troubleshooting output to
              the C(logging_file) value.
        required: false
        choices: [NOTSET, DEBUG, INFO]
        type: str
    logging_file:
        description:
            - Setting the log file name and location for troubleshooting logs.
        required: false
        default: /tmp/ansible_cyberark.log
        type: str
    api_base_url:
        description:
            - A string containing the base URL of the server hosting CyberArk's
              Privileged Account Security Web Services SDK.
            - Example U(https://<IIS_Server_Ip>/PasswordVault/api/)
        required: false
        type: str
    validate_certs:
        description:
            - If C(false), SSL certificate chain will not be validated.  This
              should only set to C(true) if you have a root CA certificate
              installed on each node.
        required: false
        default: true
        type: bool
    cyberark_session:
        description:
            - Dictionary set by a CyberArk authentication containing the
              different values to perform actions on a logged-on CyberArk
              session, please see M(cyberark.pas.cyberark_authentication) module for an
              example of cyberark_session.
        required: true
        type: dict
    identified_by:
        description:
            - When an API call is made to Get Accounts, often times the default
              parameters passed will identify more than one account. This
              parameter is used to confidently identify a single account when
              the default query can return multiple results.
        required: false
        default: username,address,platform_id
        type: str
    safe:
        description:
            - The safe in the Vault where the privileged account is to be
              located.
        required: true
        type: str
    platform_id:
        description:
            - The PolicyID of the Platform that is to be managing the account
        required: false
        type: str
    address:
        description:
            - The address of the endpoint where the privileged account is
              located.
        required: false
        type: str
    name:
        description:
            - The ObjectID of the account
        required: false
        type: str
    secret_type:
        description:
            - The value that identifies what type of account it will be.
        required: false
        default: password
        choices: [password, key]
        type: str
    secret:
        description:
            - The initial password for the creation of the account
        required: false
        type: str
    new_secret:
        description:
            - The new secret/password to be stored in CyberArk Vault.
        type: str
    username:
        description:
            - The username associated with the account.
        required: false
        type: str
    secret_management:
        description:
            - Set of parameters associated with the management of the
              credential.
        required: false
        type: dict
        suboptions:
            automatic_management_enabled:
                description:
                    - Parameter that indicates whether the CPM will manage
                        the password or not.
                default: false
                type: bool
            manual_management_reason:
                description:
                    - String value indicating why the CPM will NOT manage
                        the password.
                type: str
            management_action:
                description:
                    - CPM action flag to be placed on the account object
                        for credential rotation.
                choices: [change, change_immediately, reconcile]
                type: str
            new_secret:
                description:
                    - The actual password value that will be assigned for
                        the CPM action to be taken.
                type: str
            perform_management_action:
                description:
                    - C(always) will perform the management action in
                        every action.
                    - C(on_create) will only perform the management action
                        right after the account is created.
                choices: [always, on_create]
                default: always
                type: str
    remote_machines_access:
        description:
            - Set of parameters for defining PSM endpoint access targets.
        required: false
        type: dict
        suboptions:
            remote_machines:
                description:
                    - List of targets allowed for this account.
                type: str
            access_restricted_to_remote_machines:
                description:
                    - Whether or not to restrict access only to specified
                        remote machines.
                type: bool
    platform_account_properties:
        description:
            - Object containing key-value pairs to associate with the account,
              as defined by the account platform. These properties are
              validated against the mandatory and optional properties of the
              specified platform's definition. Optional properties that do not
              exist on the account will not be returned here. Internal
              properties are not returned.
        required: false
        type: dict
        suboptions:
            KEY:
                description:
                    - Freeform key value associated to the mandatory or
                        optional property assigned to the specified
                        Platform's definition.
                aliases: [Port, ExtrPass1Name, database]
                type: str
"""

EXAMPLES = """
- name: Logon to CyberArk Vault using PAS Web Services SDK
  cyberark.pas.cyberark_authentication:
    api_base_url: "http://components.cyberark.local"
    validate_certs: false
    username: "bizdev"
    password: "Cyberark1"

- name: Creating an Account using the PAS WebServices SDK
  cyberark.pas.cyberark_account:
    logging_level: DEBUG
    identified_by: "address,username"
    safe: "Test"
    address: "cyberark.local"
    username: "administrator-x"
    platform_id: WinServerLocal
    secret: "@N&Ibl3!"
    platform_account_properties:
        LogonDomain: "cyberark"
        OwnerName: "ansible_user"
    secret_management:
        automatic_management_enabled: true
    state: present
    cyberark_session: "{{ cyberark_session }}"
    register: cyberarkaction

- name: Rotate credential via reconcile and providing the password to be changed to
  cyberark.pas.cyberark_account:
    identified_by: "address,username"
    safe: "Domain_Admins"
    address: "prod.cyberark.local"
    username: "admin"
    platform_id: WinDomain
    platform_account_properties:
        LogonDomain: "PROD"
    secret_management:
        new_secret: "Ama123ah12@#!Xaamdjbdkl@#112"
        management_action: "reconcile"
        automatic_management_enabled: true
    state: present
    cyberark_session: "{{ cyberark_session }}"
    register: reconcileaccount

- name: Update password only in VAULT
  cyberark.pas.cyberark_account:
    identified_by: "address,username"
    safe: "Domain_Admins"
    address: "prod.cyberark.local"
    username: "admin"
    platform_id: Generic
    new_secret: "Ama123ah12@#!Xaamdjbdkl@#112"
    state: present
    cyberark_session: "{{ cyberark_session }}"
    register: updateaccount

- name: Retrieve account and password
  cyberark.pas.cyberark_account:
    identified_by: "address,username"
    safe: "Domain_Admins"
    address: "prod.cyberark.local"
    username: "admin"
    state: retrieve
    cyberark_session: "{{ cyberark_session }}"
    register: retrieveaccount

- name: Logoff from CyberArk Vault
  cyberark.pas.cyberark_authentication:
    state: absent
    cyberark_session: "{{ cyberark_session }}"
"""

RETURN = """
changed:
    description:
        - Identify if the playbook run resulted in a change to the account in
          any way.
    returned: always
    type: bool
failed:
    description: Whether playbook run resulted in a failure of any kind.
    returned: always
    type: bool
status_code:
    description: Result HTTP Status code.
    returned: success
    type: int
    sample: "200, 201, -1, 204"
result:
    description: A json dump of the resulting action.
    returned: success
    type: complex
    contains:
        address:
            description:
                - The adress of the endpoint where the privileged account is
                  located.
            returned: successful addition and modification
            type: str
            sample: dev.local
        createdTime:
            description:
                - Timeframe calculation of the timestamp of account creation.
            returned: successful addition and modification
            type: int
            sample: "1567824520"
        id:
            description: Internal ObjectID for the account object identified
            returned: successful addition and modification
            type: int
            sample: "25_21"
        name:
            description: The external ObjectID of the account
            returned: successful addition and modification
            type: str
            sample:
                - Operating System-WinServerLocal-cyberark.local-administrator
        platformAccountProperties:
            description:
                - Object containing key-value pairs to associate with the
                  account, as defined by the account platform.
            returned: successful addition and modification
            type: complex
            contains:
                KEY VALUE:
                    description:
                        - Object containing key-value pairs to associate with the
                          account, as defined by the account platform.
                    returned: successful addition and modification
                    type: str
                    sample:
                        - "LogonDomain": "cyberark"
                        - "Port": "22"
        platformId:
            description:
                - The PolicyID of the Platform that is to be managing the
                  account.
            returned: successful addition and modification
            type: str
            sample: WinServerLocal
        safeName:
            description:
                - The safe in the Vault where the privileged account is to
                  be located.
            returned: successful addition and modification
            type: str
            sample: Domain_Admins
        secretManagement:
            description:
                - Set of parameters associated with the management of
                  the credential.
            returned: successful addition and modification
            type: complex
            contains:
                automaticManagementEnabled:
                    description:
                        - Parameter that indicates whether the CPM will manage
                          the password or not.
                    returned: successful addition and modification
                    type: bool
                lastModifiedTime:
                    description:
                        - Timeframe calculation of the timestamp of account
                          modification.
                    returned: successful addition and modification
                    type: int
                    sample: "1567824520"
                manualManagementReason:
                    description:
                        - Reason for disabling automatic management of the account
                    returned: if C(automaticManagementEnabled) is set to false
                    type: str
                    sample: This is a static account
        secretType:
            description:
                - The value that identifies what type of account it will be
            returned: successful addition and modification
            type: list
            sample:
                - key
                - password
        userName:
            description: The username associated with the account
            returned: successful addition and modification
            type: str
            sample: administrator
"""


from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.http_client import HTTPException
import json
import logging

_empty = object()

ansible_specific_parameters = [
    "state",
    "api_base_url",
    "validate_certs",
    "cyberark_session",
    "identified_by",
    "logging_level",
    "logging_file",
    "new_secret",
    "secret_management.management_action",
    "secret_management.new_secret",
    "management_action",
    "secret_management.perform_management_action",
]

cyberark_fixed_properties = [
    "createdTime",
    "id",
    "name",
    "lastModifiedTime",
    "safeName",
    "secretType",
    "secret",
]

removal_value = "NO_VALUE"

cyberark_reference_fieldnames = {
    "username": "userName",
    "safe": "safeName",
    "platform_id": "platformId",
    "secret_type": "secretType",
    "platform_account_properties": "platformAccountProperties",
    "secret_management": "secretManagement",
    "manual_management_reason": "manualManagementReason",
    "automatic_management_enabled": "automaticManagementEnabled",
    "remote_machines_access": "remoteMachinesAccess",
    "access_restricted_to_remote_machines": "accessRestrictedToRemoteMachines",
    "remote_machines": "remoteMachines",
}

ansible_reference_fieldnames = {
    "userName": "username",
    "safeName": "safe",
    "platformId": "platform_id",
    "secretType": "secret_type",
    "platformAccountProperties": "platform_account_properties",
    "secretManagement": "secret_management",
    "manualManagementReason": "manual_management_reason",
    "automaticManagementEnabled": "automatic_management_enabled",
    "remoteMachinesAccess": "remote_machines_access",
    "accessRestrictedToRemoteMachines": "access_testricted_to_remoteMachines",
    "remoteMachines": "remote_machines",
}


def equal_value(existing, parameter):
    if isinstance(existing, str):
        return existing == str(parameter)
    elif isinstance(parameter, str):
        return str(existing) == parameter
    else:
        return existing == parameter


def update_account(module, existing_account):

    logging.debug("Updating Account")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {"result": existing_account}
    changed = False
    last_status_code = -1

    HTTPMethod = "PATCH"
    end_point = "/PasswordVault/api/Accounts/%s" % existing_account["id"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
    }

    payload = {"Operations": []}

    # Determining whether to add or update properties
    for parameter_name in list(module.params.keys()):
        if (
            parameter_name not in ansible_specific_parameters
            and module.params[parameter_name] is not None
        ):
            module_parm_value = module.params[parameter_name]
            cyberark_property_name = referenced_value(
                parameter_name, cyberark_reference_fieldnames, default=parameter_name
            )
            existing_account_value = referenced_value(
                cyberark_property_name,
                existing_account,
                keys=list(existing_account.keys()),
            )
            if cyberark_property_name not in cyberark_fixed_properties:
                if module_parm_value is not None and isinstance(
                    module_parm_value, dict
                ):
                    # Internal child values
                    replacing = {}
                    adding = {}
                    removing = {}
                    for child_parm_name in list(module_parm_value.keys()):
                        nested_parm_name = "%s.%s" % (parameter_name, child_parm_name)
                        if nested_parm_name not in ansible_specific_parameters:
                            child_module_parm_value = module_parm_value[child_parm_name]
                            child_cyberark_property_name = referenced_value(
                                child_parm_name,
                                cyberark_reference_fieldnames,
                                default=child_parm_name,
                            )
                            child_existing_account_value = referenced_value(
                                child_cyberark_property_name,
                                existing_account_value,
                                list(existing_account_value.keys())
                                if existing_account_value is not None
                                else {},
                            )
                            path_value = "/%s/%s" % (
                                cyberark_property_name,
                                child_cyberark_property_name,
                            )
                            if child_existing_account_value is not None:
                                logging.debug(
                                    (
                                        "child_module_parm_value: %s "
                                        "child_existing_account_value=%s path=%s"
                                    ),
                                    child_module_parm_value,
                                    child_existing_account_value,
                                    path_value
                                )
                                if child_module_parm_value == removal_value:
                                    removing.update(
                                        {
                                            child_cyberark_property_name: child_existing_account_value
                                        }
                                    )
                                elif (
                                    child_module_parm_value is not None
                                    and not equal_value(
                                        child_existing_account_value,
                                        child_module_parm_value,
                                    )
                                ):
                                    # Updating a property
                                    replacing.update(
                                        {
                                            child_cyberark_property_name: child_module_parm_value
                                        }
                                    )
                            elif (
                                child_module_parm_value is not None
                                and child_module_parm_value != removal_value
                            ):
                                # Adding a property value
                                adding.update(
                                    {
                                        child_cyberark_property_name: child_module_parm_value
                                    }
                                )
                            logging.debug(
                                "parameter_name=%s  value=%s existing=%s",
                                path_value,
                                child_module_parm_value,
                                child_existing_account_value
                            )
                    # Processing child operations
                    if len(list(adding.keys())) > 0:
                        payload["Operations"].append(
                            {
                                "op": "add",
                                "path": "/%s" % cyberark_property_name,
                                "value": adding,
                            }
                        )
                    if len(list(replacing.keys())) > 0:
                        payload["Operations"].append(
                            {
                                "op": "replace",
                                "path": "/%s" % cyberark_property_name,
                                "value": replacing,
                            }
                        )
                    if len(removing) > 0:
                        payload["Operations"].append(
                            {
                                "op": "remove",
                                "path": "/%s" % cyberark_property_name,
                                "value": removing,
                            }
                        )
                else:
                    if existing_account_value is not None:
                        if module_parm_value == removal_value:
                            payload["Operations"].append(
                                {"op": "remove", "path": "/%s" % cyberark_property_name}
                            )
                        elif not equal_value(existing_account_value, module_parm_value):
                            # Updating a property
                            payload["Operations"].append(
                                {
                                    "op": "replace",
                                    "value": module_parm_value,
                                    "path": "/%s" % cyberark_property_name,
                                }
                            )
                    elif module_parm_value != removal_value:
                        # Adding a property value
                        payload["Operations"].append(
                            {
                                "op": "add",
                                "value": module_parm_value,
                                "path": "/%s" % cyberark_property_name,
                            }
                        )
                    logging.debug(
                        "parameter_name=%s  value=%s existing=%s",
                        parameter_name, module_parm_value, existing_account_value
                    )

    if len(payload["Operations"]) != 0:
        if module.check_mode:
            logging.debug("Proceeding with Update Account (CHECK_MODE)")
            logging.debug("Operations => %s", json.dumps(payload))
            result = {"result": existing_account}
            changed = True
            last_status_code = -1
        else:
            logging.debug("Proceeding with Update Account")

            logging.debug(
                "Processing invidual operations (%d) => %s",
                len(payload["Operations"]),
                json.dumps(payload),
            )
            for operation in payload["Operations"]:
                individual_payload = [operation]
                try:
                    logging.debug(" ==> %s", json.dumps([operation]))
                    response = open_url(
                        api_base_url + end_point,
                        method=HTTPMethod,
                        headers=headers,
                        data=json.dumps(individual_payload),
                        validate_certs=validate_certs,
                    )

                    result = {"result": json.loads(response.read())}
                    changed = True
                    last_status_code = response.getcode()

                #                return (True, result, response.getcode())

                except (HTTPError, HTTPException) as http_exception:

                    if isinstance(http_exception, HTTPError):
                        res = json.load(http_exception)
                    else:
                        res = to_text(http_exception)

                    module.fail_json(
                        msg=(
                            "Error while performing update_account."
                            "Please validate parameters provided."
                            "\n*** end_point=%s%s\n ==> %s"
                            % (api_base_url, end_point, res)
                        ),
                        payload=individual_payload,
                        headers=headers,
                        status_code=http_exception.code,
                    )

                except Exception as unknown_exception:

                    module.fail_json(
                        msg=(
                            "Unknown error while performing update_account."
                            "\n*** end_point=%s%s\n%s"
                            % (api_base_url, end_point, to_text(unknown_exception))
                        ),
                        payload=individual_payload,
                        headers=headers,
                        status_code=-1,
                    )

    return (changed, result, last_status_code)


def add_account(module):

    logging.debug("Adding Account")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Prepare result, end_point, and headers
    result = {}
    HTTPMethod = "POST"
    end_point = "/PasswordVault/api/Accounts"

    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
    }

    payload = {"safeName": module.params["safe"]}

    for parameter_name in list(module.params.keys()):
        if (
            parameter_name not in ansible_specific_parameters
            and module.params[parameter_name] is not None
        ):
            cyberark_property_name = referenced_value(
                parameter_name, cyberark_reference_fieldnames, default=parameter_name
            )
            if isinstance(module.params[parameter_name], dict):
                payload[cyberark_property_name] = {}
                for dict_key in list(module.params[parameter_name].keys()):
                    cyberark_child_property_name = referenced_value(
                        dict_key, cyberark_reference_fieldnames, default=dict_key
                    )
                    logging.debug(
                        (
                            "parameter_name =%s.%s cyberark_property_name=%s "
                            "cyberark_child_property_name=%s"
                        ),
                        parameter_name,
                        dict_key,
                        cyberark_property_name,
                        cyberark_child_property_name,
                    )
                    if (
                        parameter_name + "." + dict_key
                        not in ansible_specific_parameters
                        and module.params[parameter_name][dict_key] is not None
                    ):
                        payload[cyberark_property_name][
                            cyberark_child_property_name
                        ] = deep_get(
                            module.params[parameter_name], dict_key, _empty, False
                        )
            else:
                if parameter_name not in cyberark_reference_fieldnames:
                    module_parm_value = deep_get(
                        module.params, parameter_name, _empty, False
                    )
                    if (
                        module_parm_value is not None
                        and module_parm_value != removal_value
                    ):
                        payload[
                            parameter_name
                        ] = module_parm_value  # module.params[parameter_name]
                else:
                    module_parm_value = deep_get(
                        module.params, parameter_name, _empty, True
                    )
                    if (
                        module_parm_value is not None
                        and module_parm_value != removal_value
                    ):
                        payload[
                            cyberark_reference_fieldnames[parameter_name]
                        ] = module_parm_value  # module.params[parameter_name]
            logging.debug("parameter_name =%s", parameter_name)

    logging.debug("Add Account Payload => %s", json.dumps(payload))

    try:

        if module.check_mode:
            logging.debug("Proceeding with Add Account (CHECK_MODE)")
            return (True, {"result": None}, -1)
        else:
            logging.debug("Proceeding with Add Account")
            response = open_url(
                api_base_url + end_point,
                method=HTTPMethod,
                headers=headers,
                data=json.dumps(payload),
                validate_certs=validate_certs,
            )

            result = {"result": json.loads(response.read())}

            return (True, result, response.getcode())

    except (HTTPError, HTTPException) as http_exception:

        if isinstance(http_exception, HTTPError):
            res = json.load(http_exception)
        else:
            res = to_text(http_exception)

        module.fail_json(
            msg=(
                "Error while performing add_account."
                "Please validate parameters provided."
                "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, res)
            ),
            payload=payload,
            headers=headers,
            status_code=http_exception.code,
        )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing add_account."
                "\n*** end_point=%s%s\n%s"
                % (api_base_url, end_point, to_text(unknown_exception))
            ),
            payload=payload,
            headers=headers,
            status_code=-1,
        )


def delete_account(module, existing_account):

    if module.check_mode:
        logging.debug("Deleting Account (CHECK_MODE)")
        return (True, {"result": None}, -1)
    else:
        logging.debug("Deleting Account")

        cyberark_session = module.params["cyberark_session"]
        api_base_url = cyberark_session["api_base_url"]
        validate_certs = cyberark_session["validate_certs"]

        # Prepare result, end_point, and headers
        result = {}
        HTTPMethod = "DELETE"
        end_point = "/PasswordVault/api/Accounts/%s" % existing_account["id"]

        headers = {
            "Content-Type": "application/json",
            "Authorization": cyberark_session["token"],
            "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
        }

        try:

            response = open_url(
                api_base_url + end_point,
                method=HTTPMethod,
                headers=headers,
                validate_certs=validate_certs,
            )

            result = {"result": None}

            return (True, result, response.getcode())

        except (HTTPError, HTTPException) as http_exception:

            if isinstance(http_exception, HTTPError):
                res = json.load(http_exception)
            else:
                res = to_text(http_exception)

            module.fail_json(
                msg=(
                    "Error while performing delete_account."
                    "Please validate parameters provided."
                    "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, res)
                ),
                headers=headers,
                status_code=http_exception.code,
            )

        except Exception as unknown_exception:

            module.fail_json(
                msg=(
                    "Unknown error while performing delete_account."
                    "\n*** end_point=%s%s\n%s"
                    % (api_base_url, end_point, to_text(unknown_exception))
                ),
                headers=headers,
                status_code=-1,
            )


def reset_account_if_needed(module, existing_account):

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    # Credential changes
    management_action = deep_get(
        module.params, "secret_management.management_action", "NOT_FOUND", False
    )
    cpm_new_secret = deep_get(
        module.params, "secret_management.new_secret", "NOT_FOUND", False
    )
    logging.debug(
        "management_action: %s  cpm_new_secret: %s", management_action, cpm_new_secret
    )

    # Prepare result, end_point, and headers
    result = {}
    end_point = None
    payload = {}
    existing_account_id = None
    if existing_account is not None:
        existing_account_id = existing_account["id"]
    elif module.check_mode:
        existing_account_id = 9999

    if (
        management_action == "change"
        and cpm_new_secret is not None
        and cpm_new_secret != "NOT_FOUND"
    ):
        logging.debug("CPM change secret for next CPM cycle")
        end_point = (
            "/PasswordVault/API/Accounts/%s/SetNextPassword"
        ) % existing_account_id
        payload["ChangeImmediately"] = False
        payload["NewCredentials"] = cpm_new_secret
    elif management_action == "change_immediately" and (
        cpm_new_secret == "NOT_FOUND" or cpm_new_secret is None
    ):
        logging.debug("CPM change_immediately with random secret")
        end_point = ("/PasswordVault/API/Accounts/%s/Change") % existing_account_id
        payload["ChangeEntireGroup"] = True
    elif management_action == "change_immediately" and (
        cpm_new_secret is not None and cpm_new_secret != "NOT_FOUND"
    ):
        logging.debug("CPM change immediately secret for next CPM cycle")
        end_point = (
            "/PasswordVault/API/Accounts/%s/SetNextPassword"
        ) % existing_account_id
        payload["ChangeImmediately"] = True
        payload["NewCredentials"] = cpm_new_secret
    elif management_action == "reconcile":
        logging.debug("CPM reconcile secret")
        end_point = ("/PasswordVault/API/Accounts/%s/Reconcile") % existing_account_id
    elif (
        "new_secret" in list(module.params.keys())
        and module.params["new_secret"] is not None
    ):
        logging.debug("Change Credential in Vault")
        end_point = (
            "/PasswordVault/API/Accounts/%s/Password/Update"
        ) % existing_account_id
        payload["ChangeEntireGroup"] = True
        payload["NewCredentials"] = module.params["new_secret"]

    if end_point is not None:

        if module.check_mode:
            logging.debug("Proceeding with Credential Rotation (CHECK_MODE)")
            return (True, result, -1)
        else:
            logging.debug("Proceeding with Credential Rotation")

            result = {"result": None}
            headers = {
                "Content-Type": "application/json",
                "Authorization": cyberark_session["token"],
                "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
            }
            HTTPMethod = "POST"
            try:

                response = open_url(
                    api_base_url + end_point,
                    method=HTTPMethod,
                    headers=headers,
                    data=json.dumps(payload),
                    validate_certs=validate_certs,
                )

                return (True, result, response.getcode())

            except (HTTPError, HTTPException) as http_exception:

                if isinstance(http_exception, HTTPError):
                    res = json.load(http_exception)
                else:
                    res = to_text(http_exception)

                module.fail_json(
                    msg=(
                        "Error while performing reset_account."
                        "Please validate parameters provided."
                        "\n*** end_point=%s%s\n ==> %s"
                    )
                    % (api_base_url, end_point, res),
                    headers=headers,
                    payload=payload,
                    status_code=http_exception.code,
                )

            except Exception as unknown_exception:

                module.fail_json(
                    msg=(
                        "Unknown error while performing delete_account."
                        "\n*** end_point=%s%s\n%s"
                        % (api_base_url, end_point, to_text(unknown_exception))
                    ),
                    headers=headers,
                    payload=payload,
                    status_code=-1,
                )

    else:
        return (False, result, -1)


def referenced_value(field, dct, keys=None, default=None):
    return dct[field] if field in (keys if keys is not None else dct) else default


def deep_get(dct, dotted_path, default=_empty, use_reference_table=True):
    result_dct = {}
    for key in dotted_path.split("."):
        try:
            key_field = key
            if use_reference_table:
                key_field = referenced_value(
                    key, cyberark_reference_fieldnames, default=key
                )

            if len(list(result_dct.keys())) == 0:  # No result_dct set yet
                result_dct = dct

            logging.debug(
                "keys=%s key_field=>%s   key=>%s",
                ",".join(list(result_dct.keys())),
                key_field,
                key,
            )
            result_dct = (
                result_dct[key_field]
                if key_field in list(result_dct.keys())
                else result_dct[key]
            )
            if result_dct is None:
                return default

        except KeyError as e:
            logging.debug("KeyError %s", to_text(e))
            if default is _empty:
                raise
            return default
    return result_dct


def get_account(module):

    logging.debug("Finding Account")

    identified_by_fields = module.params["identified_by"].split(",")
    logging.debug("Identified_by: %s", json.dumps(identified_by_fields))
    safe_filter = (
        quote("safeName eq ") + quote(module.params["safe"])
        if "safe" in module.params and module.params["safe"] is not None
        else None
    )
    search_string = None
    for field in identified_by_fields:
        if field not in ansible_specific_parameters:
            search_string = "%s%s" % (
                search_string + " " if search_string is not None else "",
                deep_get(module.params, field, "NOT FOUND", False),
            )

    logging.debug("Search_String => %s", search_string)
    logging.debug("Safe Filter => %s", safe_filter)

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    end_point = None
    if search_string is not None and safe_filter is not None:
        end_point = "/PasswordVault/api/accounts?filter=%s&search=%s" % (
            safe_filter,
            quote(search_string.lstrip()),
        )
    elif search_string is not None:
        end_point = ("/PasswordVault/api/accounts?search=%s") % (search_string.lstrip())
    else:
        end_point = "/PasswordVault/api/accounts?filter=%s" % (safe_filter)

    logging.debug("End Point => %s", end_point)

    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
    }

    try:

        logging.debug("Executing: " + api_base_url + end_point)
        response = open_url(
            api_base_url + end_point,
            method="GET",
            headers=headers,
            validate_certs=validate_certs,
        )

        result_string = response.read()
        accounts_data = json.loads(result_string)

        logging.debug("RESULT => %s", json.dumps(accounts_data))

        if accounts_data["count"] == 0:
            return (False, None, response.getcode())
        else:
            how_many = 0
            first_record_found = None
            for account_record in accounts_data["value"]:
                logging.debug("Acct Record => %s", json.dumps(account_record))
                found = False
                for field in identified_by_fields:
                    record_field_value = deep_get(account_record, field, "NOT FOUND")
                    logging.debug(
                        (
                            "Comparing field %s | record_field_name=%s  "
                            "record_field_value=%s   module.params_value=%s"
                        ),
                        field,
                        field,
                        record_field_value,
                        deep_get(module.params, field, "NOT FOUND"),
                    )
                    if record_field_value != "NOT FOUND" and (
                        record_field_value
                        == deep_get(module.params, field, "NOT FOUND", False)
                    ):
                        found = True
                    else:
                        found = False
                        break
                if found:
                    how_many = how_many + 1
                    if first_record_found is None:
                        first_record_found = account_record

            logging.debug(
                "How Many: %d  First Record Found => %s",
                how_many,
                json.dumps(first_record_found),
            )
            if how_many > 1:  # too many records found
                module.fail_json(
                    msg=(
                        "Error while performing get_account. "
                        "Too many rows (%d) found matching your criteria!"
                    )
                    % how_many
                )
            else:
                return (how_many == 1, first_record_found, response.getcode())

    except (HTTPError, HTTPException) as http_exception:

        if http_exception.code == 404:
            return (False, None, http_exception.code)
        else:
            module.fail_json(
                msg=(
                    "Error while performing get_account."
                    "Please validate parameters provided."
                    "\n*** end_point=%s%s\n ==> %s"
                    % (api_base_url, end_point, to_text(http_exception))
                ),
                headers=headers,
                status_code=http_exception.code,
            )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing get_account."
                "\n*** end_point=%s%s\n%s"
                % (api_base_url, end_point, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def retrieve_password(module, existing_account):
    logging.debug("Retrieving Password")

    cyberark_session = module.params["cyberark_session"]
    api_base_url = cyberark_session["api_base_url"]
    validate_certs = cyberark_session["validate_certs"]

    result = existing_account
    HTTPMethod = "POST"
    end_point = "/PasswordVault/api/Accounts/%s/Password/Retrieve" % existing_account["id"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": cyberark_session["token"],
        "User-Agent": "CyberArk/1.0 (Ansible; cyberark.pas)"
    }

    try:

        response = open_url(
            api_base_url + end_point,
            method=HTTPMethod,
            headers=headers,
            validate_certs=validate_certs,
        )

        password = response.read().decode('utf-8')

        if not (password.startswith('"') and password.endswith('"')):
            module.fail_json(
                msg=(
                    "Error while performing retrieve_password."
                    "The returned value was not formatted as expected."
                    "\n*** end_point=%s%s\n" % (api_base_url, end_point)
                ),
                headers=headers,
                status_coode=-1
            )

        password = password[1:-1]

        result["password"] = password

        logging.debug("Password Retrieved")

        return (False, result, response.getcode())

    except (HTTPError, HTTPException) as http_exception:

        res = ''
        if isinstance(http_exception, HTTPError):
            res = json.load(http_exception)
        else:
            res = to_text(http_exception)

        module.fail_json(
            msg=(
                "Error while performing retrieve_password."
                "Please validate parameters provided."
                "\n*** end_point=%s%s\n ==> %s" % (api_base_url, end_point, res)
            ),
            headers=headers,
            status_code=http_exception.code,
        )

    except Exception as unknown_exception:

        module.fail_json(
            msg=(
                "Unknown error while performing retrieve_password."
                "\n*** end_point=%s%s\n%s"
                % (api_base_url, end_point, to_text(unknown_exception))
            ),
            headers=headers,
            status_code=-1,
        )


def main():

    fields = {
        "state": {
            "type": "str",
            "choices": ["present", "absent", "retrieve"],
            "default": "present",
        },
        "logging_level": {"type": "str", "choices": ["NOTSET", "DEBUG", "INFO"]},
        "logging_file": {"type": "str", "default": "/tmp/ansible_cyberark.log"},
        "api_base_url": {"type": "str"},
        "validate_certs": {"type": "bool", "default": "true"},
        "cyberark_session": {"required": True, "type": "dict", "no_log": True},
        "identified_by": {
            "required": False,
            "type": "str",
            "default": "username,address,platform_id",
        },
        "safe": {"required": True, "type": "str"},
        "platform_id": {"required": False, "type": "str"},
        "address": {"required": False, "type": "str"},
        "name": {"required": False, "type": "str"},
        "secret_type": {
            "required": False,
            "type": "str",
            "choices": ["password", "key"],
            "default": "password",
        },
        "secret": {"required": False, "type": "str", "no_log": True},
        "new_secret": {"required": False, "type": "str", "no_log": True},
        "username": {"required": False, "type": "str"},
        "secret_management": {
            "required": False,
            "type": "dict",
            "options": {
                "automatic_management_enabled": {
                    "type": "bool",
                    "default": False,
                },
                "manual_management_reason": {"type": "str"},
                "management_action": {
                    "type": "str",
                    "choices": ["change", "change_immediately", "reconcile"],
                },
                "new_secret": {"type": "str", "no_log": True},
                "perform_management_action": {
                    "type": "str",
                    "choices": ["on_create", "always"],
                    "default": "always",
                },
            },
            "no_log": False,
        },
        "remote_machines_access": {
            "required": False,
            "type": "dict",
            "options": {
                "remote_machines": {"type": "str"},
                "access_restricted_to_remote_machines": {"type": "bool"},
            },
        },
        "platform_account_properties": {"required": False, "type": "dict"},
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    if module.params["logging_level"] is not None:
        logging.basicConfig(
            filename=module.params["logging_file"], level=module.params["logging_level"]
        )

    logging.info("Starting Module")

    state = module.params["state"]

    (found, account_record, status_code) = get_account(module)
    logging.debug(
        "Account was %s, status_code=%s", "FOUND" if found else "NOT FOUND", status_code
    )

    changed = False
    result = {"result": account_record}

    if state == "present":

        if found:  # Account already exists
            (changed, result, status_code) = update_account(module, account_record)
        else:  # Account does not exist
            (changed, result, status_code) = add_account(module)

        perform_management_action = "always"
        if "secret_management" in list(module.params.keys()):
            secret_management = module.params["secret_management"]
            if secret_management is not None and "perform_management_action" in list(
                secret_management.keys()
            ):
                perform_management_action = secret_management[
                    "perform_management_action"
                ]

        logging.debug("Result=>%s", json.dumps(result))
        if perform_management_action == "always" or (
            perform_management_action == "on_create" and not found
        ):
            (account_reset, no_result, no_status_code) = reset_account_if_needed(
                module, result["result"]
            )
            if account_reset:
                changed = True

    elif found and state == "absent":
        (changed, result, status_code) = delete_account(module, account_record)

    elif found and state == "retrieve":
        (changed, result, status_code) = retrieve_password(module, account_record)

    module.exit_json(changed=changed, result=result, status_code=status_code)


if __name__ == "__main__":
    main()
