#!/usr/bin/python

# (c) 2021-2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Grid Identity Federation"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
module: na_sg_grid_identity_federation
short_description: NetApp StorageGRID manage Grid identity federation.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Configure Grid Identity Federation within NetApp StorageGRID.
- If module is run with I(check_mode), a connectivity test will be performed using the supplied values without changing the configuration.
- This module is idempotent if I(password) is not specified.
options:
  state:
    description:
    - Whether identity federation should be enabled or not.
    type: str
    choices: ['present', 'absent']
    default: present
  username:
    description:
    - The username to bind to the LDAP server.
    type: str
  password:
    description:
    - The password associated with the username.
    type: str
  hostname:
    description:
    - The hostname or IP address of the LDAP server.
    type: str
  port:
    description:
    - The port used to connect to the LDAP server. Typically 389 for LDAP, or 636 for LDAPS.
    type: int
  base_group_dn:
    description:
    - The Distinguished Name of the LDAP subtree to search for groups.
    type: str
  base_user_dn:
    description:
    - The Distinguished Name of the LDAP subtree to search for users.
    type: str
  ldap_service_type:
    description:
    - The type of LDAP server.
    choices: ['Active Directory', 'OpenLDAP', 'Other']
    type: str
  type:
    description:
    - The type of identity source.
    - Default is C(ldap).
    type: str
    default: ldap
  ldap_user_id_attribute:
    description:
    - The LDAP attribute which contains the unique user name of a user.
    - Should be configured if I(ldap_service_type=Other).
    type: str
  ldap_user_uuid_attribute:
    description:
    - The LDAP attribute which contains the permanent unique identity of a user.
    - Should be configured if I(ldap_service_type=Other).
    type: str
  ldap_group_id_attribute:
    description:
    - The LDAP attribute which contains the group for a user.
    - Should be configured if I(ldap_service_type=Other).
    type: str
  ldap_group_uuid_attribute:
    description:
    - The LDAP attribute which contains the group's permanent unique identity.
    - Should be configured if I(ldap_service_type=Other).
    type: str
  tls:
    description:
    - Whether Transport Layer Security is used to connect to the LDAP server.
    choices: ['STARTTLS', 'LDAPS', 'Disabled']
    type: str
    default: STARTTLS
  ca_cert:
    description:
    - Custom certificate used to connect to the LDAP server.
    - If a custom certificate is not supplied, the operating system CA certificate will be used.
    type: str
"""

EXAMPLES = """
- name: test identity federation configuration
  netapp.storagegrid.na_sg_grid_identity_federation:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    ldap_service_type: "Active Directory"
    hostname: "ad.example.com"
    port: 389
    username: "binduser"
    password: "bindpass"
    base_group_dn: "DC=example,DC=com"
    base_user_dn: "DC=example,DC=com"
    tls: "Disabled"
  check_mode: true

- name: configure identity federation with AD and TLS
  netapp.storagegrid.na_sg_grid_identity_federation:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    ldap_service_type: "Active Directory"
    hostname: "ad.example.com"
    port: 636
    username: "binduser"
    password: "bindpass"
    base_group_dn: "DC=example,DC=com"
    base_user_dn: "DC=example,DC=com"
    tls: "LDAPS"
    ca_cert: |
        -----BEGIN CERTIFICATE-----
        MIIC+jCCAeICCQDmn9Gow08LTzANBgkqhkiG9w0BAQsFADA/..swCQYDVQQGEwJV
        bXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB..JFzNIXQEGnsgjV
        JGU4giuvOLOZ8Q3gyuUbkSUQDjmjpMR8PliwJ6iW2Ity89Dv..dl1TaIYI/ansyZ
        Uxk4YXeN6kUkrDtNxCg1McALzXVAfxMTtj2SFlLxne4Z6rX2..UyftQrfM13F1vY
        gK8dBPz+l+X/Uozo/xNm7gxe68p9le9/pcULst1CQn5/sPqq..kgWcSvlKUItu82
        lq3B2169rovdIaNdcvaQjMPhrDGo5rvLfMN35U3Hgbz41PL5..x2BcUE6/0ab5T4
        qKBxKa3t9twj+zpUqOzyL0PFfCE+SK5fEXAS1ow4eAcLN+eB..gR/PuvGAyIPCtE
        1+X4GrECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAFpO+04Ra..FMJPH6dBmzfb7l
        k04BWTvSlur6HiQdXY+oFQMJZzyI7MQ8v9HBIzS0ZAzYWLp4..VZhHmRxnrWyxVs
        u783V5YfQH2L4QnBDoiDefgxyfDs2PcoF5C+X9CGXmPqzst2..y/6tdOVJzdiA==
        -----END CERTIFICATE-----
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID management identity source configuration.
    returned: success
    type: dict
    sample: {
        "id": "00000000-0000-0000-0000-000000000000",
        "disable": false,
        "hostname": "10.1.2.3",
        "port": 389,
        "username": "MYDOMAIN\\\\Administrator",
        "password": "********",
        "baseGroupDn": "DC=example,DC=com",
        "baseUserDn": "DC=example,DC=com",
        "ldapServiceType": "Active Directory",
        "type": "ldap",
        "disableTLS": false,
        "enableLDAPS": false,
        "caCert": "-----BEGIN CERTIFICATE----- abcdefghijkl123456780ABCDEFGHIJKL 123456/7890ABCDEFabcdefghijklABCD -----END CERTIFICATE-----\n"
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridIdentityFederation:
    """
    Configure and modify StorageGRID Grid Identity Federation
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(required=False, type="str", choices=["present", "absent"], default="present"),
                username=dict(required=False, type="str"),
                password=dict(required=False, type="str", no_log=True),
                hostname=dict(required=False, type="str"),
                port=dict(required=False, type="int"),
                base_group_dn=dict(required=False, type="str"),
                base_user_dn=dict(required=False, type="str"),
                ldap_service_type=dict(required=False, type="str", choices=["OpenLDAP", "Active Directory", "Other"]),
                type=dict(required=False, type="str", default="ldap"),
                ldap_user_id_attribute=dict(required=False, type="str"),
                ldap_user_uuid_attribute=dict(required=False, type="str"),
                ldap_group_id_attribute=dict(required=False, type="str"),
                ldap_group_uuid_attribute=dict(required=False, type="str"),
                tls=dict(required=False, type="str", choices=["STARTTLS", "LDAPS", "Disabled"], default="STARTTLS"),
                ca_cert=dict(required=False, type="str"),
            ),
        )

        parameter_map = {
            "username": "username",
            "password": "password",
            "hostname": "hostname",
            "port": "port",
            "base_group_dn": "baseGroupDn",
            "base_user_dn": "baseUserDn",
            "ldap_service_type": "ldapServiceType",
            "ldap_user_id_attribute": "ldapUserIdAttribute",
            "ldap_user_uuid_attribute": "ldapUserUUIDAttribute",
            "ldap_group_id_attribute": "ldapGroupIdAttribute",
            "ldap_group_uuid_attribute": "ldapGroupUUIDAttribute",
            "ca_cert": "caCert",
        }
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}

        if self.parameters["state"] == "present":
            self.data["disable"] = False

        for k in parameter_map.keys():
            if self.parameters.get(k) is not None:
                self.data[parameter_map[k]] = self.parameters[k]

        if self.parameters.get("tls") == "STARTTLS":
            self.data["disableTLS"] = False
            self.data["enableLDAPS"] = False
        elif self.parameters.get("tls") == "LDAPS":
            self.data["disableTLS"] = False
            self.data["enableLDAPS"] = True
        else:
            self.data["disableTLS"] = True
            self.data["enableLDAPS"] = False

    def get_grid_identity_source(self):
        api = "api/v3/grid/identity-source"
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]
        return None

    def update_identity_federation(self, test=False):
        api = "api/v3/grid/identity-source"

        params = {}

        if test:
            params["test"] = True

        response, error = self.rest_api.put(api, self.data, params=params)
        if error:
            self.module.fail_json(msg=error, payload=self.data)

        if response is not None:
            return response["data"]
        else:
            return None

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        grid_identity_source = self.get_grid_identity_source()

        cd_action = self.na_helper.get_cd_action(grid_identity_source, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            for k in (i for i in self.data.keys() if i != "password"):
                if self.data[k] != grid_identity_source.get(k):
                    update = True
                    break

            # if a password has been specified we need to update it
            if self.data.get("password") and self.parameters["state"] == "present":
                update = True
                self.module.warn("Password attribute has been specified. Task is not idempotent.")

            if update:
                self.na_helper.changed = True

        if cd_action == "delete":
            # if identity federation is already in a disable state
            if grid_identity_source.get("disable"):
                self.na_helper.changed = False

        result_message = ""
        resp_data = grid_identity_source

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == "delete":
                self.data = dict(disable=True)
                resp_data = self.update_identity_federation()
                result_message = "Grid identity federation disabled"
            else:
                resp_data = self.update_identity_federation()
                result_message = "Grid identity federation updated"

        if self.module.check_mode:
            self.update_identity_federation(test=True)
            # if no error, connection test successful
            self.module.exit_json(changed=self.na_helper.changed, msg="Connection test successful")

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_identity_federation = SgGridIdentityFederation()
    na_sg_grid_identity_federation.apply()


if __name__ == "__main__":
    main()
