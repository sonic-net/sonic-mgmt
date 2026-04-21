#!/usr/bin/python

# (c) 2022, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Certificates"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: na_sg_grid_client_certificate
short_description: Manage Client Certificates on StorageGRID
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.11.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Client Certificates on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified certificate should exist.
    type: str
    choices: ['present', 'absent']
    default: present
  certificate_id:
    description:
    - ID of the client certificate.
    type: str
  display_name:
    description:
    - A display name for the client certificate configuration.
    - This parameter can be modified if I(certificate_id) is also specified.
    type: str
  public_key:
    description:
    - X.509 client certificate in PEM-encoding.
    type: str
  allow_prometheus:
    description:
    - Whether the external monitoring tool can access Prometheus metrics.
    type: bool
"""

EXAMPLES = """
- name: create client certificate
  netapp.storagegrid.na_sg_grid_client_certificate:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    display_name: client-cert1
    public_key: |
      -----BEGIN CERTIFICATE-----
      MIIC6DCCAdACCQC7l4WukhKD0zANBgkqhkiG9w0BAQsFADA2..swCQYDVQQGEwJB
      BAMMHnNnYW4wMS5kZXYubWljcm9icmV3Lm5ldGFwcC5hdTCC..IwDQYJKoZIhvcN
      AQEBBQADggEPADCCAQoCggEBAMvjm9I35lmKcC7ITVL8+QiZ..lvdkbfZCUQrfdy
      71inP+XmPjs0rnkhICA9ItODteRcVlO+t7nDTfm7HgG0mJFk..m0ffyEYrcx24qu
      S7gXYQjRsJmrep1awoaCa20BMGuqK2WKI3IvZ7YiT22qkBqK..+hIFffX6u3Jy+B
      77pR6YcATtpMHW/AaOx+OX9l80dIRsRZKMDxYQ==
      -----END CERTIFICATE-----
    allow_prometheus: true

- name: rename client certificate
  netapp.storagegrid.na_sg_grid_client_certificate:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    certificate_id: 00000000-0000-0000-0000-000000000000
    display_name: client-cert1-rename
    public_key: |
      -----BEGIN CERTIFICATE-----
      MIIC6DCCAdACCQC7l4WukhKD0zANBgkqhkiG9w0BAQsFADA2..swCQYDVQQGEwJB
      BAMMHnNnYW4wMS5kZXYubWljcm9icmV3Lm5ldGFwcC5hdTCC..IwDQYJKoZIhvcN
      AQEBBQADggEPADCCAQoCggEBAMvjm9I35lmKcC7ITVL8+QiZ..lvdkbfZCUQrfdy
      71inP+XmPjs0rnkhICA9ItODteRcVlO+t7nDTfm7HgG0mJFk..m0ffyEYrcx24qu
      S7gXYQjRsJmrep1awoaCa20BMGuqK2WKI3IvZ7YiT22qkBqK..+hIFffX6u3Jy+B
      77pR6YcATtpMHW/AaOx+OX9l80dIRsRZKMDxYQ==
      -----END CERTIFICATE-----
    allow_prometheus: true

- name: delete client certificate
  netapp.storagegrid.na_sg_grid_client_certificate:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: absent
    display_name: client-cert1-rename
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID server certificates.
    returned: success
    type: dict
    sample: {
        "id": "abcABC_01234-0123456789abcABCabc0123456789==",
        "displayName": "client-cert1",
        "expiryDate": "2024-01-01T00:00:00.000Z",
        "publicKey": "-----BEGIN CERTIFICATE-----MIIC6DCCAdACCQC7l4WukhKD0zANBgkqhkiG9w0BAQsFADA2MQswCQYDVQQGE...-----END CERTIFICATE-----",
        "allowPrometheus": true
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridClientCertificate:
    """
    Update StorageGRID client certificates
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
                certificate_id=dict(required=False, type="str"),
                display_name=dict(required=False, type="str"),
                public_key=dict(required=False, type="str"),
                allow_prometheus=dict(required=False, type="bool"),
            )
        )

        parameter_map = {
            "display_name": "displayName",
            "public_key": "publicKey",
            "allow_prometheus": "allowPrometheus",
        }

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["display_name", "public_key"])],
            required_one_of=[("display_name", "certificate_id")],
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
            for k in parameter_map.keys():
                if self.parameters.get(k) is not None:
                    self.data[parameter_map[k]] = self.parameters[k]

        self.module.fail_json

    def get_grid_client_certificate_id(self):
        # Check if certificate with name exists
        # Return certificate ID if found, or None
        api = "api/v3/grid/client-certificates"

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        for cert in response.get("data"):
            if cert["displayName"] == self.parameters["display_name"]:
                return cert["id"]
        return None

    def get_grid_client_certificate(self, cert_id):
        api = "api/v3/grid/client-certificates/%s" % cert_id
        account, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return account["data"]
        return None

    def create_grid_client_certificate(self):
        api = "api/v3/grid/client-certificates"

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error["text"])

        return response["data"]

    def delete_grid_client_certificate(self, cert_id):
        api = "api/v3/grid/client-certificates/" + cert_id

        self.data = None
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def update_grid_client_certificate(self, cert_id):
        api = "api/v3/grid/client-certificates/" + cert_id

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error["text"])

        return response["data"]

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        client_certificate = None

        if self.parameters.get("certificate_id"):
            client_certificate = self.get_grid_client_certificate(self.parameters["certificate_id"])

        else:
            client_cert_id = self.get_grid_client_certificate_id()
            if client_cert_id:
                client_certificate = self.get_grid_client_certificate(client_cert_id)

        cd_action = self.na_helper.get_cd_action(client_certificate, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            modify = self.na_helper.get_modified_attributes(client_certificate, self.data)

        result_message = ""
        resp_data = client_certificate

        if self.na_helper.changed and not self.module.check_mode:
            if cd_action == "delete":
                self.delete_grid_client_certificate(client_certificate["id"])
                result_message = "Client Certificate deleted"
            elif cd_action == "create":
                resp_data = self.create_grid_client_certificate()
                result_message = "Client Certificate created"
            elif modify:
                resp_data = self.update_grid_client_certificate(client_certificate["id"])
                result_message = "Client Certificate updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_certificate = SgGridClientCertificate()
    na_sg_grid_certificate.apply()


if __name__ == "__main__":
    main()
