#!/usr/bin/python

# (c) 2021, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Certificates"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: na_sg_grid_certificate
short_description: Manage the Storage API and Grid Management certificates on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Set and update the Storage API and Grid Management certificates on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified certificate should be set.
    type: str
    choices: ['present', 'absent']
    default: present
  type:
    description:
    - Which certificate to update.
    type: str
    choices: ['storage-api', 'management']
    required: true
  server_certificate:
    description:
    - X.509 server certificate in PEM-encoding.
    type: str
  ca_bundle:
    description:
    - Intermediate CA certificate bundle in concatenated PEM-encoding.
    - Omit if there is no intermediate CA.
    type: str
  private_key:
    description:
    - Certificate private key in PEM-encoding.
    - Required if I(server_certificate) is specified.
    type: str
"""

EXAMPLES = """
- name: set storage API certificate
  netapp.storagegrid.na_sg_grid_certificate:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    type: storage-api
    server_certificate: |
      -----BEGIN CERTIFICATE-----
      MIIC6DCCAdACCQC7l4WukhKD0zANBgkqhkiG9w0BAQsFADA2MQswCQYDVQQGEwJB
      BAMMHnNnYW4wMS5kZXYubWljcm9icmV3Lm5ldGFwcC5hdTCCASIwDQYJKoZIhvcN
      AQEBBQADggEPADCCAQoCggEBAMvjm9I35lmKcC7ITVL8+QiZ/klvdkbfZCUQrfdy
      71inP+XmPjs0rnkhICA9ItODteRcVlO+t7nDTfm7HgG0mJFkcJm0ffyEYrcx24qu
      S7gXYQjRsJmrep1awoaCa20BMGuqK2WKI3IvZ7YiT22qkBqKJD+hIFffX6u3Jy+B
      77pR6YcATtpMHW/AaOx+OX9l80dIRsRZKMDxYQ==
      -----END CERTIFICATE-----
    private_key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDL45vSN+ZZinAu
      L25W0+cz1Oi69AKkI7d9nbFics2ay5+7o+4rKqf3en2R4MSxiJvy+iDlOmATib5O
      x8TN5pJ9AgMBAAECggEADDLM8tHXXUoUFihzv+BUwff8p8YcbHcXFcSes+xTd5li
      po8lNsx/v2pQx4ByBkuaYLZGIEXOWS6gkp44xhIXgQKBgQD4Hq7862u5HLbmhrV3
      vs8nC69b3QKBgQDacCD8d8JpwPbg8t2VjXM3UvdmgAaLUfU7O1DWV+W3jqzmDOoN
      zWVgPbPNj0UmzvLDbgxLoxe77wjn2BHsAJVAfJ9VeQKBgGqFAegYO+wHR8lJUoa5
      ZEe8Upy2oBtvND/0dnwO2ym2FGsBJN0Gr4NKdG5vkzLsthKkcwRm0ikwEUOUZQKE
      K8J5yEVeo9K2v3wggtq8fYn6
      -----END PRIVATE KEY-----
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID server certificates.
    returned: success
    type: dict
    sample: {
        "serverCertificateEncoded": "-----BEGIN CERTIFICATE-----MIIC6DCCAdACCQC7l4WukhKD0zANBgkqhkiG9w0BAQsFADA2MQswCQYDVQQGE...-----END CERTIFICATE-----",
        "caBundleEncoded": "-----BEGIN CERTIFICATE-----MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELM...-----END CERTIFICATE-----"
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgGridCertificate:
    """
    Update StorageGRID certificates
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
                type=dict(required=True, type="str", choices=["storage-api", "management"]),
                server_certificate=dict(required=False, type="str"),
                ca_bundle=dict(required=False, type="str"),
                private_key=dict(required=False, type="str", no_log=True),
            )
        )

        parameter_map = {
            "server_certificate": "serverCertificateEncoded",
            "ca_bundle": "caBundleEncoded",
            "private_key": "privateKeyEncoded",
        }

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["server_certificate", "private_key"])],
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

    def get_grid_certificate(self, cert_type):
        api = "api/v3/grid/%s" % cert_type

        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_grid_certificate(self, cert_type):
        api = "api/v3/grid/%s/update" % cert_type

        response, error = self.rest_api.post(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        cert_type = ""
        cd_action = None

        if self.parameters.get("type") == "storage-api":
            cert_type = "storage-api-certificate"
        elif self.parameters.get("type") == "management":
            cert_type = "management-certificate"

        cert_data = self.get_grid_certificate(cert_type)

        if cert_data["serverCertificateEncoded"] is None and cert_data["caBundleEncoded"] is None:
            cd_action = self.na_helper.get_cd_action(None, self.parameters)
        else:
            cd_action = self.na_helper.get_cd_action(cert_data, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            if self.data.get("serverCertificateEncoded") is not None and self.data.get("privateKeyEncoded") is not None:
                for item in ["serverCertificateEncoded", "caBundleEncoded"]:
                    if self.data.get(item) != cert_data.get(item):
                        update = True

            if update:
                self.na_helper.changed = True

        result_message = ""
        resp_data = cert_data
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.update_grid_certificate(cert_type)
                    resp_data = self.get_grid_certificate(cert_type)
                    result_message = "Grid %s removed" % cert_type

                else:
                    self.update_grid_certificate(cert_type)
                    resp_data = self.get_grid_certificate(cert_type)
                    result_message = "Grid %s updated" % cert_type

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_certificate = SgGridCertificate()
    na_sg_grid_certificate.apply()


if __name__ == "__main__":
    main()
