#!/usr/bin/python

# (c) 2025, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Alert Receiver"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.0",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_alert_receiver
short_description: NetApp StorageGRID manage alert receiver.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '21.15.0'
author: NetApp Ansible Team (@vinaykus) <ng-ansibleteam@netapp.com>
description:
  - Create, update, or delete alert receivers on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the alert receiver should be present or absent.
    choices: ['present', 'absent']
    default: 'present'
    type: str
  type:
    description:
    - The type of notification receiver.
    required: true
    choices: ['email']
    type: str
  enable:
    description:
    - Whether alert notifications are sent to this receiver.
    type: bool
    default: true
  smtp_host:
    description:
    - The IP address or hostname of the SMTP server.
    type: str
  smtp_port:
    description:
    - The port to use to communicate with the SMTP server.
    type: int
  username:
    description:
    - Username for the SMTP server.
    type: str
  password:
    description:
    - Password for the SMTP server.
    type: str
  from_email:
    description:
    - Sender email address.
    type: str
  to_emails:
    description:
    - List of recipient email addresses.
    type: list
    elements: str
  minimum_severity:
    description:
    - Minimum severity level for triggering an alert.
    choices: ['minor', 'major', 'critical']
    type: str
  ca_cert:
    description:
    - CA certificate used to verify the identity of the SMTP server.
    type: str
  client_cert:
    description:
    - Client certificate for the SMTP server.
    type: str
  client_key:
    description:
    - The PEM-encoded private key for the client certificate.
    type: str
"""

EXAMPLES = """
- name: Create alert receiver
  netapp.storagegrid.na_sg_alert_receiver:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    type: email
    enable: true
    smtp_host: "smtp.example.com"
    smtp_port: 25
    username: "smtp-user"
    password: "smtp-password"
    from_email: "user@example.com"
    to_emails:
      - "user@example.com"
    minimum_severity: "minor"
    ca_cert: "-----BEGIN CERTIFICATE-----*******-----END CERTIFICATE-----"
    client_cert: "-----BEGIN CERTIFICATE-----*******-----END CERTIFICATE-----"
    client_key: "-----BEGIN PRIVATE KEY-----*******-----END PRIVATE KEY-----"

- name: Delete alert receiver
  netapp.storagegrid.na_sg_alert_receiver:
    api_url: "https://<storagegrid-endpoint-url>"
    auth_token: "storagegrid-auth-token"
    validate_certs: false
    state: present
    type: email
"""

RETURN = """
resp:
  description: Returns the response from the StorageGRID API for alert receiver.
  returned: success
  type: dict
  sample: {
      "type": "email",
      "enable": true,
      "smtpHost": "smtp.example.com",
      "smtpPort": 25,
      "username": "smtp-user",
      "password": "smtp-password",
      "fromEmail": "user@example.com",
      "toEmails": [
        "user@example.com"
      ],
      "minimumSeverity": "minor",
      "caCert": "-----BEGIN CERTIFICATE-----*******-----END CERTIFICATE-----",
      "clientCert": "-----BEGIN CERTIFICATE-----*******-----END CERTIFICATE-----",
      "clientKey": "-----BEGIN PRIVATE KEY-----*******-----END PRIVATE KEY-----",
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgAlertReceiver:
    """
    Create, modify and delete Alert receiver for StorageGRID
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(type="str", choices=["present", "absent"], default="present"),
                type=dict(required=True, type="str", choices=["email"]),
                enable=dict(required=False, type="bool", default=True),
                smtp_host=dict(required=False, type="str"),
                smtp_port=dict(required=False, type="int"),
                username=dict(required=False, type="str"),
                password=dict(required=False, type="str", no_log=True),
                from_email=dict(required=False, type="str"),
                to_emails=dict(required=False, type="list", elements="str"),
                minimum_severity=dict(required=False, type="str", choices=["minor", "major", "critical"]),
                ca_cert=dict(required=False, type="str"),
                client_cert=dict(required=False, type="str"),
                client_key=dict(required=False, type="str", no_log=True),
            )
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[("state", "present", ["type", "smtp_host", "smtp_port", "from_email", "to_emails", "minimum_severity"])],
            supports_check_mode=True
        )
        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Checking for the parameters passed and create new parameters list
        self.data = {}
        self.data["type"] = self.parameters["type"]

        if self.parameters.get("smtp_host"):
            self.data["smtpHost"] = self.parameters["smtp_host"]
        if self.parameters.get("smtp_port"):
            self.data["smtpPort"] = self.parameters["smtp_port"]
        if self.parameters.get("from_email"):
            self.data["fromEmail"] = self.parameters["from_email"]
        if self.parameters.get("to_emails"):
            self.data["toEmails"] = self.parameters["to_emails"]
        if self.parameters.get("minimum_severity"):
            self.data["minimumSeverity"] = self.parameters["minimum_severity"]
        if self.parameters.get("enable") is not None:
            self.data["enable"] = self.parameters["enable"]
        if self.parameters.get("username"):
            self.data["username"] = self.parameters["username"]
        if self.parameters.get("password"):
            self.data["password"] = self.parameters["password"]
        if self.parameters.get("ca_cert"):
            self.data["caCert"] = self.parameters.get("ca_cert")
        if self.parameters.get("client_cert"):
            self.data["clientCert"] = self.parameters.get("client_cert")
        if self.parameters.get("client_key"):
            self.data["clientKey"] = self.parameters.get("client_key")

    def get_alert_receiver(self):
        ''' Get alert receiver '''
        api = "api/v3/grid/alert-receivers"
        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error)
        # if alert 'type' exists, return it, else none
        for alert in response["data"]:
            if alert["type"] == self.parameters["type"]:
                self.id = alert["id"]
                return alert
        return None

    def create_alert_receiver(self):
        ''' Create alert receiver '''
        api = "api/v3/grid/alert-receivers"
        response, error = self.rest_api.post(api, self.data)
        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def delete_alert_receiver(self, alert_receiver_id):
        ''' Delete alert receiver '''
        api = "api/v3/grid/alert-receivers/%s" % alert_receiver_id
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def update_alert_receiver(self, alert_receiver_id):
        ''' Update alert receiver '''
        api = "api/v3/grid/alert-receivers/%s" % alert_receiver_id
        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)
        else:
            return response["data"]

    def apply(self):
        ''' Apply alert receiver '''

        current_receiver = self.get_alert_receiver()

        cd_action = self.na_helper.get_cd_action(current_receiver, self.parameters)
        modify = None

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            if not current_receiver["enable"] and not self.parameters["enable"]:
                self.module.exit_json(changed=False, msg="Alert receiver is disabled.")
            else:
                modify = self.na_helper.get_modified_attributes(current_receiver, self.data)

        result_message = ""
        resp_data = current_receiver
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "create":
                    resp_data = self.create_alert_receiver()
                    result_message = "Alert receiver created successfully."
                elif cd_action == "delete":
                    self.delete_alert_receiver(current_receiver["id"])
                    result_message = "Alert receiver deleted successfully."
                elif modify:
                    resp_data = self.update_alert_receiver(current_receiver["id"])
                    result_message = "Alert receiver updated successfully."

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_grid_alert_receiver = SgAlertReceiver()
    na_sg_grid_alert_receiver.apply()


if __name__ == "__main__":
    main()
