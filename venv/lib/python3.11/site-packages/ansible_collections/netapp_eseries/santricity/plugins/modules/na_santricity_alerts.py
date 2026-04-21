#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_alerts
short_description: NetApp E-Series manage email notification settings
description:
    - Certain E-Series systems have the capability to send email notifications on potentially critical events.
    - This module will allow the owner of the system to specify email recipients for these messages.
author:
    - Michael Price (@lmprice)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    state:
        description:
            - Enable/disable the sending of email-based alerts.
        type: str
        default: enabled
        required: false
        choices:
            - enabled
            - disabled
    server:
        description:
            - A fully qualified domain name, IPv4 address, or IPv6 address of a mail server.
            - To use a fully qualified domain name, you must configure a DNS server on both controllers using
             M(netapp_eseries.santricity.na_santricity_mgmt_interface).
             - Required when I(state=enabled).
        type: str
        required: false
    sender:
        description:
            - This is the sender that the recipient will see. It doesn't necessarily need to be a valid email account.
            - Required when I(state=enabled).
        type: str
        required: false
    contact:
        description:
            - Allows the owner to specify some free-form contact information to be included in the emails.
            - This is typically utilized to provide a contact phone number.
        type: str
        required: false
    recipients:
        description:
            - The email addresses that will receive the email notifications.
            - Required when I(state=enabled).
        type: list
        elements: str
        required: false
    test:
        description:
            - When a change is detected in the configuration, a test email will be sent.
            - This may take a few minutes to process.
            - Only applicable if I(state=enabled).
        type: bool
        required: false
        default: false
notes:
    - Check mode is supported.
    - Alertable messages are a subset of messages shown by the Major Event Log (MEL), of the storage-system. Examples
      of alertable messages include drive failures, failed controllers, loss of redundancy, and other warning/critical
      events.
    - This API is currently only supported with the Embedded Web Services API v2.0 and higher.
"""

EXAMPLES = """
    - name: Enable email-based alerting
      na_santricity_alerts:
        state: enabled
        sender: noreply@example.com
        server: mail@example.com
        contact: "Phone: 1-555-555-5555"
        recipients:
            - name1@example.com
            - name2@example.com
        api_url: "10.1.1.1:8443"
        api_username: "admin"
        api_password: "myPass"

    - name: Disable alerting
      na_santricity_alerts:
        state: disabled
        api_url: "10.1.1.1:8443"
        api_username: "admin"
        api_password: "myPass"
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The settings have been updated.
"""
import re

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesAlerts(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(state=dict(type='str', required=False, default='enabled', choices=['enabled', 'disabled']),
                               server=dict(type='str', required=False),
                               sender=dict(type='str', required=False),
                               contact=dict(type='str', required=False),
                               recipients=dict(type='list', elements='str', required=False),
                               test=dict(type='bool', required=False, default=False))

        required_if = [['state', 'enabled', ['server', 'sender', 'recipients']]]
        super(NetAppESeriesAlerts, self).__init__(ansible_options=ansible_options,
                                                  web_services_version="02.00.0000.0000",
                                                  required_if=required_if,
                                                  supports_check_mode=True)

        args = self.module.params
        self.alerts = args['state'] == 'enabled'
        self.server = args['server']
        self.sender = args['sender']
        self.contact = args['contact']
        self.recipients = args['recipients']
        self.test = args['test']
        self.check_mode = self.module.check_mode

        # Very basic validation on email addresses: xx@yy.zz
        email = re.compile(r"[^@]+@[^@]+\.[^@]+")

        if self.sender and not email.match(self.sender):
            self.module.fail_json(msg="The sender (%s) provided is not a valid email address." % self.sender)

        if self.recipients is not None:
            for recipient in self.recipients:
                if not email.match(recipient):
                    self.module.fail_json(msg="The recipient (%s) provided is not a valid email address." % recipient)

            if len(self.recipients) < 1:
                self.module.fail_json(msg="At least one recipient address must be specified.")

    def get_configuration(self):
        """Retrieve the current storage system alert settings."""
        if self.is_proxy():
            if self.is_embedded_available():
                try:
                    rc, result = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/device-alerts" % self.ssid)
                    return result
                except Exception as err:
                    self.module.fail_json(msg="Failed to retrieve the alerts configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))
            else:
                self.module.fail_json(msg="Setting SANtricity alerts is only available from SANtricity Web Services Proxy if the storage system has"
                                          " SANtricity Web Services Embedded available. Array [%s]." % self.ssid)
        else:
            try:
                rc, result = self.request("storage-systems/%s/device-alerts" % self.ssid)
                return result
            except Exception as err:
                self.module.fail_json(msg="Failed to retrieve the alerts configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def update_configuration(self):
        """Update the storage system alert settings."""
        config = self.get_configuration()
        update = False
        body = dict()

        if self.alerts:
            body = dict(alertingEnabled=True)
            if not config['alertingEnabled']:
                update = True

            body.update(emailServerAddress=self.server)
            if config['emailServerAddress'] != self.server:
                update = True

            body.update(additionalContactInformation=self.contact, sendAdditionalContactInformation=True)
            if self.contact and (self.contact != config['additionalContactInformation']
                                 or not config['sendAdditionalContactInformation']):
                update = True

            body.update(emailSenderAddress=self.sender)
            if config['emailSenderAddress'] != self.sender:
                update = True

            self.recipients.sort()
            if config['recipientEmailAddresses']:
                config['recipientEmailAddresses'].sort()

            body.update(recipientEmailAddresses=self.recipients)
            if config['recipientEmailAddresses'] != self.recipients:
                update = True

        elif config['alertingEnabled']:
            body = {"alertingEnabled": False, "emailServerAddress": "", "emailSenderAddress": "", "sendAdditionalContactInformation": False,
                    "additionalContactInformation": "", "recipientEmailAddresses": []}
            update = True

        if update and not self.check_mode:
            if self.is_proxy() and self.is_embedded_available():
                try:
                    rc, result = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/device-alerts" % self.ssid, method="POST", data=body)
                except Exception as err:
                    self.module.fail_json(msg="We failed to set the storage-system name! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

            else:
                try:
                    rc, result = self.request("storage-systems/%s/device-alerts" % self.ssid, method="POST", data=body)
                except Exception as err:
                    self.module.fail_json(msg="We failed to set the storage-system name! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        return update

    def send_test_email(self):
        """Send a test email to verify that the provided configuration is valid and functional."""
        if not self.check_mode:
            if self.is_proxy() and self.is_embedded_available():
                try:
                    rc, resp = self.request("storage-systems/%s/forward/devmgr/v2/storage-systems/1/device-alerts/alert-email-test" % self.ssid, method="POST")
                    if resp['response'] != 'emailSentOK':
                        self.module.fail_json(msg="The test email failed with status=[%s]! Array Id [%s]." % (resp['response'], self.ssid))
                except Exception as err:
                    self.module.fail_json(msg="We failed to send the test email! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

            else:
                try:
                    rc, resp = self.request("storage-systems/%s/device-alerts/alert-email-test" % self.ssid, method="POST")
                    if resp['response'] != 'emailSentOK':
                        self.module.fail_json(msg="The test email failed with status=[%s]! Array Id [%s]." % (resp['response'], self.ssid))
                except Exception as err:
                    self.module.fail_json(msg="We failed to send the test email! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def update(self):
        update = self.update_configuration()

        if self.test and update:
            self.send_test_email()

        if self.alerts:
            msg = 'Alerting has been enabled using server=%s, sender=%s.' % (self.server, self.sender)
        else:
            msg = 'Alerting has been disabled.'

        self.module.exit_json(msg=msg, changed=update)


def main():
    alerts = NetAppESeriesAlerts()
    alerts.update()


if __name__ == '__main__':
    main()
