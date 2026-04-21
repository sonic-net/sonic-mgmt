#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_alerts_syslog
short_description: NetApp E-Series manage syslog servers receiving storage system alerts.
description:
    - Manage the list of syslog servers that will notifications on potentially critical events.
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    servers:
        description:
            - List of dictionaries where each dictionary contains a syslog server entry.
        type: list
        elements: raw
        required: False
        suboptions:
            address:
                description:
                    - Syslog server address can be a fully qualified domain name, IPv4 address, or IPv6 address.
                required: true
            port:
                description:
                    - UDP Port must be a numerical value between 0 and 65535. Typically, the UDP Port for syslog is 514.
                required: false
                default: 514
    test:
        description:
            - This forces a test syslog message to be sent to the stated syslog server.
            - Test will only be issued when a change is made.
        type: bool
        required: false
        default: false
notes:
    - Check mode is supported.
    - This API is currently only supported with the Embedded Web Services API v2.12 (bundled with
      SANtricity OS 11.40.2) and higher.
"""

EXAMPLES = """
    - name: Add two syslog server configurations to NetApp E-Series storage array.
      na_santricity_alerts_syslog:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        servers:
            - address: "192.168.1.100"
            - address: "192.168.2.100"
              port: 514
            - address: "192.168.3.100"
              port: 1000
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The settings have been updated.
"""
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesAlertsSyslog(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(servers=dict(type="list", required=False, elements='raw'),
                               test=dict(type="bool", default=False, required=False))

        required_if = None
        mutually_exclusive = None

        super(NetAppESeriesAlertsSyslog, self).__init__(ansible_options=ansible_options,
                                                        web_services_version="02.00.0000.0000",
                                                        mutually_exclusive=mutually_exclusive,
                                                        required_if=required_if,
                                                        supports_check_mode=True)
        args = self.module.params
        if args["servers"] and len(args["servers"]) > 5:
            self.module.fail_json(msg="Maximum number of syslog servers is 5! Array Id [%s]." % self.ssid)

        self.servers = {}
        if args["servers"] is not None:
            for server in args["servers"]:
                port = 514
                if "port" in server:
                    port = server["port"]
                self.servers.update({server["address"]: port})

        self.test = args["test"]
        self.check_mode = self.module.check_mode

        # Check whether request needs to be forwarded on to the controller web services rest api.
        self.url_path_prefix = ""
        if not self.is_embedded() and self.ssid != "0" and self.ssid.lower() != "proxy":
            self.url_path_prefix = "storage-systems/%s/forward/devmgr/v2/" % self.ssid

    def get_current_configuration(self):
        """Retrieve existing alert-syslog configuration."""
        try:
            rc, result = self.request(self.url_path_prefix + "storage-systems/%s/device-alerts/alert-syslog" % ("1" if self.url_path_prefix else self.ssid))
            return result
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve syslog configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(error)))

    def is_change_required(self):
        """Determine whether changes are required."""
        current_config = self.get_current_configuration()

        # When syslog servers should exist, search for them.
        if self.servers:
            for entry in current_config["syslogReceivers"]:
                if entry["serverName"] not in self.servers.keys() or entry["portNumber"] != self.servers[entry["serverName"]]:
                    return True

            for server, port in self.servers.items():
                for entry in current_config["syslogReceivers"]:
                    if server == entry["serverName"] and port == entry["portNumber"]:
                        break
                else:
                    return True
            return False

        elif current_config["syslogReceivers"]:
            return True

        return False

    def make_request_body(self):
        """Generate the request body."""
        body = {"syslogReceivers": [], "defaultFacility": 3, "defaultTag": "StorageArray"}

        for server, port in self.servers.items():
            body["syslogReceivers"].append({"serverName": server, "portNumber": port})

        return body

    def test_configuration(self):
        """Send syslog test message to all systems (only option)."""
        try:
            rc, result = self.request(self.url_path_prefix + "storage-systems/%s/device-alerts/alert-syslog-test"
                                      % ("1" if self.url_path_prefix else self.ssid), method="POST")
        except Exception as error:
            self.module.fail_json(msg="Failed to send test message! Array Id [%s]. Error [%s]." % (self.ssid, to_native(error)))

    def update(self):
        """Update configuration and respond to ansible."""
        change_required = self.is_change_required()

        if change_required and not self.check_mode:
            try:
                rc, result = self.request(self.url_path_prefix + "storage-systems/%s/device-alerts/alert-syslog" % ("1" if self.url_path_prefix else self.ssid),
                                          method="POST", data=self.make_request_body())
            except Exception as error:
                self.module.fail_json(msg="Failed to add syslog server! Array Id [%s]. Error [%s]." % (self.ssid, to_native(error)))

            if self.test and self.servers:
                self.test_configuration()

        self.module.exit_json(msg="The syslog settings have been updated.", changed=change_required)


def main():
    settings = NetAppESeriesAlertsSyslog()
    settings.update()


if __name__ == '__main__':
    main()
