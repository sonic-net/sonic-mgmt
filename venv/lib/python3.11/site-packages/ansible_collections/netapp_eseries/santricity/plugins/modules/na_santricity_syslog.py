#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_syslog
short_description: NetApp E-Series manage syslog settings
description:
    - Allow the syslog settings to be configured for an individual E-Series storage-system
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    state:
        description:
            - Add or remove the syslog server configuration for E-Series storage array.
            - Existing syslog server configuration will be removed or updated when its address matches I(address).
            - Fully qualified hostname that resolve to an IPv4 address that matches I(address) will not be
              treated as a match.
        type: str
        choices:
            - present
            - absent
        default: present
        required: false
    address:
        description:
            - The syslog server's IPv4 address or a fully qualified hostname.
            - All existing syslog configurations will be removed when I(state=absent) and I(address=None).
        type: str
        required: false
    port:
        description:
            - This is the port the syslog server is using.
        type: int
        default: 514
        required: false
    protocol:
        description:
            - This is the transmission protocol the syslog server's using to receive syslog messages.
        type: str
        default: udp
        choices:
            - udp
            - tcp
            - tls
        required: false
    components:
        description:
            - The e-series logging components define the specific logs to transfer to the syslog server.
            - At the time of writing, 'auditLog' is the only logging component but more may become available.
        type: list
        elements: str
        default: ["auditLog"]
        required: false
    test:
        description:
            - This forces a test syslog message to be sent to the stated syslog server.
            - Only attempts transmission when I(state=present).
        type: bool
        default: false
        required: false
notes:
    - Check mode is supported.
    - This API is currently only supported with the Embedded Web Services API v2.12 (bundled with
      SANtricity OS 11.40.2) and higher.
"""

EXAMPLES = """
    - name: Add two syslog server configurations to NetApp E-Series storage array.
      na_santricity_syslog:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        state: present
        address: "{{ item }}"
        port: 514
        protocol: tcp
        component: "auditLog"
      loop:
        - "192.168.1.1"
        - "192.168.1.100"
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The settings have been updated.
syslog:
    description:
        - True if syslog server configuration has been added to e-series storage array.
    returned: on success
    sample: True
    type: bool
"""
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesSyslog(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(
            state=dict(choices=["present", "absent"], required=False, default="present"),
            address=dict(type="str", required=False),
            port=dict(type="int", default=514, required=False),
            protocol=dict(choices=["tcp", "tls", "udp"], default="udp", required=False),
            components=dict(type="list", elements="str", required=False, default=["auditLog"]),
            test=dict(type="bool", default=False, required=False))

        required_if = [["state", "present", ["address", "port", "protocol", "components"]]]
        mutually_exclusive = None

        super(NetAppESeriesSyslog, self).__init__(ansible_options=ansible_options,
                                                  web_services_version="02.00.0000.0000",
                                                  mutually_exclusive=mutually_exclusive,
                                                  required_if=required_if,
                                                  supports_check_mode=True)
        args = self.module.params

        self.syslog = args["state"] in ["present"]
        self.address = args["address"]
        self.port = args["port"]
        self.protocol = args["protocol"]
        self.components = args["components"]
        self.test = args["test"]
        self.ssid = args["ssid"]
        self.url = args["api_url"]
        self.creds = dict(url_password=args["api_password"],
                          validate_certs=args["validate_certs"],
                          url_username=args["api_username"], )

        self.components.sort()
        self.check_mode = self.module.check_mode

        # Check whether request needs to be forwarded on to the controller web services rest api.
        self.url_path_prefix = ""
        if not self.is_embedded() and self.ssid != "0" and self.ssid.lower() != "proxy":
            self.url_path_prefix = "storage-systems/%s/forward/devmgr/v2/" % self.ssid

    def get_configuration(self):
        """Retrieve existing syslog configuration."""
        try:
            rc, result = self.request(self.url_path_prefix + "storage-systems/%s/syslog" % self.ssid)
            return result
        except Exception as err:
            self.module.fail_json(msg="Failed to retrieve syslog configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def test_configuration(self, body):
        """Send test syslog message to the storage array.

        Allows fix number of retries to occur before failure is issued to give the storage array time to create
        new syslog server record.
        """
        try:
            rc, result = self.request(self.url_path_prefix + "storage-systems/%s/syslog/%s/test" % (self.ssid, body["id"]), method='POST')
        except Exception as err:
            self.module.fail_json(msg="We failed to send test message! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def update_configuration(self):
        """Post the syslog request to array."""
        config_match = None
        perfect_match = None
        update = False
        body = dict()

        # search existing configuration for syslog server entry match
        configs = self.get_configuration()
        if self.address:
            for config in configs:
                if config["serverAddress"] == self.address:
                    config_match = config
                    if (config["port"] == self.port and config["protocol"] == self.protocol and
                            len(config["components"]) == len(self.components) and
                            all(component["type"] in self.components for component in config["components"])):
                        perfect_match = config_match
                        break

        # generate body for the http request
        if self.syslog:
            if not perfect_match:
                update = True
                if config_match:
                    body.update(dict(id=config_match["id"]))
                components = [dict(type=component_type) for component_type in self.components]
                body.update(dict(serverAddress=self.address, port=self.port,
                                 protocol=self.protocol, components=components))
                self.make_configuration_request(body)

        elif config_match:

            # remove specific syslog server configuration
            if self.address:
                update = True
                body.update(dict(id=config_match["id"]))
                self.make_configuration_request(body)

            # if no address is specified, remove all syslog server configurations
            elif configs:
                update = True
                for config in configs:
                    body.update(dict(id=config["id"]))
                    self.make_configuration_request(body)

        return update

    def make_configuration_request(self, body):
        # make http request(s)
        if not self.check_mode:
            try:
                if self.syslog:
                    if "id" in body:
                        rc, result = self.request(self.url_path_prefix + "storage-systems/%s/syslog/%s" % (self.ssid, body["id"]),
                                                  method='POST', data=body)
                    else:
                        rc, result = self.request(self.url_path_prefix + "storage-systems/%s/syslog" % self.ssid, method='POST', data=body)
                        body.update(result)

                    # send syslog test message
                    if self.test:
                        self.test_configuration(body)

                elif "id" in body:
                    rc, result = self.request(self.url_path_prefix + "storage-systems/%s/syslog/%s" % (self.ssid, body["id"]), method='DELETE')

            # This is going to catch cases like a connection failure
            except Exception as err:
                self.module.fail_json(msg="We failed to modify syslog configuration! Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

    def update(self):
        """Update configuration and respond to ansible."""
        update = self.update_configuration()
        self.module.exit_json(msg="The syslog settings have been updated.", changed=update)


def main():
    settings = NetAppESeriesSyslog()
    settings.update()


if __name__ == "__main__":
    main()
