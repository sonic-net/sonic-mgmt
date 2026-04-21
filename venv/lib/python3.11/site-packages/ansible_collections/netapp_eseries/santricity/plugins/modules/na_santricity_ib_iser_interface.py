#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_ib_iser_interface
short_description: NetApp E-Series manage InfiniBand iSER interface configuration
description:
    - Configure settings of an E-Series InfiniBand iSER interface IPv4 address configuration.
author:
    - Michael Price (@lmprice)
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    controller:
        description:
            - The controller that owns the port you want to configure.
            - Controller names are presented alphabetically, with the first controller as A, the second as B, and so on.
            - Current hardware models have either 1 or 2 available controllers, but that is not a guaranteed hard limitation and could change in the future.
        type: str
        required: true
        choices:
            - A
            - B
    channel:
        description:
            - The InfiniBand HCA port you wish to modify.
            - Ports start left to right and start with 1.
        type: int
        required: true
    address:
        description:
            - The IPv4 address to assign to the interface.
            - Should be specified in xx.xx.xx.xx form.
        type: str
        required: true
notes:
    - Check mode is supported.
"""

EXAMPLES = """
    - name: Configure the first port on the A controller with a static IPv4 address
      na_santricity_ib_iser_interface:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        controller: "A"
        channel: "1"
        address: "192.168.1.100"
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The interface settings have been updated.
enabled:
    description:
        - Indicates whether IPv4 connectivity has been enabled or disabled.
        - This does not necessarily indicate connectivity. If dhcp was enabled without a dhcp server, for instance,
          it is unlikely that the configuration will actually be valid.
    returned: on success
    sample: True
    type: bool
"""
import re

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesIbIserInterface(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(controller=dict(type="str", required=True, choices=["A", "B"]),
                               channel=dict(type="int", required=True),
                               address=dict(type="str", required=True))

        super(NetAppESeriesIbIserInterface, self).__init__(ansible_options=ansible_options,
                                                           web_services_version="02.00.0000.0000",
                                                           supports_check_mode=True)

        args = self.module.params
        self.controller = args["controller"]
        self.channel = args["channel"]
        self.address = args["address"]
        self.check_mode = self.module.check_mode

        self.get_target_interface_cache = None

        # A relatively primitive regex to validate that the input is formatted like a valid ip address
        address_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if self.address and not address_regex.match(self.address):
            self.module.fail_json(msg="An invalid ip address was provided for address.")

    def get_interfaces(self):
        """Retrieve and filter all hostside interfaces for IB iSER."""
        ifaces = []
        try:
            rc, ifaces = self.request("storage-systems/%s/interfaces?channelType=hostside" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to retrieve defined host interfaces. Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        # Filter out non-ib-iser interfaces
        ib_iser_ifaces = []
        for iface in ifaces:
            if ((iface["ioInterfaceTypeData"]["interfaceType"] == "iscsi" and
                 iface["ioInterfaceTypeData"]["iscsi"]["interfaceData"]["type"] == "infiniband" and
                 iface["ioInterfaceTypeData"]["iscsi"]["interfaceData"]["infinibandData"]["isIser"]) or
                    (iface["ioInterfaceTypeData"]["interfaceType"] == "ib" and
                     iface["ioInterfaceTypeData"]["ib"]["isISERSupported"])):
                ib_iser_ifaces.append(iface)

        if not ib_iser_ifaces:
            self.module.fail_json(msg="Failed to detect any InfiniBand iSER interfaces! Array [%s] - %s." % self.ssid)

        return ib_iser_ifaces

    def get_controllers(self):
        """Retrieve a mapping of controller labels to their references
        {
            'A': '070000000000000000000001',
            'B': '070000000000000000000002',
        }
        :return: the controllers defined on the system
        """
        controllers = list()
        try:
            rc, controllers = self.request("storage-systems/%s/graph/xpath-filter?query=/controller/id" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to retrieve controller list! Array Id [%s]. Error [%s]."
                                      % (self.ssid, to_native(err)))

        controllers.sort()

        controllers_dict = {}
        i = ord('A')
        for controller in controllers:
            label = chr(i)
            controllers_dict[label] = controller
            i += 1

        return controllers_dict

    def get_ib_link_status(self):
        """Determine the infiniband link status. Returns dictionary keyed by interface reference number."""
        link_statuses = {}
        try:
            rc, result = self.request("storage-systems/%s/hardware-inventory" % self.ssid)
            for link in result["ibPorts"]:
                link_statuses.update({link["channelPortRef"]: link["linkState"]})
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve ib link status information! Array Id [%s]. Error [%s]."
                                  % (self.ssid, to_native(error)))

        return link_statuses

    def get_target_interface(self):
        """Search for the selected IB iSER interface"""
        if self.get_target_interface_cache is None:
            ifaces = self.get_interfaces()
            ifaces_status = self.get_ib_link_status()
            controller_id = self.get_controllers()[self.controller]

            controller_ifaces = []
            for iface in ifaces:
                if iface["ioInterfaceTypeData"]["interfaceType"] == "iscsi" and iface["controllerRef"] == controller_id:
                    controller_ifaces.append([iface["ioInterfaceTypeData"]["iscsi"]["channel"], iface,
                                              ifaces_status[iface["ioInterfaceTypeData"]["iscsi"]["channelPortRef"]]])
                elif iface["ioInterfaceTypeData"]["interfaceType"] == "ib" and iface["controllerRef"] == controller_id:
                    controller_ifaces.append([iface["ioInterfaceTypeData"]["ib"]["channel"], iface,
                                              iface["ioInterfaceTypeData"]["ib"]["linkState"]])

            sorted_controller_ifaces = sorted(controller_ifaces)
            if self.channel < 1 or self.channel > len(controller_ifaces):
                status_msg = ", ".join(["%s (link %s)" % (index + 1, values[2])
                                        for index, values in enumerate(sorted_controller_ifaces)])
                self.module.fail_json(msg="Invalid controller %s HCA channel. Available channels: %s, Array Id [%s]."
                                          % (self.controller, status_msg, self.ssid))

            self.get_target_interface_cache = sorted_controller_ifaces[self.channel - 1][1]
        return self.get_target_interface_cache

    def is_change_required(self):
        """Determine whether change is required."""
        changed_required = False
        iface = self.get_target_interface()
        if (iface["ioInterfaceTypeData"]["interfaceType"] == "iscsi" and
                iface["ioInterfaceTypeData"]["iscsi"]["ipv4Data"]["ipv4AddressData"]["ipv4Address"] != self.address):
            changed_required = True

        elif iface["ioInterfaceTypeData"]["interfaceType"] == "ib" and iface["ioInterfaceTypeData"]["ib"]["isISERSupported"]:
            for properties in iface["commandProtocolPropertiesList"]["commandProtocolProperties"]:
                if (properties["commandProtocol"] == "scsi" and
                        properties["scsiProperties"]["scsiProtocolType"] == "iser" and
                        properties["scsiProperties"]["iserProperties"]["ipv4Data"]["ipv4AddressData"]["ipv4Address"] != self.address):
                    changed_required = True

        return changed_required

    def make_request_body(self):
        iface = self.get_target_interface()
        body = {"iscsiInterface": iface["ioInterfaceTypeData"][iface["ioInterfaceTypeData"]["interfaceType"]]["id"],
                "settings": {"tcpListenPort": [],
                             "ipv4Address": [self.address],
                             "ipv4SubnetMask": [],
                             "ipv4GatewayAddress": [],
                             "ipv4AddressConfigMethod": [],
                             "maximumFramePayloadSize": [],
                             "ipv4VlanId": [],
                             "ipv4OutboundPacketPriority": [],
                             "ipv4Enabled": [],
                             "ipv6Enabled": [],
                             "ipv6LocalAddresses": [],
                             "ipv6RoutableAddresses": [],
                             "ipv6PortRouterAddress": [],
                             "ipv6AddressConfigMethod": [],
                             "ipv6OutboundPacketPriority": [],
                             "ipv6VlanId": [],
                             "ipv6HopLimit": [],
                             "ipv6NdReachableTime": [],
                             "ipv6NdRetransmitTime": [],
                             "ipv6NdStaleTimeout": [],
                             "ipv6DuplicateAddressDetectionAttempts": [],
                             "maximumInterfaceSpeed": []}}
        return body

    def update(self):
        """Make any necessary updates."""
        update_required = self.is_change_required()
        if update_required and not self.check_mode:
            try:
                rc, result = self.request("storage-systems/%s/symbol/setIscsiInterfaceProperties"
                                          % self.ssid, method="POST", data=self.make_request_body())
            except Exception as error:
                self.module.fail_json(msg="Failed to modify the interface! Array Id [%s]. Error [%s]."
                                          % (self.ssid, to_native(error)))
            self.module.exit_json(msg="The interface settings have been updated.", changed=update_required)

        self.module.exit_json(msg="No changes were required.", changed=update_required)


def main():
    ib_iser = NetAppESeriesIbIserInterface()
    ib_iser.update()


if __name__ == "__main__":
    main()
