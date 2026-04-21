#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_nvme_interface
short_description: NetApp E-Series manage NVMe interface configuration
description: Configure settings of an E-Series NVMe interface
author:
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    address:
        description:
            - The IPv4 address to assign to the NVMe interface
        type: str
        required: false
    subnet_mask:
        description:
            - The subnet mask to utilize for the interface.
            - Only applicable when configuring RoCE
            - Mutually exclusive with I(config_method=dhcp)
        type: str
        required: false
    gateway:
        description:
            - The IPv4 gateway address to utilize for the interface.
            - Only applicable when configuring RoCE
            - Mutually exclusive with I(config_method=dhcp)
        type: str
        required: false
    config_method:
        description:
            - The configuration method type to use for this interface.
            - Only applicable when configuring RoCE
            - dhcp is mutually exclusive with I(address), I(subnet_mask), and I(gateway).
        type: str
        choices:
            - dhcp
            - static
        required: false
        default: dhcp
    mtu:
        description:
            - The maximum transmission units (MTU), in bytes.
            - Only applicable when configuring RoCE
            - This allows you to configure a larger value for the MTU, in order to enable jumbo frames
              (any value > 1500).
            - Generally, it is necessary to have your host, switches, and other components not only support jumbo
              frames, but also have it configured properly. Therefore, unless you know what you're doing, it's best to
              leave this at the default.
        type: int
        default: 1500
        required: false
        aliases:
            - max_frame_size
    speed:
        description:
            - This is the ethernet port speed measured in Gb/s.
            - Value must be a supported speed or auto for automatically negotiating the speed with the port.
            - Only applicable when configuring RoCE
            - The configured ethernet port speed should match the speed capability of the SFP on the selected port.
        type: str
        required: false
        default: auto
    state:
        description:
            - Whether or not the specified RoCE interface should be enabled.
            - Only applicable when configuring RoCE
        choices:
            - enabled
            - disabled
        type: str
        required: false
        default: enabled
    channel:
        description:
            - This option specifies the which NVMe controller channel to configure.
            - The list of choices is not necessarily comprehensive. It depends on the number of ports
              that are available in the system.
            - The numerical value represents the number of the channel (typically from left to right on the HIC),
              beginning with a value of 1.
        type: int
        required: true
    controller:
        description:
            - The controller that owns the port you want to configure.
            - Controller names are presented alphabetically, with the first controller as A and the second as B.
        type: str
        required: true
        choices: [A, B]
"""
EXAMPLES = """
"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The interface settings have been updated.
"""
import re

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native


class NetAppESeriesNvmeInterface(NetAppESeriesModule):
    def __init__(self):
        ansible_options = dict(address=dict(type="str", required=False),
                               subnet_mask=dict(type="str", required=False),
                               gateway=dict(type="str", required=False),
                               config_method=dict(type="str", required=False, default="dhcp", choices=["dhcp", "static"]),
                               mtu=dict(type="int", default=1500, required=False, aliases=["max_frame_size"]),
                               speed=dict(type="str", default="auto", required=False),
                               state=dict(type="str", default="enabled", required=False, choices=["enabled", "disabled"]),
                               channel=dict(type="int", required=True),
                               controller=dict(type="str", required=True, choices=["A", "B"]))

        required_if = [["config_method", "static", ["address", "subnet_mask"]]]
        super(NetAppESeriesNvmeInterface, self).__init__(ansible_options=ansible_options,
                                                         web_services_version="02.00.0000.0000",
                                                         required_if=required_if,
                                                         supports_check_mode=True)

        args = self.module.params
        self.address = args["address"]
        self.subnet_mask = args["subnet_mask"]
        self.gateway = args["gateway"]
        self.config_method = "configDhcp" if args["config_method"] == "dhcp" else "configStatic"
        self.mtu = args["mtu"]
        self.speed = args["speed"]
        self.enabled = args["state"] == "enabled"
        self.channel = args["channel"]
        self.controller = args["controller"]

        address_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if self.address and not address_regex.match(self.address):
            self.module.fail_json(msg="An invalid ip address was provided for address. Address [%s]." % self.address)
        if self.subnet_mask and not address_regex.match(self.subnet_mask):
            self.module.fail_json(msg="An invalid ip address was provided for subnet_mask. Subnet mask [%s]." % self.subnet_mask)
        if self.gateway and not address_regex.match(self.gateway):
            self.module.fail_json(msg="An invalid ip address was provided for gateway. Gateway [%s]." % self.gateway)

        self.get_target_interface_cache = None

    def get_nvmeof_interfaces(self):
        """Retrieve all interfaces that are using nvmeof"""
        ifaces = list()
        try:
            rc, ifaces = self.request("storage-systems/%s/interfaces?channelType=hostside" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve defined host interfaces. Array Id [%s]. Error [%s]."
                                      % (self.ssid, to_native(error)))

        # Filter out all not nvme-nvmeof hostside interfaces.
        nvmeof_ifaces = []
        for iface in ifaces:
            interface_type = iface["ioInterfaceTypeData"]["interfaceType"]
            properties = iface["commandProtocolPropertiesList"]["commandProtocolProperties"]

            try:
                link_status = iface["ioInterfaceTypeData"]["ib"]["linkState"]
            except Exception as error:
                link_status = iface["ioInterfaceTypeData"]["ethernet"]["interfaceData"]["ethernetData"]["linkStatus"]

            if (properties and properties[0]["commandProtocol"] == "nvme" and
                    properties[0]["nvmeProperties"]["commandSet"] == "nvmeof"):
                nvmeof_ifaces.append({"properties": properties[0]["nvmeProperties"]["nvmeofProperties"],
                                      "reference": iface["interfaceRef"],
                                      "channel": iface["ioInterfaceTypeData"][iface["ioInterfaceTypeData"]["interfaceType"]]["channel"],
                                      "interface_type": interface_type,
                                      "interface": iface["ioInterfaceTypeData"][interface_type],
                                      "controller_id": iface["controllerRef"],
                                      "link_status": link_status})
        return nvmeof_ifaces

    def get_controllers(self):
        """Retrieve a mapping of controller labels to their references"""
        controllers = list()
        try:
            rc, controllers = self.request("storage-systems/%s/graph/xpath-filter?query=/controller/id" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve controller list! Array Id [%s]. Error [%s]."
                                      % (self.ssid, to_native(error)))

        controllers.sort()
        controllers_dict = {}
        i = ord("A")
        for controller in controllers:
            label = chr(i)
            controllers_dict[label] = controller
            i += 1

        return controllers_dict

    def get_target_interface(self):
        """Retrieve the targeted controller interface"""
        if self.get_target_interface_cache is None:
            ifaces = self.get_nvmeof_interfaces()
            controller_id = self.get_controllers()[self.controller]

            controller_ifaces = []
            for iface in ifaces:
                if iface["controller_id"] == controller_id:
                    controller_ifaces.append(iface)

            sorted_controller_ifaces = sorted(controller_ifaces, key=lambda x: x["channel"])
            if self.channel < 1 or self.channel > len(controller_ifaces):
                status_msg = ", ".join(["%s (link %s)" % (index + 1, iface["link_status"])
                                        for index, iface in enumerate(sorted_controller_ifaces)])
                self.module.fail_json(msg="Invalid controller %s NVMe channel. Available channels: %s, Array Id [%s]."
                                          % (self.controller, status_msg, self.ssid))

            self.get_target_interface_cache = sorted_controller_ifaces[self.channel - 1]

        return self.get_target_interface_cache

    def update(self):
        """Update the storage system's controller nvme interface if needed."""
        update_required = False
        body = {}

        iface = self.get_target_interface()
        if iface["properties"]["provider"] == "providerInfiniband":
            if (iface["properties"]["ibProperties"]["ipAddressData"]["addressType"] != "ipv4" or
                    iface["properties"]["ibProperties"]["ipAddressData"]["ipv4Data"]["ipv4Address"] != self.address):
                update_required = True
                body = {"settings": {"ibSettings": {"networkSettings": {"ipv4Address": self.address}}}}

        elif iface["properties"]["provider"] == "providerRocev2":
            interface_data = iface["interface"]["interfaceData"]["ethernetData"]
            current_speed = interface_data["currentInterfaceSpeed"].lower().replace("speed", "").replace("gig", "")
            interface_supported_speeds = [str(speed).lower().replace("speed", "").replace("gig", "")
                                          for speed in interface_data["supportedInterfaceSpeeds"]]
            if self.speed not in interface_supported_speeds:
                self.module.fail_json(msg="Unsupported interface speed! Options %s. Array [%s]."
                                          % (interface_supported_speeds, self.ssid))

            roce_properties = iface["properties"]["roceV2Properties"]
            if self.enabled != roce_properties["ipv4Enabled"]:
                update_required = True
            if self.address and roce_properties["ipv4Data"]["ipv4AddressConfigMethod"] != self.config_method:
                update_required = True
            if self.address and roce_properties["ipv4Data"]["ipv4AddressData"]["ipv4Address"] != self.address:
                update_required = True
            if self.subnet_mask and roce_properties["ipv4Data"]["ipv4AddressData"]["ipv4SubnetMask"] != self.subnet_mask:
                update_required = True
            if self.gateway and roce_properties["ipv4Data"]["ipv4AddressData"]["ipv4GatewayAddress"] != self.gateway:
                update_required = True
            if self.speed and self.speed != current_speed:
                update_required = True
            if (self.mtu and iface["interface"]["interfaceData"]["ethernetData"][
                    "maximumFramePayloadSize"] != self.mtu):
                update_required = True

            if update_required:
                body = {"id": iface["reference"], "settings": {"roceV2Settings": {
                    "networkSettings": {"ipv4Enabled": self.enabled,
                                        "ipv4Settings": {"configurationMethod": self.config_method}}}}}

                if self.config_method == "configStatic":
                    if self.address:
                        body["settings"]["roceV2Settings"]["networkSettings"]["ipv4Settings"].update(
                            {"address": self.address})
                    if self.subnet_mask:
                        body["settings"]["roceV2Settings"]["networkSettings"]["ipv4Settings"].update(
                            {"subnetMask": self.subnet_mask})
                    if self.gateway:
                        body["settings"]["roceV2Settings"]["networkSettings"]["ipv4Settings"].update(
                            {"gatewayAddress": self.gateway})
                if self.speed:
                    if self.speed == "auto":
                        body["settings"]["roceV2Settings"]["networkSettings"].update({"interfaceSpeed": "speedAuto"})
                    else:
                        body["settings"]["roceV2Settings"]["networkSettings"].update(
                            {"interfaceSpeed": "speed%sgig" % self.speed})
                if self.mtu:
                    body["settings"]["roceV2Settings"]["networkSettings"].update({"interfaceMtu": self.mtu})

        if update_required and not self.module.check_mode:
            try:
                rc, iface = self.request("storage-systems/%s/nvmeof/interfaces/%s" % (self.ssid, iface["reference"]),
                                         method="POST", data=body)
            except Exception as error:
                self.module.fail_json(msg="Failed to configure interface. Array Id [%s]. Error [%s]."
                                          % (self.ssid, to_native(error)))

            self.module.exit_json(msg="NVMeoF interface settings have been updated.", changed=update_required)
        self.module.exit_json(msg="No changes have been made.", changed=update_required)


def main():
    nvmeof_interface = NetAppESeriesNvmeInterface()
    nvmeof_interface.update()


if __name__ == "__main__":
    main()
