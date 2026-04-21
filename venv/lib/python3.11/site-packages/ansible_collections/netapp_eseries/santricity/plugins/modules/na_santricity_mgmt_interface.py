#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: na_santricity_mgmt_interface
short_description: NetApp E-Series manage management interface configuration
description:
    - Configure the E-Series management interfaces
author:
    - Michael Price (@lmprice)
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    state:
        description:
            - Enable or disable IPv4 network interface configuration.
            - Either IPv4 or IPv6 must be enabled otherwise error will occur.
            - Assumed to be I(state==enabled) when I(config_method) is specified unless defined.
        choices:
            - enabled
            - disabled
        type: str
        required: false
    controller:
        description:
            - The controller that owns the port you want to configure.
            - Controller names are represented alphabetically, with the first controller as A,
              the second as B, and so on.
            - Current hardware models have either 1 or 2 available controllers, but that is not a guaranteed hard
             limitation and could change in the future.
        choices:
            - A
            - B
        type: str
        required: true
    port:
        description:
            - The ethernet port configuration to modify.
            - The channel represents the port number left to right on the controller, beginning with 1.
            - Required when I(config_method) is specified.
        type: int
        required: false
    address:
        description:
            - The IPv4 address to assign to the interface.
            - Should be specified in xx.xx.xx.xx form.
            - Mutually exclusive with I(config_method=dhcp)
        type: str
        required: false
    subnet_mask:
        description:
            - The subnet mask to utilize for the interface.
            - Should be specified in xx.xx.xx.xx form.
            - Mutually exclusive with I(config_method=dhcp)
        type: str
        required: false
    gateway:
        description:
            - The IPv4 gateway address to utilize for the interface.
            - Should be specified in xx.xx.xx.xx form.
            - Mutually exclusive with I(config_method=dhcp)
        type: str
        required: false
    config_method:
        description:
            - The configuration method type to use for network interface ports.
            - dhcp is mutually exclusive with I(address), I(subnet_mask), and I(gateway).
        choices:
            - dhcp
            - static
        type: str
        required: false
    dns_config_method:
        description:
            - The configuration method type to use for DNS services.
            - dhcp is mutually exclusive with I(dns_address), and I(dns_address_backup).
        choices:
            - dhcp
            - static
        type: str
        required: false
    dns_address:
        description:
            - Primary IPv4 or IPv6 DNS server address
        type: str
        required: false
    dns_address_backup:
        description:
            - Secondary IPv4 or IPv6 DNS server address
        type: str
        required: false
    ntp_config_method:
        description:
            - The configuration method type to use for NTP services.
            - disable is mutually exclusive with I(ntp_address) and I(ntp_address_backup).
            - dhcp is mutually exclusive with I(ntp_address) and I(ntp_address_backup).
        choices:
            - disabled
            - dhcp
            - static
        type: str
        required: false
    ntp_address:
        description:
            - Primary IPv4, IPv6, or FQDN NTP server address
        type: str
        required: false
    ntp_address_backup:
        description:
            - Secondary IPv4, IPv6, or FQDN NTP server address
        type: str
        required: false
    ssh:
        description:
            - Enable ssh access to the controller for debug purposes.
            - This is a controller-level setting.
            - rlogin/telnet will be enabled for ancient equipment where ssh is not available.
        type: bool
        required: false
notes:
    - Check mode is supported.
    - It is highly recommended to have a minimum of one up management port on each controller.
    - When using SANtricity Web Services Proxy, use M(netapp_eseries.santricity.na_santricity_storage_system) to update
      management paths. This is required because of a known issue and will be addressed in the proxy version 4.1. After
      the resolution the management ports should automatically be updated.
    - The interface settings are applied synchronously, but changes to the interface itself (receiving a new IP address
      via dhcp, etc), can take seconds or minutes longer to take effect.
"""

EXAMPLES = """
    - name: Configure the first port on the A controller with a static IPv4 address
      na_santricity_mgmt_interface:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        port: "1"
        controller: "A"
        config_method: static
        address: "192.168.1.100"
        subnet_mask: "255.255.255.0"
        gateway: "192.168.1.1"

    - name: Disable ipv4 connectivity for the second port on the B controller
      na_santricity_mgmt_interface:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        port: "2"
        controller: "B"
        enable_interface: no

    - name: Enable ssh access for ports one and two on controller A
      na_santricity_mgmt_interface:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        port: "1"
        controller: "A"
        ssh: yes

    - name: Configure static DNS settings for the first port on controller A
      na_santricity_mgmt_interface:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        port: "1"
        controller: "A"
        dns_config_method: static
        dns_address: "192.168.1.100"
        dns_address_backup: "192.168.1.1"

"""

RETURN = """
msg:
    description: Success message
    returned: on success
    type: str
    sample: The interface settings have been updated.
available_embedded_api_urls:
    description: List containing available web services embedded REST API urls
    returned: on success
    type: list
    sample:
"""
from time import sleep

from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
from ansible.module_utils._text import to_native
from ansible.module_utils import six

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

try:
    import ipaddress
except ImportError:
    HAS_IPADDRESS = False
else:
    HAS_IPADDRESS = True


def is_ipv4(address):
    """Determine whether address is IPv4."""
    try:
        if six.PY2:
            address = six.u(address)
        ipaddress.IPv4Address(address)
        return True
    except Exception as error:
        return False


def is_ipv6(address):
    """Determine whether address is IPv6."""
    try:
        if six.PY2:
            address = six.u(address)
        ipaddress.IPv6Address(address)
        return True
    except Exception as error:
        return False


class NetAppESeriesMgmtInterface(NetAppESeriesModule):
    MAXIMUM_VERIFICATION_TIMEOUT = 120

    def __init__(self):
        ansible_options = dict(state=dict(type="str", choices=["enabled", "disabled"], required=False),
                               controller=dict(type="str", required=True, choices=["A", "B"]),
                               port=dict(type="int"),
                               address=dict(type="str", required=False),
                               subnet_mask=dict(type="str", required=False),
                               gateway=dict(type="str", required=False),
                               config_method=dict(type="str", required=False, choices=["dhcp", "static"]),
                               dns_config_method=dict(type="str", required=False, choices=["dhcp", "static"]),
                               dns_address=dict(type="str", required=False),
                               dns_address_backup=dict(type="str", required=False),
                               ntp_config_method=dict(type="str", required=False, choices=["disabled", "dhcp", "static"]),
                               ntp_address=dict(type="str", required=False),
                               ntp_address_backup=dict(type="str", required=False),
                               ssh=dict(type="bool", required=False))

        required_if = [["config_method", "static", ["port", "address", "subnet_mask"]],
                       ["dns_config_method", "static", ["dns_address"]],
                       ["ntp_config_method", "static", ["ntp_address"]]]

        super(NetAppESeriesMgmtInterface, self).__init__(ansible_options=ansible_options,
                                                         web_services_version="02.00.0000.0000",
                                                         required_if=required_if,
                                                         supports_check_mode=True)

        args = self.module.params
        if args["state"] is None:
            if args["config_method"] is not None:
                self.enable_interface = True
            else:
                self.enable_interface = None
        else:
            self.enable_interface = args["state"] == "enabled"

        self.controller = args["controller"]
        self.channel = args["port"]

        self.config_method = args["config_method"]
        self.address = args["address"]
        self.subnet_mask = args["subnet_mask"]
        self.gateway = args["gateway"]

        self.dns_config_method = args["dns_config_method"]
        self.dns_address = args["dns_address"]
        self.dns_address_backup = args["dns_address_backup"]

        self.ntp_config_method = args["ntp_config_method"]
        self.ntp_address = args["ntp_address"]
        self.ntp_address_backup = args["ntp_address_backup"]

        self.ssh = args["ssh"]

        self.body = {}
        self.interface_info = {}
        self.alt_interface_addresses = []
        self.all_interface_addresses = []
        self.use_alternate_address = False
        self.alt_url_path = None

        self.available_embedded_api_urls = []

    def get_controllers(self):
        """Retrieve a mapping of controller labels to their references
        :return: controllers defined on the system. Example: {'A': '070000000000000000000001', 'B': '070000000000000000000002'}
        """
        try:
            rc, controllers = self.request("storage-systems/%s/controllers" % self.ssid)
        except Exception as err:
            controllers = list()
            self.module.fail_json(msg="Failed to retrieve the controller settings. Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        controllers.sort(key=lambda c: c['physicalLocation']['slot'])
        controllers_dict = dict()
        i = ord('A')
        for controller in controllers:
            label = chr(i)
            settings = dict(controllerSlot=controller['physicalLocation']['slot'],
                            controllerRef=controller['controllerRef'],
                            ssh=controller['networkSettings']['remoteAccessEnabled'])
            controllers_dict[label] = settings
            i += 1
        return controllers_dict

    def update_target_interface_info(self, retries=60):
        """Discover and update cached interface info."""
        net_interfaces = list()
        try:
            rc, net_interfaces = self.request("storage-systems/%s/configuration/ethernet-interfaces" % self.ssid)
        except Exception as error:
            if retries > 0:
                self.update_target_interface_info(retries=retries - 1)
                return
            else:
                self.module.fail_json(msg="Failed to retrieve defined management interfaces. Array Id [%s]. Error [%s]." % (self.ssid, to_native(error)))

        iface = None
        channels = {}
        controller_info = self.get_controllers()[self.controller]
        controller_ref = controller_info["controllerRef"]
        controller_ssh = controller_info["ssh"]
        controller_dns = None
        controller_ntp = None
        dummy_interface_id = None  # Needed for when a specific interface is not required (ie dns/ntp/ssh changes only)
        for net in net_interfaces:
            if net["controllerRef"] == controller_ref:
                channels.update({net["channel"]: net["linkStatus"]})
                if dummy_interface_id is None:
                    dummy_interface_id = net["interfaceRef"]
                if controller_dns is None:
                    controller_dns = net["dnsProperties"]
                if controller_ntp is None:
                    controller_ntp = net["ntpProperties"]

            if net["ipv4Enabled"] and net["linkStatus"] == "up":
                self.all_interface_addresses.append(net["ipv4Address"])
            if net["controllerRef"] == controller_ref and net["channel"] == self.channel:
                iface = net
            elif net["ipv4Enabled"] and net["linkStatus"] == "up":
                self.alt_interface_addresses.append(net["ipv4Address"])

        # Add controller specific information (ssh, dns and ntp)
        self.interface_info.update({
            "id": dummy_interface_id,
            "controllerRef": controller_ref,
            "ssh": controller_ssh,
            "dns_config_method": controller_dns["acquisitionProperties"]["dnsAcquisitionType"],
            "dns_servers": controller_dns["acquisitionProperties"]["dnsServers"],
            "ntp_config_method": controller_ntp["acquisitionProperties"]["ntpAcquisitionType"],
            "ntp_servers": controller_ntp["acquisitionProperties"]["ntpServers"],
        })

        # Add interface specific information when configuring IP address.
        if self.config_method is not None:
            if iface is None:
                available_controllers = ["%s (%s)" % (channel, status) for channel, status in channels.items()]
                self.module.fail_json(
                    msg="Invalid port number! Controller %s ports: [%s]. Array [%s]" % (
                        self.controller, ",".join(available_controllers), self.ssid
                    )
                )
            else:
                self.interface_info.update({
                    "id": iface["interfaceRef"],
                    "controllerSlot": iface["controllerSlot"],
                    "channel": iface["channel"],
                    "link_status": iface["linkStatus"],
                    "enabled": iface["ipv4Enabled"],
                    "config_method": iface["ipv4AddressConfigMethod"],
                    "address": iface["ipv4Address"],
                    "subnet_mask": iface["ipv4SubnetMask"],
                    "gateway": iface["ipv4GatewayAddress"],
                    "ipv6_enabled": iface["ipv6Enabled"],
                })

    def update_body_enable_interface_setting(self):
        """Enable or disable the IPv4 network interface."""
        change_required = False
        if not self.enable_interface and not self.interface_info["ipv6_enabled"]:
            self.module.fail_json(msg="Either IPv4 or IPv6 must be enabled. Array [%s]." % self.ssid)

        if self.enable_interface != self.interface_info["enabled"]:
            change_required = True
        self.body.update({"ipv4Enabled": self.enable_interface})
        return change_required

    def update_body_interface_settings(self):
        """Update network interface settings."""
        change_required = False
        if self.config_method == "dhcp":
            if self.interface_info["config_method"] != "configDhcp":
                if self.interface_info["address"] in self.url:
                    self.use_alternate_address = True
                change_required = True
            self.body.update({"ipv4AddressConfigMethod": "configDhcp"})
        else:
            self.body.update({"ipv4AddressConfigMethod": "configStatic", "ipv4Address": self.address, "ipv4SubnetMask": self.subnet_mask})
            if self.interface_info["config_method"] != "configStatic":
                change_required = True
            if self.address and self.interface_info["address"] != self.address:
                if self.interface_info["address"] in self.url:
                    self.use_alternate_address = True
                change_required = True
            if self.subnet_mask and self.interface_info["subnet_mask"] != self.subnet_mask:
                change_required = True
            if self.gateway and self.interface_info["gateway"] != self.gateway:
                self.body.update({"ipv4GatewayAddress": self.gateway})
                change_required = True

        return change_required

    def update_body_dns_server_settings(self):
        """Add DNS server information to the request body."""
        change_required = False
        if self.dns_config_method == "dhcp":
            if self.interface_info["dns_config_method"] != "dhcp":
                change_required = True
            self.body.update({"dnsAcquisitionDescriptor": {"dnsAcquisitionType": "dhcp"}})

        elif self.dns_config_method == "static":
            dns_servers = []
            if ((self.dns_address and self.dns_address_backup and (not self.interface_info["dns_servers"] or
                                                                   len(self.interface_info["dns_servers"]) != 2)) or
                    (self.dns_address and not self.dns_address_backup and (not self.interface_info["dns_servers"] or
                                                                           len(self.interface_info["dns_servers"]) != 1))):
                change_required = True

            # Check primary DNS address
            if self.dns_address:
                if is_ipv4(self.dns_address):
                    dns_servers.append({"addressType": "ipv4", "ipv4Address": self.dns_address})
                    if (not self.interface_info["dns_servers"] or len(self.interface_info["dns_servers"]) < 1 or
                            self.interface_info["dns_servers"][0]["addressType"] != "ipv4" or
                            self.interface_info["dns_servers"][0]["ipv4Address"] != self.dns_address):
                        change_required = True
                elif is_ipv6(self.dns_address):
                    dns_servers.append({"addressType": "ipv6", "ipv6Address": self.dns_address})
                    if (not self.interface_info["dns_servers"] or len(self.interface_info["dns_servers"]) < 1 or
                            self.interface_info["dns_servers"][0]["addressType"] != "ipv6" or
                            self.interface_info["dns_servers"][0]["ipv6Address"].replace(":", "").lower() != self.dns_address.replace(":", "").lower()):
                        change_required = True
                else:
                    self.module.fail_json(msg="Invalid IP address! DNS address must be either IPv4 or IPv6. Address [%s]."
                                              " Array [%s]." % (self.dns_address, self.ssid))

            # Check secondary DNS address
            if self.dns_address_backup:
                if is_ipv4(self.dns_address_backup):
                    dns_servers.append({"addressType": "ipv4", "ipv4Address": self.dns_address_backup})
                    if (not self.interface_info["dns_servers"] or len(self.interface_info["dns_servers"]) < 2 or
                            self.interface_info["dns_servers"][1]["addressType"] != "ipv4" or
                            self.interface_info["dns_servers"][1]["ipv4Address"] != self.dns_address_backup):
                        change_required = True
                elif is_ipv6(self.dns_address_backup):
                    dns_servers.append({"addressType": "ipv6", "ipv6Address": self.dns_address_backup})
                    if (not self.interface_info["dns_servers"] or len(self.interface_info["dns_servers"]) < 2 or
                            self.interface_info["dns_servers"][1]["addressType"] != "ipv6" or
                            self.interface_info["dns_servers"][1]["ipv6Address"].replace(":", "").lower() != self.dns_address_backup.replace(":", "").lower()):
                        change_required = True
                else:
                    self.module.fail_json(msg="Invalid IP address! DNS address must be either IPv4 or IPv6. Address [%s]."
                                              " Array [%s]." % (self.dns_address, self.ssid))

            self.body.update({"dnsAcquisitionDescriptor": {"dnsAcquisitionType": "stat", "dnsServers": dns_servers}})

        return change_required

    def update_body_ntp_server_settings(self):
        """Add NTP server information to the request body."""
        change_required = False
        if self.ntp_config_method == "disabled":
            if self.interface_info["ntp_config_method"] != "disabled":
                change_required = True
            self.body.update({"ntpAcquisitionDescriptor": {"ntpAcquisitionType": "disabled"}})

        elif self.ntp_config_method == "dhcp":
            if self.interface_info["ntp_config_method"] != "dhcp":
                change_required = True
            self.body.update({"ntpAcquisitionDescriptor": {"ntpAcquisitionType": "dhcp"}})

        elif self.ntp_config_method == "static":
            ntp_servers = []
            if ((self.ntp_address and self.ntp_address_backup and (not self.interface_info["ntp_servers"] or
                                                                   len(self.interface_info["ntp_servers"]) != 2)) or
                    (self.ntp_address and not self.ntp_address_backup and (not self.interface_info["ntp_servers"] or
                                                                           len(self.interface_info["ntp_servers"]) != 1))):
                change_required = True

            # Check primary NTP address
            if self.ntp_address:
                if is_ipv4(self.ntp_address):
                    ntp_servers.append({"addrType": "ipvx", "ipvxAddress": {"addressType": "ipv4", "ipv4Address": self.ntp_address}})
                    if (not self.interface_info["ntp_servers"] or len(self.interface_info["ntp_servers"]) < 1 or
                            self.interface_info["ntp_servers"][0]["addrType"] != "ipvx" or
                            self.interface_info["ntp_servers"][0]["ipvxAddress"]["addressType"] != "ipv4" or
                            self.interface_info["ntp_servers"][0]["ipvxAddress"]["ipv4Address"] != self.ntp_address):
                        change_required = True
                elif is_ipv6(self.ntp_address):
                    ntp_servers.append({"addrType": "ipvx", "ipvxAddress": {"addressType": "ipv6", "ipv6Address": self.ntp_address}})
                    if (not self.interface_info["ntp_servers"] or len(self.interface_info["ntp_servers"]) < 1 or
                            self.interface_info["ntp_servers"][0]["addrType"] != "ipvx" or
                            self.interface_info["ntp_servers"][0]["ipvxAddress"]["addressType"] != "ipv6" or
                            self.interface_info["ntp_servers"][0]["ipvxAddress"][
                                "ipv6Address"].replace(":", "").lower() != self.ntp_address.replace(":", "").lower()):
                        change_required = True
                else:
                    ntp_servers.append({"addrType": "domainName", "domainName": self.ntp_address})
                    if (not self.interface_info["ntp_servers"] or len(self.interface_info["ntp_servers"]) < 1 or
                            self.interface_info["ntp_servers"][0]["addrType"] != "domainName" or
                            self.interface_info["ntp_servers"][0]["domainName"] != self.ntp_address):
                        change_required = True

            # Check secondary NTP address
            if self.ntp_address_backup:
                if is_ipv4(self.ntp_address_backup):
                    ntp_servers.append({"addrType": "ipvx", "ipvxAddress": {"addressType": "ipv4", "ipv4Address": self.ntp_address_backup}})
                    if (not self.interface_info["ntp_servers"] or len(self.interface_info["ntp_servers"]) < 2 or
                            self.interface_info["ntp_servers"][1]["addrType"] != "ipvx" or
                            self.interface_info["ntp_servers"][1]["ipvxAddress"]["addressType"] != "ipv4" or
                            self.interface_info["ntp_servers"][1]["ipvxAddress"]["ipv4Address"] != self.ntp_address_backup):
                        change_required = True
                elif is_ipv6(self.ntp_address_backup):
                    ntp_servers.append({"addrType": "ipvx", "ipvxAddress": {"addressType": "ipv6", "ipv6Address": self.ntp_address_backup}})
                    if (not self.interface_info["ntp_servers"] or len(self.interface_info["ntp_servers"]) < 2 or
                            self.interface_info["ntp_servers"][1]["addrType"] != "ipvx" or
                            self.interface_info["ntp_servers"][1]["ipvxAddress"]["addressType"] != "ipv6" or
                            self.interface_info["ntp_servers"][1]["ipvxAddress"][
                                "ipv6Address"].replace(":", "").lower() != self.ntp_address_backup.replace(":", "").lower()):
                        change_required = True
                else:
                    ntp_servers.append({"addrType": "domainName", "domainName": self.ntp_address_backup})
                    if (not self.interface_info["ntp_servers"] or len(self.interface_info["ntp_servers"]) < 2 or
                            self.interface_info["ntp_servers"][1]["addrType"] != "domainName" or
                            self.interface_info["ntp_servers"][1]["domainName"].lower() != self.ntp_address_backup.lower()):
                        change_required = True

            self.body.update({"ntpAcquisitionDescriptor": {"ntpAcquisitionType": "stat", "ntpServers": ntp_servers}})

        return change_required

    def update_body_ssh_setting(self):
        """Configure network interface ports for remote ssh access."""
        change_required = False
        if self.interface_info["ssh"] != self.ssh:
            change_required = True
        self.body.update({"enableRemoteAccess": self.ssh})
        return change_required

    def update_request_body(self):
        """Verify all required changes have been made."""
        self.update_target_interface_info()
        self.body = {"controllerRef": self.get_controllers()[self.controller]["controllerRef"], "interfaceRef": self.interface_info["id"]}

        change_required = False
        if self.enable_interface is not None:
            change_required = self.update_body_enable_interface_setting()
        if self.config_method is not None:
            change_required = self.update_body_interface_settings() or change_required
        if self.dns_config_method is not None:
            change_required = self.update_body_dns_server_settings() or change_required
        if self.ntp_config_method is not None:
            change_required = self.update_body_ntp_server_settings() or change_required
        if self.ssh is not None:
            change_required = self.update_body_ssh_setting() or change_required

        self.module.log("update_request_body change_required: %s" % change_required)
        return change_required

    def update_url(self, retries=60):
        """Update eseries base class url if on is available."""
        for address in self.alt_interface_addresses:
            if address not in self.url and address != "0.0.0.0":
                parsed_url = urlparse.urlparse(self.url)
                location = parsed_url.netloc.split(":")
                location[0] = address
                self.url = "%s://%s/" % (parsed_url.scheme, ":".join(location))
                self.available_embedded_api_urls = ["%s://%s/%s" % (parsed_url.scheme, ":".join(location), self.DEFAULT_REST_API_PATH)]
                self.module.warn("Using alternate address [%s]" % self.available_embedded_api_urls[0])
                break
        else:
            if retries > 0:
                sleep(1)
                self.update_target_interface_info()
                self.update_url(retries=retries - 1)
            else:
                self.module.warn("Unable to obtain an alternate url!")

    def update(self):
        """Update controller with new interface, dns service, ntp service and/or remote ssh access information."""
        change_required = self.update_request_body()

        # Build list of available web services rest api urls
        self.available_embedded_api_urls = []
        parsed_url = urlparse.urlparse(self.url)
        location = parsed_url.netloc.split(":")
        for address in self.all_interface_addresses:
            location[0] = address
            self.available_embedded_api_urls = ["%s://%s/%s" % (parsed_url.scheme, ":".join(location), self.DEFAULT_REST_API_PATH)]

        if change_required and not self.module.check_mode:

            # Update url if currently used interface will be modified
            if self.is_embedded():
                if self.use_alternate_address:
                    self.update_url()
                if self.address:
                    parsed_url = urlparse.urlparse(self.url)
                    location = parsed_url.netloc.split(":")
                    location[0] = self.address
                    self.available_embedded_api_urls.append("%s://%s/%s" % (parsed_url.scheme, ":".join(location), self.DEFAULT_REST_API_PATH))
            else:
                self.available_embedded_api_urls = ["%s/%s" % (self.url, self.DEFAULT_REST_API_PATH)]

            # Update management interface
            try:
                rc, response = self.request("storage-systems/%s/configuration/ethernet-interfaces" % self.ssid, method="POST", data=self.body)
            except Exception as error:
                pass

            # Validate all changes have been made
            for retries in range(self.MAXIMUM_VERIFICATION_TIMEOUT):
                if not self.update_request_body():
                    break
                sleep(1)
            else:
                self.module.warn("Changes failed to complete! Timeout waiting for management interface to update. Array [%s]." % self.ssid)
            self.module.exit_json(msg="The interface settings have been updated.", changed=change_required,
                                  available_embedded_api_urls=self.available_embedded_api_urls)
        self.module.exit_json(msg="No changes are required.", changed=change_required,
                              available_embedded_api_urls=self.available_embedded_api_urls if self.is_embedded() else [])


def main():
    interface = NetAppESeriesMgmtInterface()
    interface.update()


if __name__ == "__main__":
    main()
