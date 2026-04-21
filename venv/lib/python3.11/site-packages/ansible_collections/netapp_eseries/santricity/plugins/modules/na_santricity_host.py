#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: na_santricity_host
short_description: NetApp E-Series manage eseries hosts
description: Create, update, remove hosts on NetApp E-series storage arrays
author:
    - Kevin Hulquest (@hulquest)
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
options:
    name:
        description:
            - If the host doesn't yet exist, the label/name to assign at creation time.
            - If the hosts already exists, this will be used to uniquely identify the host to make any required changes
        type: str
        required: True
        aliases:
            - label
    state:
        description:
            - Set to absent to remove an existing host
            - Set to present to modify or create a new host definition
        type: str
        choices:
            - absent
            - present
        default: present
    host_type:
        description:
            - Host type includes operating system and multipath considerations.
            - If not specified, the default host type will be utilized. Default host type can be set using M(netapp_eseries.santricity.na_santricity_global).
            - For storage array specific options see M(netapp_eseries.santricity.na_santricity_facts).
            - All values are case-insensitive.
            - AIX MPIO - The Advanced Interactive Executive (AIX) OS and the native MPIO driver
            - AVT 4M - Silicon Graphics, Inc. (SGI) proprietary multipath driver
            - HP-UX - The HP-UX OS with native multipath driver
            - Linux ATTO - The Linux OS and the ATTO Technology, Inc. driver (must use ATTO FC HBAs)
            - Linux DM-MP - The Linux OS and the native DM-MP driver
            - Linux Pathmanager - The Linux OS and the SGI proprietary multipath driver
            - Mac - The Mac OS and the ATTO Technology, Inc. driver
            - ONTAP - FlexArray
            - Solaris 11 or later - The Solaris 11 or later OS and the native MPxIO driver
            - Solaris 10 or earlier - The Solaris 10 or earlier OS and the native MPxIO driver
            - SVC - IBM SAN Volume Controller
            - VMware - ESXi OS
            - Windows - Windows Server OS and Windows MPIO with a DSM driver
            - Windows Clustered - Clustered Windows Server OS and Windows MPIO with a DSM driver
            - Windows ATTO - Windows OS and the ATTO Technology, Inc. driver
        type: str
        required: False
        aliases:
            - host_type_index
    ports:
        description:
            - A list of host ports you wish to associate with the host.
            - Host ports are uniquely identified by their WWN or IQN. Their assignments to a particular host are
             uniquely identified by a label and these must be unique.
        type: list
        elements: dict
        required: False
        suboptions:
            type:
                description:
                  - The interface type of the port to define.
                  - Acceptable choices depend on the capabilities of the target hardware/software platform.
                required: true
                choices:
                  - iscsi
                  - sas
                  - fc
                  - ib
                  - nvmeof
            label:
                description:
                    - A unique label to assign to this port assignment.
                required: true
            port:
                description:
                    - The WWN or IQN of the hostPort to assign to this port definition.
                required: true
    force_port:
        description:
            - Allow ports that are already assigned to be re-assigned to your current host
        required: false
        type: bool
        default: false
"""

EXAMPLES = """
    - name: Define or update an existing host named "Host1"
      na_santricity_host:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        name: "Host1"
        state: present
        host_type_index: Linux DM-MP
        ports:
          - type: "iscsi"
            label: "PORT_1"
            port: "iqn.1996-04.de.suse:01:56f86f9bd1fe"
          - type: "fc"
            label: "FC_1"
            port: "10:00:FF:7C:FF:FF:FF:01"
          - type: "fc"
            label: "FC_2"
            port: "10:00:FF:7C:FF:FF:FF:00"

    - name: Ensure a host named "Host2" doesn"t exist
      na_santricity_host:
        ssid: "1"
        api_url: "https://192.168.1.100:8443/devmgr/v2"
        api_username: "admin"
        api_password: "adminpass"
        validate_certs: true
        name: "Host2"
        state: absent
"""

RETURN = """
msg:
    description:
        - A user-readable description of the actions performed.
    returned: on success
    type: str
    sample: The host has been created.
id:
    description:
        - the unique identifier of the host on the E-Series storage-system
    returned: on success when state=present
    type: str
    sample: 00000000600A098000AAC0C3003004700AD86A52
ssid:
    description:
        - the unique identifer of the E-Series storage-system with the current api
    returned: on success
    type: str
    sample: 1
api_url:
    description:
        - the url of the API that this request was proccessed by
    returned: on success
    type: str
    sample: https://webservices.example.com:8443
"""
import re

from ansible.module_utils._text import to_native
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule


class NetAppESeriesHost(NetAppESeriesModule):
    PORT_TYPES = ["iscsi", "sas", "fc", "ib", "nvmeof"]

    def __init__(self):
        ansible_options = dict(state=dict(type="str", default="present", choices=["absent", "present"]),
                               ports=dict(type="list", elements="dict", required=False),
                               force_port=dict(type="bool", default=False),
                               name=dict(type="str", required=True, aliases=["label"]),
                               host_type=dict(type="str", required=False, aliases=["host_type_index"]))

        super(NetAppESeriesHost, self).__init__(ansible_options=ansible_options,
                                                web_services_version="02.00.0000.0000",
                                                supports_check_mode=True)

        self.check_mode = self.module.check_mode
        args = self.module.params
        self.ports = args["ports"]
        self.force_port = args["force_port"]
        self.name = args["name"]
        self.state = args["state"]

        self.post_body = dict()
        self.all_hosts = list()
        self.host_obj = dict()
        self.new_ports = list()
        self.ports_for_update = list()
        self.ports_for_removal = list()

        # Update host type with the corresponding index
        host_type = args["host_type"]
        if host_type:
            host_type = host_type.lower()
            if host_type in [key.lower() for key in list(self.HOST_TYPE_INDEXES.keys())]:
                self.host_type_index = self.HOST_TYPE_INDEXES[host_type]
            elif host_type.isdigit():
                self.host_type_index = int(args["host_type"])
            else:
                self.module.fail_json(msg="host_type must be either a host type name or host type index found integer the documentation.")
        else:
            self.host_type_index = None

        if not self.url.endswith("/"):
            self.url += "/"

        # Fix port representation if they are provided with colons
        if self.ports is not None:
            for port in self.ports:
                port["type"] = port["type"].lower()
                port["port"] = port["port"].lower()

                if port["type"] not in self.PORT_TYPES:
                    self.module.fail_json(msg="Invalid port type! Port interface type must be one of [%s]." % ", ".join(self.PORT_TYPES))

                # Determine whether address is 16-byte WWPN and, if so, remove
                if re.match(r"^(0x)?[0-9a-f]{16}$", port["port"].replace(":", "")):
                    port["port"] = port["port"].replace(":", '').replace("0x", "")

                    if port["type"] == "ib":
                        port["port"] = "0" * (32 - len(port["port"])) + port["port"]

    @property
    def default_host_type(self):
        """Return the default host type index."""
        try:
            rc, default_index = self.request("storage-systems/%s/graph/xpath-filter?query=/sa/defaultHostTypeIndex" % self.ssid)
            return default_index[0]
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve default host type index")

    @property
    def valid_host_type(self):
        host_types = None
        try:
            rc, host_types = self.request("storage-systems/%s/host-types" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to get host types. Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        try:
            match = list(filter(lambda host_type: host_type["index"] == self.host_type_index, host_types))[0]
            return True
        except IndexError:
            self.module.fail_json(msg="There is no host type with index %s" % self.host_type_index)

    def check_port_types(self):
        """Check to see whether the port interface types are available on storage system."""
        try:
            rc, interfaces = self.request("storage-systems/%s/interfaces?channelType=hostside" % self.ssid)

            for port in self.ports:
                for interface in interfaces:

                    # Check for IB iSER
                    if port["type"] == "ib" and "iqn" in port["port"]:
                        if ((interface["ioInterfaceTypeData"]["interfaceType"] == "iscsi" and
                                interface["ioInterfaceTypeData"]["iscsi"]["interfaceData"]["type"] == "infiniband" and
                                interface["ioInterfaceTypeData"]["iscsi"]["interfaceData"]["infinibandData"]["isIser"]) or
                                (interface["ioInterfaceTypeData"]["interfaceType"] == "ib" and
                                 interface["ioInterfaceTypeData"]["ib"]["isISERSupported"])):
                            port["type"] = "iscsi"
                            break
                    # Check for NVMe
                    elif (port["type"] == "nvmeof" and "commandProtocolPropertiesList" in interface and
                          "commandProtocolProperties" in interface["commandProtocolPropertiesList"] and
                          interface["commandProtocolPropertiesList"]["commandProtocolProperties"]):
                        if interface["commandProtocolPropertiesList"]["commandProtocolProperties"][0]["commandProtocol"] == "nvme":
                            break
                    # Check SAS, FC, iSCSI
                    elif ((port["type"] == "fc" and interface["ioInterfaceTypeData"]["interfaceType"] == "fibre") or
                          (port["type"] == interface["ioInterfaceTypeData"]["interfaceType"])):
                        break
                else:
                    # self.module.fail_json(msg="Invalid port type! Type [%s]. Port [%s]." % (port["type"], port["label"]))
                    self.module.warn("Port type not found in hostside interfaces! Type [%s]. Port [%s]." % (port["type"], port["label"]))
        except Exception as error:
            # For older versions of web services
            for port in self.ports:
                if port["type"] == "ib" and "iqn" in port["port"]:
                    port["type"] = "iscsi"
                    break

    def assigned_host_ports(self, apply_unassigning=False):
        """Determine if the hostPorts requested have already been assigned and return list of required used ports."""
        used_host_ports = {}
        for host in self.all_hosts:
            if host["label"].lower() != self.name.lower():
                for host_port in host["hostSidePorts"]:

                    # Compare expected ports with those from other hosts definitions.
                    for port in self.ports:
                        if port["port"] == host_port["address"] or port["label"].lower() == host_port["label"].lower():
                            if not self.force_port:
                                self.module.fail_json(msg="Port label or address is already used and force_port option is set to false!")
                            else:
                                # Determine port reference
                                port_ref = [port["hostPortRef"] for port in host["ports"]
                                            if port["hostPortName"] == host_port["address"]]
                                port_ref.extend([port["initiatorRef"] for port in host["initiators"]
                                                 if port["nodeName"]["iscsiNodeName"] == host_port["address"]])

                                # Create dictionary of hosts containing list of port references
                                if host["hostRef"] not in used_host_ports.keys():
                                    used_host_ports.update({host["hostRef"]: port_ref})
                                else:
                                    used_host_ports[host["hostRef"]].extend(port_ref)

        # Unassign assigned ports
        if apply_unassigning:
            for host_ref in used_host_ports.keys():
                try:
                    rc, resp = self.request("storage-systems/%s/hosts/%s" % (self.ssid, host_ref), method="POST",
                                            data={"portsToRemove": used_host_ports[host_ref]})
                except Exception as err:
                    self.module.fail_json(msg="Failed to unassign host port. Host Id [%s]. Array Id [%s]. Ports [%s]. Error [%s]."
                                              % (self.host_obj["id"], self.ssid, used_host_ports[host_ref], to_native(err)))

    @property
    def host_exists(self):
        """Determine if the requested host exists
        As a side effect, set the full list of defined hosts in "all_hosts", and the target host in "host_obj".
        """
        match = False
        all_hosts = list()

        try:
            rc, all_hosts = self.request("storage-systems/%s/hosts" % self.ssid)
        except Exception as err:
            self.module.fail_json(msg="Failed to determine host existence. Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        # Augment the host objects
        for host in all_hosts:
            for port in host["hostSidePorts"]:
                port["type"] = port["type"].lower()
                port["address"] = port["address"].lower()

            # Augment hostSidePorts with their ID (this is an omission in the API)
            ports = dict((port["label"], port["id"]) for port in host["ports"])
            ports.update(dict((port["label"], port["id"]) for port in host["initiators"]))

            for host_side_port in host["hostSidePorts"]:
                if host_side_port["label"] in ports:
                    host_side_port["id"] = ports[host_side_port["label"]]

            if host["label"].lower() == self.name.lower():
                self.host_obj = host
                match = True

        self.all_hosts = all_hosts
        return match

    @property
    def needs_update(self):
        """Determine whether we need to update the Host object
        As a side effect, we will set the ports that we need to update (portsForUpdate), and the ports we need to add
        (newPorts), on self.
        """
        changed = False
        if self.host_obj["hostTypeIndex"] != self.host_type_index:
            changed = True

        current_host_ports = dict((port["id"], {"type": port["type"], "port": port["address"], "label": port["label"]})
                                  for port in self.host_obj["hostSidePorts"])

        if self.ports:
            for port in self.ports:
                for current_host_port_id in current_host_ports.keys():
                    if port == current_host_ports[current_host_port_id]:
                        current_host_ports.pop(current_host_port_id)
                        break

                    elif port["port"] == current_host_ports[current_host_port_id]["port"]:
                        if self.port_on_diff_host(port) and not self.force_port:
                            self.module.fail_json(msg="The port you specified [%s] is associated with a different host."
                                                      " Specify force_port as True or try a different port spec" % port)

                        if (port["label"] != current_host_ports[current_host_port_id]["label"] or
                                port["type"] != current_host_ports[current_host_port_id]["type"]):
                            current_host_ports.pop(current_host_port_id)
                            self.ports_for_update.append({"portRef": current_host_port_id, "port": port["port"],
                                                          "label": port["label"], "hostRef": self.host_obj["hostRef"]})
                            break
                else:
                    self.new_ports.append(port)

            self.ports_for_removal = list(current_host_ports.keys())
            changed = any([self.new_ports, self.ports_for_update, self.ports_for_removal, changed])
        return changed

    def port_on_diff_host(self, arg_port):
        """ Checks to see if a passed in port arg is present on a different host"""
        for host in self.all_hosts:

            # Only check "other" hosts
            if host["name"].lower() != self.name.lower():
                for port in host["hostSidePorts"]:

                    # Check if the port label is found in the port dict list of each host
                    if arg_port["label"].lower() == port["label"].lower() or arg_port["port"].lower() == port["address"].lower():
                        return True
        return False

    def update_host(self):
        self.post_body = {"name": self.name, "hostType": {"index": self.host_type_index}}

        # Remove ports that need reassigning from their current host.
        if self.ports:
            self.assigned_host_ports(apply_unassigning=True)
            self.post_body["portsToUpdate"] = self.ports_for_update
            self.post_body["portsToRemove"] = self.ports_for_removal
            self.post_body["ports"] = self.new_ports

        if not self.check_mode:
            try:
                rc, self.host_obj = self.request("storage-systems/%s/hosts/%s" % (self.ssid, self.host_obj["id"]), method="POST",
                                                 data=self.post_body, ignore_errors=True)
            except Exception as err:
                self.module.fail_json(msg="Failed to update host. Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))

        self.module.exit_json(changed=True)

    def create_host(self):
        # Remove ports that need reassigning from their current host.
        self.assigned_host_ports(apply_unassigning=True)

        # needs_reassignment = False
        post_body = dict(name=self.name,
                         hostType=dict(index=self.host_type_index))

        if self.ports:
            post_body.update(ports=self.ports)

        if not self.host_exists:
            if not self.check_mode:
                try:
                    rc, self.host_obj = self.request("storage-systems/%s/hosts" % self.ssid, method="POST", data=post_body, ignore_errors=True)
                except Exception as err:
                    self.module.fail_json(msg="Failed to create host. Array Id [%s]. Error [%s]." % (self.ssid, to_native(err)))
        else:
            payload = self.build_success_payload(self.host_obj)
            self.module.exit_json(changed=False, msg="Host already exists. Id [%s]. Host [%s]." % (self.ssid, self.name), **payload)

        payload = self.build_success_payload(self.host_obj)
        self.module.exit_json(changed=True, msg="Host created.")

    def remove_host(self):
        try:
            rc, resp = self.request("storage-systems/%s/hosts/%s" % (self.ssid, self.host_obj["id"]), method="DELETE")
        except Exception as err:
            self.module.fail_json(msg="Failed to remove host.  Host[%s]. Array Id [%s]. Error [%s]." % (self.host_obj["id"], self.ssid, to_native(err)))

    def build_success_payload(self, host=None):
        keys = []  # ["id"]

        if host:
            result = dict((key, host[key]) for key in keys)
        else:
            result = dict()
        result["ssid"] = self.ssid
        result["api_url"] = self.url
        return result

    def apply(self):
        if self.state == "present":
            if self.host_type_index is None:
                self.host_type_index = self.default_host_type

            self.check_port_types()
            if self.host_exists:
                if self.needs_update and self.valid_host_type:
                    self.update_host()
                else:
                    payload = self.build_success_payload(self.host_obj)
                    self.module.exit_json(changed=False, msg="Host already present; no changes required.", **payload)
            elif self.valid_host_type:
                self.create_host()
        else:
            payload = self.build_success_payload()
            if self.host_exists:
                self.remove_host()
                self.module.exit_json(changed=True, msg="Host removed.", **payload)
            else:
                self.module.exit_json(changed=False, msg="Host already absent.", **payload)


def main():
    host = NetAppESeriesHost()
    host.apply()


if __name__ == "__main__":
    main()
