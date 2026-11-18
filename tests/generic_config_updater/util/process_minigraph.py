"""Legacy neighbor removal with opt-in single-ASIC interface cleanup."""

import xml.etree.ElementTree as ET
import json
import logging
import shutil
import os
import sys

NS_VAL = "Microsoft.Search.Autopilot.Evolution"
NS_A_VAL = "http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution"
NS = "{" + NS_VAL + "}"
NS_A = "{" + NS_A_VAL + "}"

logger = logging.getLogger(__name__)


class MinigraphRefactor:
    def __init__(self, leaf_router):
        self.leafrouter_name = leaf_router

    def remove_bgp_sessions(self, root):
        peering_sessions = root.find(f".//{NS}PeeringSessions")
        removed_sessions = 0
        if peering_sessions:
            for session in list(peering_sessions.findall(f"{NS}BGPSession")):
                start_router = session.find(f"{NS}StartRouter")
                end_router = session.find(f"{NS}EndRouter")
                if start_router is not None and start_router.text == self.leafrouter_name or \
                   end_router is not None and end_router.text == self.leafrouter_name:
                    peering_sessions.remove(session)
                    # print(f"Removed session: {ET.tostring(session, encoding='unicode')}")
                    removed_sessions += 1
        return removed_sessions

    def remove_bgp_router(self, root):
        routers = root.find(f".//{NS}Routers")
        removed_router = False
        if routers:
            for router in list(routers.findall(f"{NS_A}BGPRouterDeclaration")):
                hostname = router.find(f"{NS_A}Hostname")
                if hostname is not None and hostname.text == self.leafrouter_name:
                    routers.remove(router)
                    # print(f"Removed router: {ET.tostring(router, encoding='unicode')}")
                    removed_router = True
        return removed_router

    def parse_device(self, device):
        name = None
        for node in device:
            if node.tag == f"{NS}Hostname":
                name = node.text
        return name

    def remove_device(self, root):
        devices = root.find(f".//{NS}PngDec/{NS}Devices")
        removed_device = False
        for device in list(devices):
            hostname = self.parse_device(device)
            if hostname is not None and hostname == self.leafrouter_name:
                devices.remove(device)
                # print(f"Removed device: {ET.tostring(device, encoding='unicode')}")
                removed_device = True
        return removed_device

    def remove_device_interface_links(self, root):
        device_links = root.find(f".//{NS}PngDec/{NS}DeviceInterfaceLinks")
        removed_links = 0
        if device_links:
            for link in list(device_links.findall(f"{NS}DeviceLinkBase")):
                start_device = link.find(f"{NS}StartDevice").text
                end_device = link.find(f"{NS}EndDevice").text
                if self.leafrouter_name in [start_device, end_device]:
                    device_links.remove(link)
                    # print(f"Removed device link: {ET.tostring(link, encoding='unicode')}")
                    removed_links += 1
        return removed_links

    def remove_link_metadata(self, root):
        metadata_declaration = root.find(f".//{NS}LinkMetadataDeclaration")
        removed_metadata = 0
        if metadata_declaration is not None:
            for link in metadata_declaration.findall(f"{NS}Link"):
                for link_metadata in list(link.findall(f"{NS_A}LinkMetadata")):
                    key = link_metadata.find(f"{NS_A}Key")
                    if key is not None and self.leafrouter_name in key.text:
                        link.remove(link_metadata)
                        print(f"Removed LinkMetadata with key: {key.text}")
                        removed_metadata += 1
        return removed_metadata

    def process_minigraph(self, input_file, output_file):
        ET.register_namespace('', NS_VAL)
        ET.register_namespace('a', NS_A_VAL)

        tree = ET.parse(input_file)
        root = tree.getroot()

        results = {
            "removed_sessions": self.remove_bgp_sessions(root),
            "removed_router": self.remove_bgp_router(root),
            "removed_device": self.remove_device(root),
            "removed_links": self.remove_device_interface_links(root),
            "removed_metadata": self.remove_link_metadata(root)
        }

        tree.write(output_file)

        print(json.dumps(results, indent=2))
        if results["removed_sessions"] == 0:
            return False
        return True


class SingleAsicMinigraphRefactor(MinigraphRefactor):
    """Also remove affected PortChannel/IP interfaces and return affected ports."""

    def __init__(self, leaf_router, port_name_to_alias_map=None):
        super().__init__(leaf_router)
        self.affected_ports = set()
        self.affected_portchannels = set()
        self.port_name_to_alias_map = port_name_to_alias_map or {}

    def _affected_port_identifiers(self):
        """Match both physical port names and minigraph interface aliases."""
        identifiers = set(self.affected_ports)
        for port in self.affected_ports:
            alias = self.port_name_to_alias_map.get(port)
            if alias:
                identifiers.add(alias)
        return identifiers

    def remove_device_interface_links(self, root):
        """Remove target links and collect their local port names."""
        device_links = root.find(f".//{NS}PngDec/{NS}DeviceInterfaceLinks")
        removed_links = 0
        if device_links:
            for link in list(device_links.findall(f"{NS}DeviceLinkBase")):
                start_device = link.find(f"{NS}StartDevice").text
                end_device = link.find(f"{NS}EndDevice").text
                if self.leafrouter_name in [start_device, end_device]:
                    if start_device == self.leafrouter_name:
                        local_port = link.find(f"{NS}EndPort").text
                    else:
                        local_port = link.find(f"{NS}StartPort").text
                    if local_port:
                        self.affected_ports.add(local_port)
                    device_links.remove(link)
                    removed_links += 1
        return removed_links

    def remove_portchannel_interfaces(self, root):
        """Remove PortChannels attached to affected ports by name or alias."""
        if not self.affected_ports:
            return 0

        affected_identifiers = self._affected_port_identifiers()
        removed_portchannels = 0

        for dpg_info in root.findall(f".//{NS}DeviceDataPlaneInfo"):
            portchannel_interfaces = dpg_info.find(f"{NS}PortChannelInterfaces")
            if portchannel_interfaces is None:
                continue

            for portchannel in list(portchannel_interfaces.findall(f"{NS}PortChannel")):
                name_elem = portchannel.find(f"{NS}Name")
                attach_to_elem = portchannel.find(f"{NS}AttachTo")

                if attach_to_elem is None or attach_to_elem.text is None:
                    continue

                attached_ports = set(attach_to_elem.text.split(';'))

                if attached_ports & affected_identifiers:
                    pc_name = name_elem.text if name_elem is not None else "unknown"
                    self.affected_portchannels.add(pc_name)
                    portchannel_interfaces.remove(portchannel)
                    logger.info("Removed PortChannel: %s (AttachTo: %s)", pc_name, attach_to_elem.text)
                    removed_portchannels += 1

        return removed_portchannels

    def remove_ip_interfaces(self, root):
        """Remove IP interfaces attached to affected ports or PortChannels."""
        affected_attachments = self._affected_port_identifiers() | self.affected_portchannels
        if not affected_attachments:
            return 0

        removed_interfaces = 0

        for dpg_info in root.findall(f".//{NS}DeviceDataPlaneInfo"):
            ip_interfaces = dpg_info.find(f"{NS}IPInterfaces")
            if ip_interfaces is None:
                continue

            for ip_interface in list(ip_interfaces.findall(f"{NS}IPInterface")):
                attach_to_elem = ip_interface.find(f"{NS}AttachTo")

                if attach_to_elem is None or attach_to_elem.text is None:
                    continue

                if attach_to_elem.text in affected_attachments:
                    prefix_elem = ip_interface.find(f"{NS}Prefix")
                    prefix = prefix_elem.text if prefix_elem is not None else "unknown"
                    ip_interfaces.remove(ip_interface)
                    logger.info("Removed IPInterface: AttachTo=%s, Prefix=%s", attach_to_elem.text, prefix)
                    removed_interfaces += 1

        return removed_interfaces

    def remove_link_metadata(self, root):
        metadata_declaration = root.find(f".//{NS}LinkMetadataDeclaration")
        removed_metadata = 0
        if metadata_declaration is not None:
            for link in metadata_declaration.findall(f"{NS}Link"):
                for link_metadata in list(link.findall(f"{NS_A}LinkMetadata")):
                    key = link_metadata.find(f"{NS_A}Key")
                    if key is not None and self.leafrouter_name in key.text:
                        link.remove(link_metadata)
                        logger.info("Removed LinkMetadata with key: %s", key.text)
                        removed_metadata += 1
        return removed_metadata

    def process_minigraph(self, input_file, output_file):
        """Remove neighbor interfaces and return (success, affected_ports).

        success is False and affected_ports is empty when no BGP sessions match.
        """
        import defusedxml.ElementTree as SafeET

        ET.register_namespace('', NS_VAL)
        ET.register_namespace('a', NS_A_VAL)

        tree = SafeET.parse(input_file)
        root = tree.getroot()

        # Collect local ports before removing their PortChannel/IP references.
        results = {
            "removed_sessions": self.remove_bgp_sessions(root),
            "removed_router": self.remove_bgp_router(root),
            "removed_device": self.remove_device(root),
            "removed_links": self.remove_device_interface_links(root),
            "removed_portchannels": self.remove_portchannel_interfaces(root),
            "removed_ip_interfaces": self.remove_ip_interfaces(root),
            "removed_metadata": self.remove_link_metadata(root),
            "affected_ports": list(self.affected_ports),
            "affected_portchannels": list(self.affected_portchannels)
        }

        tree.write(output_file)

        logger.info(json.dumps(results, indent=2))
        if results["removed_sessions"] == 0:
            return False, set()
        return True, self.affected_ports


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_minigraph.xml> <output_minigraph.xml>")
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    backup_file = f"{input_file}.backup"
    if not os.path.exists(backup_file):
        shutil.copy2(input_file, backup_file)
        # print(f"Backup created: {backup_file}")

    refactor = MinigraphRefactor("ARISTA01T1")
    refactor.process_minigraph(input_file, output_file)


if __name__ == "__main__":
    main()
