import defusedxml.ElementTree as ET
import json
import shutil
import os
import sys
import logging

NS_VAL = "Microsoft.Search.Autopilot.Evolution"
NS_A_VAL = "http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution"
NS = "{" + NS_VAL + "}"
NS_A = "{" + NS_A_VAL + "}"

logger = logging.getLogger(__name__)


class MinigraphRefactor:
    """Refactors minigraph.xml to remove a T1 neighbor and its associated configuration.

    This class removes a specified leaf router (T1 neighbor) from the minigraph,
    including:
    - BGP sessions
    - BGP router declarations
    - Device definitions
    - Device interface links
    - PortChannel interfaces that use the affected ports
    - IP interfaces that reference those PortChannels
    - Link metadata

    After applying these changes and reloading the minigraph, the affected ports
    will have admin_status=down (read from port_config.ini defaults) because they
    are no longer referenced in the minigraph configuration.
    """

    def __init__(self, leaf_router):
        self.leafrouter_name = leaf_router
        # Ports connected to the target neighbor, collected during link removal
        self.affected_ports = set()
        # PortChannels that use the affected ports, collected during PortChannel removal
        self.affected_portchannels = set()

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
                    # logger.info(f"Removed session: {ET.tostring(session, encoding='unicode')}")
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
                    # logger.info(f"Removed router: {ET.tostring(router, encoding='unicode')}")
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
                # logger.info(f"Removed device: {ET.tostring(device, encoding='unicode')}")
                removed_device = True
        return removed_device

    def remove_device_interface_links(self, root):
        """Remove DeviceLinkBase entries that connect to the target neighbor.

        Also collects the local port names from these links for subsequent
        PortChannel and IPInterface removal.

        Returns:
            int: Number of links removed
        """
        device_links = root.find(f".//{NS}PngDec/{NS}DeviceInterfaceLinks")
        removed_links = 0
        if device_links:
            for link in list(device_links.findall(f"{NS}DeviceLinkBase")):
                start_device = link.find(f"{NS}StartDevice").text
                end_device = link.find(f"{NS}EndDevice").text
                if self.leafrouter_name in [start_device, end_device]:
                    # Collect the local port (the one NOT on the target neighbor)
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
        """Remove PortChannel entries that use the affected ports.

        Finds PortChannel elements under DeviceDataPlaneInfo/PortChannelInterfaces
        where AttachTo contains any of the affected ports. The AttachTo field can
        contain multiple ports separated by semicolons (e.g., "Ethernet48;Ethernet56").

        Returns:
            int: Number of PortChannel entries removed
        """
        if not self.affected_ports:
            return 0

        removed_portchannels = 0

        # Find all DeviceDataPlaneInfo elements (there may be multiple for multi-ASIC)
        for dpg_info in root.findall(f".//{NS}DeviceDataPlaneInfo"):
            portchannel_interfaces = dpg_info.find(f"{NS}PortChannelInterfaces")
            if portchannel_interfaces is None:
                continue

            for portchannel in list(portchannel_interfaces.findall(f"{NS}PortChannel")):
                name_elem = portchannel.find(f"{NS}Name")
                attach_to_elem = portchannel.find(f"{NS}AttachTo")

                if attach_to_elem is None or attach_to_elem.text is None:
                    continue

                # AttachTo can contain multiple ports: "Ethernet48;Ethernet56"
                attached_ports = set(attach_to_elem.text.split(';'))

                # Check if any affected port is in this PortChannel
                if attached_ports & self.affected_ports:
                    pc_name = name_elem.text if name_elem is not None else "unknown"
                    self.affected_portchannels.add(pc_name)
                    portchannel_interfaces.remove(portchannel)
                    logger.info("Removed PortChannel: %s (AttachTo: %s)", pc_name, attach_to_elem.text)
                    removed_portchannels += 1

        return removed_portchannels

    def remove_ip_interfaces(self, root):
        """Remove IPInterface entries that reference affected PortChannels or ports.

        Finds IPInterface elements under DeviceDataPlaneInfo/IPInterfaces where
        AttachTo matches any affected PortChannel or affected port.

        Returns:
            int: Number of IPInterface entries removed
        """
        # Combine affected ports and portchannels for lookup
        affected_attachments = self.affected_ports | self.affected_portchannels
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
        """Process minigraph to remove target neighbor and associated config.

        Removes the target leaf router and all associated configuration including:
        - BGP sessions
        - BGP router declaration
        - Device definition
        - Device interface links
        - PortChannel interfaces using affected ports
        - IP interfaces on affected PortChannels/ports
        - Link metadata

        Args:
            input_file: Path to input minigraph XML
            output_file: Path to write modified minigraph XML

        Returns:
            tuple: (success: bool, affected_ports: set)
                   success is False if no BGP sessions were found for the target
                   affected_ports contains the local port names that were connected
                   to the target neighbor (for admin_status verification)
        """
        ET.register_namespace('', NS_VAL)
        ET.register_namespace('a', NS_A_VAL)

        tree = ET.parse(input_file)
        root = tree.getroot()

        # Order matters: remove links first to collect affected ports,
        # then remove PortChannels that use those ports,
        # then remove IPInterfaces that reference those PortChannels
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
        logger.info("Usage: %s <input_minigraph.xml> <output_minigraph.xml>", sys.argv[0])
        sys.exit(1)

    input_file, output_file = sys.argv[1], sys.argv[2]

    backup_file = f"{input_file}.backup"
    if not os.path.exists(backup_file):
        shutil.copy2(input_file, backup_file)
        # logger.info(f"Backup created: {backup_file}")

    refactor = MinigraphRefactor("ARISTA01T1")
    success, affected_ports = refactor.process_minigraph(input_file, output_file)
    if affected_ports:
        logger.info("Affected ports (should become admin_status=down): %s", sorted(affected_ports))


if __name__ == "__main__":
    main()
