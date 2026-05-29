import xml.etree.ElementTree as ET
import json
import shutil
import os
import sys

NS_VAL = "Microsoft.Search.Autopilot.Evolution"
NS_A_VAL = "http://schemas.datacontract.org/2004/07/Microsoft.Search.Autopilot.Evolution"
NS = "{" + NS_VAL + "}"
NS_A = "{" + NS_A_VAL + "}"


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
