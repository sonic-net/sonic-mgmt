"""
Utility classes for loading and managing testbed data.
"""

import itertools
import os
import re
import yaml
from typing import Any, Dict, List, Optional

from devutil.device_inventory import DeviceInfo, DeviceInventory


class TestBed(object):
    """Data model that represents a testbed object."""

    @classmethod
    def from_file(
        cls,
        device_inventories: List[DeviceInventory],
        testbed_file: str = "testbed.yaml",
        testbed_pattern: Optional[str] = None,
    ) -> Dict[str, "TestBed"]:
        """Load all testbed objects from YAML file.

        Args:
            testbed_file (str): Path to testbed file.
            testbed_pattern (str): Regex pattern to filter testbeds.
            hosts (HostManager): AnsibleHosts object that contains all hosts in the testbed.

        Returns:
            dict: Testbed name to testbed object mapping.
        """
        # Check existence of testbed file
        if not os.path.isfile(testbed_file):
            raise ValueError("Testbed file {} does not exist.".format(testbed_file))

        # Parse testbed_pattern as regex
        if testbed_pattern:
            testbed_pattern = re.compile(testbed_pattern)

        # Load testbed file
        with open(testbed_file, "r") as f:
            raw_testbeds = yaml.safe_load(f)

        # Loop through each raw testbed object and create TestBed object that matches with testbed_pattern regex
        testbeds = {}
        for raw_testbed in raw_testbeds:
            if testbed_pattern and not testbed_pattern.match(raw_testbed["conf-name"]):
                continue
            testbeds[raw_testbed["conf-name"]] = cls(raw_testbed, device_inventories)

        return testbeds

    def __init__(self, raw_dict: Any, device_inventories: List[DeviceInventory]):
        """Initialize a testbed object.

        Args:
            raw_dict (dict): Raw testbed data object.
            hosts (AnsibleHosts): AnsibleHosts object that contains all hosts in the testbed.
        """
        # Assign all fields in raw_dict to this object
        for key, value in raw_dict.items():
            setattr(self, key.replace("-", "_"), value)

        # Create a PTF node object
        self.ptf_node = DeviceInfo(
            hostname=self.ptf,
            management_ip=self.ptf_ip.split("/")[0],
            hw_sku="Container",
            device_type="PTF",
            protocol="ssh",
        )

        self.console_nodes = {}
        self.fanout_nodes = {}
        self.root_fanout_nodes = {}
        self.server_nodes = {}

        # Loop through each DUT in the testbed and find the device info
        self.dut_nodes = {}
        for dut in raw_dict["dut"]:
            for inv in device_inventories:
                device = inv.get_device(dut)
                if device is not None:
                    self.dut_nodes[dut] = device
                    self.link_dut_related_devices(inv, device)
                    break
            else:
                print(f"Error: Failed to find device info for DUT {dut}")

        # Some testbeds are dummy ones and doesn't have inv_name specified,
        # so we need to use "unknown" as inv_name instead.
        if not hasattr(self, "inv_name"):
            self.inv_name = "unknown"

    def link_dut_related_devices(self, inv: DeviceInventory, dut: DeviceInfo) -> None:
        """Link all devices that is relavent to the given DUT."""
        links = inv.links.get_links(dut.hostname)
        if links is None:
            return None

        # Get all DUT VLANs
        dut_vlan_list = []
        for link in links.values():
            dut_vlan_list.extend(link.vlan_ranges)
        dut_vlans = list(itertools.chain(*dut_vlan_list))

        # Use the VLANs to find all connected nodes
        linked_devices = []
        visited_devices = {dut.hostname: True}
        pending_devices = [dut]
        while len(pending_devices) > 0:
            device_name = pending_devices.pop(0).hostname

            # Enumerate all links of the device and find the ones with VLANs used by the DUT
            device_links = inv.links.get_links(device_name)
            for link in device_links.values():
                link_has_vlan = False
                for dut_vlan in dut_vlans:
                    for link_vlan_range in link.vlan_ranges:
                        if dut_vlan in link_vlan_range:
                            link_has_vlan = True
                            break
                    if link_has_vlan:
                        break

                # The link has VLANs used by the DUTs
                if link_has_vlan:
                    if link.end_device in visited_devices:
                        continue
                    visited_devices[link.end_device] = True

                    peer_device = inv.get_device(link.end_device)
                    if peer_device is None:
                        raise ValueError(f"Link to device is defined by failed to find device info: {link.end_device}")

                    # Count the peer device as linked and add it to the pending list
                    linked_devices.append(peer_device)
                    pending_devices.append(peer_device)

        # print(f"Linked devices for DUT {dut.hostname}:")
        for linked_device in linked_devices:
            if "Root" in linked_device.device_type:
                self.root_fanout_nodes[linked_device.hostname] = linked_device
                # print(f"  RootFanout: {linked_device.hostname}")
            elif "Fanout" in linked_device.device_type:
                self.fanout_nodes[linked_device.hostname] = linked_device
                # print(f"  Fanout: {linked_device.hostname}")
            elif linked_device.device_type == "Server":
                self.server_nodes[linked_device.hostname] = linked_device
                # print(f"  Server: {linked_device.hostname}")
            elif linked_device.device_type == "DevSonic":
                raise ValueError(f"Found VLAN ID being used by 2 DUTs: {dut.hostname} and "
                                 f"{linked_device.hostname}! Please fix the testbed config.")
            else:
                raise ValueError(f"Unknown device type: {linked_device.device_type} "
                                 f"(DUT: {dut.hostname}, Linked: {linked_device.hostname})")

        dut_console_node_name = f"{dut.hostname}-console"
        dut_console_node = inv.get_device(dut_console_node_name)
        if dut_console_node is not None:
            self.console_nodes[dut_console_node.hostname] = dut_console_node
