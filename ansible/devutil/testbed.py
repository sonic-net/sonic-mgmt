"""
Utility classes for loading and managing testbed data.
"""

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

        # Loop through each DUT in the testbed and find the device info
        self.dut_nodes = {}
        for dut in raw_dict["dut"]:
            for inv in device_inventories:
                device = inv.get_device(dut)
                if device is not None:
                    self.dut_nodes[dut] = device
                    break
            else:
                print(f"Error: Failed to find device info for DUT {dut}")

        # Some testbeds are dummy ones and doesn't have inv_name specified,
        # so we need to use "unknown" as inv_name instead.
        if not hasattr(self, "inv_name"):
            self.inv_name = "unknown"
