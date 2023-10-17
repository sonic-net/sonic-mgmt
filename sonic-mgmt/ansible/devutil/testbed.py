"""
Utility classes for loading and managing testbed data.
"""

import os
import re
import yaml


class TestBed(object):
    """Data model that represents a testbed object."""

    @classmethod
    def from_file(cls, testbed_file="testbed.yaml", testbed_pattern=None, hosts=None):
        """Load all testbed objects from YAML file.

        Args:
            testbed_file (str): Path to testbed file.
            testbed_pattern (str): Regex pattern to filter testbeds.
            hosts (AnsibleHosts): AnsibleHosts object that contains all hosts in the testbed.

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
            testbeds[raw_testbed["conf-name"]] = cls(raw_testbed, hosts=hosts)

        return testbeds

    def __init__(self, raw_dict, hosts=None):
        """Initialize a testbed object.

        Args:
            raw_dict (dict): Raw testbed data object.
            hosts (AnsibleHosts): AnsibleHosts object that contains all hosts in the testbed.
        """
        # Assign all fields in raw_dict to this object
        for key, value in raw_dict.items():
            setattr(self, key.replace("-", "_"), value)

        # Create a PTF node object
        self.ptf_node = TestBedNode(self.ptf, hosts)

        # Loop through each DUT in the testbed and create TestBedNode object
        self.dut_nodes = {}
        for dut in raw_dict["dut"]:
            self.dut_nodes[dut] = TestBedNode(dut, hosts)

        # Some testbeds are dummy ones and doesn't have inv_name specified,
        # so we need to use "unknown" as inv_name instead.
        if not hasattr(self, "inv_name"):
            self.inv_name = "unknown"


class TestBedNode(object):
    """Data model that represents a testbed node object."""

    def __init__(self, name, hosts=None):
        """Initialize a testbed node object.

        Args:
            name (str): Node name.
            ansible_vars (dict): Ansible variables of the node.
        """
        self.name = name
        self.ssh_ip = None
        self.ssh_user = None
        self.ssh_pass = None

        if hosts:
            try:
                host_vars = hosts.get_host_vars(self.name)
                self.ssh_ip = host_vars["ansible_host"]
                self.ssh_user = host_vars["creds"]["username"]
                self.ssh_pass = host_vars["creds"]["password"][0]
            except Exception as e:
                print(
                    "Error: Failed to get host vars for {}: {}".format(
                        self.name, str(e)
                    )
                )
                self.ssh_ip = None
                self.ssh_user = None
                self.ssh_pass = None
