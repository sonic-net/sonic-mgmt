import logging
import os
import inspect
import yaml
from collections import defaultdict

try:
    import ipaddr as ipaddress
except ImportError:
    import ipaddress

TESTBED_LOG = "/tmp/testbed_debug.txt"

# Default testbed file paths relative to ansible directory
DEFAULT_TESTBED_FILES = [
    'testbed.yaml',
    'testbed.nut.yaml'
]


class ParseTestbedTopoinfo():
    """Parse the testbed file used to describe whole testbed info - adapted from test_facts.py"""

    def __init__(self, testbed_file):
        self.testbed_filename = testbed_file
        self.testbed_topo = defaultdict()

    def read_testbed_topo(self):
        def _cidr_to_ip_mask(network):
            if hasattr(ipaddress, 'IPNetwork'):
                # ipaddr library
                addr = ipaddress.IPNetwork(network)
                return str(addr.ip), str(addr.netmask)
            else:
                # ipaddress library
                addr = ipaddress.ip_network(network, strict=False)
                return str(addr.network_address), str(addr.netmask)

        def _read_testbed_topo_from_yaml():
            """Read yaml testbed info file."""
            with open(self.testbed_filename) as f:
                tb_info = yaml.safe_load(f)
                for tb in tb_info:
                    if "ptf_ip" in tb and tb["ptf_ip"]:
                        tb["ptf_ip"], tb["ptf_netmask"] = \
                            _cidr_to_ip_mask(tb["ptf_ip"])
                    if "ptf_ipv6" in tb and tb["ptf_ipv6"]:
                        tb["ptf_ipv6"], tb["ptf_netmask_v6"] = \
                            _cidr_to_ip_mask(tb["ptf_ipv6"])

                    # Handle dut field - convert to duts
                    if "dut" in tb:
                        dut_value = tb.pop("dut")
                        if isinstance(dut_value, list):
                            tb["duts"] = dut_value
                        else:
                            tb["duts"] = [dut_value] if dut_value else []
                    else:
                        tb["duts"] = []

                    tb["duts_map"] = {dut: i for i, dut in enumerate(tb["duts"])}

                    if 'servers' in tb:
                        tb['multi_servers_tacacs_ip'], _ = \
                            _cidr_to_ip_mask(list(tb['servers'].values())[0]["ptf_ip"])

                    self.testbed_topo[tb["conf-name"]] = tb

        if self.testbed_filename.endswith(".yaml") or self.testbed_filename.endswith(".yml"):
            _read_testbed_topo_from_yaml()
        else:
            raise ValueError(f"Unsupported testbed file format: {self.testbed_filename}")

    def get_testbed_info(self, testbed_name):
        if testbed_name:
            return self.testbed_topo[testbed_name]
        else:
            return self.testbed_topo


def get_testbed_facts(testbed_files=None, testbed_names=None):
    """
    @summary: Load testbed_facts from testbed YAML files using test_facts.py logic
    @param testbed_files: A list of testbed file paths (optional)
    @param testbed_names: A list of testbed names to filter (optional)
    @return: A dict, testbed_facts
    """
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    ansible_path = os.path.join(
        os.path.dirname(os.path.abspath(filename)), '../')

    # Set default testbed files if not provided
    if testbed_files is None:
        testbed_files = []
        for testbed_file in DEFAULT_TESTBED_FILES:
            full_path = os.path.join(ansible_path, testbed_file)
            if os.path.exists(full_path):
                testbed_files.append(full_path)
    else:
        # Convert relative paths to absolute paths
        absolute_files = []
        for testbed_file in testbed_files:
            if not os.path.isabs(testbed_file):
                testbed_file = os.path.join(ansible_path, testbed_file)
            absolute_files.append(testbed_file)
        testbed_files = absolute_files

    if not testbed_files:
        return {
            'testbeds': [],
            'testbed_names': [],
            'groups': {},
            'validation_errors': ['No testbed files found'],
            'summary': {'total_testbeds': 0, 'valid_testbeds': 0}
        }

    try:
        all_testbeds = {}
        validation_errors = []

        # Load testbeds from all files
        for testbed_file in testbed_files:
            if not os.path.exists(testbed_file):
                validation_errors.append(f"Testbed file not found: {testbed_file}")
                continue

            try:
                topo_parser = ParseTestbedTopoinfo(testbed_file)
                topo_parser.read_testbed_topo()
                file_testbeds = topo_parser.get_testbed_info(None)  # Get all testbeds
                all_testbeds.update(file_testbeds)
            except Exception as e:
                validation_errors.append(f"Error loading {testbed_file}: {str(e)}")

        # Filter by testbed names if specified
        if testbed_names:
            filtered_testbeds = {name: all_testbeds[name] for name in testbed_names if name in all_testbeds}
            missing_testbeds = set(testbed_names) - set(all_testbeds.keys())
            for missing in missing_testbeds:
                validation_errors.append(f"Testbed '{missing}' not found in any testbed file")
            all_testbeds = filtered_testbeds

        # Convert to list format and organize data
        testbeds_list = list(all_testbeds.values())
        testbed_names_list = list(all_testbeds.keys())

        # Group testbeds by group-name
        groups = {}
        topologies = {}
        for testbed in testbeds_list:
            group_name = testbed.get('group-name')
            topo = testbed.get('topo')
            conf_name = testbed.get('conf-name')

            if group_name:
                if group_name not in groups:
                    groups[group_name] = []
                groups[group_name].append(conf_name)

            if topo:
                if topo not in topologies:
                    topologies[topo] = []
                topologies[topo].append(conf_name)

        facts = {
            'testbeds': testbeds_list,
            'testbed_names': testbed_names_list,
            'groups': groups,
            'topologies': topologies,
            'validation_errors': validation_errors,
            'summary': {
                'total_testbeds': len(testbeds_list),
                'valid_testbeds': len(testbeds_list),
                'invalid_testbeds': 0,
                'unique_groups': len(groups),
                'unique_topologies': len(topologies)
            }
        }

        if validation_errors:
            logging.error("Testbed validation errors found:")
            for error in validation_errors:
                logging.error(f"  - {error}")

        return facts

    except Exception as e:
        logging.error(f"Failed to load testbed facts: {str(e)}")
        return {
            'testbeds': [],
            'testbed_names': [],
            'groups': {},
            'validation_errors': [f"Failed to load testbed facts: {str(e)}"],
            'summary': {'total_testbeds': 0, 'valid_testbeds': 0}
        }


def get_testbeds_by_group(group_name, testbed_files=None):
    """
    @summary: Get all testbeds belonging to a specific group
    @param group_name: The group name to filter by
    @param testbed_files: Optional list of testbed files
    @return: A list of testbed configurations
    """
    facts = get_testbed_facts(testbed_files)

    group_testbeds = []
    for testbed in facts['testbeds']:
        if testbed.get('group-name') == group_name:
            group_testbeds.append(testbed)

    return group_testbeds


def get_testbeds_by_topology(topology, testbed_files=None):
    """
    @summary: Get all testbeds using a specific topology
    @param topology: The topology name to filter by
    @param testbed_files: Optional list of testbed files
    @return: A list of testbed configurations
    """
    facts = get_testbed_facts(testbed_files)

    topo_testbeds = []
    for testbed in facts['testbeds']:
        if testbed.get('topo') == topology:
            topo_testbeds.append(testbed)

    return topo_testbeds


def get_testbed_by_name(testbed_name, testbed_files=None):
    """
    @summary: Get a specific testbed configuration by name
    @param testbed_name: The testbed conf-name to find
    @param testbed_files: Optional list of testbed files
    @return: A testbed configuration dict or None if not found
    """
    facts = get_testbed_facts(testbed_files, [testbed_name])

    for testbed in facts['testbeds']:
        if testbed.get('conf-name') == testbed_name:
            return testbed

    return None


def validate_testbed_files(testbed_files=None):
    """
    @summary: Validate testbed configuration files
    @param testbed_files: Optional list of testbed files
    @return: A dict with validation results
    """
    facts = get_testbed_facts(testbed_files)

    return {
        'valid': len(facts['validation_errors']) == 0,
        'errors': facts['validation_errors'],
        'summary': facts['summary']
    }


def get_all_testbed_names(testbed_files=None):
    """
    @summary: Get all testbed names from configuration files
    @param testbed_files: Optional list of testbed files
    @return: A list of testbed names
    """
    facts = get_testbed_facts(testbed_files)
    return facts['testbed_names']


def get_testbed_groups(testbed_files=None):
    """
    @summary: Get all unique group names from testbed configurations
    @param testbed_files: Optional list of testbed files
    @return: A list of group names
    """
    facts = get_testbed_facts(testbed_files)
    return list(facts['groups'].keys())


def get_testbed_topologies(testbed_files=None):
    """
    @summary: Get all unique topology names from testbed configurations
    @param testbed_files: Optional list of testbed files
    @return: A list of topology names
    """
    facts = get_testbed_facts(testbed_files)
    return list(facts['topologies'].keys())
