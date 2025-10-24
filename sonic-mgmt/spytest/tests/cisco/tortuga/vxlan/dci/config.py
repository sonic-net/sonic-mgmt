from typing import Any, Dict, List
import yaml
import tortuga_common_utils as t_common
from spytest import st


def configure_pre_sonic_bgp(config_file, nodes, add=True) -> bool:
    """
    Configure or deconfigure FRR/BGP settings that must be applied before SONiC interface configuration.
    Executes pre-sonic-bgp commands via vtysh on specified devices in parallel.
    
    :param config_file: Path to YAML configuration file containing device configurations
    :param nodes: Dictionary mapping device names to SPyTest device objects
    :param add: True to apply configuration, False to remove configuration
    :return: True if all configuration operations succeed, False otherwise
    """
    config_jobs = []
    with open(config_file, "r") as file:
        configuration: Dict[str, Dict[str, Dict[str, str]]] = yaml.load(file, Loader=yaml.FullLoader)
        # list of switches
        for switch, value in configuration.items():
            # needed when we want to operate on specific nodes only
            if not nodes.get(switch):
                continue
            if add:
                config_jobs.append([t_common.config_node, nodes[switch], value["pre-sonic-bgp"]["config"], "vtysh"])
            else:
                config_jobs.append([t_common.config_node, nodes[switch], value["pre-sonic-bgp"]["deconfig"], "vtysh"])
    if len(config_jobs) > 0:
        st.log("Configuring devices, this will take some time...")
        [out, _] = st.exec_all(config_jobs)
        return False if False in out else True
    return True


def configure_sonic(config_file, nodes, add=True) -> bool:
    """
    Configure or deconfigure SONiC network interfaces, VXLAN settings, and system parameters.
    Executes SONiC CLI commands on specified devices in parallel.
    
    :param config_file: Path to YAML configuration file containing device configurations
    :param nodes: Dictionary mapping device names to SPyTest device objects
    :param add: True to apply configuration, False to remove configuration
    :return: True if all configuration operations succeed, False otherwise
    """
    config_jobs = []
    with open(config_file, "r") as file:
        configuration: Dict[str, Dict[str, Dict[str, str]]] = yaml.load(file, Loader=yaml.FullLoader)
        # list of switches
        for switch, value in configuration.items():
            # needed when we want to operate on specific nodes only
            if not nodes.get(switch):
                continue
            if add:
                config_jobs.append([t_common.config_node, nodes[switch], configuration[switch]["sonic"]["config"], ""])
            else:
                config_jobs.append(
                    [t_common.config_node, nodes[switch], configuration[switch]["sonic"]["deconfig"], ""]
                )
    if len(config_jobs) > 0:
        st.log("Configuring devices, this will take some time...")
        [out, _] = st.exec_all(config_jobs)
        return False if False in out else True
    return True


def configure_bgp(config_file, nodes, add=True) -> bool:
    """
    Configure or deconfigure BGP EVPN settings including neighbors, address families, and route policies.
    Executes BGP configuration commands via vtysh on specified devices in parallel.
    
    :param config_file: Path to YAML configuration file containing device configurations
    :param nodes: Dictionary mapping device names to SPyTest device objects
    :param add: True to apply configuration, False to remove configuration
    :return: True if all configuration operations succeed, False otherwise
    """
    config_jobs = []
    with open(config_file, "r") as file:
        configuration: Dict[str, Dict[str, Dict[str, str]]]= yaml.load(file, Loader=yaml.FullLoader)
        # list of switches
        for switch, value in configuration.items():
            # needed when we want to operate on specific nodes only
            if not nodes.get(switch):
                continue
            if add:
                config_jobs.append([t_common.config_node, nodes[switch], value["bgp"]["config"], "vtysh"])
            else:
                config_jobs.append([t_common.config_node, nodes[switch], value["bgp"]["deconfig"], "vtysh"])
    if len(config_jobs) > 0:
        st.log("Configuring devices, this will take some time...")
        [out, _] = st.exec_all(config_jobs)
        return False if False in out else True
    return True


def configure_devices(config_file, nodes, add=True) -> bool:
    """
    Master function to configure or deconfigure all devices with complete DCI setup.
    Orchestrates the configuration sequence: pre-sonic-bgp → sonic → bgp for add,
    and reverse order (bgp → sonic → pre-sonic-bgp) for remove operations.
    
    :param config_file: Path to YAML configuration file containing device configurations
    :param nodes: Dictionary mapping device names to SPyTest device objects
    :param add: True to apply full configuration, False to remove full configuration
    :return: True if all configuration steps succeed, False otherwise
    """
    if add:
        st.log("Applying configuration to devices...")
        if not configure_pre_sonic_bgp(config_file, nodes, add):
            return False
        if not configure_sonic(config_file, nodes, add):
            return False
        if not configure_bgp(config_file, nodes, add):
            return False
    else:
        st.log("Removing configuration from devices...")
        if not configure_bgp(config_file, nodes, add):
            return False
        if not configure_sonic(config_file, nodes, add):
            return False
        if not configure_pre_sonic_bgp(config_file, nodes, add):
            return False
    return True


def run_clis_on_duts(duts_config, is_bgp = False) -> bool:
    """
    Execute CLI commands on multiple devices in parallel using vtysh.
    Designed for running specific configuration commands like DCI neighbor settings
    across multiple devices simultaneously for efficient test execution.
    
    :param duts_config: List of tuples where each tuple contains (device, config_commands_list)
    :return: True if all CLI commands execute successfully on all devices, False otherwise
    """
    config_jobs = []
    for dut, config in duts_config:
        if is_bgp:
            config_jobs.append([t_common.config_node, dut, config, "vtysh"])
        else:
            config_jobs.append([t_common.config_node, dut, config])

    if len(config_jobs) > 0:
        st.log(f"Running parallel config jobs...")
        [out, _] = st.exec_all(config_jobs)
        return False if False in out else True
    return True
