import yaml
import tortuga_common_utils as t_common
from spytest import st


def configure_pre_sonic_bgp(config_file, nodes, add=True) -> bool:
    """
    Function to configure the devices using the updated config file
    :param updated_config_file: updated config file
    :param nodes: nodes to be configured
    :return: True if configuration is successful, False otherwise
    """
    config_jobs = []
    with open(config_file, "r") as file:
        configuration = yaml.load(file, Loader=yaml.FullLoader)
        # list of switches
        for switch, value in configuration.items():
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
    Function to configure the devices using the updated config file
    :param updated_config_file: updated config file
    :param nodes: nodes to be configured
    :return: True if configuration is successful, False otherwise
    """
    config_jobs = []
    with open(config_file, "r") as file:
        configuration = yaml.load(file, Loader=yaml.FullLoader)
        # list of switches
        for switch, value in configuration.items():
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
    Function to configure the devices using the updated config file
    :param updated_config_file: updated config file
    :param nodes: nodes to be configured
    :return: True if configuration is successful, False otherwise
    """
    config_jobs = []
    with open(config_file, "r") as file:
        configuration = yaml.load(file, Loader=yaml.FullLoader)
        # list of switches
        for switch, value in configuration.items():
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
    Function to configure the devices using the updated config file
    :param updated_config_file: updated config file
    :param nodes: nodes to be configured
    :return: True if configuration is successful, False otherwise
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
