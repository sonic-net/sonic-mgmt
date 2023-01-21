import os
import re
import time
from jinja2 import Template
from tests.common.devices.eos import EosHost
from tests.common.utilities import wait_until
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_utils import clear_failed_flag_and_restart


DEFAULT_ISIS_INSTANCE = 'test'
NBR_BACKUP_PATH = '/tmp/isis'
NBR_BACKUP_FILE = '{}_isis.cfg'
EOS_ISIS_TEMPLATE = 'wan/isis/template/eos_isis_config.j2'
SONIC_ISIS_TEMPLATE = 'wan/isis/template/sonic_isis_config.j2'
SONIC_ISIS_CFG_FILE = '/tmp/isis_config.json'


# Temporarily use this method to check bgp container restart count hit start-limit-hit
# Once frrcfgd is used, can skip bgp container restart procedure
def is_hiting_start_limit(duthost, service_name):
    """
    @summary: Determine whether the service can not be restarted is due to start-limit-hit or not
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(service_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def add_dev_isis_attr(device, attr_dict):
    device.host.options['variable_manager'].extra_vars.update(attr_dict)


def del_dev_isis_attr(device, attr_list):
    for attr in attr_list:
        device.host.options['variable_manager'].extra_vars.pop(attr, None)


def get_systemid_from_ipaddr(ipaddr):
    regex_ipv4 = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})')
    match = regex_ipv4.match(ipaddr)
    if match:
        res = ''
        for i in range(1, 5):
            res += '0'*(3-len(match.group(i))) + match.group(i)
        net = re.sub(r'(.{4})', '\\1.', res).strip('.')
        return net
    return None


def get_device_systemid(device):
    hostaddr = device.host.options["inventory_manager"].get_host(device.hostname).get_vars()['ansible_host']
    return get_systemid_from_ipaddr(hostaddr)


def convert_ipaddr_to_netaddr(ipaddr):
    """
    Convert IP address to ISIS net address

    Args:
        ipaddr: IP address
    """
    return '49.0001.' + get_systemid_from_ipaddr(ipaddr) + '.00'


def remove_sonic_isis_config(duthost):
    """
    Remove isis configuration on SONiC

    Args:
        duthost: DUT host object
    """
    sonic_isis_template = Template(open(SONIC_ISIS_TEMPLATE).read())
    duthost.copy(content=sonic_isis_template.render(), dest=SONIC_ISIS_CFG_FILE)
    duthost.shell("sudo sonic-cfggen -j '{}' --write-to-db".format(SONIC_ISIS_CFG_FILE))
    try:
        duthost.restart_service("bgp")
    except RunAnsibleModuleFail:
        if is_hiting_start_limit(duthost, "bgp"):
            clear_failed_flag_and_restart(duthost, "bgp")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")


def remove_nbr_isis_config(nbrhost):
    """
    Remove isis configuration on neighbor device

    Args:
        nbrhost: Neighbor host object
    """
    nbr_backup_file = NBR_BACKUP_FILE.format(nbrhost.hostname)
    if os.path.exists(os.path.join(NBR_BACKUP_PATH, nbr_backup_file)):
        res = nbrhost.load_configuration(os.path.join(NBR_BACKUP_PATH, nbr_backup_file))
        pytest_require(res, 'Failed to load default configuration')


def config_sonic_isis(duthost):
    """
    Configure isis on SONiC device

    Args:
        duthost: DUT host object
    """
    sonic_isis_template = Template(open(SONIC_ISIS_TEMPLATE).read())
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    duthost.copy(content=sonic_isis_template.render(**hostvars), dest=SONIC_ISIS_CFG_FILE)
    duthost.shell("sudo sonic-cfggen -j '{}' --write-to-db".format(SONIC_ISIS_CFG_FILE))
    try:
        duthost.restart_service("bgp")
    except RunAnsibleModuleFail:
        if is_hiting_start_limit(duthost, "bgp"):
            clear_failed_flag_and_restart(duthost, "bgp")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "swss"),
                  "SWSS not started.")
    time.sleep(20)


def config_nbr_isis(nbrhost):
    """
    Configure isis on neighbor device

    Args:
        nbrhost: Neighbor host object
    """
    nbr_backup_file = os.path.join(NBR_BACKUP_PATH, NBR_BACKUP_FILE.format(nbrhost.hostname))
    if isinstance(nbrhost, EosHost):
        nbr_isis_template = EOS_ISIS_TEMPLATE

    res = nbrhost.load_configuration(nbr_isis_template, nbr_backup_file)
    pytest_require(res, 'Failed to load default configuration')


def config_device_isis(device):
    """
    Configure isis on target device

    Args:
        device: Target device host object
    """
    if isinstance(device, EosHost):
        config_nbr_isis(device)
    else:
        config_sonic_isis(device)


def generate_isis_config(device, port_list):
    """
    Generate isis configuration and update related parameters into extra_vars

    Args:
        device: Target device host object
        port_list: Ports intend to enable ISIS
    """
    dev_net = convert_ipaddr_to_netaddr(
        device.host.options["inventory_manager"].get_host(device.hostname).get_vars()['ansible_host']
    )
    device.host.options['variable_manager'].extra_vars.update({'isis_intfs': port_list,
                                                               'isis_instance': DEFAULT_ISIS_INSTANCE,
                                                               'isis_net': dev_net})


def get_dev_ports(selected_connections):
    """
    Return device based port list, convert 1:1 mapping to dict

    Args:
        selected_connections: include a list of items such as (dut_host, dut_port, nbr_host, nbr_port)
        which describes the connection between port_channels in different devices.
    """
    dev_ports = {}
    for item in selected_connections:
        if item[0] not in dev_ports.keys():
            dev_ports[item[0]] = [item[1]]
        else:
            dev_ports[item[0]].append(item[1])

        if item[2] not in dev_ports.keys():
            dev_ports[item[2]] = [item[3]]
        else:
            dev_ports[item[2]].append(item[3])

    for k, v in dev_ports.items():
        v.append('Loopback0')

    return dev_ports


def setup_isis(selected_connections):
    """
    Setup ISIS based on connections between devices

    Args:
        selected_connections: include a list of items such as (dut_host, dut_port, nbr_host, nbr_port)
        which describes the connection between port_channels in different devices.
    """
    for device, port_list in get_dev_ports(selected_connections).items():
        generate_isis_config(device, port_list)
        config_device_isis(device)


def teardown_isis(selected_connections):
    """
    Teardown ISIS based on connections between devices

    Args:
        connected_ports: include a list of items such as (dut_host, dut_port, nbr_host, nbr_port)
        which describes the connection between port_channels in different devices.
    """
    for device in get_dev_ports(selected_connections).keys():
        if isinstance(device, EosHost):
            remove_nbr_isis_config(device)
        else:
            remove_sonic_isis_config(device)


def get_nbr_name(nbrhosts, nbrhost):
    """
    Get neighbor name used in show command.
    (nbrhost.hostname is like 'VM0100' and show command result is the hostname like 'ARISTA01T1')

    Args:
        nbrhosts: Neighbor device object list
        nbrhost: Selected neighbor device object
    """
    for name, v in nbrhosts.items():
        if nbrhost == v['host']:
            nbr_name = name
            return nbr_name
