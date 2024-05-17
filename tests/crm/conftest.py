import pytest
import time
import json
import logging
import re
import ipaddress

from test_crm import RESTORE_CMDS, get_nh_ip
from tests.common.helpers.crm import CRM_POLLING_INTERVAL
from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until, recover_acl_rule
from tests.common.platform.interface_utils import parse_intf_status
from tests.common.mellanox_data import is_mellanox_device
from tests.common.helpers.dut_utils import get_sai_sdk_dump_file

logger = logging.getLogger(__name__)


def pytest_runtest_teardown(item, nextitem):
    """ called after ``pytest_runtest_call``.

    :arg nextitem: the scheduled-to-be-next test item (None if no further
                   test item is scheduled).  This argument can be used to
                   perform exact teardowns, i.e. calling just enough finalizers
                   so that nextitem only needs to call setup-functions.
    """
    failures = []
    crm_threshold_name = RESTORE_CMDS.get("crm_threshold_name")
    restore_cmd = "bash -c \"sonic-db-cli CONFIG_DB hset 'CRM|Config' {threshold_name}_threshold_type percentage \
    && sonic-db-cli CONFIG_DB hset 'CRM|Config' {threshold_name}_high_threshold {high} \
    && sonic-db-cli CONFIG_DB hset 'CRM|Config' {threshold_name}_low_threshold {low}\""
    if item.rep_setup.passed and not item.rep_call.skipped:
        # Restore CRM threshods
        if crm_threshold_name:
            crm_thresholds = item.funcargs["crm_thresholds"]
            cmd = restore_cmd.format(threshold_name=crm_threshold_name, high=crm_thresholds[crm_threshold_name]["high"],
                                     low=crm_thresholds[crm_threshold_name]["low"])
            logger.info("Restore CRM thresholds. Execute: {}".format(cmd))
            # Restore default CRM thresholds
            item.funcargs["duthost"].command(cmd)

        test_name = item.function.__name__
        duthosts = item.funcargs['duthosts']
        hostname = item.funcargs['enum_rand_one_per_hwsku_frontend_hostname']
        dut = None
        if duthosts and hostname:   # unable to test hostname in duthosts
            dut = duthosts[hostname]

        if not dut:
            dut = item.funcargs['duthost']
            logger.warning('fallback to use duthost {} instead from {} {}'.format(dut.hostname, duthosts, hostname))
            hostname = dut.hostname

        logger.info("Execute test cleanup: dut {} {}".format(hostname, json.dumps(RESTORE_CMDS, indent=4)))
        # Restore DUT after specific test steps
        # Test case name is used to mitigate incorrect cleanup if some of tests was failed on cleanup step and list of
        # cleanup commands was not cleared
        for cmd in RESTORE_CMDS[test_name]:
            logger.info(cmd)
            try:
                if isinstance(cmd, dict):
                    recover_acl_rule(dut, cmd["data_acl"])
                else:
                    dut.shell(cmd)
            except RunAnsibleModuleFail as err:
                failures.append("Failure during command execution '{command}':\n{error}"
                                .format(command=cmd, error=str(err)))

        RESTORE_CMDS[test_name] = []

        if RESTORE_CMDS["wait"]:
            logger.info("Waiting {} seconds to process cleanup...".format(RESTORE_CMDS["wait"]))
            time.sleep(RESTORE_CMDS["wait"])

        if failures:
            message = "\n".join(failures)
            pytest.fail(message)


@pytest.fixture(scope="module", autouse=True)
def crm_thresholds(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cmd = "sonic-db-cli CONFIG_DB hget \"CRM|Config\" {threshold_name}_{type}_threshold"
    crm_res_list = ["ipv4_route", "ipv6_route", "ipv4_nexthop", "ipv6_nexthop", "ipv4_neighbor", "ipv6_neighbor",
                    "nexthop_group_member", "nexthop_group", "acl_counter", "acl_entry", "fdb_entry"]
    res = {}
    for item in crm_res_list:
        high = duthost.command(cmd.format(threshold_name=item, type="high"))["stdout_lines"][0]
        low = duthost.command(cmd.format(threshold_name=item, type="low"))["stdout_lines"][0]
        res[item] = {}
        res[item]["high"] = high
        res[item]["low"] = low

    return res


@pytest.fixture(scope="module", autouse=True)
def crm_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo, enum_frontend_asic_index):
    """ Return tuple of two DUT interfaces """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)

    if "backend" in tbinfo["topo"]["name"]:
        crm_intf1 = mg_facts["minigraph_vlan_sub_interfaces"][0]["attachto"]
        crm_intf2 = mg_facts["minigraph_vlan_sub_interfaces"][2]["attachto"]
    else:
        crm_intf1 = None
        crm_intf2 = None
        intf_status = asichost.show_interface(command='status')['ansible_facts']['int_status']

        # 1. we try to get crm interfaces from portchannel interfaces
        for a_pc in mg_facts["minigraph_portchannels"]:
            if a_pc not in intf_status:
                continue
            if intf_status[a_pc]['oper_state'] == 'up':
                # this is a pc that I can use.
                if crm_intf1 is None:
                    crm_intf1 = a_pc
                elif crm_intf2 is None:
                    crm_intf2 = a_pc

        if crm_intf1 is not None and crm_intf2 is not None:
            return (crm_intf1, crm_intf2)

        # 2.  we try to get crm interfaces from routed interfaces
        for a_intf in mg_facts["minigraph_interfaces"]:
            intf = a_intf['attachto']
            if intf not in intf_status:
                continue
            if intf_status[intf]['oper_state'] == 'up':
                if crm_intf1 is None:
                    crm_intf1 = intf
                elif crm_intf2 is None:
                    crm_intf2 = intf

    if crm_intf1 is not None and crm_intf2 is not None:
        return (crm_intf1, crm_intf2)

    if crm_intf1 is None or crm_intf2 is None:
        pytest.skip("Not enough interfaces on this host/asic (%s/%s) to support test." % (duthost.hostname,
                                                                                          asichost.asic_index))


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_time = 2

    # Get polling interval
    output = duthost.command('crm show summary')['stdout']
    parsed = re.findall(r'Polling Interval: +(\d+) +second', output)
    original_crm_polling_interval = int(parsed[0])

    # Set CRM polling interval to 1 second
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))["stdout"]
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

    yield

    # Set CRM polling interval to original value
    duthost.command("crm config polling interval {}".format(original_crm_polling_interval))["stdout"]
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


def get_intf_list(duthost, tbinfo, enum_frontend_asic_index):
    """ Return the interface list which would influence fdb entry by mac learning """
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
    intf_connect_with_ptf = []
    for intf, intf_desc in mg_facts["minigraph_neighbors"].items():
        if "Server" in intf_desc['name']:
            intf_connect_with_ptf.append(intf)
    return intf_connect_with_ptf


def check_interface_status(duthost, intf_list, expected_oper='up'):
    """ Check interface status """
    output = duthost.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    for intf in intf_list:
        if intf not in intf_status:
            logging.info("Missing status for interface %s" % intf)
            return False
        if intf_status[intf]["oper"] != expected_oper:
            logging.info("Oper status of interface {} is {}, expected {}".format(intf, intf_status[intf]["oper"],
                                                                                 expected_oper))
            return False
    return True


def configure_a_route_with_same_prefix_as_vlan_for_mlnx(duthost, asichost, tbinfo, crm_interface):
    """
    For mellanox device, the crm available counter is related to LPM tree.
    When shutdown all interfaces in vlan (e.g. vlan 1000),
    it will cause the route (e.g. 192.168.0.1/21 )for vlan to be removed, we have only one route for the prefix (21),
    so after it is removed, the corresponding prefix in LPM tree will be removed too,
    which will lead to the LPM tree structure is changed.
    LPM tree change might cause available counter change dramatically,
    but we cannot estimate how long the change is ready.
    Therefore, it will lead the first case of test_crm_route fail occasionally
    because the expected available counter is not decreased.
    So, we add another route with the same prefix(21) as the vlan's so that the LPM tree is not changed.
    """
    # Get NH IP
    nh_ip = get_nh_ip(duthost, asichost, crm_interface, '4')

    dump_ip_for_construct_test_route_with_same_prefix_as_vlan_interface = '21.21.21.21'
    network_with_same_prefix_as_vlan_interface = str(
        ipaddress.IPv4Interface(
            f"{dump_ip_for_construct_test_route_with_same_prefix_as_vlan_interface}/"
            f"{get_vlan_ipv4_prefix_len(asichost, tbinfo)}").network)
    add_route_command = f"sudo ip route add {network_with_same_prefix_as_vlan_interface} via {nh_ip}"
    duthost.shell(add_route_command)
    assert wait_until(30, 5, 0, check_route_exist, duthost, network_with_same_prefix_as_vlan_interface, nh_ip), \
        f"Failed to add route {network_with_same_prefix_as_vlan_interface} via {nh_ip} "

    # Get sai sdk dump file in case test fail, we can get the LPM tree information
    get_sai_sdk_dump_file(duthost, "sai_sdk_dump_before_shutdown_vlan_ports")

    del_dump_route_with_same_prefix_as_vlan_interface_cmd = \
        f" sudo ip route del {network_with_same_prefix_as_vlan_interface} via {nh_ip}"

    return del_dump_route_with_same_prefix_as_vlan_interface_cmd


def check_route_exist(duthost, network_with_same_prefix_as_vlan_interface, nh_ip):
    route_output = duthost.shell(f"show ip route {network_with_same_prefix_as_vlan_interface}")["stdout"]
    return f"Routing entry for {network_with_same_prefix_as_vlan_interface}" in route_output and nh_ip in route_output


def get_vlan_ipv4_prefix_len(asichost, tbinfo):
    mg_facts = asichost.get_extended_minigraph_facts(tbinfo)
    for vlan_port_data in mg_facts["minigraph_vlan_interfaces"]:
        if ipaddress.ip_interface(vlan_port_data['addr']).version == 4:
            logger.info(f"vlan interface v4 prefix is :{vlan_port_data['prefixlen']}")
            return vlan_port_data['prefixlen']
    assert False, "Not find v4 prefix for vlan interface config"


@pytest.fixture(scope="module", autouse=True)
def shutdown_unnecessary_intf(
        duthosts, tbinfo, enum_frontend_asic_index, enum_rand_one_per_hwsku_frontend_hostname, crm_interface):
    """ Shutdown unused interfaces to avoid fdb entry influenced by mac learning """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    intfs_connect_with_ptf = get_intf_list(duthost, tbinfo, enum_frontend_asic_index)
    if intfs_connect_with_ptf:
        if is_mellanox_device(duthost):
            del_dump_route_with_same_prefix_as_vlan_interface_cmd = configure_a_route_with_same_prefix_as_vlan_for_mlnx(
                duthost, asichost, tbinfo, crm_interface)
        logger.info("Shutdown interfaces: {}".format(intfs_connect_with_ptf))
        duthost.shutdown_multiple(intfs_connect_with_ptf)
        assert wait_until(300, 20, 0, check_interface_status, duthost, intfs_connect_with_ptf, 'down'), \
            "All interfaces should be down!"

        if is_mellanox_device(duthost):
            # Get sai sdk dump file in case test fail, we can get the LPM tree information
            get_sai_sdk_dump_file(duthost, "sai_sdk_dump_after_shutdown_vlan_ports")

    yield

    if intfs_connect_with_ptf:
        logger.info("Startup interfaces: {}".format(intfs_connect_with_ptf))
        duthost.no_shutdown_multiple(intfs_connect_with_ptf)
        assert wait_until(300, 20, 0, check_interface_status, duthost, intfs_connect_with_ptf), \
            "All interfaces should be up!"
        if is_mellanox_device(duthost):
            duthost.shell(del_dump_route_with_same_prefix_as_vlan_interface_cmd)


@pytest.fixture(scope="module")
def collector(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """ Fixture for sharing variables between test cases """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    data = {}
    for asic in duthost.asics:
        data[asic.asic_index] = {}

    yield data


@pytest.fixture(scope="function")
def cleanup_ptf_interface(duthosts, ip_ver, enum_rand_one_per_hwsku_frontend_hostname,
                          enum_frontend_asic_index, ptfhost):

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    if ip_ver == "4":
        ip_remove_cmd = "config interface ip remove Ethernet1 2.2.2.1/24"
    else:
        ip_remove_cmd = "config interface ip remove Ethernet1 2001::2/64"
    check_vlan_cmd = "show vlan br | grep -w 'Ethernet1'"

    yield

    if duthost.facts["asic_type"] == "marvell":
        asichost.shell(ip_remove_cmd)
        # Check if member not removed
        output = asichost.shell(check_vlan_cmd, module_ignore_errors=True)
        if "Ethernet1" not in output['stdout']:
            asichost.sonichost.add_member_to_vlan(1000, 'Ethernet1', is_tagged=False)
        ptfhost.remove_ip_addresses()
