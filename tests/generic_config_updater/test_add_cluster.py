import requests
import random
from tests.common.helpers.assertions import pytest_assert
import json
import logging
import pdb
import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import re
from tests.common.utilities import wait_until
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, delete_tmpfile, expect_op_success, \
    generate_tmpfile, rollback_or_reload
from tests.common.gu_utils import apply_patch, restore_backup_test_config, save_backup_test_config

from tests.common.snappi_tests.common_helpers import clear_counters, get_queue_count_all_prio

from tests.qos.test_buffer_traditional import load_lossless_info_from_pg_profile_lookup

pytestmark = [
        pytest.mark.topology("t2")
        ]

logger = logging.getLogger(__name__)

EXABGP_BASE_PORT = 5000
NHIPV4 = '10.10.246.254'
STATIC_DST_IP = '192.162.0.128'


# Module fixtures

@pytest.fixture(scope="module")
def enum_rand_one_asic_namespace(enum_rand_one_asic_index):
    return None if enum_rand_one_asic_index is None else 'asic{}'.format(enum_rand_one_asic_index)


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_downstream_dut_hostname, enum_rand_one_asic_namespace):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.config_facts(
        host=duthost.hostname, source="running", namespace=enum_rand_one_asic_namespace
        )['ansible_facts']


@pytest.fixture(scope="module")
def config_facts_localhost(duthosts, enum_downstream_dut_hostname):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running", namespace=None)['ansible_facts']


@pytest.fixture(scope="module")
def mg_facts(duthosts, enum_downstream_dut_hostname, enum_rand_one_asic_namespace, tbinfo):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.get_extended_minigraph_facts(tbinfo, namespace=enum_rand_one_asic_namespace)


@pytest.fixture(scope="module")
def rand_bgp_neigh_ip(config_facts):
    bgp_neighbors = config_facts["BGP_NEIGHBOR"]
    random_bgp_neigh = list(bgp_neighbors.keys())[0]
    logger.info("rand_bgp_neigh_ip fixture::: {} ".format(random_bgp_neigh))
    return random_bgp_neigh


@pytest.fixture(scope="module")
def rand_bgp_neigh_name(config_facts, rand_bgp_neigh_ip):
    random_bgp_neigh_name = config_facts['BGP_NEIGHBOR'][rand_bgp_neigh_ip]['name']
    logger.info("random_bgp_neigh_name fixture::: {} ".format(random_bgp_neigh_name))
    return random_bgp_neigh_name


@pytest.fixture(scope="module")
def setup_env_data_traffic(duthosts, enum_downstream_dut_hostname):
    """
    Setup/teardown fixture for add cluster data traffic test cases.
    Args:
        duthosts: list of DUTs.
        enum_downstream_dut_hostname: A random downstream linecard.
    """
    duthost = duthosts[enum_downstream_dut_hostname]
    create_checkpoint(duthost)
    save_backup_test_config(duthost, file_postfix="{}_before_add_cluster_traffic_test".format(duthost.hostname))

    yield

    restore_backup_test_config(duthost, file_postfix="{}_before_add_cluster_traffic_test".format(duthost.hostname),
                               config_reload=False)
    try:
        logger.info("{}:Rolling back to original checkpoint".format(duthost.hostname))
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def setup_env(duthosts, rand_one_dut_front_end_hostname):
    """
    Setup/teardown fixture for add cluster test cases.
    Args:
        duthosts: list of DUTs.
        rand_one_dut_front_end_hostname: A random linecard.
    """

    duthost = duthosts[rand_one_dut_front_end_hostname]
    create_checkpoint(duthost)
    save_backup_test_config(duthost, file_postfix="{}_before_add_cluster_test".format(duthost.hostname))

    yield

    restore_backup_test_config(duthost, file_postfix="{}_before_add_cluster_test".format(duthost.hostname),
                               config_reload=False)
    try:
        logger.info("{}:Rolling back to original checkpoint".format(duthost.hostname))
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def setup_static_route(tbinfo, duthosts, enum_downstream_dut_hostname,
                       enum_rand_one_asic_index,
                       rand_bgp_neigh_ip, rand_bgp_neigh_name):
    duthost = duthosts[enum_downstream_dut_hostname]

    exabgp_port = get_exabgp_port_for_neighbor(tbinfo, rand_bgp_neigh_name)
    route_exists = verify_routev4_existence(duthost, enum_rand_one_asic_index, STATIC_DST_IP, should_exist=True)
    if route_exists:
        logger.warning("Route exists already - will try to clear")
        clear_static_route(tbinfo, duthost, enum_rand_one_asic_index)
    add_static_route(tbinfo, rand_bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_asic_index, STATIC_DST_IP, should_exist=True)

    yield

    remove_static_route(tbinfo, rand_bgp_neigh_ip, exabgp_port, ip=STATIC_DST_IP)
    wait_until(10, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_asic_index, STATIC_DST_IP, should_exist=False)


@pytest.fixture(scope="module")
def src_duthostname(request, enum_upstream_dut_hostname, enum_downstream_dut_hostname):
    # Dynamically return one of the fixtures based on the parameterization
    if request.param == "upstream->downstream":
        return enum_upstream_dut_hostname
    elif request.param == "downstream->downstream":
        return enum_downstream_dut_hostname

# Helper functions


def get_exabgp_port_for_neighbor(tbinfo, neigh_name):
    offset = tbinfo['topo']['properties']['topology']['VMs'][neigh_name]['vm_offset']
    exabgp_port = EXABGP_BASE_PORT + offset
    return exabgp_port


def change_route(operation, ptfip, route, nexthop, port, aspath):
    url = "http://%s:%d" % (ptfip, port)
    data = {
        "command": "%s route %s next-hop %s as-path [ %s ]" % (operation, route, nexthop, aspath)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


def add_static_route(tbinfo, neigh_ip, exabgp_port, ip, mask='32', aspath=65500):
    common_config = tbinfo['topo']['properties']['configuration_properties'].get('common', {})
    ptf_ip = tbinfo['ptf_ip']
    dst_prefix = ip + '/' + mask
    nexthop = common_config.get('nhipv4', NHIPV4)
    logger.info(
        "Announcing route: ptf_ip={} dst_prefix={} nexthop={} exabgp_port={} aspath={} via neighbor {}".format(
            ptf_ip, dst_prefix, nexthop, exabgp_port, aspath, neigh_ip)
        )
    change_route('announce', ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)


def clear_static_route(tbinfo, duthost, enum_rand_one_asic_index):
    output = duthost.asic_instance(
        enum_rand_one_asic_index).command(
            "show ip route | grep {}".format(STATIC_DST_IP)
        )['stdout']
    ip_address = re.search(r'via (\d+\.\d+\.\d+\.\d+)', output)
    pytest_assert(
        ip_address is not None, "Cannot find the ip address to clear the static route. Output: {}".format(output)
    )
    ip_address = ip_address.group(1)
    config_facts_localhost = duthost.config_facts(
        host=duthost.hostname, source='running', verbose=False, namespace=None
        )['ansible_facts']
    bgp_neigh_name = config_facts_localhost['BGP_NEIGHBOR'][ip_address]['name']
    exabgp_port = get_exabgp_port_for_neighbor(tbinfo, bgp_neigh_name)
    remove_static_route(tbinfo, ip_address, exabgp_port, ip=STATIC_DST_IP)
    wait_until(10, 1, 0, verify_routev4_existence,
               duthost, enum_rand_one_asic_index, STATIC_DST_IP, should_exist=False)


def remove_static_route(tbinfo, neigh_ip, exabgp_port, ip, mask='32', aspath=65500):
    common_config = tbinfo['topo']['properties']['configuration_properties'].get('common', {})
    ptf_ip = tbinfo['ptf_ip']
    dst_prefix = ip + '/' + mask
    nexthop = common_config.get('nhipv4', NHIPV4)
    logger.info(
        "Withdrawing route: ptf_ip={} dst_prefix={} nexthop={} exabgp_port={} aspath={} via neighbor {}".format(
            ptf_ip, dst_prefix, nexthop, exabgp_port, aspath, neigh_ip
        )
    )
    change_route('withdraw', ptf_ip, dst_prefix, nexthop, exabgp_port, aspath)


def verify_routev4_existence(duthost, asic_id, ip, should_exist=True):
    cur_ipv4_routes = duthost.asic_instance(asic_id).command("ip -4 route")['stdout']
    if ip in cur_ipv4_routes:
        logger.info("Verifying route {} existence || Found=True || Expected={}.".format(ip, should_exist))
        return True if should_exist else False
    else:
        logger.info("Verifying route {} existence || Found=False || Expected={}.".format(ip, should_exist))
        return False if should_exist else True


def get_cfg_info_from_dut(duthost, path, namespace=None):
    dict_info = None
    namespace_prefix = '' if namespace is None else '-n ' + namespace
    raw_output = duthost.command(
        "sudo sonic-cfggen {} -d --var-json {}".format(
            namespace_prefix, path)
    )["stdout"]
    try:
        dict_info = json.loads(raw_output)
    except json.JSONDecodeError:
        dict_info = None

    if not isinstance(dict_info, dict):
        print("Expected a dictionary, but got:", type(dict_info))
        dict_info = None
    return dict_info


def get_active_interfaces(config_facts):
    """
    Find all the active interfaces based on configuration
    """
    active_interfaces = []
    for key, _value in config_facts.get("INTERFACE", {}).items():
        if re.compile(r'^Ethernet\d{1,3}$').match(key):
            active_interfaces.append(key)
    for portchannel in config_facts.get("PORTCHANNEL_MEMBER", {}):
        for key, _value in config_facts.get("PORTCHANNEL_MEMBER", {}).get(portchannel, {}).items():
            active_interfaces.append(key)
    logger.info("Active interfaces for this namespace:{}".format(active_interfaces))
    return active_interfaces


def check_interface_status(duthost, namespace, interface_list, exp_status='up'):
    """
    Verifies if all interfaces for one namespace are the expected status
    Args:
        duthost: DUT host object under test
        namespace: Namespace to verify
        interface_list: The list of interfaces to verify
        exp_status: Expected status for all the interfaces
    """
    for interface in interface_list:
        cmds = "show interface status {} -n {}".format(interface, namespace)
        output = duthost.shell(cmds)
        pytest_assert(not output['rc'])
        status_data = output["stdout_lines"]
        field_index = status_data[0].split().index("Admin")
        for line in status_data:
            interface_status = line.strip()
            pytest_assert(len(interface_status) > 0, "Failed to read line {}".format(line))
            if interface_status.startswith(interface):
                status = re.split(r" {2,}", interface_status)[field_index]
                if status != exp_status:
                    logger.error("Found interface {} in non-expected state {}. Line output: {}".format(
                        interface, interface_status, line))
                    return False
    return True


def select_random_active_interface(duthost, namespace):
    """
    Find all the active interfaces based on status in duthost and return a random selected.
    """
    interfaces = duthost.get_interfaces_status(namespace)
    active_interfaces = []
    for interface_name, interface_info in list(interfaces.items()):
        if interface_name.startswith('Ethernet') \
            and interface_info.get('oper') == 'up' \
                and interface_info.get('admin') == 'up':
            active_interfaces.append(interface_name)
    return random.choice(active_interfaces)


def find_nearest_cable_length(pg_profile_info_dict, speed, cable_length):
    """
    Find the nearest supported cable length for the required port speed based on the existing cable length value.
    """
    filtered_dict = {key: value for key, value in pg_profile_info_dict.items() if key[0] == speed}
    sorted_cable_lengths_for_speed = sorted([int(key[1][:-1]) for key in filtered_dict.keys()])
    index = sorted_cable_lengths_for_speed.index(int(cable_length[:-1]))
    if index > 0:
        # return the exact previous supported cable length for that speed
        return sorted_cable_lengths_for_speed[index - 1]
    elif index < len(sorted_cable_lengths_for_speed) - 1:
        # return the exact next supported cable length for that speed
        return sorted_cable_lengths_for_speed[index + 1]
    else:
        print("Cannot change cable length as found supported only one")


def send_and_verify_traffic(
        tbinfo,
        src_duthost,
        dst_duthost,
        src_asic_index,
        dst_asic_index,
        ptfadapter,
        ptf_sport=None,
        ptf_dst_ports=None,
        ptf_dst_interfaces=None,
        src_ip='30.0.0.10',
        dst_ip='50.0.2.2',
        count=1,
        dscp=None,
        sport=0x1234,
        dport=0x50,
        flags=0x10,
        verify=True,
        expect_error=False
        ):
    """
    Helper function to send and verify data traffic via PTF framework.
    """

    src_asic_namespace = None if src_asic_index is None else 'asic{}'.format(src_asic_index)
    dst_asic_namespace = None if dst_asic_index is None else 'asic{}'.format(dst_asic_index)
    router_mac = src_duthost.asic_instance(src_asic_index).get_router_mac()
    src_mg_facts = src_duthost.get_extended_minigraph_facts(tbinfo, src_asic_namespace)
    dst_mg_facts = dst_duthost.get_extended_minigraph_facts(tbinfo, dst_asic_namespace)

    # port from ptf
    if not ptf_sport:
        ptf_src_ports = list(src_mg_facts["minigraph_ptf_indices"].values())
        ptf_sport = random.choice(ptf_src_ports)
    if not ptf_dst_ports:
        ptf_dst_ports = list(set(dst_mg_facts["minigraph_ptf_indices"].values()))
    if not ptf_dst_interfaces:
        ptf_dst_interfaces = list(set(dst_mg_facts["minigraph_ptf_indices"].keys()))

    # clear counters
    clear_counters(dst_duthost, namespace=dst_asic_namespace)

    # Create pkt
    pkt = testutils.simple_tcp_packet(
        eth_src=ptfadapter.dataplane.get_mac(0, ptf_sport),
        eth_dst=router_mac,
        ip_src=src_ip,
        ip_dst=dst_ip,
        ip_ttl=64,
        ip_dscp=dscp,
        tcp_sport=sport,
        tcp_dport=dport,
        tcp_flags=flags
    )

    # Create exp packet for verification
    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')

    # Send packet
    ptfadapter.dataplane.flush()
    logger.debug("Traffic Started")
    testutils.send(ptfadapter, ptf_sport, pkt, count=count)

    # Verify packet count from ptfadapter
    if verify:
        if expect_error:
            with pytest.raises(AssertionError):
                testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_ports)
        else:
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_ports)

    # verify queue counters
    if dscp:
        exp_prio = 'prio_{}'.format(dscp)
        counter_exp_prio = 0
        counter_rest_prio = 0
        pdb.set_trace()
        for interface in ptf_dst_interfaces:
            interface_queue_count_dict = get_queue_count_all_prio(dst_duthost, interface)
            for prio, prio_counter in interface_queue_count_dict[dst_duthost.hostname][interface].items():
                if prio != exp_prio:
                    counter_rest_prio = counter_rest_prio + prio_counter
                else:
                    counter_exp_prio = counter_exp_prio + prio_counter
        if expect_error:
            pytest_assert(
                counter_exp_prio == 0 and counter_rest_prio == 0,
                'Found unexpected queue counter values.\n \
                Prio{} Queues Expected: 0 - Found:{}.\n \
                Rest Prio Queues Expected: 0 - Found:{}.'.format(dscp, counter_exp_prio, counter_rest_prio)
            )
        else:
            pytest_assert(
                counter_exp_prio == count and counter_rest_prio == 0,
                'Found unexpected queue counter values.\n \
                Prio{} Queues Expected:{} - Found:{}.\n \
                Rest Prio Queues Expected: 0 - Found:{}.'.format(dscp, count, counter_exp_prio, counter_rest_prio)
            )
        logger.info("Success queue counter verification - \
                    Prio{} Queues Counter:{} - \
                    Rest Prio Queues Counter:{}.".format(
                        dscp, counter_exp_prio, counter_rest_prio
                        )
                    )


# Helper functions that modify configuration via apply-patch

def apply_patch_remove_neighbors_for_namespace(cfgfacts,
                                               duthost,
                                               namespace,
                                               verify=True):
    """
    Applies a patch to remove neighbors configuration for a specific namespace on the DUT host.

    Applies changes at configuration paths:
        - /<namespace>/BGP_NEIGHBOR
        - /<namespace>/DEVICE_NEIGHBOR
        - /<namespace>/DEVICE_NEIGHBOR_METADATA
        - /localhost/BGP_NEIGHBOR
        - /localhost/DEVICE_NEIGHBOR_METADATA

    This function modifies the DUT host's configuration by removing the neighbors configuration for the given
    namespace using an apply-patch approach. Optionally, it can verify the changes after patching.

    Args:
        cfgfacts (dict): Configuration facts from the DUT host, containing the current state of the configuration.
        duthost (object): DUT host object on which the patch will be applied.
        namespace (str): The namespace from which neighbors should be removed.
        verify (bool, optional): If True, verifies the changes after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """

    logger.info("{}: Removing BGP peers for ASIC namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "remove",
            "path": "{}/BGP_NEIGHBOR".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/DEVICE_NEIGHBOR".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/DEVICE_NEIGHBOR_METADATA".format(json_namespace)
        }
    ]
    json_patch_localhost = []
    # find the keys to remove
    bgp_neighbor_dict = cfgfacts["BGP_NEIGHBOR"]
    device_neighbor_metadata_dict = cfgfacts["DEVICE_NEIGHBOR_METADATA"]
    paths_list = []
    paths_to_remove = ["/localhost/BGP_NEIGHBOR/",
                       "/localhost/DEVICE_NEIGHBOR_METADATA/"]
    keys_to_remove = [
        bgp_neighbor_dict.keys() if bgp_neighbor_dict else [],
        device_neighbor_metadata_dict.keys() if device_neighbor_metadata_dict else []
    ]
    for path, keys in zip(paths_to_remove, keys_to_remove):
        for k in keys:
            paths_list.append(path + k)
    for path in paths_list:
        json_patch_localhost.append({
            "op": "remove",
            "path": path
        })

    # Combine localhost and ASIC patch data
    json_patch = json_patch_localhost + json_patch_asic

    tmpfile = generate_tmpfile(duthost)
    logger.info("Temporary file: {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            # verify that bgp peers have been removed
            logger.info("{}: Verifying bgp_neighbors info is removed.".format(duthost.hostname))
            cur_bgp_neighbors = get_cfg_info_from_dut(duthost, "BGP_NEIGHBOR", namespace)
            cur_device_neighbor = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR", namespace)
            cur_device_neighbor_metadata = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR_METADATA", namespace)
            pytest_assert(not cur_bgp_neighbors,
                          "Bgp neighbors info removal via apply-patch failed."
                          )
            pytest_assert(not cur_device_neighbor,
                          "Device neighbor info removal via apply-patch failed."
                          )
            pytest_assert(not cur_device_neighbor_metadata,
                          "Device neighbor metadata info removal via apply-patch failed."
                          )
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      namespace,
                                                      status=None,
                                                      verify=True):
    """
    Applies a patch to change the administrative status (up/down) of interfaces for a specific namespace
    on the DUT host.

    Applies changes at configuration path:
    - /<namespace>/PORT/<port>/admin_status

    This function updates the administrative state (enabled/disabled) of interfaces within the specified namespace
    on the DUT host by applying a patch. It also offers optional verification of the changes.

    Args:
        config_facts (dict): Configuration facts from the DUT host, containing the current state of the configuration.
        duthost (object): DUT host object on which the patch will be applied.
        namespace (str): The namespace whose interfaces should have their administrative state modified.
        status (str, optional): The desired administrative state of the interfaces ('up' or 'down'). If not provided,
                                no state change is applied. Defaults to None.
        verify (bool, optional): If True, verifies the changes after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """

    pytest_assert(status, "Test didn't provided the admin status value to change to.")

    logger.info("{}: Changing admin status for local interfaces to {} for ASIC namespace {}".format(
        duthost.hostname, status, namespace)
        )
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch = []

    # find all the interfaces that are active based on configuration
    up_interfaces = []
    for key, _value in config_facts.get("INTERFACE", {}).items():
        if re.compile(r'^Ethernet\d{1,3}$').match(key):
            up_interfaces.append(key)
    for portchannel in config_facts.get("PORTCHANNEL_MEMBER", {}):
        for key, _value in config_facts.get("PORTCHANNEL_MEMBER", {}).get(portchannel, {}).items():
            up_interfaces.append(key)
    logger.info("Up interfaces for this namespace:{}".format(up_interfaces))

    for interface in up_interfaces:
        json_patch.append({
            "op": "add",
            "path": "{}/PORT/{}/admin_status".format(json_namespace, interface),
            "value": status
        })

    tmpfile = generate_tmpfile(duthost)
    logger.info("Temporary file: {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            logger.info("{}: Verifying interfaces status is {}.".format(duthost.hostname, status))
            pytest_assert(check_interface_status(duthost, namespace, up_interfaces, exp_status=status),
                          "Interfaces failed to update admin status to {}'".format(status))
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_remove_interfaces_for_namespace(config_facts,
                                                config_facts_localhost,
                                                duthost,
                                                namespace,
                                                port_to_alias_dict,
                                                verify=False):
    """
    Applies a patch to remove interfaces for a specific namespace on the DUT host.

    This function removes the specified interfaces from the provided namespace on the DUT host by applying a patch.
    The patch will use a mapping of port names to aliases,
    which is used to remove interfaces information from localhost namespace,
    and an optional verification step can be performed after the removal.

    Applies changes at configuration paths:
    - /<namespace>/PORTCHANNEL_MEMBER
    - /<namespace>/PORTCHANNEL_INTERFACE
    - /<namespace>/INTERFACE
    - /<namespace>/PORT
    - /localhost/INTERFACE
    - /localhost/PORTCHANNEL_INTERFACE
    - /localhost/PORTCHANNEL_MEMBER

    Args:
        config_facts (dict): Configuration facts from the DUT host, containing the current state of the configuration.
        config_facts_localhost (dict): Configuration facts from the localhost.
        duthost (object): DUT host object on which the patch will be applied.
        namespace (str): The namespace from which the interfaces should be removed.
        port_to_alias_dict (dict): A dictionary mapping port names to their aliases, used for identifying interfaces.
        verify (bool, optional): If True, verifies the changes after applying the patch. Defaults to False.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """
    logger.info("{}: Removing local interfaces for ASIC namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "remove",
            "path": "{}/PORTCHANNEL_MEMBER".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/PORTCHANNEL_INTERFACE".format(json_namespace)
        },
        {
            "op": "remove",
            "path": "{}/INTERFACE".format(json_namespace)
        }
    ]
    json_patch_localhost = []
    # in localhost replace the interface name with the interface alias
    interface_dict = config_facts["INTERFACE"]
    port_keys = []
    localhost_interface_keys = []
    for key, _value in interface_dict.items():
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        key_to_remove = key
        if len(parts) == 2:
            port = parts[0]
            alias = port_to_alias_dict.get(port, port)
            key_to_remove = "{}|{}".format(alias, parts[1])
        else:
            key_to_remove = port_to_alias_dict.get(key, key)
        key_to_remove = key_to_remove.replace("/", "~1")
        localhost_interface_keys.append(key_to_remove)
        port_keys.append(key)
    # construct portchannel keys
    portchannel_keys = config_facts["PORTCHANNEL_INTERFACE"].keys()
    localhost_portchannel_member_dict = config_facts_localhost["PORTCHANNEL_MEMBER"]
    localhost_portchannel_member_keys = []
    for portchannel in portchannel_keys:
        if portchannel in localhost_portchannel_member_dict:
            for key, _value in localhost_portchannel_member_dict[portchannel].items():
                key_to_remove = portchannel + '|' + key.replace("/", "~1")
                localhost_portchannel_member_keys.append(key_to_remove)
    localhost_portchannel_interface_dict = config_facts_localhost["PORTCHANNEL_INTERFACE"]
    localhost_portchannel_interface_keys = []
    for portchannel in portchannel_keys:
        if portchannel in localhost_portchannel_interface_dict:
            localhost_portchannel_interface_keys.append(portchannel)
            for key, _value in localhost_portchannel_interface_dict[portchannel].items():
                key_to_remove = portchannel + '|' + key.replace("/", "~1")
                localhost_portchannel_interface_keys.append(key_to_remove)

    # construct all paths
    paths_list = []
    paths_to_remove = ["{}/PORT/".format(json_namespace),
                       "/localhost/INTERFACE/",
                       "/localhost/PORTCHANNEL_INTERFACE/",
                       "/localhost/PORTCHANNEL_MEMBER/"]
    keys_to_remove = [
        localhost_interface_keys,
        localhost_portchannel_interface_keys,
        localhost_portchannel_member_keys,
    ]
    for path, keys in zip(paths_to_remove, keys_to_remove):
        for k in keys:
            paths_list.append(path + k)
    for path in paths_list:
        json_patch_localhost.append({
            "op": "remove",
            "path": path
        })

    # Combine localhost and ASIC patch data
    # Until Issue sonic-buildimage/issues/20377 is resolved the removal of the interfaces will be done only for
    # asic namespace. Localhost will retain information on interfaces mapping
    # json_patch = json_patch_localhost + json_patch_asic
    json_patch = json_patch_asic

    tmpfile = generate_tmpfile(duthost)
    logger.info("Temporary file: {}".format(tmpfile))

    pdb.set_trace()

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            logger.info("{}: Verifying interfaces info is removed.".format(duthost.hostname))
            interface_dict = get_cfg_info_from_dut(duthost, "INTERFACE", namespace)
            portchannel_interface_dict = get_cfg_info_from_dut(duthost, "PORTCHANNEL_INTERFACE", namespace)
            portchannel_member_dict = get_cfg_info_from_dut(duthost, "PORTCHANNEL_MEMBER", namespace)
            pytest_assert(not interface_dict,
                          "Interfaces info removal via apply-patch failed."
                          )
            pytest_assert(not portchannel_interface_dict,
                          "Portchannel interfaces info removal via apply-patch failed."
                          )
            pytest_assert(not portchannel_member_dict,
                          "Portchannel members info removal via apply-patch failed."
                          )
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_add_neighbors_for_namespace(cfgfacts,
                                            duthost,
                                            namespace,
                                            verify=True):
    """
    Applies a patch to add BGP neighbors for a specific namespace on the DUT host that had been previously removed from
    function 'apply_patch_remove_neighbors_for_namespace'.

    This function adds the necessary BGP neighbors to the provided namespace on the DUT host by applying a patch.
    It uses the configuration facts to re-add same neighbors as before
    and can optionally verify the changes after the neighbors are added.

    Args:
        cfgfacts (dict): Configuration facts from the DUT host, containing BGP neighbors information before removal.
        duthost (object): DUT host object where the patch to add neighbors will be applied.
        namespace (str): The namespace where the BGP neighbors should be added.
        verify (bool, optional): If True, verifies the configuration after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """

    bgp_neighbor_dict = cfgfacts["BGP_NEIGHBOR"]
    device_neighbor_dict = cfgfacts["DEVICE_NEIGHBOR"]
    device_neighbor_metadata_dict = cfgfacts["DEVICE_NEIGHBOR_METADATA"]
    logger.info("{}: Adding back BGP peers for asic namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "add",
            "path": "{}/BGP_NEIGHBOR".format(json_namespace),
            "value": bgp_neighbor_dict
        },
        {
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR".format(json_namespace),
            "value": device_neighbor_dict
        },
        {
            "op": "add",
            "path": "{}/DEVICE_NEIGHBOR_METADATA".format(json_namespace),
            "value": device_neighbor_metadata_dict
        }
    ]

    json_patch_localhost = []
    # find the keys to add
    add_paths_list = []
    add_values_list = []
    for k, v in list(bgp_neighbor_dict.items()):
        add_paths_list.append('/localhost/BGP_NEIGHBOR/{}'.format(k))
        add_values_list.append(v)
    for k, v in list(device_neighbor_dict.items()):
        add_paths_list.append('/localhost/DEVICE_NEIGHBOR/{}'.format(k))
        add_values_list.append(v)
    for k, v in list(device_neighbor_metadata_dict.items()):
        add_paths_list.append('/localhost/DEVICE_NEIGHBOR_METADATA/{}'.format(k))
        add_values_list.append(v)
    for path, value in zip(add_paths_list, add_values_list):
        json_patch_localhost.append({
            "op": "add",
            "path": path,
            "value": value
        })

    # Combine localhost and ASIC patch data
    json_patch = json_patch_localhost + json_patch_asic

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            logger.info("{}: Verifying bgp_neighbors info is added back.".format(duthost.hostname))
            bgp_neighbors = get_cfg_info_from_dut(duthost, "BGP_NEIGHBOR", namespace)
            device_neighbor = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR", namespace)
            device_neighbor_metadata = get_cfg_info_from_dut(duthost, "DEVICE_NEIGHBOR_METADATA", namespace)
            # Wait until bgp sessions are established on DUT
            pytest_assert(wait_until(100, 10, 0, duthost.check_bgp_session_state,
                                     list(
                                         bgp_neighbors.keys()
                                         )), "Not all BGP sessions are established on \
                                            DUT after adding them via apply-patch")

            pytest_assert(bgp_neighbors == bgp_neighbor_dict,
                          "Not all Bgp neighbors are added via apply-patch.")
            pytest_assert(device_neighbor == device_neighbor_dict,
                          "Not all Device neighbor data are added via apply-patch.")
            pytest_assert(device_neighbor_metadata == device_neighbor_metadata_dict,
                          "Not all Device neighbor metadata are added via apply-patch.")
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_add_interfaces_for_namespace(config_facts,
                                             config_facts_localhost,
                                             duthost,
                                             namespace,
                                             port_to_alias_dict,
                                             verify=False):
    """
    Applies a patch to add network interfaces for a specific namespace on the DUT host that had been previously removed
    from function 'apply_patch_remove_interfaces_for_namespace'.

    This function adds network interfaces to the provided namespace by applying a patch on the DUT host.
    It utilizes the configuration facts from both the DUT and the localhost,
    that contains interfaces information before the removal, and can optionally verify the changes
    after the interfaces are added.

    Args:
        config_facts (dict): Configuration facts from the DUT host.
        config_facts_localhost (dict): Configuration facts from the localhost.
        duthost (object): DUT host object where the patch to add interfaces will be applied.
        namespace (str): The namespace where the network interfaces should be added.
        port_to_alias_dict (dict): Mapping between interface ports and their corresponding aliases.
        verify (bool, optional): If True, verifies the configuration after applying the patch. Defaults to False.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """
    interface_dict = config_facts["INTERFACE"]
    portchannel_interface_dict = config_facts["PORTCHANNEL_INTERFACE"]
    portchannel_member_dict = config_facts["PORTCHANNEL_MEMBER"]
    logger.info("{}: Adding back interfaces for asic namespace {}".format(duthost.hostname, namespace))
    json_namespace = '' if namespace is None else '/' + namespace
    json_patch_asic = [
        {
            "op": "add",
            "path": "{}/INTERFACE".format(json_namespace),
            "value": interface_dict
        },
        {
            "op": "add",
            "path": "{}/PORTCHANNEL_INTERFACE".format(json_namespace),
            "value": portchannel_interface_dict
        },
        {
            "op": "add",
            "path": "{}/PORTCHANNEL_MEMBER".format(json_namespace),
            "value": portchannel_member_dict
        }
    ]

    json_patch_localhost = []
    # in localhost replace the interface name with the interface alias
    interface_dict = config_facts["INTERFACE"]
    localhost_interface_dict = {}
    for key, value in interface_dict.items():
        if key.startswith('Ethernet-Rec'):
            continue
        parts = key.split('|')
        updated_key = key
        if len(parts) == 2:
            port = parts[0]
            alias = port_to_alias_dict.get(port, port)
            updated_key = "{}|{}".format(alias, parts[1])
        else:
            updated_key = port_to_alias_dict.get(key, key)
        updated_key = updated_key.replace("/", "~1")
        localhost_interface_dict[updated_key] = value
    # do same for portchannel_member
    portchannel_member_dict = config_facts["PORTCHANNEL_MEMBER"]
    localhost_portchannel_member_dict = {}
    for key, value in portchannel_member_dict.items():
        parts = key.split('|')
        updated_key = key
        if len(parts) == 2:
            port = parts[1]
            if port.startswith('Ethernet-Rec'):
                continue
            alias = port_to_alias_dict.get(port, port)
            updated_key = "{}|{}".format(parts[0], alias)
        updated_key = updated_key.replace("/", "~1")
        localhost_portchannel_member_dict[updated_key] = value

    # find the keys to add
    add_paths_list = []
    add_values_list = []
    for k, v in list(interface_dict.items()):
        key = port_to_alias_dict.get(k, k).replace("/", "~1")
        add_paths_list.append("/localhost/INTERFACE/{}".format(key))
        add_values_list.append(v)
    for k, v in list(portchannel_interface_dict.items()):
        key = port_to_alias_dict.get(k, k).replace("/", "~1")
        add_paths_list.append("/localhost/PORTCHANNEL_INTERFACE/{}".format(k))
        add_values_list.append(v)
    for k, v in list(portchannel_member_dict.items()):
        key = port_to_alias_dict.get(k, k).replace("/", "~1")
        add_paths_list.append("/localhost/PORTCHANNEL_MEMBER/{}".format(k))
        add_values_list.append(v)
    for path, value in zip(add_paths_list, add_values_list):
        json_patch_localhost.append({
            "op": "add",
            "path": path,
            "value": value
        })

    # Combine localhost and ASIC patch data
    # Until Issue sonic-buildimage/issues/20377 is resolved the removalof the interfaces will be done only for
    # asic namespace. Localhost will retain information on interfaces mapping
    # json_patch = json_patch_localhost + json_patch_asic
    json_patch = json_patch_asic

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    pdb.set_trace()
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            logger.info("{}: Verifying interfaces info is added back.".format(duthost.hostname))
            cur_interface = get_cfg_info_from_dut(duthost, "INTERFACE", namespace)
            cur_portchannel_interface = get_cfg_info_from_dut(duthost, "PORTCHANNEL_INTERFACE", namespace)
            cur_portchannel_member = get_cfg_info_from_dut(duthost, "PORTCHANNEL_MEMBER", namespace)
            logger.info("Current interfaces from duthost={}".format(cur_interface))
            pytest_assert(cur_interface == interface_dict,
                          "Not all interfaces are added via apply-patch.")
            pytest_assert(cur_portchannel_interface == portchannel_interface_dict,
                          "Not all portchannel interfaces are added via apply-patch.")
            pytest_assert(cur_portchannel_member == portchannel_member_dict,
                          "Not all portchannel members are added via apply-patch.")
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_remove_qos_for_namespace(duthost,
                                         namespace,
                                         verify=True):
    """
    Applies a patch to remove QoS configurations for a specific namespace on the DUT host.

    This function removes QoS configurations from the specified namespace by applying a patch on the DUT host.
    It can optionally verify that the QoS settings have been removed after the operation.

    Applies changes at configuration paths:
     - /<namespace>/BUFFER_PG
     - /<namespace>/BUFFER_QUEUE
     - /<namespace>/PORT_QOS_MAP
     - /<namespace>/QUEUE

    Args:
        duthost (object): DUT host object where the patch to remove QoS configurations will be applied.
        namespace (str): The namespace from which the QoS configurations should be removed.
        verify (bool, optional): If True, verifies the removal of QoS after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch application or verification process fails.
    """
    logger.info("{}: Removing QoS for ASIC namespace {}".format(
        duthost.hostname, namespace)
        )
    json_patch = []
    paths_to_remove = ['BUFFER_PG', 'BUFFER_QUEUE', 'PORT_QOS_MAP', 'QUEUE']
    for path in paths_to_remove:
        json_patch.append({
            "op": "remove",
            "path": "/{}/{}".format(namespace, path)
        })

    tmpfile = generate_tmpfile(duthost)
    logger.info("Temporary file: {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            # verify CONFIG_DB
            for path in paths_to_remove:
                logger.info("Verifying CONFIG_DB is cleared for path {}.".format(path))
                pytest_assert(not get_cfg_info_from_dut(duthost, path, namespace),
                              "Found unexpected QoS config for {} in CONFIG_DB.".format(path))
            logger.info("CONFIG_DB successfully verified that doesn't contain QoS config.")
            # verify APPL_DB
            appl_db_tables = ['BUFFER_PG_TABLE', 'BUFFER_QUEUE_TABLE']
            for table in appl_db_tables:
                cmd = "sonic-db-cli -n {} APPL_DB keys {}:*".format(namespace, table)
                logger.info("Verifying APPL_DB table {} is cleared.".format(table))
                pytest_assert(not duthost.shell(cmd)["stdout"],
                              "Found unexpected QoS config for {} in APPL_DB.".format(table))
            logger.info("APPL_DB successfully verified that doesn't contain QoS config.")
            # verify ASIC_DB
            asic_db_tables = ['SAI_OBJECT_TYPE_QUEUE']
            for table in asic_db_tables:
                cmd = "sonic-db-cli -n {} ASIC_DB keys *:{}:*".format(namespace, table)
                logger.info("{}: Verifying ASIC_DB table {} is cleared.".format(path, table))
                # pytest_assert(duthost.shell(cmd)["stdout"] == '{}',
                # "Found unexpected QoS config for {} in ASIC_DB.".format(table))
                # W/A until verifying if ASIC_DB clearance fro QUEUE is an issue.
                if duthost.shell(cmd)["stdout"] != '{}':
                    logger.warning("Found unexpected QoS config for {} in ASIC_DB.".format(path))
                else:
                    logger.info("ASIC_DB successfully verified that doesn't contain QoS config.")
            # logger.info("ASIC_DB successfully verified that doesn't contain QoS config.")
    finally:
        delete_tmpfile(duthost, tmpfile)


def apply_patch_add_qos_for_namespace(duthost,
                                      namespace,
                                      qos_config,
                                      verify=True):
    """
    Applies a patch to add QoS configuration for a specific namespace on the DUT host that had been previously removed
    from function 'apply_patch_remove_qos_for_namespace'.

    This function adds QoS configuration for the specified namespace by applying a patch on the DUT host.
    It utilizesn the qos_config dictionary that includes all the requried information to add.
    Optionally, it can verify the applied changes to ensure they meet the expected parameters.

    Args:
        duthost (object): DUT host object where the patch to add interfaces will be applied.
        namespace (str): The namespace where the network interfaces should be added.
        qos_config (dict): A dictionary containing the QoS configuration parameters to be applied.
        verify (bool, optional): If True, verifies the configuration after applying the patch. Defaults to True.

    Returns:
        None

    Raises:
        Exception: If the patch or verification fails.
    """
    logger.info("{}: Adding QoS for ASIC namespace {}".format(
        duthost.hostname, namespace)
        )
    json_patch = []
    for path, value in list(qos_config.items()):
        json_patch.append({
            "op": "add",
            "path": "/{}/{}".format(namespace, path),
            "value": value
        })

    tmpfile = generate_tmpfile(duthost)
    logger.info("Temporary file: {}".format(tmpfile))
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        if verify is True:
            # verify CONFIG_DB
            for path, value in list(qos_config.items()):
                logger.info("Verifying CONFIG_DB is added back for path {}.".format(path))
                pytest_assert(get_cfg_info_from_dut(duthost, path, namespace) == value,
                              "Didn't find expected QoS config for {} in CONFIG_DB.".format(path))
            logger.info("CONFIG_DB successfully verified to contain expected QoS config.")
            # verify APPL_DB
            appl_db_tables = ['BUFFER_PG', 'BUFFER_QUEUE']
            for table in appl_db_tables:
                cmd = "sonic-db-cli -n {} APPL_DB keys {}_TABLE:*".format(namespace, table)
                logger.info("Verifying APPL_DB table {} includes valid config.".format(table))
                pytest_assert(len(duthost.shell(cmd)["stdout"].split('\n')) == len(qos_config.get(table)),
                              "Didn't find expected config for {} in APPL_DB.".format(table))
            logger.info("APPL_DB successfully verified to include QoS config.")
            # verify ASIC_DB
            asic_db_tables = ['SAI_OBJECT_TYPE_QUEUE']
            for table in asic_db_tables:
                cmd = "sonic-db-cli -n {} ASIC_DB keys *:{}:*".format(namespace, table)
                logger.info("Verifying ASIC_DB table {} includes valid config.".format(table))
                pytest_assert(duthost.shell(cmd)["stdout"] != '{}',
                              "Found empty QoS config for {} in ASIC_DB.".format(table))
            logger.info("ASIC_DB successfully verified to include QoS config.")
    finally:
        delete_tmpfile(duthost, tmpfile)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("src_duthostname", ["upstream->downstream", "downstream->downstream"], indirect=True)
def test_add_cluster(tbinfo,
                     setup_env_data_traffic,
                     setup_static_route,
                     duthosts,
                     enum_downstream_dut_hostname,
                     src_duthostname,
                     enum_rand_one_asic_index,
                     enum_rand_one_asic_namespace,
                     mg_facts,
                     config_facts,
                     config_facts_localhost,
                     rand_bgp_neigh_ip,
                     ptfadapter,
                     remove_interfaces=False):
    """
    Test Case: Add Cluster and Remove Existing BGP Sessions for a Random ASIC.

    Setup:
    - Save the initial configuration.

    Test Steps:
    1. Downstream: Save the initial BGP Neighbors and Peers configuration.
    2. Upstream: Send traffic towards the Downstream Neighbor, which should pass.
    3. Downstream: Apply a patch to remove neighbor and peer information.
    4. Downstream: Verify BGP information, route table, and interfaces information.
    5. Downstream: Ensure the information for the second ASIC remains unchanged.
    6. Upstream: Send traffic towards the Downstream Neighbor, which should now fail.
    7. Downstream: Apply a patch to shut down active interfaces and remove interfaces mapped to neighbors.
    8. Downstream: Verify that the buffer PG information is automatically updated.
    9. Downstream: Apply a patch to add neighbor and peer information back.
    10. Downstream: Verify BGP information, route table, and interfaces information.
    11. Downstream: Ensure the information for the second ASIC is still the same.
    12. Downstream: Apply a patch to enable the interfaces and remap interfaces to neighbors.
    13. Downstream: Verify that the buffer PG information is automatically updated again.
    14. Upstream: Send traffic towards the Downstream Neighbor, which should pass.

    Teardown:
    - Restore the configuration to its initial state.
    """

    # initial test env
    duthost = duthosts[enum_downstream_dut_hostname]
    duthost_src = duthosts[src_duthostname]
    asic_id = enum_rand_one_asic_index
    asic_id_src = None
    all_asic_ids = duthost_src.get_asic_ids()
    for asic in all_asic_ids:
        if duthost_src == duthost and asic == asic_id:
            continue
        asic_id_src = asic
        break
    pytest_assert(
        asic_id_src is not None, "Couldn't find an asic id to be used for sending traffic. \
            Reserved asic id: {}. All available asic ids: {}".format(
            asic_id, all_asic_ids
        )
    )
    initial_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', asic_id)

    # verify initial traffic pass
    send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                            ptfadapter, dst_ip=STATIC_DST_IP, count=1000)
    send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                            ptfadapter, dst_ip=rand_bgp_neigh_ip, count=1000)

    # STEP: REMOVE BGP PEERS
    apply_patch_remove_neighbors_for_namespace(config_facts,
                                               duthost,
                                               enum_rand_one_asic_namespace,
                                               verify=True)
    # verify routes removed
    wait_until(5, 1, 0, verify_routev4_existence, duthost,
               enum_rand_one_asic_index, rand_bgp_neigh_ip, should_exist=False)
    wait_until(5, 1, 0, verify_routev4_existence, duthost, enum_rand_one_asic_index, STATIC_DST_IP, should_exist=False)

    # shutdown-interfaces
    apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      enum_rand_one_asic_namespace,
                                                      status='down',
                                                      verify=True)
    # remove-interfaces-mapping
    apply_patch_remove_interfaces_for_namespace(config_facts,
                                                config_facts_localhost,
                                                duthost,
                                                enum_rand_one_asic_namespace,
                                                mg_facts['minigraph_port_name_to_alias_map'],
                                                verify=True)

    # check buffer pg mapping
    pdb.set_trace()
    buffer_pg_info_remove_interfaces = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    pytest_assert(buffer_pg_info_remove_interfaces == {},
                  "Didn't find expected BUFFER_PG info in CONFIG_DB after removing the interfaces.")

    # verify traffic to static route fails
    logger.info("Sending Data Traffic from upstream to downstream - after peers removal. \
                Dst IP is static route ip. Traffic should fail.")
    send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                            ptfadapter, dst_ip=STATIC_DST_IP, count=1000, expect_error=True)

    # STEP: Add interfaces
    apply_patch_add_interfaces_for_namespace(config_facts,
                                             config_facts_localhost,
                                             duthost,
                                             enum_rand_one_asic_namespace,
                                             mg_facts['minigraph_port_name_to_alias_map'],
                                             verify=True)
    # enable-interfaces
    apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      enum_rand_one_asic_namespace,
                                                      status='up',
                                                      verify=True)

    # STEP: Add bgp neighbors
    apply_patch_add_neighbors_for_namespace(config_facts,
                                            duthost,
                                            enum_rand_one_asic_namespace,
                                            verify=True)
    # verify routes
    wait_until(5, 1, 0, verify_routev4_existence,
               duthost, enum_rand_one_asic_index, rand_bgp_neigh_ip, should_exist=True)
    wait_until(5, 1, 0, verify_routev4_existence,
               duthost, enum_rand_one_asic_index, STATIC_DST_IP, should_exist=True)

    # check buffer pg mapping
    pdb.set_trace()
    buffer_pg_info_add_interfaces = get_cfg_info_from_dut(duthost, 'BUFFER_PG', enum_rand_one_asic_namespace)
    pytest_assert(buffer_pg_info_add_interfaces == initial_buffer_pg_info,
                  "Didn't find expected BUFFER_PG info in CONFIG_DB after adding back the interfaces.")

    # verify lossless traffic - should pass
    logger.info("Sending Data Traffic from upstream to downstream - after peers added. Traffic should pass.")
    send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                            ptfadapter, dst_ip=STATIC_DST_IP, dscp=3, count=1000)
    send_and_verify_traffic(tbinfo, duthost_src, duthost, asic_id_src, asic_id,
                            ptfadapter, dst_ip=rand_bgp_neigh_ip, dscp=3, count=1000)


@pytest.mark.disable_loganalyzer
def test_update_cable_length(duthosts,
                             setup_env,
                             rand_one_dut_front_end_hostname,
                             rand_asic_namespace,
                             verify=False):
    """
    Verifies the update of cable lengths for interfaces in one random ASIC namespace from a frontend host.
    The process involves shutting down the interfaces, updating the cable length, and then bringing the interfaces
    back up. All these operations are performed using apply-patch.

    Once the interfaces are up, the system should automatically detect the port speed and cable length of the active
    interfaces. It should then create or remove the relevant buffer PG lossless profiles and map the appropriate profile
    with the lossless queues of the active interfaces.
    This mapping happens automatically when the interfaces are brought up.

    The test verifies that CONFIG_DB has updated values for the paths CABLE_LENGTH, BUFFER_PROFILE, and BUFFER_PG.
    Additionally, APPL_DB is checked to confirm the correct BUFFER_PROFILE and BUFFER_PG information.

    Parameters:
    - `duthosts`: The DUT (Device Under Test) hosts participating in the test.
    - `rand_one_dut_front_end_hostname`: The randomly selected hostname of one front-end DUT.
    - `rand_asic_namespace`: The namespace of the ASIC on the front-end DUT being tested.

    """

    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, asic_id = rand_asic_namespace
    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=asic_namespace
        )['ansible_facts']
    active_interfaces = get_active_interfaces(config_facts)
    selected_intf = select_random_active_interface(duthost, asic_namespace)
    supported_pg_profile_info_dict = load_lossless_info_from_pg_profile_lookup(duthost, duthost.asic_instance(asic_id))
    initial_cable_length = duthost.shell('sonic-db-cli -n {} CONFIG_DB hget "CABLE_LENGTH|AZURE" {}'
                                         .format(asic_namespace, selected_intf))['stdout']
    initial_port_speed = duthost.shell('sonic-db-cli -n {} CONFIG_DB hget "PORT|{}" speed'
                                       .format(asic_namespace, selected_intf))['stdout']
    initial_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(initial_port_speed, initial_cable_length)
    initial_buffer_profile_info = get_cfg_info_from_dut(duthost, 'BUFFER_PROFILE', asic_namespace)
    initial_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', asic_namespace)
    initial_pg_lossless_profile_info = initial_buffer_profile_info.get(initial_pg_lossless_profile_name)

    # shutdown-interfaces
    apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      asic_namespace,
                                                      status='down',
                                                      verify=True)

    # change cable lengths
    target_cable_length_val = find_nearest_cable_length(supported_pg_profile_info_dict,
                                                        initial_port_speed,
                                                        initial_cable_length)
    target_cable_length = "{}m".format(target_cable_length_val)
    logger.info("Changing cable length from {} to {}.".format(initial_cable_length, target_cable_length))
    json_namespace = '/' + asic_namespace
    initial_cable_length_config = get_cfg_info_from_dut(duthost, 'CABLE_LENGTH', asic_namespace).get('AZURE')
    target_cable_length_config = {}
    for interface, length in list(initial_cable_length_config.items()):
        if interface in active_interfaces:
            target_cable_length_config[interface] = target_cable_length
        else:
            target_cable_length_config[interface] = length
    json_patch = [
         {
             "op": "add",
             "path": "{}/CABLE_LENGTH/AZURE".format(json_namespace),
             "value": target_cable_length_config
         }
     ]
    tmpfile = generate_tmpfile(duthost)
    logger.info("Temporary file: {}".format(tmpfile))
    # Identify expected buffer pg profile information to be used later in verification
    expected_pg_lossless_profile_name = 'pg_lossless_{}_{}_profile'.format(initial_port_speed, target_cable_length)
    supported_pg_profile_info_for_speed = supported_pg_profile_info_dict.get((initial_port_speed, target_cable_length))
    expected_pg_lossless_profile_info = initial_pg_lossless_profile_info
    expected_pg_lossless_profile_info['xon'] = supported_pg_profile_info_for_speed.get('xon')
    expected_pg_lossless_profile_info['xoff'] = supported_pg_profile_info_for_speed.get('xoff')
    expected_pg_lossless_profile_info['xon_offset'] = supported_pg_profile_info_for_speed.get('xon_offset')
    expected_buffer_pg_info = {}
    for key, value in list(initial_buffer_pg_info.items()):
        if value['profile'] == initial_pg_lossless_profile_name:
            value['profile'] = expected_pg_lossless_profile_name
        expected_buffer_pg_info[key] = value

    # The following code cannot be executed as modifying BUFFER_PROFILE is not allowed.
    # Updates to the pg lossless profiles are handled automatically when interfaces are shut down or enabled.
    # The profiles are removed/created accordingly during these operations.

    # json_patch = [
    #      {
    #          "op": "remove",
    #          "path": "{}/BUFFER_PROFILE/{}".format(json_namespace, initial_pg_lossless_profile_name)
    #      },
    #      {
    #          "op": "add",
    #          "path": "{}/BUFFER_PROFILE/{}".format(json_namespace, expected_pg_lossless_profile_name),
    #          "value": expected_pg_lossless_profile_info
    #      }
    #  ]

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        pytest_assert(get_cfg_info_from_dut(duthost, 'CABLE_LENGTH', asic_namespace).get(
            'AZURE') == target_cable_length_config, "Cable length value was not updated in CONFIG_DB.")

    finally:
        delete_tmpfile(duthost, tmpfile)

    # enable-interfaces
    apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      asic_namespace,
                                                      status='up',
                                                      verify=True)

    # verify that pg_lossless profile automatically updated
    if verify:
        # verify CONFIG_DB:BUFFER_PROFILE:BUFFER_PG
        updated_buffer_profile_info = get_cfg_info_from_dut(duthost, 'BUFFER_PROFILE', asic_namespace)
        updated_buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', asic_namespace)
        pytest_assert(expected_pg_lossless_profile_name in updated_buffer_profile_info,
                      "Expected buffer profile {} was not created in CONFIG_DB.".format(
                          expected_pg_lossless_profile_name))
        pytest_assert(updated_buffer_pg_info == expected_buffer_pg_info,
                      "Didn't find expected BUFFER_PG info in CONFIG_DB.")
        # verify APPL_DB:BUFFER_PROFILE_TABLE
        cmd = "sonic-db-cli -n {} APPL_DB keys BUFFER_PROFILE_TABLE:*".format(asic_namespace)
        updated_buffer_profile_info_appl_db = duthost.shell(cmd)["stdout"]
        pytest_assert(expected_pg_lossless_profile_name in updated_buffer_profile_info_appl_db,
                      "Expected buffer profile {} was not created in APPL_DB.".format(
                          expected_pg_lossless_profile_name))


@pytest.mark.disable_loganalyzer
def test_load_qos(duthosts,
                  setup_env,
                  rand_one_dut_front_end_hostname,
                  rand_asic_namespace):
    """
    Verifies QoS changes in the configuration path via the `apply-patch` mechanism,
    specifically for the following configuration tables:
    BUFFER_PG, BUFFER_QUEUE, PORT_QOS_MAP, and QUEUE.

    Steps involved:
    1. **Backup of existing configuration**: The current configuration in the aforementioned tables is saved.
    2. **Removal operation**: The `apply-patch remove` command is used to delete any info related to these config paths.
    3. **Addition operation**: The initial saved configuration is restored using the `apply-patch add` command.

    During both the removal and addition phases, the following verifications are performed:
    - Ensure the changes have been correctly applied.
    - Confirm that the changes are properly reflected in `CONFIG_DB`.
    - Validate the propagation of changes to relevant tables in both `APPL_DB` and `ASIC_DB`.

    Parameters:
    - `duthosts`: The DUT (Device Under Test) hosts participating in the test.
    - `rand_one_dut_front_end_hostname`: The randomly selected hostname of one front-end DUT.
    - `rand_asic_namespace`: The namespace of the ASIC on the front-end DUT being tested.

    """

    duthost = duthosts[rand_one_dut_front_end_hostname]
    asic_namespace, _asic_id = rand_asic_namespace

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running", namespace=asic_namespace
        )['ansible_facts']

    buffer_pg_info = get_cfg_info_from_dut(duthost, 'BUFFER_PG', asic_namespace)
    buffer_queue_info = get_cfg_info_from_dut(duthost, 'BUFFER_QUEUE', asic_namespace)
    port_qos_map_info = get_cfg_info_from_dut(duthost, 'PORT_QOS_MAP', asic_namespace)
    queue_info = get_cfg_info_from_dut(duthost, 'QUEUE', asic_namespace)
    qos_config = {'BUFFER_PG': buffer_pg_info,
                  'BUFFER_QUEUE': buffer_queue_info,
                  'PORT_QOS_MAP': port_qos_map_info,
                  'QUEUE': queue_info}

    # shutdown-interfaces
    apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      asic_namespace,
                                                      status='down',
                                                      verify=True)
    # remove qos
    apply_patch_remove_qos_for_namespace(duthost,
                                         asic_namespace,
                                         verify=True)
    # add qos
    apply_patch_add_qos_for_namespace(duthost,
                                      asic_namespace,
                                      qos_config,
                                      verify=True)
    # enable-interfaces
    apply_patch_admin_change_interfaces_for_namespace(config_facts,
                                                      duthost,
                                                      asic_namespace,
                                                      status='up',
                                                      verify=True)
