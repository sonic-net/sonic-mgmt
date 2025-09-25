"""-----------------------------------------------
  _   _  _   _     _
 |_) /  |_) |_)   | \  _   _.  _| |  _   _ |
 |   \_ |_) |_)   |_/ (/_ (_| (_| | (_) (_ |<
-----------------------------------------------

Design Principles
-----------------

1) Due to the high complexity of the TB setup required to reproduce a deadlock scenario,
this test is designed to maximize incremental validation. Every setup step that can break
 will break at some point, and we should ensure the first log message seen in the
backtrace tells exactly what the issue is.

2) Assertion failures should contain sizeable messages explaining the failure. Other logs
before the exception can be helpful, but the exception itself should contain enough info
to uniquely classify the issue.

3) The main test body needs to ignore the 'pcbb' test parametrization except for validation
purposes. The test cannot start changing config based on whether we're in PCBB-enabled or
disabled mode, as this will invalidate the deadlock reproduction attempt.

4) Do not throw an exception in a loop over multiple things that could have an exception.
Instead, construct a list of all the failure cases, and fail if its length is non-zero.
The error will then show the entire scope of the problem, rather than just the failing
first case.


Topology Overview
-----------------

The DualToR snappi test topology consists of 2 ToRs, 1 T1, and an Ixia. The Ixia should be
connected to 2 ports on the Upper T0, 2 ports on the Lower T0, and 1 port on the T1.
Currently the T1 port must be a faster speed than T0 in order to cause a deadlock. One
TODO item is to use 2 ports for the deadlock procedure to have more flexibility past this
restriction.

This diagram shows the basic port [P] layout:

             +----------------------------------+
             |                                  |
             |               T1                 |
             |                                  |
             +-[P]-----------[P]------------[P]-+
                |             |              |
+--------------[P]-+          |           +-[P]--------------+
|                  |          |           |                  |
|     Upper T0     |          |           |     Lower T0     |
|                  |          |           |                  |
+----------[P]-[P]-+          |           +-[P]-[P]----------+
            |   |             |              |   |
       +---[P]-[P]-----------[P]------------[P]-[P]---+
       |                                              |
       |                    TGEN                      |
       |                                              |
       +----------------------------------------------+

Note that the TGEN connected to the T0s is impersonating either a Y-cable or a NIC with 2
ports. Thus there are only 2 "servers" being impersonated by the Ixia with 4 ports. The
device IP/mac information should thus match for each T0. For example, if the Upper T0 is
connected to Ixia's virtual devices at 192.168.0.10 and 192.168.0.12, then the Ixia's
other devices on the ports to the Lower T0 should also have these addresses
respectively. This enables the bounceback route inserted on the ToR with a down mux to
arrive correctly at the other ToR and get forwarded to the Ixia.


Additional Notes
----------------

- sonic_lab_links.csv should declare all inter-device links in addition to snappi/ixia links.
  This is used for pathfinding algorithms.
- 't1' should be present in the T1 device name, and vice versa for 't0'.


Known Issues
------------

If you get an error like this:
E             File "/usr/local/lib/python3.8/dist-packages/snappi_ixnetwork/resourcegroup.py", line 67, in set_group
E               raise Exception(
E           Port 57Port 58Port 59Port 60

This is the snappi_ixnetwork bug that is intended to be patched in patcher.py. However,
this doesn't work on the first run, since snappi_ixnetwork is already imported
elsewhere. Try rerunning.

"""

# Patch snappi_ixnetwork bug that breaks breakout ports.
from tests.snappi_tests.dualtor.patcher import patch_snappi_ixnetwork
patch_snappi_ixnetwork()
# TODO: Patcher doesn't fix the first run, but subsequent runs work.

import pytest
import random
import time

from tests.common.snappi_tests.common_helpers import traffic_flow_mode, get_interface_stats, \
    get_interface_stats_from_duthosts, compare_interface_stats, \
    get_pfc_counters_multihost, compare_pfc_counters, scan_pfc_counters, flatten_pfc_counts

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut, \
    fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_multi_base_config, cleanup_config, get_snappi_ports_for_rdma, \
    get_snappi_ports, get_snappi_ports_multi_dut, clear_fabric_counters, check_fabric_counters, \
    get_snappi_ports_single_dut       # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list, \
    lossy_prio_list, all_prio_list, disable_pfcwd                                                     # noqa: F401
# from tests.snappi_tests.cisco.helper import disable_voq_watchdog                  # noqa: F401 # TODO: Uncomment import

# TODO: Only needed for unabstracted work, will eventually be removed
from tests.common.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.snappi_tests.dualtor.utilities import set_tunnel_qos_remap_multidut

import logging
logger = logging.getLogger(__name__)

# Testplan: docs/testplan/TODO
# This test-script covers following testcases:
# TODO

# TODO: Use snappi's variable
LINK_UP = 'up'

# Number of packets used to find the path a packet takes through the topology
PATH_DETECTION_COUNT = 100000
# Percentage error allowed in path detection
PATH_DETECTION_MARGIN_PERCENT = 1
SANITIZATION_MARGIN_PERCENT = 10

DEFAULT_SEND_SEC = 10
# TODO: Revise deadlock attempt code to dynamically detect how much send time is required to cause a deadlock.
DEADLOCK_ATTEMPT_FLOW_SEC = 30

# The number of interface interactions required to perform different T2 -> T1 -> Dualtor -> Server
# paths when only counting T1 and dualtor interfaces.
BOUNCE_BACK_PATH_LENGTH = 8
STRAIGHT_THROUGH_PATH_LENGTH = 4
# Reproducing a deadlock requires a bare minimum of 4 ports in a TX/RX PFC state. A PFC
# loop requires bidirectional PFC to both ToRs. Currently used for more restrictive checks
# to try and isolate testing issues as early on as possible.
DEADLOCK_MIN_PORTS_INVOLVED = 4


def inc_ip_address(addr):
    num_strs = addr.split('.')
    last_str = num_strs[-1]
    last = int(last_str)
    pytest_assert(last < 255, "IP {} cannot be incremented on last byte".format(addr))
    num_strs[-1] = str(last + 1)
    return ".".join(num_strs)


def is_margin_eq(value, expected, percent):
    return (100 * abs(value - expected) / float(expected)) <= percent


def pytest_assert_eq(a, b, msg=""):
    if msg != "":
        msg = ": " + msg
    pytest_assert(a == b, "Failed eq check: {} == {}{}".format(a, b, msg))


def pytest_assert_neq(a, b, msg=""):
    if msg != "":
        msg = ": " + msg
    pytest_assert(a != b, "Failed neq check: {} != {}{}".format(a, b, msg))


DEVICE_CONFIGS = [{'name': 'Device to T1 E224', # TODO: Autogenerate device name from input parameters
                   'port_id': 2,
                   'mac': "00:12:01:00:00:01",
                   'ipv4': "10.0.224.3",
                   'prefix': 24,
                   'gateway': "10.0.224.2"},
                  {'name': 'Device on Port 3.1 to LT0:E240', # "Simulated" TGEN servers, with dualtor-matching IPs and macs.
                   'port_id': 57,
                   'mac': "00:15:01:00:00:01",
                   'ipv4': "192.168.0.10",
                   'prefix': 21,
                   'gateway': "192.168.0.1"},
                  {'name': 'Device on Port 3.2 to T0:E240',
                   'port_id': 58,
                   'mac': "00:15:01:00:00:01",
                   'ipv4': "192.168.0.10",
                   'prefix': 21,
                   'gateway': "192.168.0.1"},
                  {'name': 'Device on Port 3.3 to LT0:E224',
                   'port_id': 59,
                   'mac': "00:14:01:00:00:01",
                   'ipv4': "192.168.0.12",
                   'prefix': 21,
                   'gateway': "192.168.0.1"},
                  {'name': 'Device on Port 3.4 to T0:E224',
                   'port_id': 60,
                   'mac': "00:14:01:00:00:01",
                   'ipv4': "192.168.0.12",
                   'prefix': 21,
                   'gateway': "192.168.0.1"},
]

# Maps 'name' -> 'device'
SNAPPI_DEVICES = {}


def port_id_to_snappi_port_config(config, port_id):
    for port in config.ports:
        curr_port_id = int(port.location.split(';')[-1])
        if curr_port_id == port_id:
            return port
    pytest_assert(False, "Unable to find port config by ID {}".format(port_id))


def device_name_to_eth_name(name):
    return 'Ethernet {}'.format(name)


def device_name_to_ipv4_name(name):
    return 'Ipv4 {}'.format(name)


def device_names_to_flow_name(src_dev_name, dst_dev_name):
    return 'Flow {} -> {}'.format(src_dev_name, dst_dev_name)


def get_device(dev_name):
    return SNAPPI_DEVICES[dev_name]


def add_device(config, **kwargs):
    # Parameter parsing
    pytest_assert(None not in kwargs.values())
    name = kwargs['name']
    port_id = kwargs['port_id']
    mac = kwargs['mac']
    ipv4 = kwargs['ipv4']
    prefix = kwargs['prefix']
    gateway = kwargs['gateway']

    # Add new device
    device = config.devices.add()
    device.name = name

    # Attach ethernet layer to device
    ethernet = device.ethernets.add()
    ethernet.name = device_name_to_eth_name(name)
    ethernet.connection.port_name = port_id_to_snappi_port_config(config, port_id).name
    ethernet.mac = mac

    # Attach ipv4 layer to ethernet layer
    ip_stack = ethernet.ipv4_addresses.add()
    ip_stack.name = device_name_to_ipv4_name(name)
    ip_stack.address = ipv4
    ip_stack.prefix = prefix
    ip_stack.gateway = gateway
    return device


def add_flow(config, src_dev_name, dst_dev_name):
    pytest_assert(src_dev_name in SNAPPI_DEVICES, "Source device {} not created".format(src_dev_name))
    pytest_assert(dst_dev_name in SNAPPI_DEVICES, "Destination device {} not created".format(dst_dev_name))
    # Construct flow
    flow = config.flows.add()
    flow.name = device_names_to_flow_name(src_dev_name, dst_dev_name)
    flow.tx_rx.device.tx_names = [device_name_to_ipv4_name(src_dev_name)]
    flow.tx_rx.device.rx_names = [device_name_to_ipv4_name(dst_dev_name)]
    flow.size.fixed = 1024
    flow.rate.percentage = 10
    flow.duration.fixed_packets.packets = PATH_DETECTION_COUNT

    # IP settings
    eth, ipv4 = flow.packet.ethernet().ipv4()
    # RAW mode does not work, probably a snappi/ixia API shortcoming
    ipv4.priority.choice = ipv4.priority.DSCP
    ipv4.priority.dscp.phb.values = [3]
    ipv4.priority.dscp.ecn.value = ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
    return flow


def start_protocols(snappi_api):
    # Start protocols
    if "control_state" in dir(snappi_api):
        cs = snappi_api.control_state()
        cs.protocol.all.set(cs.protocol.all.START)
        snappi_api.set_control_state(cs)
    else:
        ps = snappi_api.protocol_state()
        ps.state = ps.START
        snappi_api.set_protocol_state(ps)


def start_stop_traffic(snappi_api, start_or_stop : bool, flow_names=[]):
    # Starting traffic auto-applies it
    pytest_assert(isinstance(flow_names, list), "Snappi requires a list of flow names")
    if "control_state" in dir(snappi_api):
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.flow_names = flow_names
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START if start_or_stop else cs.traffic.flow_transmit.STOP
        snappi_api.set_control_state(cs)
    else:
        ts = snappi_api.transmit_state()
        ts.flow_names = flow_names
        ts.state = ts.START if start_or_stop else ts.STOP
        snappi_api.set_transmit_state(ts)


def start_traffic(snappi_api, flow_names=[]):
    start_stop_traffic(snappi_api, True, flow_names)


def stop_traffic(snappi_api, flow_names=[]):
    start_stop_traffic(snappi_api, False, flow_names)


def validate_snappi_device_state(snappi_api, get_snappi_ports):
    # Grab all metrics
    req = snappi_api.metrics_request()
    metrics = snappi_api.get_metrics(req)

    # Validate ports up
    pytest_assert_eq(len(metrics.port_metrics), len(get_snappi_ports), "Unexpected number of ports in metrics response")
    for pm in metrics.port_metrics:
        pytest_assert_eq(pm.link.lower(), LINK_UP, "Link not up on port {}".format(pm.name))
        logger.info("Validated link up for port {}".format(pm.name))

    # Validate IPv4 neighbor/gateway resolved
    states_req = snappi_api.states_request()
    states_resp = snappi_api.get_states(states_req)
    pytest_assert_eq(len(states_resp.ipv4_neighbors), len(DEVICE_CONFIGS))
    for neigh in states_resp.ipv4_neighbors:
        pytest_assert(neigh.link_layer_address is not None,
                      "Failed to resolve IP gateway {} on ethernet {}".format(neigh.ipv4_address, neigh.ethernet_name))
        logger.info("Resolved IPv4 gateway address {} on ethernet {} has mac {}".format(
            neigh.ipv4_address, neigh.ethernet_name, neigh.link_layer_address))


def create_devices(snappi_api, config, port_configs, device_configs : dict, snappi_devices : dict):
    # Global options
    config.options.port_options.location_preemption = True  # Forcefully take ports.
    # Order all ports by ID
    for snappi_port_dct in port_configs:
        # Create the port
        port_id = snappi_port_dct['port_id']
        location = snappi_port_dct['location']
        port_name = "Port {}".format(port_id)
        snappi_port_dct['port_name'] = port_name # Store for later
        port = config.ports.add()
        port.name = port_name
        port.location = location
        # L1 settings
        speed_mbps = snappi_port_dct['speed']
        speed_gbps = int(int(speed_mbps) / 1000)
        # TODO: Where does the other name show up? Need to be unique for any reason?
        l1_config = config.layer1.add()
        port_names = [port_name]
        l1_config.port_names = port_names
        logger.info("Adding L1 config for ports: {}".format(port_names))
        l1_config.name = 'L1 config {}'.format(";".join(port_names))
        l1_config.speed = "speed_{}_gbps".format(speed_gbps)
        l1_config.ieee_media_defaults = False
        l1_config.auto_negotiate = False
        l1_config.auto_negotiation.link_training = False
        l1_config.auto_negotiation.rs_fec = True

    # Device config
    for device_config in device_configs:
        device = add_device(config, **device_config)
        snappi_devices[device_config['name']] = device


def to_hostport(hostname, port):
    return "{}:{}".format(hostname, port)


def expand_hostport(hostport):
    return hostport.split(":")


def find_hostport(device_name, get_snappi_ports):
    port_id = None
    for dev_config in DEVICE_CONFIGS:
        if dev_config['name'] == device_name:
            port_id = dev_config['port_id']
            break
    pytest_assert(port_id is not None, "Device config not found for device {}".format(device_name))
    hostport = None
    for port in get_snappi_ports:
        if int(port['port_id']) == port_id:
            hostport = to_hostport(port['peer_device'], port['peer_port'])
            break
    pytest_assert(hostport is not None, "Hostport not found for device {} port ID {}".format(device_name, port_id))
    return hostport


def sanitize_flow_stats(delta_int_stats, non_trivial_count_threshold):
    """
    If the flow(s) is working correctly with no drops, then all RX counters must be equal
    to TX counters across all DUTs. This provides some initial sanity before proceeding to
    more advanced testing.
    """
    pytest_assert(non_trivial_count_threshold >= 1000,
                  "Flow traversal RX=TX sanitization cannot be done with small packet count {}".format(non_trivial_count_threshold))
    for hostname in delta_int_stats:
        rx_total = 0
        tx_total = 0
        for port in delta_int_stats[hostname]:
            rx_total += delta_int_stats[hostname][port]['rx_ok']
            tx_total += delta_int_stats[hostname][port]['tx_ok']
        if rx_total < non_trivial_count_threshold and tx_total < non_trivial_count_threshold:
            # Ignore check for small counts
            continue
        pytest_assert(is_margin_eq(tx_total, rx_total, SANITIZATION_MARGIN_PERCENT),
                      "DUT {} received {} packets but transmitted {}".format(hostname, rx_total, tx_total))


def pathfinder(src_dev_name, dst_dev_name, delta_int_stats, get_snappi_ports, conn_graph_facts):
    """
    Takes the counters returned from compare_interface_stats to identify the packet path.
    One purpose of this is for validation, but it can also play a significantly beneficial
    role in debugging efforts.
    """
    src_hostport = find_hostport(src_dev_name, get_snappi_ports)
    dst_hostport = find_hostport(dst_dev_name, get_snappi_ports)
    rx_hostports = []
    tx_hostports = []
    intf_to_peer_map = {}
    intf_traversed = {}
    for hostname in delta_int_stats:
        # Inter-DUT link construction
        for port in conn_graph_facts['device_conn'][hostname]:
            # TODO: Better check for ixia device
            peer_hostname = conn_graph_facts['device_conn'][hostname][port]['peerdevice']
            peer_port = conn_graph_facts['device_conn'][hostname][port]['peerport']
            # Bidirectional lookup link
            for host in [hostname, peer_hostname]:
                if host not in intf_to_peer_map:
                    intf_to_peer_map[host] = {}
            intf_to_peer_map[hostname][port] = (peer_hostname, peer_port)
            intf_to_peer_map[peer_hostname][peer_port] = (hostname, port)
        # Stat occurrence mapping
        intf_traversed[hostname] = {'rx_ports': {},
                                    'tx_ports': {}}
        for port in delta_int_stats[hostname]:
            rx_ok = delta_int_stats[hostname][port]['rx_ok']
            tx_ok = delta_int_stats[hostname][port]['tx_ok']
            if is_margin_eq(rx_ok, PATH_DETECTION_COUNT, PATH_DETECTION_MARGIN_PERCENT):
                intf_traversed[hostname]['rx_ports'][port] = False
                hostport = to_hostport(hostname, port)  #TODO RM
                rx_hostports.append(hostport)
            if is_margin_eq(tx_ok, PATH_DETECTION_COUNT, PATH_DETECTION_MARGIN_PERCENT):
                intf_traversed[hostname]['tx_ports'][port] = False
                hostport = to_hostport(hostname, port)
                tx_hostports.append(hostport)
    # Validate source is present to start pathfinding
    pytest_assert(src_hostport in rx_hostports, "Flow source port was not received on the appropriate hostport {}".format(src_hostport))
    pytest_assert_eq(len(rx_hostports), len(tx_hostports), "There should be the same number of TX and RX ports")
    pytest_assert(len(rx_hostports) > 0, "No port stat traversal found")
    stat_ports_traversed = len(rx_hostports) + len(tx_hostports)
    # Visit first node
    paths = []
    def rover(curr_path, curr_host, curr_rx_port):
        if len(curr_path) > 0 and len(curr_path) == stat_ports_traversed:
            # All stats on DUTs accounted for, report the path
            paths.append(list(curr_path))
            return
        if curr_host not in intf_traversed:
            # No stat available for traversal, this is likely an Ixia port, failed to
            # properly use all stats on this path, return.
            return
        pytest_assert(curr_rx_port in intf_traversed[curr_host]['rx_ports'])
        pytest_assert(not intf_traversed[curr_host]['rx_ports'][curr_rx_port])
        intf_traversed[curr_host]['rx_ports'][curr_rx_port] = True
        curr_path.append(to_hostport(curr_host, curr_rx_port))
        for tx_port in intf_traversed[curr_host]['tx_ports']:
            traversed = intf_traversed[curr_host]['tx_ports'][tx_port]
            if not traversed:
                # Traverse this TX
                intf_traversed[curr_host]['tx_ports'][tx_port] = True
                curr_path.append(to_hostport(curr_host, tx_port))
                # Attempt to find a path from the new host
                pytest_assert(curr_host in intf_to_peer_map,
                              "Host {} not defined in device inter-links".format(curr_host))
                pytest_assert(tx_port in intf_to_peer_map[curr_host],
                              "Host {} port {} does not have a link mapping definition in sonic lab links".format(curr_host, tx_port))
                new_host, rx_port = intf_to_peer_map[curr_host][tx_port]
                rover(curr_path, new_host, rx_port)
                # Revert traversal of TX
                pytest_assert_eq(curr_path.pop(), to_hostport(curr_host, tx_port),
                                 "Current trailing TX path node unexpected")
                intf_traversed[curr_host]['tx_ports'][tx_port] = False
        # Revert traversal of RX
        pytest_assert_eq(curr_path.pop(), to_hostport(curr_host, curr_rx_port),
                         "Current trailing RX path node unexpected")
        intf_traversed[curr_host]['rx_ports'][curr_rx_port] = False
    src_host, src_port = expand_hostport(src_hostport)
    rover([], src_host, src_port)
    pytest_assert(len(paths) > 0,
                  "Failed to find a path from snappi device {} to {} " +
                  "given stats indicating RX ports {} and TX ports {}".format(
                      src_dev_name, dst_dev_name, rx_hostports, tx_hostports))
    if len(paths) > 1:
        logger.warning("Unexpectedly was able to find another possible path for this flow, " +
                       "path detection and usage may be errant. Returning first path.")
    # After pathfinding, validate destination. If destination fails, report the actual path taken.
    pytest_assert(dst_hostport in tx_hostports,
                  "Flow dest port was not transmitted from the appropriate hostport {}, actual path {}".format(dst_hostport, paths[0]))
    return paths[0]


def add_bb_flow(snappi_api, config, get_snappi_ports, conn_graph_facts, duthosts, src_dev_name, dst_dev_name):
    """
    Advanced BB flow detection routine.
    Identifies flow path and customizes the flow to take a BounceBack path rather than straight-through.
    Assumes that the specified src and dst port IDs are correctly configured with the peer ToR in the correct
    standby mux state to cause a BounceBack to be needed.
    """
    # Create a new flow and explicitly set some important parameters
    flow = add_flow(config, src_dev_name, dst_dev_name)
    flow.size.fixed = 1024
    flow.rate.percentage = 10
    flow.duration.fixed_packets.packets = PATH_DETECTION_COUNT


    snappi_api.set_config(config)
    start_protocols(snappi_api)
    time.sleep(5)
    MAX_BB_FLOW_ATTEMPTS = 20
    success = False
    num_attempts = 0 # flow above counts as first attempt
    while not success and num_attempts < MAX_BB_FLOW_ATTEMPTS:
        int_stats_old = get_interface_stats_from_duthosts(duthosts)
        start_traffic(snappi_api, [flow.name])
        time.sleep(10) # TODO: Detect traffic termination
        int_stats_new = get_interface_stats_from_duthosts(duthosts)
        delta = compare_interface_stats(int_stats_old, int_stats_new)
        sanitize_flow_stats(delta, PATH_DETECTION_COUNT)
        path = pathfinder(src_dev_name, dst_dev_name, delta, get_snappi_ports, conn_graph_facts)
        if len(path) == BOUNCE_BACK_PATH_LENGTH:
            logger.info("Constructed flow with BounceBack path {}".format(path))
            success = True
        elif len(path) == STRAIGHT_THROUGH_PATH_LENGTH:
            # TODO: Can't increment device addr, that'll break the other flow. Need to change just the flow. Probably need a UDP port.
            # Increment source IP addr on the snappi/ixia device to cycle the hash on T1
            src_dev = get_device(src_dev_name)
            pytest_assert_eq(len(src_dev.ethernets), 1,
                             "BB flow detection requires a single ethernet ({})".format(len(src_dev.ethernets)))
            eth = src_dev.ethernets[0]
            pytest_assert_eq(len(eth.ipv4_addresses), 1,
                             "BB flow detection requires a single IPV4 ({})".format(
                                 len(src_dev.ethernets[0].ipv4_addresses)))
            ipv4 = eth.ipv4_addresses[0]
            # TODO: Improve prefix check
            pytest_assert(ipv4.prefix <= 24, "IPV4 addr prefix {} too large to increment IP addr".format(ipv4.prefix))
            new_ip_addr = inc_ip_address(ipv4.address)
            logger.info("Flow has been identified as StraightThrough, " +
                        "reconfiguring device source IP from {} to {}".format(ipv4.address, new_ip_addr))
            ipv4.address = new_ip_addr
            snappi_api.set_config(config)
            start_protocols(snappi_api)
            time.sleep(5)
            validate_snappi_device_state(snappi_api, get_snappi_ports)
        else:
            pytest_assert(False, "Invalid path length {} detected, path taken for flow: {}".format(len(path), path))
    pytest_assert(success, "Failed to find a bounce-back path")
    return flow


@pytest.mark.parametrize("pcbb", [True, False])
def test_deadlock(snappi_api,                   # noqa: F811
                  conn_graph_facts,             # noqa: F811
                  duthosts,
                  prio_dscp_map,                # noqa: F811
                  lossless_prio_list,           # noqa: F811
                  lossy_prio_list,              # noqa: F811
                  tbinfo,
                  get_snappi_ports,             # noqa: F811
                  disable_pfcwd,                # noqa: F811
                  pcbb,
                  on_test_end_enable_tunnel_qos_remap):
    """
    TODO

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list(list): list of lossless priorities
        lossy_prio_list(list): list of lossy priorities.
        tbinfo(key): element to identify testbed info name.
        get_snappi_ports(pytest fixture): returns list of ports based on linecards selected.
        disable_pfcwd(pytest fixture): function scope pytest fixture
    Returns:
        N/A

    """

    # Enable or disable PCBB
    set_tunnel_qos_remap_multidut(duthosts, pcbb)

    # Validate MUX state
    # TODO

    # Validate PFC counters are not incrementing. If fails, one example reason would be
    # that the disable_pfcwd isn't cycling on a function scope.
    pfc_counters_old = get_pfc_counters_multihost(duthosts)
    time.sleep(5)
    pfc_counters_new = get_pfc_counters_multihost(duthosts)
    pfc_delta = compare_pfc_counters(pfc_counters_old, pfc_counters_new)
    non_zero_pfc_locs = flatten_pfc_counts(pfc_delta)
    if len(non_zero_pfc_locs) > 0:
        msg = "On test start, found an apparent PFC-deadlock:\n"
        for hostname, cntr_type, port, prio, delta in non_zero_pfc_locs:
            msg += "Host {} has {} PFC{} on port {} (count = {})\n".format(hostname, cntr_type, prio, port, delta)
    else:
        msg = "No PFC counts detected on any ports"
    logger.info(msg)
    # Note: If this is failing, one possible suspect is the disable_pfcwd function.  This
    # needs to be run after every test parametrization in order to clear out
    # deadlock. This does depend on the order of the parametrization execution (PCBB or
    # non-PCBB first).
    # A second option is PCBB thinks it's enabled, but is improperly deployed. Do a "show
    # pfc prio" on each DUT and validate PFC priorities have 2,3,4,6 in some locations and
    # not others.
    pytest_assert_eq(len(non_zero_pfc_locs), 0, msg)

    # Validate port speeds are satisfactory for deadlock
    # TODO: Revise the deadlock technique to no longer require oversubscription via port
    # speed, use a second port.
    t1_port_speeds = []
    t0_port_speeds = []
    for snappi_port in get_snappi_ports:
        if 't1' in snappi_port['peer_device'].lower():
            t1_port_speeds.append(int(snappi_port['speed']))
        elif 't0' in snappi_port['peer_device'].lower():
            t0_port_speeds.append(int(snappi_port['speed']))
    pytest_assert_eq(len(set(t0_port_speeds)), 1, "All t0 port speeds facing ixia should match")
    t0_speed = t0_port_speeds[0]
    pytest_assert_eq(len(set(t1_port_speeds)), 1, "All t1 port speeds facing ixia should match")
    t1_speed = t1_port_speeds[0]
    pytest_assert(t0_speed < t1_speed,
                  "T0 port speeds ({}) must be less than T1 port speeds for snappi " +
                  "facing ports to induce oversubscription".format(t0_speed, t1_speed))
    # Total bandwidth of both flows must exceed T0 port speed, but must individually not
    # exceed it. Choose 75% of the T0 port speed.
    flow_rate_from_t1 = 75 * (float(t0_speed) / t1_speed)
    logger.info("Choosing T1 flow rate percentage {}%".format(flow_rate_from_t1))

    # Construct snappi config
    config = snappi_api.config()
    create_devices(snappi_api, config, get_snappi_ports, DEVICE_CONFIGS, SNAPPI_DEVICES)
    snappi_api.set_config(config)
    start_protocols(snappi_api)
    time.sleep(5) # TODO: Analyze whether sleeps are needed here and elsewhere
    validate_snappi_device_state(snappi_api, get_snappi_ports)

    # Define custom test flows
    t1_upper_bounce_to_lower_flow = add_bb_flow(snappi_api, config, get_snappi_ports, conn_graph_facts, duthosts,
                                                'Device to T1 E224', 'Device on Port 3.1 to LT0:E240')
    t1_lower_bounce_to_upper_flow = add_bb_flow(snappi_api, config, get_snappi_ports, conn_graph_facts, duthosts,
                                                'Device to T1 E224', 'Device on Port 3.4 to T0:E224')

    # Customize flow to the rate required to cause a deadlock
    logger.info("Setting flow rates to {}% for {} seconds".format(flow_rate_from_t1, DEADLOCK_ATTEMPT_FLOW_SEC))
    for flow in [t1_upper_bounce_to_lower_flow, t1_lower_bounce_to_upper_flow]:
        flow.rate.percentage = flow_rate_from_t1
        flow.duration.fixed_seconds.seconds = DEADLOCK_ATTEMPT_FLOW_SEC

    # Push config change
    snappi_api.set_config(config)

    pfc_counters_old = get_pfc_counters_multihost(duthosts)

    # Start all traffic to attempt a deadlock
    start_traffic(snappi_api)
    time.sleep(DEADLOCK_ATTEMPT_FLOW_SEC + 5)

    # Validate PFC counters have increased due to oversubscription
    pfc_counters_new = get_pfc_counters_multihost(duthosts)
    pfc_delta = compare_pfc_counters(pfc_counters_old, pfc_counters_new)
    logger.info("After deadlock oversubscription, analyzing PFC count changes:")
    non_zero_pfc_locs = flatten_pfc_counts(pfc_delta)
    cnt_ports_with_pfc = {'tx': 0, 'rx': 0}
    for hostname, cntr_type, port, prio, delta in non_zero_pfc_locs:
        logger.info("  PFC {} prio {} count on host {} port {} increased by {}".format(
            cntr_type, prio, hostname, port, delta))
        cnt_ports_with_pfc[cntr_type] += 1
    # During a deadlock attempt, a sizeable minimum number of ports should be transmitting
    # and receiving PFC. If few ports are transmitting, the attempt is not well-designed
    # to maximize chance of deadlock. The deadlock repro parametrization (pcbb=False)
    # should ensure the attempt is good, but there may be a regression in the PCBB-enabled
    # run.
    #
    # Note: If fails on only the pcbb=False parametrization, it's very likely there's a
    # problem with the sonic-buildimage qos_config.j2 or the platform/hwsku's qos j2
    # file. The maps need to be configured properly.
    for cntr_type in cnt_ports_with_pfc:
        pytest_assert(cnt_ports_with_pfc[cntr_type] >= DEADLOCK_MIN_PORTS_INVOLVED,
                      "DUT must start {} PFC in at least {} locations to create a deadlock".format(
                          cntr_type, DEADLOCK_MIN_PORTS_INVOLVED))

    # Gather PFC deadlock information
    pfc_counters_old = pfc_counters_new
    time.sleep(5)
    pfc_counters_new = get_pfc_counters_multihost(duthosts)
    pfc_delta = compare_pfc_counters(pfc_counters_old, pfc_counters_new)
    non_zero_pfc_locs = flatten_pfc_counts(pfc_delta)
    if len(non_zero_pfc_locs) > 0:
        msg = "Found PFC deadlock on the following hosts/cntr_type/ports/priorities:\n"
        for hostname, cntr_type, port, prio, delta in non_zero_pfc_locs:
            msg += "Host {} has {} PFC{} on port {} (count = {})\n".format(hostname, cntr_type, prio, port, delta)
    else:
        msg = "No PFC deadlock detected on any ports"

    # Validate deadlock is reproduced if-and-only-if pcbb is deactivated
    logger.info(msg)
    deadlock_detected = len(non_zero_pfc_locs) != 0
    if pcbb:
        pytest_assert(not deadlock_detected, msg)
    else:
        pytest_assert(deadlock_detected, msg)

    # TODO: Validate DUT mux port state is correct
    # TODO: Validate correct queue is being taken for flow

    # Teardown
    # import pdb; pdb.set_trace()
    # snappi_api.assistant.Session.remove()
