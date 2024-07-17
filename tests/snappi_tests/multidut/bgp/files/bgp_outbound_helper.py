import logging
import random
import paramiko
import json
import time
from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)  # noqa: F401
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import create_ip_list  # noqa: F401
from tests.snappi_tests.variables import T1_SNAPPI_AS_NUM, T2_SNAPPI_AS_NUM, T1_DUT_AS_NUM, T2_DUT_AS_NUM, t1_ports, \
     t2_uplink_portchannel_members, t1_t2_dut_ipv4_list, v4_prefix_length, v6_prefix_length, \
     t1_t2_dut_ipv6_list, t1_t2_snappi_ipv4_list, \
     t1_t2_snappi_ipv6_list, t2_dut_portchannel_ipv4_list, t2_dut_portchannel_ipv6_list, \
     snappi_portchannel_ipv4_list, snappi_portchannel_ipv6_list, AS_PATHS, \
     BGP_TYPE, TIMEOUT, t1_side_interconnected_port, t2_side_interconnected_port  # noqa: F401

logger = logging.getLogger(__name__)
total_routes = 0


def run_bgp_outbound_service_restart_test(api,
                                          traffic_type,
                                          snappi_extra_params):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        traffic_type : IPv4 or IPv6 traffic choice
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    duthosts = [duthost1, duthost2, duthost3]
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    service_names = snappi_extra_params.multi_dut_params.service_names
    host_name = snappi_extra_params.multi_dut_params.host_name
    iteration = snappi_extra_params.iteration

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    """ Create snappi config """
    for route_range in route_ranges:
        snappi_bgp_config = __snappi_bgp_config(api,
                                                duthosts,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_service_flap(duthosts,
                                         api,
                                         snappi_bgp_config,
                                         traffic_type,
                                         iteration,
                                         service_names,
                                         host_name,
                                         route_range)


def run_bgp_outbound_link_flap_test(api,
                                    traffic_type,
                                    snappi_extra_params):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        traffic_type : IPv4 or IPv6 traffic choice
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """

    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    duthosts = [duthost1, duthost2, duthost3]
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    iteration = snappi_extra_params.iteration
    flap_event = snappi_extra_params.multi_dut_params.flap_event

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports)

    """ Create snappi config """
    for route_range in route_ranges:
        snappi_bgp_config = __snappi_bgp_config(api,
                                                duthosts,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_link_flap(duthosts,
                                      api,
                                      snappi_bgp_config,
                                      flap_event,
                                      traffic_type,
                                      iteration,
                                      route_range)


def duthost_bgp_config(duthosts,
                       snappi_ports):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthosts (pytest fixture): duthosts fixture
        snappi_ports (pytest fixture): Ports mapping info of T0 testbed
    """
    logger.info('--------------- T1 Snappi Section --------------------')
    t1_config_db = json.loads(duthosts[0].shell("sonic-cfggen -d --print-data")['stdout'])
    interfaces = dict()
    loopback_interfaces = dict()
    loopback_interfaces.update({"Loopback0": {}})
    loopback_interfaces.update({"Loopback0|1.1.1.1/32": {}})
    loopback_interfaces.update({"Loopback0|1::1/128": {}})
    for index, custom_port in enumerate(t1_ports[duthosts[0].hostname]):
        interface_name = {custom_port: {}}
        v4_interface = {f"{custom_port}|{t1_t2_dut_ipv4_list[index]}/{v4_prefix_length}": {}}
        v6_interface = {f"{custom_port}|{t1_t2_dut_ipv6_list[index]}/{v6_prefix_length}": {}}
        interfaces.update(interface_name)
        interfaces.update(v4_interface)
        interfaces.update(v6_interface)
        logger.info('Configuring IPs {} / {} on {} in {}'.
                    format(t1_t2_dut_ipv4_list[index],
                           t1_t2_dut_ipv6_list[index], custom_port, duthosts[0].hostname))

    bgp_neighbors = dict()
    device_neighbors = dict()
    device_neighbor_metadatas = dict()
    for index, custom_port in enumerate(t1_ports[duthosts[0].hostname]):
        for snappi_port in snappi_ports:
            if custom_port == snappi_port['peer_port'] and snappi_port['peer_device'] == duthosts[0].hostname:
                bgp_neighbor = \
                        {
                            t1_t2_snappi_ipv4_list[index]:
                            {
                                "admin_status": "up",
                                "asn": T1_SNAPPI_AS_NUM,
                                "holdtime": "10",
                                "keepalive": "3",
                                "local_addr": t1_t2_dut_ipv4_list[index],
                                "name": "snappi-sonic",
                                "nhopself": "0",
                                "rrclient": "0"
                            },
                            t1_t2_snappi_ipv6_list[index]:
                            {
                                "admin_status": "up",
                                "asn": T1_SNAPPI_AS_NUM,
                                "holdtime": "10",
                                "keepalive": "3",
                                "local_addr": t1_t2_dut_ipv6_list[index],
                                "name": "snappi-sonic",
                                "nhopself": "0",
                                "rrclient": "0"
                            },
                        }
                bgp_neighbors.update(bgp_neighbor)
                device_neighbor = {
                                            custom_port:
                                            {
                                                "name": "snappi-sonic"+str(index),
                                                "port": "Ethernet1"
                                            }
                                        }
                device_neighbors.update(device_neighbor)
                device_neighbor_metadata = {
                                                "snappi-sonic"+str(index):
                                                {
                                                    "hwsku": "Snappi",
                                                    "mgmt_addr": "172.16.149.206",
                                                    "type": "ToRRouter"
                                                }
                                            }
                device_neighbor_metadatas.update(device_neighbor_metadata)
    logger.info('T1 Dut AS Number: {}'.format(T1_DUT_AS_NUM))
    logger.info('T1 side Snappi AS Number: {}'.format(T1_SNAPPI_AS_NUM))
    logger.info('\n')
    logger.info('---------------T1 Inter-Connectivity Section --------------------')
    logger.info('\n')
    index = len(t1_ports[duthosts[0].hostname])
    interface_name = {t1_side_interconnected_port: {}}
    v4_interface = {f"{t1_side_interconnected_port}|{t1_t2_dut_ipv4_list[index]}/{v4_prefix_length}": {}}
    v6_interface = {f"{t1_side_interconnected_port}|{t1_t2_dut_ipv6_list[index]}/{v6_prefix_length}": {}}
    interfaces.update(interface_name)
    interfaces.update(v4_interface)
    interfaces.update(v6_interface)
    logger.info('Configuring IP {} / {} on {} in {} for the T1 interconnectivity'.
                format(t1_t2_dut_ipv4_list[index],
                       t1_t2_dut_ipv6_list[index], t1_side_interconnected_port, duthosts[0].hostname))

    logger.info('Configuring BGP in T1 by writing into config_db')
    bgp_neighbor = {
                        t1_t2_snappi_ipv4_list[index]:
                        {
                            "admin_status": "up",
                            "asn": T2_DUT_AS_NUM,
                            "holdtime": "10",
                            "keepalive": "3",
                            "local_addr": t1_t2_dut_ipv4_list[index],
                            "name": "T2",
                            "nhopself": "0",
                            "rrclient": "0"
                        },
                        t1_t2_snappi_ipv6_list[index]:
                        {
                            "admin_status": "up",
                            "asn": T2_DUT_AS_NUM,
                            "holdtime": "10",
                            "keepalive": "3",
                            "local_addr": t1_t2_dut_ipv6_list[index],
                            "name": "T2",
                            "nhopself": "0",
                            "rrclient": "0"
                        },
                    }
    bgp_neighbors.update(bgp_neighbor)
    device_neighbor = {
                                t1_side_interconnected_port:
                                {
                                    "name": "T2",
                                    "port": "Ethernet1"
                                }
                            }
    device_neighbors.update(device_neighbor)
    device_neighbor_metadata = {
                                    "T2":
                                    {
                                        "hwsku": "Sonic-Dut",
                                        "mgmt_addr": "172.16.149.206",
                                        "type": "SpineRouter"
                                    }
                                }
    device_neighbor_metadatas.update(device_neighbor_metadata)
    if "INTERFACE" not in t1_config_db.keys():
        t1_config_db["INTERFACE"] = interfaces
    else:
        t1_config_db["INTERFACE"].update(interfaces)

    if "LOOPBACK_INTERFACE" not in t1_config_db.keys():
        t1_config_db["LOOPBACK_INTERFACE"] = loopback_interfaces
    else:
        t1_config_db["LOOPBACK_INTERFACE"].update(loopback_interfaces)

    if "BGP_NEIGHBOR" not in t1_config_db.keys():
        t1_config_db["BGP_NEIGHBOR"] = bgp_neighbors
    else:
        t1_config_db["BGP_NEIGHBOR"].update(bgp_neighbors)

    if "DEVICE_NEIGHBOR" not in t1_config_db.keys():
        t1_config_db["DEVICE_NEIGHBOR"] = device_neighbors
    else:
        t1_config_db["DEVICE_NEIGHBOR"].update(device_neighbors)

    if 'DEVICE_NEIGHBOR_METADATA' not in t1_config_db.keys():
        t1_config_db["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadatas
    else:
        t1_config_db["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadatas)

    with open("/tmp/temp_config.json", 'w') as fp:
        json.dump(t1_config_db, fp, indent=4)
    duthosts[0].copy(src="/tmp/temp_config.json", dest="/etc/sonic/config_db.json")

    logger.info('Reloading config_db.json to apply IP and BGP configuration on {}'.format(duthosts[0].hostname))
    pytest_assert('Error' not in duthosts[0].shell("sudo config reload -f -y \n")['stderr'],
                  'Error while reloading config in {} !!!!!'.format(duthosts[0].hostname))
    logger.info('Config Reload Successful in {} !!!'.format(duthosts[0].hostname))

    logger.info('\n')
    logger.info('---------------T2 Downlink Inter-Connectivity Section --------------------')
    logger.info('\n')
    logger.info('T1 Dut AS Number: {}'.format(T1_DUT_AS_NUM))
    logger.info('T2 Dut AS Number: {}'.format(T2_DUT_AS_NUM))

    interfaces = dict()
    loopback_interfaces = dict()
    loopback_interfaces.update({"Loopback0": {}})
    loopback_interfaces.update({"Loopback0|2.2.2.2/32": {}})
    loopback_interfaces.update({"Loopback0|2::2/128": {}})
    index = len(t1_ports[duthosts[0].hostname])
    interface_name = {t2_side_interconnected_port['port_name']: {}}
    v4_interface = {
                    f"{t2_side_interconnected_port['port_name']}|{t1_t2_snappi_ipv4_list[index]}/{v4_prefix_length}": {}
                }
    v6_interface = {
                    f"{t2_side_interconnected_port['port_name']}|{t1_t2_snappi_ipv6_list[index]}/{v6_prefix_length}": {}
                }
    interfaces.update(interface_name)
    interfaces.update(v4_interface)
    interfaces.update(v6_interface)
    device_neighbor = {
                            t2_side_interconnected_port['port_name']:
                            {
                                "name": "T1",
                                "port": "Ethernet1"
                            }
                        }

    device_neighbor_metadata = {
                                    "T1":
                                    {
                                        "hwsku": "Sonic-Dut",
                                        "mgmt_addr": t1_t2_dut_ipv4_list[index],
                                        "type": "LeafRouter"
                                    }
                                }
    bgp_neighbor = {
                        t1_t2_dut_ipv4_list[index]:
                        {
                            "admin_status": "up",
                            "asn": T1_DUT_AS_NUM,
                            "holdtime": "10",
                            "keepalive": "3",
                            "local_addr": t1_t2_snappi_ipv4_list[index],
                            "name": "T1",
                            "nhopself": "0",
                            "rrclient": "0"
                        },
                        t1_t2_dut_ipv6_list[index]:
                        {
                            "admin_status": "up",
                            "asn": T1_DUT_AS_NUM,
                            "holdtime": "10",
                            "keepalive": "3",
                            "local_addr": t1_t2_snappi_ipv6_list[index],
                            "name": "T1",
                            "nhopself": "0",
                            "rrclient": "0"
                        },
                    }

    if t2_side_interconnected_port['asic_value'] is not None:
        config_db = 'config_db'+list(t2_side_interconnected_port['asic_value'])[-1]+'.json'
        t2_config_db = json.loads(duthosts[2].shell("sonic-cfggen -d -n {} --print-data".
                                  format(t2_side_interconnected_port['asic_value']))['stdout'])
    else:
        config_db = 'config_db.json'
        t2_config_db = json.loads(duthosts[2].shell("sonic-cfggen -d --print-data")['stdout'])

    if "INTERFACE" not in t2_config_db.keys():
        t2_config_db["INTERFACE"] = interfaces
    else:
        t2_config_db["INTERFACE"].update(interfaces)

    if "LOOPBACK_INTERFACE" not in t2_config_db.keys():
        t2_config_db["LOOPBACK_INTERFACE"] = loopback_interfaces
    else:
        t2_config_db["LOOPBACK_INTERFACE"].update(loopback_interfaces)

    if "DEVICE_NEIGHBOR" not in t2_config_db.keys():
        t2_config_db["DEVICE_NEIGHBOR"] = device_neighbor
    else:
        t2_config_db["DEVICE_NEIGHBOR"].update(device_neighbor)

    if 'DEVICE_NEIGHBOR_METADATA' not in t2_config_db.keys():
        t2_config_db["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadata
    else:
        t2_config_db["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadata)

    if "BGP_NEIGHBOR" not in t2_config_db.keys():
        t2_config_db["BGP_NEIGHBOR"] = bgp_neighbor
    else:
        t2_config_db["BGP_NEIGHBOR"].update(bgp_neighbor)

    with open("/tmp/temp_config.json", 'w') as fp:
        json.dump(t2_config_db, fp, indent=4)
    duthosts[2].copy(src="/tmp/temp_config.json", dest="/etc/sonic/%s" % config_db)

    logger.info('Reloading config_db.json to apply IP and BGP configuration on {}'.format(duthosts[2].hostname))

    pytest_assert('Error' not in duthosts[2].shell("sudo config reload -f -y \n")['stderr'],
                  'Error while reloading config in {} !!!!!'.format(duthosts[2].hostname))
    logger.info('Config Reload Successful in {} !!!'.format(duthosts[2].hostname))

    logger.info('--------------- T2 Uplink - Tgen Section --------------------')
    logger.info('T2 Dut AS Number: {}'.format(T2_DUT_AS_NUM))
    logger.info('T2 side Snappi AS Number: {}'.format(T2_SNAPPI_AS_NUM))
    loopback_interfaces = dict()
    loopback_interfaces.update({"Loopback0": {}})
    loopback_interfaces.update({"Loopback0|3.3.3.3/32": {}})
    loopback_interfaces.update({"Loopback0|3::3/128": {}})
    index = 0
    for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
        bgp_neighbors = dict()
        device_neighbors = dict()
        device_neighbor_metadatas = dict()
        PORTCHANNELS = dict()
        PORTCHANNEL_INTERFACES = dict()
        PORTCHANNEL_MEMBERS = dict()
        if asic_value is not None:
            config_db = 'config_db'+list(asic_value)[-1]+'.json'
            t2_config_db = json.loads(duthosts[1].shell("sonic-cfggen -d -n {} --print-data".
                                      format(asic_value))['stdout'])
        else:
            config_db = 'config_db.json'
            t2_config_db = json.loads(duthosts[1].shell("sonic-cfggen -d --print-data")['stdout'])
        for portchannel, port_set in portchannel_info.items():
            for port in port_set:
                device_neighbor = {
                    port: {
                        "name": "snappi_"+portchannel,
                        "port": "snappi_"+port,
                    }
                }
                device_neighbors.update(device_neighbor)
                MEMBER = {f"{portchannel}|{port}": {}}
                PORTCHANNEL_MEMBERS.update(MEMBER)
            PORTCHANNEL = {
                                portchannel:
                                {
                                    "admin_status": "up",
                                    "lacp_key": "auto",
                                    "min_links": "1",
                                    "mtu": "9100"
                                }
                          }
            PORTCHANNELS.update(PORTCHANNEL)
            logger.info('Creating {} in {}'.format(portchannel, duthosts[1].hostname))
            interface_name = {portchannel: {}}
            v4_interface = {f"{portchannel}|{t2_dut_portchannel_ipv4_list[index]}/{v4_prefix_length}": {}}
            v6_interface = {f"{portchannel}|{t2_dut_portchannel_ipv6_list[index]}/{v6_prefix_length}": {}}
            PORTCHANNEL_INTERFACES.update(interface_name)
            PORTCHANNEL_INTERFACES.update(v4_interface)
            PORTCHANNEL_INTERFACES.update(v6_interface)
            logger.info('Configuring IPs {} / {} on {} in {}'.
                        format(t2_dut_portchannel_ipv4_list[index],
                               t2_dut_portchannel_ipv6_list[index], portchannel, duthosts[1].hostname))
        for portchannel in portchannel_info:
            device_neighbor_metadata = {
                                            "snappi_"+portchannel:
                                            {
                                                "hwsku": "Ixia",
                                                "mgmt_addr": snappi_portchannel_ipv4_list[index],
                                                "type": "AZNGHub"
                                            },
                                        }
            bgp_neighbor = {
                                snappi_portchannel_ipv4_list[index]:
                                {
                                    "admin_status": "up",
                                    "asn": T2_SNAPPI_AS_NUM,
                                    "holdtime": "10",
                                    "keepalive": "3",
                                    "local_addr": t2_dut_portchannel_ipv4_list[index],
                                    "name": "snappi_"+portchannel,
                                    "nhopself": "0",
                                    "rrclient": "0"
                                },
                                snappi_portchannel_ipv6_list[index]:
                                {
                                    "admin_status": "up",
                                    "asn": T2_SNAPPI_AS_NUM,
                                    "holdtime": "10",
                                    "keepalive": "3",
                                    "local_addr": t2_dut_portchannel_ipv6_list[index],
                                    "name": "snappi_"+portchannel,
                                    "nhopself": "0",
                                    "rrclient": "0"
                                },
                            }
            bgp_neighbors.update(bgp_neighbor)
            device_neighbor_metadatas.update(device_neighbor_metadata)
            index = index + 1
        if "LOOPBACK_INTERFACE" not in t2_config_db.keys():
            t2_config_db["LOOPBACK_INTERFACE"] = loopback_interfaces
        else:
            t2_config_db["LOOPBACK_INTERFACE"].update(loopback_interfaces)

        if "PORTCHANNEL_INTERFACE" not in t2_config_db.keys():
            t2_config_db["PORTCHANNEL_INTERFACE"] = PORTCHANNEL_INTERFACES
        else:
            t2_config_db["PORTCHANNEL_INTERFACE"].update(PORTCHANNEL_INTERFACES)

        if "PORTCHANNEL" not in t2_config_db.keys():
            t2_config_db["PORTCHANNEL"] = PORTCHANNELS
        else:
            t2_config_db["PORTCHANNEL"].update(PORTCHANNELS)

        if "PORTCHANNEL_MEMBER" not in t2_config_db.keys():
            t2_config_db["PORTCHANNEL_MEMBER"] = PORTCHANNEL_MEMBERS
        else:
            t2_config_db["PORTCHANNEL_MEMBER"].update(PORTCHANNEL_MEMBERS)

        if "DEVICE_NEIGHBOR" not in t2_config_db.keys():
            t2_config_db["DEVICE_NEIGHBOR"] = device_neighbors
        else:
            t2_config_db["DEVICE_NEIGHBOR"].update(device_neighbors)

        if 'DEVICE_NEIGHBOR_METADATA' not in t2_config_db.keys():
            t2_config_db["DEVICE_NEIGHBOR_METADATA"] = device_neighbor_metadatas
        else:
            t2_config_db["DEVICE_NEIGHBOR_METADATA"].update(device_neighbor_metadatas)

        if "BGP_NEIGHBOR" not in t2_config_db.keys():
            t2_config_db["BGP_NEIGHBOR"] = bgp_neighbors
        else:
            t2_config_db["BGP_NEIGHBOR"].update(bgp_neighbors)
        with open("/tmp/temp_config.json", 'w') as fp:
            json.dump(t2_config_db, fp, indent=4)
        duthosts[1].copy(src="/tmp/temp_config.json", dest="/etc/sonic/%s" % config_db)

    logger.info('Reloading config to apply IP and BGP configuration on {}'.format(duthosts[1].hostname))
    pytest_assert('Error' not in duthosts[1].shell("sudo config reload -f -y \n")['stderr'],
                  'Error while reloading config in {} !!!!!'.format(duthosts[1].hostname))
    logger.info('Config Reload Successful in {} !!!'.format(duthosts[1].hostname))
    wait(120, "For configs to be loaded on the duts")


def generate_mac_address():
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def __snappi_bgp_config(api,
                        duthosts,
                        snappi_ports,
                        traffic_type,
                        route_range):
    """
    Creating  BGP config on TGEN

    Args:
        api (pytest fixture): snappi API
        duthosts: multipath + 1
        snappi_ports :  Number of IPv4/IPv6 Routes
        traffic_type: IPv4 or IPv6 routes
        route_range: speed of the port used for test
    """
    ipv4_src, ipv6_src = [], []
    ipv4_dest, ipv6_dest = [], []
    global total_routes
    total_routes = 0
    config = api.config()
    # get all the t1 and uplink ports from variables
    t1_variable_ports = t1_ports[duthosts[0].hostname]
    t2_variable_ports = []
    port_tuple = []
    for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
        for portchannel, ports in portchannel_info.items():
            port_tuple.append(ports)
            for port in ports:
                t2_variable_ports.append(port)

    snappi_t1_ports = []
    snappi_t2_ports = []
    for snappi_port in snappi_ports:
        for port in t1_variable_ports:
            if snappi_port['peer_device'] == duthosts[0].hostname and snappi_port['peer_port'] == port:
                snappi_t1_ports.append(snappi_port)
        for port in t2_variable_ports:
            if snappi_port['peer_device'] == duthosts[1].hostname and snappi_port['peer_port'] == port:
                snappi_t2_ports.append(snappi_port)
    # Adding Ports
    for index, snappi_test_port in enumerate(snappi_t1_ports):
        snappi_test_port['name'] = 'Test_Port_%d' % index
        config.ports.port(name='Test_Port_%d' % index, location=snappi_test_port['location'])
    for index, snappi_test_port in enumerate(snappi_t2_ports, len(snappi_t1_ports)):
        snappi_test_port['name'] = 'Test_Port_%d' % index
        config.ports.port(name='Test_Port_%d' % index, location=snappi_test_port['location'])

    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = snappi_ports[0]['speed']
    layer1.auto_negotiate = False

    temp = 0
    for lag_count, port_set in enumerate(port_tuple):
        lag = config.lags.lag(name="LAG %d" % lag_count)[-1]
        lag.protocol.lacp.actor_system_id = generate_mac_address()
        m = '0' + hex(lag_count % 15+1).split('0x')[1]

        for index, port in enumerate(port_set):
            n = '0'+hex(index % 15+1).split('0x')[1]
            for snappi_t2_port in snappi_t2_ports:
                if port == snappi_t2_port['peer_port']:
                    lp = lag.ports.port(port_name=snappi_t2_port['name'])[-1]
                    lp.ethernet.name = "Eth%d" % temp
                    lp.ethernet.mac = "00:%s:00:00:00:%s" % (n, m)
                    logger.info('\n')
                    temp += 1

        device = config.devices.device(name="T2 Device {}".format(lag_count))[-1]
        eth = device.ethernets.add()
        eth.port_name = lag.name
        eth.name = 'T2_Ethernet_%d' % lag_count
        eth.mac = "00:00:00:00:00:%s" % m

        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T2_IPv4_%d' % lag_count
        ipv4.address = snappi_portchannel_ipv4_list[lag_count]
        ipv4.gateway = t2_dut_portchannel_ipv4_list[lag_count]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T2_IPv6_%d' % lag_count
        ipv6.address = snappi_portchannel_ipv6_list[lag_count]
        ipv6.gateway = t2_dut_portchannel_ipv6_list[lag_count]
        ipv6.prefix = v6_prefix_length

        bgpv4 = device.bgp
        bgpv4.router_id = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv4_int = bgpv4.ipv4_interfaces.add()
        bgpv4_int.ipv4_name = ipv4.name
        bgpv4_peer = bgpv4_int.peers.add()
        bgpv4_peer.name = 'T2_BGP_%d' % lag_count
        bgpv4_peer.as_type = BGP_TYPE
        bgpv4_peer.peer_address = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv4_peer.as_number = int(T2_SNAPPI_AS_NUM)

        route_range1 = bgpv4_peer.v4_routes.add(name="T2_IPv4_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv4']):
            route_range1.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])

        ipv4_dest.append(route_range1.name)

        bgpv6 = device.bgp
        bgpv6.router_id = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv6_int = bgpv6.ipv6_interfaces.add()
        bgpv6_int.ipv6_name = ipv6.name
        bgpv6_peer = bgpv6_int.peers.add()
        bgpv6_peer.name = 'T2_BGP+_%d' % lag_count
        bgpv6_peer.as_type = BGP_TYPE
        bgpv6_peer.peer_address = t2_dut_portchannel_ipv6_list[lag_count]
        bgpv6_peer.as_number = int(T2_SNAPPI_AS_NUM)

        route_range2 = bgpv6_peer.v6_routes.add(name="T2_IPv6_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv6']):
            route_range2.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])

        ipv6_dest.append(route_range2.name)

    for index, port in enumerate(snappi_t1_ports):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        device = config.devices.device(name="T1 Device {}".format(index))[-1]
        eth = device.ethernets.add()
        eth.port_name = port['name']
        eth.name = 'T1_Ethernet_%d' % index
        eth.mac = "00:10:00:00:00:%s" % m
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T1_IPv4_%d' % index
        ipv4.address = t1_t2_snappi_ipv4_list[index]
        ipv4.gateway = t1_t2_dut_ipv4_list[index]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T1_IPv6_%d' % index
        ipv6.address = t1_t2_snappi_ipv6_list[index]
        ipv6.gateway = t1_t2_dut_ipv6_list[index]
        ipv6.prefix = v6_prefix_length
        ipv4_src.append(ipv4.name)
        ipv6_src.append(ipv6.name)

        if index != 0:
            bgpv4 = device.bgp
            bgpv4.router_id = t1_t2_snappi_ipv4_list[index]
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'T1_BGP_%d' % index
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = t1_t2_dut_ipv4_list[index]
            bgpv4_peer.as_number = int(T1_SNAPPI_AS_NUM)

            route_range1 = bgpv4_peer.v4_routes.add(name="T1_IPv4_Routes_%d" % (index))
            for route_index, routes in enumerate(route_range['IPv4']):
                route_range1.addresses.add(
                    address=routes[0], prefix=routes[1], count=routes[2])
            ipv4_dest.append(route_range1.name)
            as_path = route_range1.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = AS_PATHS

            bgpv6 = device.bgp
            bgpv6.router_id = t1_t2_snappi_ipv4_list[index]
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'T1_BGP+_%d' % index
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = t1_t2_dut_ipv6_list[index]
            bgpv6_peer.as_number = int(T1_SNAPPI_AS_NUM)

            route_range2 = bgpv6_peer.v6_routes.add(name="T1_IPv6_Routes_%d" % (index))
            for route_index, routes in enumerate(route_range['IPv6']):
                route_range2.addresses.add(
                    address=routes[0], prefix=routes[1], count=routes[2])
            ipv6_dest.append(route_range2.name)
            as_path = route_range2.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = AS_PATHS

    def createTrafficItem(traffic_name, source, destination):
        logger.info('{} Source : {}'.format(traffic_name, source))
        logger.info('{} Destination : {}'.format(traffic_name, destination))
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = source
        flow1.tx_rx.device.rx_names = destination
        flow1.size.fixed = 1024
        flow1.rate.percentage = 10
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    if traffic_type == 'IPv4':
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4_Traffic", [ipv4_src[0]], ipv4_dest)
    else:
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv6 Traffic", [ipv6_src[0]], ipv6_dest)
    return config


def get_flow_stats(api):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    request = api.metrics_request()
    request.flow.flow_names = []
    return api.get_metrics(request).flow_metrics


def get_port_stats(api):
    """
    Args:
        api (pytest fixture): Snappi API
    """
    request = api.metrics_request()
    return api.get_metrics(request).port_metrics


def get_convergence_for_link_flap(duthosts,
                                  api,
                                  bgp_config,
                                  flap_event,
                                  traffic_type,
                                  iteration,
                                  route_range):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        flap_event: contains hostname and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
    """
    api.set_config(bgp_config)
    t2_port_index_start = len(t1_ports[duthosts[0].hostname])
    avg_pld = []
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    for i in range(0, iteration):
        logger.info(
            '|--------------------------- Iteration : {} -----------------------|'.format(i+1))
        logger.info("Starting all protocols ...")
        ps = api.protocol_state()
        ps.state = ps.START
        api.set_protocol_state(ps)
        wait(TIMEOUT, "For Protocols To start")

        logger.info('Starting Traffic')
        ts = api.transmit_state()
        ts.state = ts.START
        api.set_transmit_state(ts)
        wait(TIMEOUT, "For Traffic To start")

        flow_stats = get_flow_stats(api)
        port_stats = get_port_stats(api)
        logger.info('\n')
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if int(port_stat.name.split('_')[-1]) >= t2_port_index_start-1:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
        logger.info('\n')
        logger.info('Loss %: {}'.format(int(flow_stats[0].loss)))
        pytest_assert(int(flow_stats[0].loss) == 0, 'Loss Observed in traffic flow before link Flap')

        sum_t2_rx_frame_rate = 0
        for port_stat in port_stats:
            if int(port_stat.name.split('_')[-1]) >= t2_port_index_start:
                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)
        # Flap the required test port
        if duthosts[0].hostname == flap_event['hostname']:
            logger.info(' Shutting down {} port of {} dut !!'.
                        format(flap_event['port_name'], flap_event['hostname']))
            duthosts[0].command('sudo config interface shutdown {} \n'.
                                format(flap_event['port_name']))
        elif 'snappi_sonic' == flap_event['hostname'] and isinstance(flap_event['port_name'], list):
            for port in flap_event['port_name']:
                ixn_port = ixnetwork.Vport.find(Name=port)[0]
                ixn_port.LinkUpDn("down")
            logger.info('Shutting down snappi ports : {}'.format(flap_event['port_name']))
        wait(TIMEOUT, "For link to shutdown")

        flow_stats = get_flow_stats(api)
        delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION (ms): {}'.format(pkt_loss_duration))
        avg_pld.append(pkt_loss_duration)

        pytest_assert(float((int(flow_stats[0].frames_tx_rate) - int(flow_stats[0].frames_tx_rate)) /
                      int(flow_stats[0].frames_tx_rate)) < 0.005,
                      'Traffic has not converged after link flap')

        if duthosts[0].hostname == flap_event['hostname']:
            logger.info(' Starting up {} port of {} dut !!'.
                        format(flap_event['port_name'], flap_event['hostname']))
            duthosts[0].command('sudo config interface startup {} \n'.
                                format(flap_event['port_name']))
        elif 'snappi_sonic' == flap_event['hostname'] and isinstance(flap_event['port_name'], list):
            for port in flap_event['port_name']:
                ixn_port = ixnetwork.Vport.find(Name=port)[0]
                ixn_port.LinkUpDn("up")
            logger.info('Starting up snappi ports : {}'.format(flap_event['port_name']))
        wait(TIMEOUT+20, "For link to startup")
        logger.info('\n')
        port_stats = get_port_stats(api)
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if int(port_stat.name.split('_')[-1]) >= t2_port_index_start-1:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
        logger.info('Stopping Traffic')
        ts = api.transmit_state()
        ts.state = ts.STOP
        api.set_transmit_state(ts)

        logger.info("Stopping all protocols ...")
        ps = api.protocol_state()
        ps.state = ps.STOP
        api.set_protocol_state(ps)
        logger.info('\n')

    columns = ['Event Name', 'Iterations', 'Traffic Type', 'Route Count', 'Avg Calculated Packet Loss Duration (ms)']
    logger.info("\n%s" % tabulate([[f"{flap_event['hostname']}:{flap_event['port_name']} \
                Link Flap", iteration, traffic_type, total_routes, mean(avg_pld)]], headers=columns, tablefmt="psql"))


def kill_process_inside_container(duthost, container_name, process_id):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        process_id: process id that needs to be killed inside container
    """
    username = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['sonicadmin_user']
    password = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['sonicadmin_password']
    ip = duthost.mgmt_ip
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port=22, username=username, password=password)
    command = f'docker exec {container_name} kill {process_id}'
    stdin, stdout, stderr = ssh.exec_command(command)


def get_container_names(duthost):
    """
    Args:
        duthost (pytest fixture): duthost fixture
    """
    container_names = duthost.shell('docker ps --format \{\{.Names\}\}')['stdout_lines']  # noqa: W605
    return container_names


def check_container_status_up(duthost, container_name, timeout):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        timeout(secs): Maximum time limit for polling
    """
    start_time = time.time()
    while True:
        running_containers_list = get_container_names(duthost)
        if container_name in running_containers_list:
            logger.info('PASS: {} is RUNNING after process kill'.format(container_name))
            break
        logger.info('Polling for {} to come UP.....'.format(container_name))
        elapsed_time = time.time() - start_time
        pytest_assert(elapsed_time < timeout, "Container did not come up in {} \
                      seconds after process kill".format(timeout))
        time.sleep(1)


def check_container_status_down(duthost, container_name, timeout):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        timeout(secs): Maximum time limit for polling
    """
    start_time = time.time()
    while True:
        running_containers_list = get_container_names(duthost)
        if container_name not in running_containers_list:
            logger.info('PASS: {} is DOWN after process kill'.format(container_name))
            break
        logger.info('Polling for {} to go Down.....'.format(container_name))
        elapsed_time = time.time() - start_time
        pytest_assert(elapsed_time < timeout, "Container is still running for {} \
                      seconds after process kill".format(timeout))
        time.sleep(1)


def get_container_names_from_asic_count(duthost, container_name):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
    """
    container_names = []
    platform_summary = duthost.shell('show platform summary')['stdout_lines']
    for line in platform_summary:
        if 'ASIC Count' in line:
            count = int(line.split(':')[-1].lstrip())
    for i in range(0, count):
        container_names.append(container_name+str(i))
    return container_names


def get_convergence_for_service_flap(duthosts,
                                     api,
                                     bgp_config,
                                     traffic_type,
                                     iteration,
                                     service_names,
                                     host_name,
                                     route_range):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        service_names : Name of the container in which specific service needs to be flapped
        host_name : Dut hostname
    """
    api.set_config(bgp_config)
    t2_port_index_start = len(t1_ports[duthosts[0].hostname])
    table = []
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    for container_name, process_name in service_names.items():
        for duthost in duthosts:
            container_names = get_container_names_from_asic_count(duthost, container_name)
            if duthost.hostname == host_name:
                for container in container_names:
                    row = []
                    avg_pld = []
                    for i in range(0, iteration):
                        logger.info(
                            '|---------------------------{} Iteration : {} --------------\
                            ---------|'.format(container, i+1))
                        logger.info("Starting all protocols ...")
                        ps = api.protocol_state()
                        ps.state = ps.START
                        api.set_protocol_state(ps)
                        wait(TIMEOUT, "For Protocols To start")

                        logger.info('Starting Traffic')
                        ts = api.transmit_state()
                        ts.state = ts.START
                        api.set_transmit_state(ts)
                        wait(TIMEOUT, "For Traffic To start")

                        flow_stats = get_flow_stats(api)
                        logger.info('Loss %: {}'.format(int(flow_stats[0].loss)))
                        logger.info('\n')
                        port_stats = get_port_stats(api)
                        logger.info('Rx Snappi Port Name : Rx Frame Rate')
                        for port_stat in port_stats:
                            if int(port_stat.name.split('_')[-1]) >= t2_port_index_start-1:
                                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving \
                                              any packet'.format(port_stat.name))
                        pytest_assert(int(flow_stats[0].loss) == 0, 'Loss Observed in traffic \
                                      flow before killing service in {}')
                        logger.info('\n')
                        sum_t2_rx_frame_rate = 0
                        for port_stat in port_stats:
                            if int(port_stat.name.split('_')[-1]) >= t2_port_index_start:
                                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)
                        logger.info('Killing {}:{} service in {}'.format(container, process_name, host_name))
                        PID = duthost.shell('docker exec {}  ps aux | grep {} \n'.
                                            format(container, process_name))['stdout'].split(' ')[10]
                        all_containers = get_container_names(duthost)
                        logger.info('Runnnig containers before process kill: {}'.format(all_containers))
                        kill_process_inside_container(duthost, container, PID)
                        check_container_status_down(duthost, container, timeout=20)
                        check_container_status_up(duthost, container, timeout=120)
                        wait(180, "For Flows to be evenly distributed")
                        port_stats = get_port_stats(api)
                        for port_stat in port_stats:
                            if int(port_stat.name.split('_')[-1]) > t2_port_index_start-1:
                                logger.info('{}: {}'.format(port_stat.name, port_stat.frames_rx_rate))
                                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet \
                                              after container is up'.format(port_stat.name))
                        flow_stats = get_flow_stats(api)
                        delta_frames = flow_stats[0].frames_tx - flow_stats[0].frames_rx
                        pkt_loss_duration = 1000*(delta_frames/sum_t2_rx_frame_rate)
                        logger.info('Delta Frames : {}'.format(delta_frames))
                        logger.info('PACKET LOSS DURATION (ms): {}'.format(pkt_loss_duration))
                        avg_pld.append(pkt_loss_duration)

                        logger.info('Stopping Traffic')
                        ts = api.transmit_state()
                        ts.state = ts.STOP
                        api.set_transmit_state(ts)
                        wait(TIMEOUT, "For Traffic To stop")

                        logger.info("Stopping all protocols ...")
                        ps = api.protocol_state()
                        ps.state = ps.STOP
                        api.set_protocol_state(ps)
                        wait(TIMEOUT, "For Protocols To stop")
                        logger.info('\n')
                    row.append(host_name)
                    row.append(f'{container}')
                    row.append(f'{process_name}')
                    row.append(iteration)
                    row.append(traffic_type)
                    row.append(total_routes)
                    row.append(mean(avg_pld))
                    table.append(row)
    columns = ['Hostname', 'Container Name', 'Process Name', 'Iterations', 'Traffic Type',
               'Route Count', 'Avg Calculated Packet Loss Duration (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))
