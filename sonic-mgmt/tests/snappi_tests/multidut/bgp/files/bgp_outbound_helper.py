import logging
import random
import paramiko
import json
import time
import math
import pexpect
from ixnetwork_restpy import SessionAssistant
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import (wait, wait_until)  # noqa: F401
from tests.common.helpers.assertions import pytest_assert  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import create_ip_list  # noqa: F401
from tests.snappi_tests.variables import T1_SNAPPI_AS_NUM, T2_SNAPPI_AS_NUM, T1_DUT_AS_NUM, T2_DUT_AS_NUM, t1_ports, \
     t2_uplink_portchannel_members, t1_t2_dut_ipv4_list, v4_prefix_length, v6_prefix_length, \
     t1_t2_dut_ipv6_list, t1_t2_snappi_ipv4_list, portchannel_count, \
     t1_t2_snappi_ipv6_list, t2_dut_portchannel_ipv4_list, t2_dut_portchannel_ipv6_list, \
     snappi_portchannel_ipv4_list, snappi_portchannel_ipv6_list, AS_PATHS, \
     BGP_TYPE, t1_side_interconnected_port, t2_side_interconnected_port, router_ids, \
     snappi_community_for_t1, snappi_community_for_t2, SNAPPI_TRIGGER, DUT_TRIGGER, \
     fanout_presence, t2_uplink_fanout_info  # noqa: F401

logger = logging.getLogger(__name__)
total_routes = 0
fanout_uplink_snappi_info = []


def run_dut_configuration(snappi_extra_params):
    """
    Configures the dut for the test

        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    duthosts = [duthost1, duthost2, duthost3]
    test_name = snappi_extra_params.test_name
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports

    duthost_bgp_config(duthosts,
                       snappi_ports,
                       test_name)


def run_bgp_outbound_uplink_blackout_test(api,
                                          snappi_extra_params,
                                          creds):
    """
    Run outbound test for uplink blackout
    Args:
        api (pytest fixture): snappi API
        creds (dict): DUT credentials
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
    blackout_percentage = snappi_extra_params.multi_dut_params.BLACKOUT_PERCENTAGE
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                duthosts,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_blackout(duthosts,
                                     api,
                                     snappi_bgp_config,
                                     traffic_type,
                                     iteration,
                                     blackout_percentage,
                                     route_range,
                                     test_name,
                                     creds)


def run_bgp_outbound_tsa_tsb_test(api,
                                  snappi_extra_params,
                                  creds,
                                  is_supervisor):
    """
    Run outbound test with TSA TSB on the dut

    Args:
        api (pytest fixture): snappi API
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    """
    if snappi_extra_params is None:
        snappi_extra_params = SnappiTestParams()  # noqa F821

    duthost1 = snappi_extra_params.multi_dut_params.duthost1
    duthost2 = snappi_extra_params.multi_dut_params.duthost2
    duthost3 = snappi_extra_params.multi_dut_params.duthost3
    duthost4 = snappi_extra_params.multi_dut_params.duthost4
    duthosts = [duthost1, duthost2, duthost3, duthost4]
    route_ranges = snappi_extra_params.ROUTE_RANGES
    snappi_ports = snappi_extra_params.multi_dut_params.multi_dut_ports
    device_name = snappi_extra_params.device_name
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                duthosts,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_tsa_tsb(duthosts,
                                    api,
                                    snappi_bgp_config,
                                    traffic_type,
                                    iteration,
                                    device_name,
                                    route_range,
                                    test_name,
                                    creds,
                                    is_supervisor)


def run_bgp_outbound_process_restart_test(api,
                                          creds,
                                          snappi_extra_params):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
        creds (dict): DUT credentials
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
    process_names = snappi_extra_params.multi_dut_params.process_names
    host_name = snappi_extra_params.multi_dut_params.host_name
    iteration = snappi_extra_params.iteration
    test_name = snappi_extra_params.test_name

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports,
                       test_name)

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                duthosts,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_process_flap(duthosts,
                                         api,
                                         snappi_bgp_config,
                                         traffic_type,
                                         iteration,
                                         process_names,
                                         host_name,
                                         route_range,
                                         test_name,
                                         creds)


def run_bgp_outbound_link_flap_test(api,
                                    creds,
                                    snappi_extra_params):
    """
    Run Local link failover test

    Args:
        api (pytest fixture): snappi API
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
    flap_details = snappi_extra_params.multi_dut_params.flap_details
    test_name = snappi_extra_params.test_name

    """ Create bgp config on dut """
    duthost_bgp_config(duthosts,
                       snappi_ports,
                       test_name)

    """ Create snappi config """
    for route_range in route_ranges:
        traffic_type = []
        for key, value in route_range.items():
            traffic_type.append(key)
        snappi_bgp_config = __snappi_bgp_config(api,
                                                duthosts,
                                                snappi_ports,
                                                traffic_type,
                                                route_range)

        get_convergence_for_link_flap(duthosts,
                                      api,
                                      snappi_bgp_config,
                                      flap_details,
                                      traffic_type,
                                      iteration,
                                      route_range,
                                      test_name,
                                      creds)


def duthost_bgp_config(duthosts,
                       snappi_ports,
                       test_name):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthosts (pytest fixture): duthosts fixture
        snappi_ports (pytest fixture): Ports mapping info of T0 testbed
        test_name: Name of the test
    """
    logger.info('\n')
    logger.info('--------------- T1 Snappi Section --------------------')
    logger.info('\n')
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
        logger.info('Configuring IPs {}/{} , {}/{} on {} in {}'.
                    format(t1_t2_dut_ipv4_list[index], v4_prefix_length,
                           t1_t2_dut_ipv6_list[index], v6_prefix_length, custom_port, duthosts[0].hostname))

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
                                "name": "snappi-sonic"+str(index),
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
                                "name": "snappi-sonic"+str(index),
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
    logger.info('Configuring IP {}/{} , {}/{} on {} in {} for the T1 interconnectivity'.
                format(t1_t2_dut_ipv4_list[index], v4_prefix_length,
                       t1_t2_dut_ipv6_list[index], v6_prefix_length, t1_side_interconnected_port,
                       duthosts[0].hostname))

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
    logger.info('Configuring IP {}/{} , {}/{} on {} in {} for the T1 interconnectivity'.
                format(t1_t2_snappi_ipv4_list[index], v4_prefix_length,
                       t1_t2_snappi_ipv6_list[index], v6_prefix_length,
                       t2_side_interconnected_port['port_name'], duthosts[2].hostname))
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
    logger.info('\n')
    logger.info('--------------- T2 Uplink - Tgen Section --------------------')
    logger.info('\n')
    logger.info('T2 Dut AS Number: {}'.format(T2_DUT_AS_NUM))
    logger.info('T2 side Snappi AS Number: {}'.format(T2_SNAPPI_AS_NUM))
    loopback_interfaces = dict()
    loopback_interfaces.update({"Loopback0": {}})
    loopback_interfaces.update({"Loopback0|3.3.3.3/32": {}})
    loopback_interfaces.update({"Loopback0|3::3/128": {}})
    index = 0
    index_2 = 0
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
            if 'Portchannel Flap' in test_name:
                min_link = len(port_set)
            else:
                min_link = 1
            PORTCHANNEL = {
                                portchannel:
                                {
                                    "admin_status": "up",
                                    "lacp_key": "auto",
                                    "min_links": str(min_link),
                                    "mtu": "9100"
                                }
                          }
            PORTCHANNELS.update(PORTCHANNEL)
            logger.info('\n')
            logger.info('Creating {} in {}'.format(portchannel, duthosts[1].hostname))
            logger.info('Setting min_links to {} for {}'.format(min_link, portchannel))
            interface_name = {portchannel: {}}
            v4_interface = {f"{portchannel}|{t2_dut_portchannel_ipv4_list[index_2]}/{v4_prefix_length}": {}}
            v6_interface = {f"{portchannel}|{t2_dut_portchannel_ipv6_list[index_2]}/{v6_prefix_length}": {}}
            PORTCHANNEL_INTERFACES.update(interface_name)
            PORTCHANNEL_INTERFACES.update(v4_interface)
            PORTCHANNEL_INTERFACES.update(v6_interface)
            logger.info('Configuring IPs {}/{} , {}/{} on {} in {}'.
                        format(t2_dut_portchannel_ipv4_list[index_2], v4_prefix_length,
                               t2_dut_portchannel_ipv6_list[index_2], v6_prefix_length,
                               portchannel, duthosts[1].hostname))
            index_2 = index_2 + 1
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
    wait(DUT_TRIGGER, "For configs to be loaded on the duts")


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
        duthosts(pytest fixture): duthosts fixture
        snappi_ports : Snappi port list
        traffic_type: IPv4 or IPv6 traffic
        route_range: v4 and v6 route combination
    """
    global fanout_uplink_snappi_info
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
        if index == 0:
            snappi_test_port['name'] = 'Snappi_Tx_Port'
        else:
            snappi_test_port['name'] = 'Snappi_Backup_T2_%d' % index
        config.ports.port(name=snappi_test_port['name'], location=snappi_test_port['location'])

    for _, snappi_test_port in enumerate(snappi_t2_ports):
        po = 1
        for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
            for portchannel, portchannel_members in portchannel_info.items():
                for index, mem_port in enumerate(portchannel_members, 1):
                    if snappi_test_port['peer_port'] == mem_port and \
                       snappi_test_port['peer_device'] == duthosts[1].hostname:
                        snappi_test_port['name'] = 'Snappi_Uplink_PO_{}_Link_{}'.format(po, index)
                        fanout_uplink_snappi_info.append(snappi_test_port)
                        config.ports.port(name=snappi_test_port['name'], location=snappi_test_port['location'])
                    else:
                        continue
                po = po + 1

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

        device = config.devices.device(name="T3 Device {}".format(lag_count))[-1]
        eth = device.ethernets.add()
        eth.port_name = lag.name
        eth.name = 'T3_Ethernet_%d' % lag_count
        eth.mac = "00:00:00:00:00:%s" % m

        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'T3_IPv4_%d' % lag_count
        ipv4.address = snappi_portchannel_ipv4_list[lag_count]
        ipv4.gateway = t2_dut_portchannel_ipv4_list[lag_count]
        ipv4.prefix = v4_prefix_length
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'T3_IPv6_%d' % lag_count
        ipv6.address = snappi_portchannel_ipv6_list[lag_count]
        ipv6.gateway = t2_dut_portchannel_ipv6_list[lag_count]
        ipv6.prefix = v6_prefix_length

        bgpv4 = device.bgp
        bgpv4.router_id = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv4_int = bgpv4.ipv4_interfaces.add()
        bgpv4_int.ipv4_name = ipv4.name
        bgpv4_peer = bgpv4_int.peers.add()
        bgpv4_peer.name = 'T3_BGP_%d' % lag_count
        bgpv4_peer.as_type = BGP_TYPE
        bgpv4_peer.peer_address = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv4_peer.as_number = int(T2_SNAPPI_AS_NUM)

        route_range1 = bgpv4_peer.v4_routes.add(name="T3_IPv4_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv4']):
            route_range1.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])
        for community in snappi_community_for_t2:
            manual_as_community = route_range1.communities.add()
            manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
            manual_as_community.as_number = int(community.split(":")[0])
            manual_as_community.as_custom = int(community.split(":")[1])
        ipv4_dest.append(route_range1.name)

        bgpv6 = device.bgp
        bgpv6.router_id = t2_dut_portchannel_ipv4_list[lag_count]
        bgpv6_int = bgpv6.ipv6_interfaces.add()
        bgpv6_int.ipv6_name = ipv6.name
        bgpv6_peer = bgpv6_int.peers.add()
        bgpv6_peer.name = 'T3_BGP+_%d' % lag_count
        bgpv6_peer.as_type = BGP_TYPE
        bgpv6_peer.peer_address = t2_dut_portchannel_ipv6_list[lag_count]
        bgpv6_peer.as_number = int(T2_SNAPPI_AS_NUM)

        route_range2 = bgpv6_peer.v6_routes.add(name="T3_IPv6_Routes_%d" % (lag_count))
        for route_index, routes in enumerate(route_range['IPv6']):
            route_range2.addresses.add(
                address=routes[0], prefix=routes[1], count=routes[2])
        for community in snappi_community_for_t2:
            manual_as_community = route_range2.communities.add()
            manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
            manual_as_community.as_number = int(community.split(":")[0])
            manual_as_community.as_custom = int(community.split(":")[1])
        ipv6_dest.append(route_range2.name)

    for index, port in enumerate(snappi_t1_ports):
        if len(str(hex(index+1).split('0x')[1])) == 1:
            m = '0'+hex(index+1).split('0x')[1]
        else:
            m = hex(index+1).split('0x')[1]

        if index == 0:
            device = config.devices.device(name="T0 Device {}".format(index))[-1]
            eth = device.ethernets.add()
            eth.port_name = port['name']
            eth.name = 'T0_Ethernet_%d' % index
            eth.mac = "00:10:00:00:00:%s" % m
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'T0_IPv4_%d' % index
            ipv4.address = t1_t2_snappi_ipv4_list[index]
            ipv4.gateway = t1_t2_dut_ipv4_list[index]
            ipv4.prefix = v4_prefix_length
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'T0_IPv6_%d' % index
            ipv6.address = t1_t2_snappi_ipv6_list[index]
            ipv6.gateway = t1_t2_dut_ipv6_list[index]
            ipv6.prefix = v6_prefix_length
            ipv4_src.append(ipv4.name)
            ipv6_src.append(ipv6.name)
        else:
            device = config.devices.device(name="Backup T2 Device {}".format(index))[-1]
            eth = device.ethernets.add()
            eth.port_name = port['name']
            eth.name = 'Backup_T2_Ethernet_%d' % index
            eth.mac = "00:10:00:00:00:%s" % m
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'Backup_T2_IPv4_%d' % index
            ipv4.address = t1_t2_snappi_ipv4_list[index]
            ipv4.gateway = t1_t2_dut_ipv4_list[index]
            ipv4.prefix = v4_prefix_length
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'Backup_T2_IPv6_%d' % index
            ipv6.address = t1_t2_snappi_ipv6_list[index]
            ipv6.gateway = t1_t2_dut_ipv6_list[index]
            ipv6.prefix = v6_prefix_length

            bgpv4 = device.bgp
            bgpv4.router_id = t1_t2_snappi_ipv4_list[index]
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'Backup_T2_BGP_%d' % index
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = t1_t2_dut_ipv4_list[index]
            bgpv4_peer.as_number = int(T1_SNAPPI_AS_NUM)

            if 'IPv4' in route_range.keys():
                route_range1 = bgpv4_peer.v4_routes.add(name="Backup_T2_IPv4_Routes_%d" % (index))
                for route_index, routes in enumerate(route_range['IPv4']):
                    route_range1.addresses.add(
                        address=routes[0], prefix=routes[1], count=routes[2])
                ipv4_dest.append(route_range1.name)
                as_path = route_range1.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = AS_PATHS
                for community in snappi_community_for_t1:
                    manual_as_community = route_range1.communities.add()
                    manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
                    manual_as_community.as_number = int(community.split(":")[0])
                    manual_as_community.as_custom = int(community.split(":")[1])

            bgpv6 = device.bgp
            bgpv6.router_id = t1_t2_snappi_ipv4_list[index]
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'Backup_T2_BGP+_%d' % index
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = t1_t2_dut_ipv6_list[index]
            bgpv6_peer.as_number = int(T1_SNAPPI_AS_NUM)

            if 'IPv6' in route_range.keys():
                route_range2 = bgpv6_peer.v6_routes.add(name="Backup_T2_IPv6_Routes_%d" % (index))
                for route_index, routes in enumerate(route_range['IPv6']):
                    route_range2.addresses.add(
                        address=routes[0], prefix=routes[1], count=routes[2])
                ipv6_dest.append(route_range2.name)
                as_path = route_range2.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = AS_PATHS
                for community in snappi_community_for_t1:
                    manual_as_community = route_range2.communities.add()
                    manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
                    manual_as_community.as_number = int(community.split(":")[0])
                    manual_as_community.as_custom = int(community.split(":")[1])

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

    if 'IPv4' in traffic_type and 'IPv6' in traffic_type:
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4_Traffic", [ipv4_src[0]], ipv4_dest)
        createTrafficItem("IPv6_Traffic", [ipv6_src[0]], ipv6_dest)
    elif 'IPv6' in traffic_type and 'IPv4' not in traffic_type:
        for route in route_range['IPv6']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv6 Traffic", [ipv6_src[0]], ipv6_dest)
    elif 'IPv4' in traffic_type and 'IPv6' not in traffic_type:
        for route in route_range['IPv4']:
            total_routes = total_routes+route[2]
        createTrafficItem("IPv4 Traffic", [ipv4_src[0]], ipv4_dest)
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


def flap_single_fanout_port(fanout_ip, creds, port_name, state):
    """
    Args:
        fanout_ip (pytest fixture): IP of the fanout device
        creds (dict): DUT credentials
        port_name: Name of the fanout port to be flapped
        state: State of the interface to be up/down
    """
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(fanout_ip, port=22, username=username, password=password)
    if state == 'up':
        command = f'sudo config interface startup {port_name}'
    elif state == 'down':
        command = f'sudo config interface shutdown {port_name}'
    stdin, stdout, stderr = ssh.exec_command(command)


def get_convergence_for_link_flap(duthosts,
                                  api,
                                  bgp_config,
                                  flap_details,
                                  traffic_type,
                                  iteration,
                                  route_range,
                                  test_name,
                                  creds):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        flap_details: contains device name and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        test_name: Name of the test
        creds (pytest fixture): DUT credentials
    """
    api.set_config(bgp_config)
    avg_pld = []
    avg_pld2 = []
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(router_ids[index])
            logger.info('Setting Router id {} for {}'.format(router_ids[index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue
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
        wait(SNAPPI_TRIGGER, "For Protocols To start")
        logger.info('Verifying protocol sessions state')
        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
        protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)
        logger.info('Starting Traffic')
        ts = api.transmit_state()
        ts.state = ts.START
        api.set_transmit_state(ts)
        wait(SNAPPI_TRIGGER, "For Traffic To start")

        flow_stats = get_flow_stats(api)
        port_stats = get_port_stats(api)

        logger.info('\n')
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
        logger.info('\n')
        for i in range(0, len(traffic_type)):
            logger.info('{} Loss %: {}'.format(flow_stats[i].name, int(flow_stats[i].loss)))
            pytest_assert(int(flow_stats[i].loss) == 0, f'Loss Observed in {flow_stats[i].name} before link Flap')

        sum_t2_rx_frame_rate = 0
        for port_stat in port_stats:
            if 'Snappi_Uplink' in port_stat.name:
                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)
        # Flap the required test port
        if duthosts[0].hostname == flap_details['device_name']:
            logger.info(' Shutting down {} port of {} dut !!'.
                        format(flap_details['port_name'], flap_details['device_name']))
            duthosts[0].command('sudo config interface shutdown {} \n'.
                                format(flap_details['port_name']))
            wait(DUT_TRIGGER, "For link to shutdown")
        elif 'Ixia' == flap_details['device_name']:
            if fanout_presence is False:
                ixn_port = ixnetwork.Vport.find(Name=flap_details['port_name'])[0]
                ixn_port.LinkUpDn("down")
                logger.info('Shutting down snappi port : {}'.format(flap_details['port_name']))
                wait(SNAPPI_TRIGGER, "For link to shutdown")
            else:
                for port in fanout_uplink_snappi_info:
                    if flap_details['port_name'] == port['name']:
                        uplink_port = port['peer_port']
                for fanout_info in t2_uplink_fanout_info:
                    for port_mapping in fanout_info['port_mapping']:
                        if uplink_port == port_mapping['uplink_port']:
                            fanout_port = port_mapping['fanout_port']
                            fanout_ip = fanout_info['fanout_ip']
                            break
                pytest_assert(fanout_port is not None, 'Unable to get fanout port info')
                flap_single_fanout_port(fanout_ip, creds, fanout_port, state='down')
                logger.info(' Shutting down {} from {}'.format(fanout_port, fanout_ip))
                wait(DUT_TRIGGER, "For link to shutdown")
        flow_stats = get_flow_stats(api)
        for i in range(0, len(traffic_type)):
            pytest_assert(float((int(flow_stats[i].frames_tx_rate) - int(flow_stats[i].frames_rx_rate)) /
                          int(flow_stats[i].frames_tx_rate)) < 0.005,
                          'Traffic has not converged after link flap')
        logger.info('Traffic has converged after link flap')

        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION  After Link Down (ms): {}'.format(pkt_loss_duration))
        avg_pld.append(pkt_loss_duration)

        logger.info('Performing Clear Stats')
        ixnetwork.ClearStats()
        if duthosts[0].hostname == flap_details['device_name']:
            logger.info(' Starting up {} port of {} dut !!'.
                        format(flap_details['port_name'], flap_details['device_name']))
            duthosts[0].command('sudo config interface startup {} \n'.
                                format(flap_details['port_name']))
            wait(DUT_TRIGGER, "For link to startup")
        elif 'Ixia' == flap_details['device_name']:
            if fanout_presence is False:
                ixn_port = ixnetwork.Vport.find(Name=flap_details['port_name'])[0]
                ixn_port.LinkUpDn("up")
                logger.info('Starting up snappi port : {}'.format(flap_details['port_name']))
                wait(SNAPPI_TRIGGER, "For link to startup")
            else:
                flap_single_fanout_port(fanout_ip, creds, fanout_port, state='up')
                logger.info('Starting up {} from {}'.format(fanout_port, fanout_ip))
                wait(DUT_TRIGGER, "For link to startup")
        logger.info('\n')
        port_stats = get_port_stats(api)
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))

        flow_stats = get_flow_stats(api)
        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION After Link Up (ms): {}'.format(pkt_loss_duration))
        avg_pld2.append(pkt_loss_duration)
        logger.info('Stopping Traffic')
        ts = api.transmit_state()
        ts.state = ts.STOP
        api.set_transmit_state(ts)

        logger.info("Stopping all protocols ...")
        ps = api.protocol_state()
        ps.state = ps.STOP
        api.set_protocol_state(ps)
        logger.info('\n')

    columns = ['Test Name', 'Iterations', 'Traffic Type', 'Uplink ECMP Paths', 'Route Count',
               'Avg Calculated Packet Loss Duration (ms)']
    logger.info("\n%s" % tabulate([[test_name+' (Link Down)', iteration, traffic_type, portchannel_count,
                                  total_routes, mean(avg_pld)], [test_name+' (Link Up)', iteration,
                                  traffic_type, portchannel_count, total_routes, mean(avg_pld2)]], headers=columns,
                                  tablefmt="psql"))


def kill_process_inside_container(duthost, container_name, process_id, creds):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        container_name (str): Container name running in dut
        process_id: process id that needs to be killed inside container
        creds (dict): DUT credentials
    """
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')
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
    container_names = duthost.shell('docker ps --format \{\{.Names\}\}')['stdout_lines']   # noqa: W605
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
        time.sleep(5)


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
        time.sleep(5)


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


def get_convergence_for_process_flap(duthosts,
                                     api,
                                     bgp_config,
                                     traffic_type,
                                     iteration,
                                     process_names,
                                     host_name,
                                     route_range,
                                     test_name,
                                     creds):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        process_names : Name of the container in which specific process needs to be killed
        host_name : Dut hostname
        test_name: Name of the test
        creds (dict): DUT credentials
    """
    api.set_config(bgp_config)
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(router_ids[index])
            logger.info('Setting Router id {} for {}'.format(router_ids[index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue

    table = []
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    for container_name, process_name in process_names.items():
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
                        wait(SNAPPI_TRIGGER, "For Protocols To start")
                        logger.info('Verifying protocol sessions state')
                        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
                        protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)
                        logger.info('Starting Traffic')
                        ts = api.transmit_state()
                        ts.state = ts.START
                        api.set_transmit_state(ts)
                        wait(SNAPPI_TRIGGER, "For Traffic To start")

                        flow_stats = get_flow_stats(api)
                        for i in range(0, len(traffic_type)):
                            logger.info('{} Loss %: {}'.
                                        format(flow_stats[i].name, int(flow_stats[i].loss)))
                        logger.info('\n')
                        port_stats = get_port_stats(api)
                        logger.info('Rx Snappi Port Name : Rx Frame Rate')
                        for port_stat in port_stats:
                            if 'Snappi_Tx_Port' not in port_stat.name:
                                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving \
                                              any packet'.format(port_stat.name))
                        pytest_assert(int(flow_stats[0].loss) == 0, 'Loss Observed in traffic \
                                      flow before killing service in {}')
                        logger.info('\n')
                        sum_t2_rx_frame_rate = 0
                        for port_stat in port_stats:
                            if 'Snappi_Uplink' in port_stat.name:
                                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)
                        logger.info('Killing {}:{} service in {}'.format(container, process_name, host_name))
                        PID = duthost.shell('docker exec {}  ps aux | grep {} \n'.
                                            format(container, process_name))['stdout'].split(' ')[10]
                        all_containers = get_container_names(duthost)
                        logger.info('Runnnig containers before process kill: {}'.format(all_containers))
                        kill_process_inside_container(duthost, container, PID, creds)
                        check_container_status_down(duthost, container, timeout=60)
                        check_container_status_up(duthost, container, timeout=DUT_TRIGGER)
                        wait(DUT_TRIGGER, "For Flows to be evenly distributed")
                        port_stats = get_port_stats(api)
                        for port_stat in port_stats:
                            if 'Snappi_Tx_Port' not in port_stat.name:
                                logger.info('{}: {}'.format(port_stat.name, port_stat.frames_rx_rate))
                                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet \
                                              after container is up'.format(port_stat.name))
                        flow_stats = get_flow_stats(api)
                        delta_frames = 0
                        for i in range(0, len(traffic_type)):
                            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
                        pkt_loss_duration = 1000*(delta_frames/sum_t2_rx_frame_rate)
                        logger.info('Delta Frames : {}'.format(delta_frames))
                        logger.info('PACKET LOSS DURATION (ms): {}'.format(pkt_loss_duration))
                        avg_pld.append(pkt_loss_duration)

                        logger.info('Stopping Traffic')
                        ts = api.transmit_state()
                        ts.state = ts.STOP
                        api.set_transmit_state(ts)
                        wait(SNAPPI_TRIGGER, "For Traffic To stop")

                        logger.info("Stopping all protocols ...")
                        ps = api.protocol_state()
                        ps.state = ps.STOP
                        api.set_protocol_state(ps)
                        wait(SNAPPI_TRIGGER, "For Protocols To stop")
                        logger.info('\n')
                    row.append(test_name)
                    row.append(f'{container}')
                    row.append(f'{process_name}')
                    row.append(iteration)
                    row.append(traffic_type)
                    row.append(portchannel_count)
                    row.append(total_routes)
                    row.append(mean(avg_pld))
                    table.append(row)
    columns = ['Test Name', 'Container Name', 'Process Name', 'Iterations', 'Traffic Type',
               'Uplink ECMP Paths', 'Route Count', 'Avg Calculated Packet Loss Duration (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def exec_tsa_tsb_cmd_on_linecard(duthost, creds, tsa_tsb_cmd):
    """
    @summary: Issue TSA/TSB command on supervisor card using user credentials
    Verify command is executed on supervisor card
    @returns: None
    """
    try:
        dut_ip = duthost.mgmt_ip
        sonic_username = creds['sonicadmin_user']
        sonic_password = creds['sonicadmin_password']
        logger.info('sonic-username: {}, sonic_password: {}'.format(sonic_username, sonic_password))
        ssh_cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {}@{}".format(sonic_username, dut_ip)
        connect = pexpect.spawn(ssh_cmd)
        time.sleep(10)
        connect.expect('.*[Pp]assword:')
        connect.sendline(sonic_password)
        time.sleep(10)
        connect.sendline(tsa_tsb_cmd)
        time.sleep(10)
        connect.expect('.*[Pp]assword for username \'{}\':'.format(sonic_username))
        connect.sendline(sonic_password)
        time.sleep(20)
    except pexpect.exceptions.EOF:
        pytest_assert(False, "EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest_assert(False, "Timeout reached")
    except Exception as e:
        pytest_assert(False, "Cannot connect to DUT {} host via SSH: {}".format(duthost.hostname, e))


def get_convergence_for_tsa_tsb(duthosts,
                                api,
                                snappi_bgp_config,
                                traffic_type,
                                iteration,
                                device_name,
                                route_range,
                                test_name,
                                creds,
                                is_supervisor):

    """
    Args:
        duthost (pytest fixture): duthost fixture
        api (pytest fixture): Snappi API
        snappi_bgp_config: __snappi_bgp_config
        flap_details: contains device name and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        device_name: Device in which TSA, TSB needs to be performed
        route_range: V4 and v6 routes
        test_name: Name of the test
    """
    api.set_config(snappi_bgp_config)
    avg_pld = []
    avg_pld2 = []
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(router_ids[index])
            logger.info('Setting Router id {} for {}'.format(router_ids[index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue
    logger.info('\n')
    logger.info('Testing with Route Range: {}'.format(route_range))
    logger.info('\n')
    logger.info('Issuing TSB before starting test to ensure DUT to be in proper state')
    for duthost in duthosts:
        if duthost.hostname == device_name:
            if is_supervisor is True:
                exec_tsa_tsb_cmd_on_linecard(duthost, creds, "sudo TSB")
            else:
                duthost.command('sudo TSB')
    wait(DUT_TRIGGER, "For TSB")
    try:
        for i in range(0, iteration):
            logger.info(
                '|--------------------------- Iteration : {} -----------------------|'.format(i+1))
            logger.info("Starting all protocols ...")
            ps = api.protocol_state()
            ps.state = ps.START
            api.set_protocol_state(ps)
            wait(SNAPPI_TRIGGER, "For Protocols To start")
            logger.info('Verifying protocol sessions state')
            protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
            protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)
            logger.info('Starting Traffic')
            ts = api.transmit_state()
            ts.state = ts.START
            api.set_transmit_state(ts)
            wait(SNAPPI_TRIGGER, "For Traffic To start")
            flow_stats = get_flow_stats(api)
            port_stats = get_port_stats(api)

            logger.info('\n')
            logger.info('Rx Snappi Port Name : Rx Frame Rate')
            for port_stat in port_stats:
                if 'Snappi_Tx_Port' not in port_stat.name:
                    logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                    pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
            logger.info('\n')
            for i in range(0, len(traffic_type)):
                logger.info('{} Loss %: {}'.format(flow_stats[i].name, int(flow_stats[i].loss)))
                pytest_assert(int(flow_stats[i].loss) == 0, f'Loss Observed in {flow_stats[i].name} before link Flap')

            # Getting rx rate on uplink ports
            sum_t2_rx_frame_rate = 0
            for port_stat in port_stats:
                if 'Snappi_Uplink' in port_stat.name:
                    sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)

            logger.info('Issuing TSA on {}'.format(device_name))
            for duthost in duthosts:
                if duthost.hostname == device_name:
                    if is_supervisor is True:
                        exec_tsa_tsb_cmd_on_linecard(duthost, creds, "sudo TSA")
                    else:
                        duthost.command('sudo TSA')
            wait(DUT_TRIGGER, "For TSA")
            flow_stats = get_flow_stats(api)
            for i in range(0, len(traffic_type)):
                logger.info(flow_stats[i].frames_tx_rate)
                logger.info(flow_stats[i].frames_rx_rate)
                pytest_assert(float((int(flow_stats[i].frames_tx_rate) - int(flow_stats[i].frames_rx_rate)) /
                              int(flow_stats[i].frames_tx_rate)) < 0.005,
                              'Traffic has not converged after TSA')
            logger.info('Traffic has converged after issuing TSA command in {}'.format(device_name))
            flow_stats = get_flow_stats(api)
            delta_frames = 0
            for i in range(0, len(traffic_type)):
                delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
            pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
            logger.info('Delta Frames : {}'.format(delta_frames))
            logger.info('PACKET LOSS DURATION  After TSA (ms): {}'.format(pkt_loss_duration))
            avg_pld.append(pkt_loss_duration)

            logger.info('Performing Clear Stats')
            ixnetwork.ClearStats()
            logger.info('Issuing TSB on {}'.format(device_name))
            for duthost in duthosts:
                if duthost.hostname == device_name:
                    if is_supervisor is True:
                        exec_tsa_tsb_cmd_on_linecard(duthost, creds, "sudo TSB")
                    else:
                        duthost.command('sudo TSB')

            wait(DUT_TRIGGER, "For TSB")
            logger.info('\n')
            port_stats = get_port_stats(api)
            logger.info('Rx Snappi Port Name : Rx Frame Rate')
            for port_stat in port_stats:
                if 'Snappi_Tx_Port' not in port_stat.name:
                    logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                    pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))

            flow_stats = get_flow_stats(api)
            delta_frames = 0
            for i in range(0, len(traffic_type)):
                delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
            pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
            logger.info('Delta Frames : {}'.format(delta_frames))
            logger.info('PACKET LOSS DURATION After TSB (ms): {}'.format(pkt_loss_duration))
            avg_pld2.append(pkt_loss_duration)
            logger.info('Stopping Traffic')
            ts = api.transmit_state()
            ts.state = ts.STOP
            api.set_transmit_state(ts)

            logger.info("Stopping all protocols ...")
            ps = api.protocol_state()
            ps.state = ps.STOP
            api.set_protocol_state(ps)
            logger.info('\n')

        columns = ['Test Name', 'Iterations', 'Traffic Type', 'Uplink ECMP Paths', 'Route Count',
                   'Avg Calculated Packet Loss Duration (ms)']
        logger.info("\n%s" % tabulate([[test_name+' (TSA)', iteration, traffic_type, portchannel_count,
                                      total_routes, mean(avg_pld)], [test_name+' (TSB)', iteration,
                                      traffic_type, portchannel_count, total_routes, mean(avg_pld2)]],
                                      headers=columns, tablefmt="psql"))
    except Exception as e:
        logger.info(e)
        logger.info('Since an exception occurred, Issuing TSB, to ensure DUT to be in proper state')
        for duthost in duthosts:
            if duthost.hostname == device_name:
                if is_supervisor is True:
                    exec_tsa_tsb_cmd_on_linecard(duthost, creds, "sudo TSB")
                else:
                    duthost.command('sudo TSB')
        wait(DUT_TRIGGER, "For TSB")


def flap_fanout_ports(fanout_ip_port_mapping, creds, state):
    """
    Args:

    """
    username = creds.get('sonicadmin_user')
    password = creds.get('sonicadmin_password')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for fanout_ip, req_ports in fanout_ip_port_mapping.items():
        ssh.connect(fanout_ip, port=22, username=username, password=password)
        if state == 'down':
            for port_name in req_ports:
                time.sleep(0.05)
                stdin, stdout, stderr = ssh.exec_command(f'sudo config interface shutdown {port_name}')
                logger.info('Shutting down {}'.format(port_name))
        elif state == 'up':
            for port_name in req_ports:
                time.sleep(0.05)
                stdin, stdout, stderr = ssh.exec_command(f'sudo config interface startup {port_name}')
                logger.info('Starting up {}'.format(port_name))


def add_value_to_key(dictionary, key, value):
    if key in dictionary:
        dictionary[key] = dictionary[key] + [value]
    else:
        dictionary[key] = [value]


def get_convergence_for_blackout(duthosts,
                                 api,
                                 snappi_bgp_config,
                                 traffic_type,
                                 iteration,
                                 blackout_percentage,
                                 route_range,
                                 test_name,
                                 creds):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        api (pytest fixture): Snappi API
        bgp_config: __snappi_bgp_config
        flap_details: contains device name and port / services that needs to be flapped
        traffic_type : IPv4 / IPv6 traffic type
        iteration : Number of iterations
        test_name: Name of the test
    """
    api.set_config(snappi_bgp_config)
    avg_pld = []
    avg_pld2 = []
    test_platform = TestPlatform(api._address)
    test_platform.Authenticate(api._username, api._password)
    session = SessionAssistant(IpAddress=api._address, UserName=api._username,
                               SessionId=test_platform.Sessions.find()[-1].Id, Password=api._password)
    ixnetwork = session.Ixnetwork
    for index, topology in enumerate(ixnetwork.Topology.find()):
        try:
            topology.DeviceGroup.find()[0].RouterData.find().RouterId.Single(router_ids[index])
            logger.info('Setting Router id {} for {}'.format(router_ids[index], topology.DeviceGroup.find()[0].Name))
        except Exception:
            logger.info('Skipping Router id for {}, Since bgp is not configured'.
                        format(topology.DeviceGroup.find()[0].Name))
            continue
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
        wait(SNAPPI_TRIGGER, "For Protocols To start")
        logger.info('Verifying protocol sessions state')
        protocolsSummary = StatViewAssistant(ixnetwork, 'Protocols Summary')
        protocolsSummary.CheckCondition('Sessions Down', StatViewAssistant.EQUAL, 0)
        logger.info('Starting Traffic')
        ts = api.transmit_state()
        ts.state = ts.START
        api.set_transmit_state(ts)
        wait(SNAPPI_TRIGGER, "For Traffic To start")

        flow_stats = get_flow_stats(api)
        port_stats = get_port_stats(api)

        logger.info('\n')
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))
        logger.info('\n')
        for i in range(0, len(traffic_type)):
            logger.info('{} Loss %: {}'.format(flow_stats[i].name, int(flow_stats[i].loss)))
            pytest_assert(int(flow_stats[i].loss) == 0, f'Loss Observed in {flow_stats[i].name} before link Flap')

        sum_t2_rx_frame_rate = 0
        for port_stat in port_stats:
            if 'Snappi_Uplink' in port_stat.name:
                sum_t2_rx_frame_rate = sum_t2_rx_frame_rate + int(port_stat.frames_rx_rate)

        # Link Down
        portchannel_dict = {}
        for asic_value, portchannel_info in t2_uplink_portchannel_members[duthosts[1].hostname].items():
            portchannel_dict.update(portchannel_info)
        number_of_po = math.ceil(blackout_percentage * len(portchannel_dict)/100)
        snappi_port_names = []
        for snappi_port in fanout_uplink_snappi_info:
            uplink_ports = []
            for i, (key, value) in enumerate(portchannel_dict.items(), 1):
                if i <= number_of_po:
                    uplink_ports += value
                    if i == int(snappi_port['name'].split('_')[3]):
                        snappi_port_names.append(snappi_port['name'])
        if fanout_presence is False:
            for snappi_port_name in snappi_port_names:
                time.sleep(0.05)
                ixn_port = ixnetwork.Vport.find(Name=snappi_port_name)[0]
                ixn_port.LinkUpDn("down")
                logger.info('Shutting down snappi port : {}'.format(snappi_port_name))
            wait(SNAPPI_TRIGGER, "For links to shutdown")
        else:
            required_fanout_mapping = {}
            for uplink_port in uplink_ports:
                for fanout_info in t2_uplink_fanout_info:
                    for port_mapping in fanout_info['port_mapping']:
                        if uplink_port == port_mapping['uplink_port']:
                            fanout_ip = fanout_info['fanout_ip']
                            add_value_to_key(required_fanout_mapping, fanout_ip, port_mapping['fanout_port'])
            flap_fanout_ports(required_fanout_mapping, creds, state='down')
            wait(DUT_TRIGGER, "For links to shutdown")

        flow_stats = get_flow_stats(api)
        for i in range(0, len(traffic_type)):
            pytest_assert(float((int(flow_stats[i].frames_tx_rate) - int(flow_stats[i].frames_rx_rate)) /
                          int(flow_stats[i].frames_tx_rate)) < 0.005,
                          'Traffic has not converged after link flap')
        logger.info('Traffic has converged after link flap')

        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION  After Link Down (ms): {}'.format(pkt_loss_duration))
        avg_pld.append(pkt_loss_duration)

        logger.info('Performing Clear Stats')
        ixnetwork.ClearStats()

        # Link Up
        if fanout_presence is False:
            for snappi_port_name in snappi_port_names:
                time.sleep(0.05)
                ixn_port = ixnetwork.Vport.find(Name=snappi_port_name)[0]
                ixn_port.LinkUpDn("up")
                logger.info('Starting up snappi port : {}'.format(snappi_port_name))
            wait(SNAPPI_TRIGGER, "For links to shutdown")
        else:
            flap_fanout_ports(required_fanout_mapping, creds, state='up')
            wait(DUT_TRIGGER, "For links to startup")

        logger.info('\n')
        port_stats = get_port_stats(api)
        logger.info('Rx Snappi Port Name : Rx Frame Rate')
        for port_stat in port_stats:
            if 'Snappi_Tx_Port' not in port_stat.name:
                logger.info('{} : {}'.format(port_stat.name, port_stat.frames_rx_rate))
                pytest_assert(port_stat.frames_rx_rate > 0, '{} is not receiving any packet'.format(port_stat.name))

        flow_stats = get_flow_stats(api)
        delta_frames = 0
        for i in range(0, len(traffic_type)):
            delta_frames = delta_frames + flow_stats[i].frames_tx - flow_stats[i].frames_rx
        pkt_loss_duration = 1000 * (delta_frames / sum_t2_rx_frame_rate)
        logger.info('Delta Frames : {}'.format(delta_frames))
        logger.info('PACKET LOSS DURATION After Link Up (ms): {}'.format(pkt_loss_duration))
        avg_pld2.append(pkt_loss_duration)
        logger.info('Stopping Traffic')
        ts = api.transmit_state()
        ts.state = ts.STOP
        api.set_transmit_state(ts)

        logger.info("Stopping all protocols ...")
        ps = api.protocol_state()
        ps.state = ps.STOP
        api.set_protocol_state(ps)
        logger.info('\n')

    columns = ['Test Name', 'Iterations', 'Traffic Type', 'Uplink ECMP Paths', 'Route Count',
               'Avg Calculated Packet Loss Duration (ms)']
    logger.info("\n%s" % tabulate([[test_name+' (Link Down)', iteration, traffic_type, portchannel_count,
                                  total_routes, mean(avg_pld)], [test_name+' (Link Up)', iteration,
                                  traffic_type, portchannel_count, total_routes, mean(avg_pld2)]], headers=columns,
                                  tablefmt="psql"))
