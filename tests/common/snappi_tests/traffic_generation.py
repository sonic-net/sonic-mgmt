"""
This module allows various snappi based tests to generate various traffic configurations.
"""
import pytest
import time
import logging
import re
import sys
import random
import pandas as pd
from datetime import datetime
from tests.common.utilities import (wait, wait_until)   # noqa: F401
from tabulate import tabulate

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.common_helpers import config_capture_settings, get_egress_queue_count, \
    pfc_class_enable_vector, get_lossless_buffer_size, get_pg_dropped_packets, \
    sec_to_nanosec, get_pfc_frame_count, packet_capture, get_tx_frame_count, get_rx_frame_count, \
    traffic_flow_mode, get_pfc_count, clear_counters, get_interface_stats, get_queue_count_all_prio, \
    get_pfcwd_stats, get_interface_counters_detailed
from tests.common.snappi_tests.port import select_ports, select_tx_port
from tests.common.snappi_tests.snappi_helpers import wait_for_arp, fetch_snappi_flow_metrics, \
    fetch_flow_metrics_for_macsec    # noqa: F401
from .variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.common.snappi_tests.snappi_fixtures import gen_data_flow_dest_ip
from tests.common.cisco_data import is_cisco_device
from tests.common.reboot import reboot
from tests.common.macsec.macsec_helper import get_macsec_counters, clear_macsec_counters, \
    get_dict_macsec_counters  # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.port import SnappiPortConfig

# Imported to support rest_py in ixnetwork
from ixnetwork_restpy.assistants.statistics.statviewassistant import StatViewAssistant
from random import getrandbits


logger = logging.getLogger(__name__)

SNAPPI_POLL_DELAY_SEC = 2
CONTINUOUS_MODE = -5
ANSIBLE_POLL_DELAY_SEC = 4
UDP_PORT_START = 5000
ECN_CAPABLE_TRANSPORT_1 = 1


def setup_base_traffic_config(testbed_config,
                              port_config_list,
                              port_id,
                              num_tx_ports=1,
                              num_rx_ports=1):
    """
    Generate base configurations of flows, including test flows, background flows and
    pause storm. Test flows and background flows are also known as data flows.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        port_id (int): ID of DUT port to test
        num_tx_ports (int): Number of TX ports to select (default: 1)
        num_rx_ports (int): Number of RX ports to select (default: 1)

    Returns:
        base_flow_config (dict): base flow configuration containing dut_port_config, tx_mac,
            rx_mac, tx_port_config, rx_port_config, tx_port_name, rx_port_name
            dict key-value pairs (all keys are strings):
                tx_port_id (int or list): ID(s) of ixia TX port(s) ex. 1 or [1, 2]
                rx_port_id (int or list): ID(s) of ixia RX port(s) ex. 2 or [2, 3]
                tx_port_config (SnappiPortConfig or list): port config obj(s) for ixia TX port(s)
                rx_port_config (SnappiPortConfig or list): port config obj(s) for ixia RX port(s)
                tx_mac (str or list): MAC address(es) of ixia TX port(s) ex. '00:00:fa:ce:fa:ce' or
                                    ['00:00:fa:ce:fa:ce', '00:00:fa:ce:fa:ce']
                rx_mac (str or list): MAC address(es) of ixia RX port(s) ex. '00:00:fa:ce:fa:ce' or
                                    ['00:00:fa:ce:fa:ce', '00:00:fa:ce:fa:ce']
                tx_port_name (str or list): name(s) of ixia TX port(s) ex. 'Port 1' or ['Port 1', 'Port 2']
                rx_port_name (str or list): name(s) of ixia RX port(s) ex. 'Port 2' or ['Port 2', 'Port 3']
                dut_port_config (dict): a dictionary with "Tx" and "Rx" keys, each containing a list of dictionaries
                                        of tx and rx ports on the peer (switch) side, and the associated test
                                        priorities ex. {"Tx": [{'Ethernet4':[3, 4]}],
                                        "Rx": [{'Ethernet8':[3, 4]}]} for single port
                                        or {"Tx": [{'Ethernet4':[3, 4]}, {'Ethernet12':[3, 4]}],
                                        "Rx": [{'Ethernet8':[3, 4]}]} for multiple ports
                test_flow_name_dut_rx_port_map (dict): Mapping of test flow name to DUT RX port(s)
                                                  ex. {'flow1': [Ethernet4, Ethernet8]}
                test_flow_name_dut_tx_port_map (dict): Mapping of test flow name to DUT TX port(s)
                                                  ex. {'flow1': [Ethernet4, Ethernet8]}
    """
    base_flow_config = {}

    if num_rx_ports == 1:
        rx_port_id = port_id
        rx_port_id_list = [rx_port_id]
    else:
        rx_port_id = port_id
        rx_port_id_list = [rx_port_id]

    if num_tx_ports == 1:
        tx_port_id_list, _ = select_ports(port_config_list=port_config_list,
                                          pattern="many to one",
                                          rx_port_id=rx_port_id)
        pytest_assert(len(tx_port_id_list) > 0, "Cannot find any TX ports")
        tx_port_id = select_tx_port(tx_port_id_list=tx_port_id_list,
                                    rx_port_id=rx_port_id)
        pytest_assert(tx_port_id is not None, "Cannot find a suitable TX port")
        tx_port_id_list = [tx_port_id]
    else:
        tx_port_id_list, _ = select_ports(port_config_list=port_config_list,
                                          pattern="many to one",
                                          rx_port_id=rx_port_id)
        pytest_assert(len(tx_port_id_list) >= num_tx_ports,
                      f"Cannot find enough TX ports. Need {num_tx_ports}, found {len(tx_port_id_list)}")
        tx_port_id_list = select_tx_port(tx_port_id_list=tx_port_id_list,
                                         rx_port_id=rx_port_id,
                                         num_tx_ports=num_tx_ports)
        pytest_assert(tx_port_id_list is not None, "Cannot find suitable TX ports")

    base_flow_config["rx_port_id"] = rx_port_id_list if num_rx_ports > 1 else rx_port_id
    base_flow_config["tx_port_id"] = tx_port_id_list if num_tx_ports > 1 else tx_port_id_list[0]

    tx_port_configs = [next((x for x in port_config_list if x.id == tx_id), None) for tx_id in tx_port_id_list]
    rx_port_configs = [next((x for x in port_config_list if x.id == rx_id), None) for rx_id in rx_port_id_list]

    base_flow_config["tx_port_config"] = tx_port_configs if num_tx_ports > 1 else tx_port_configs[0]
    base_flow_config["rx_port_config"] = rx_port_configs if num_rx_ports > 1 else rx_port_configs[0]

    dut_port_config = {"Tx": [], "Rx": []}

    for tx_config in tx_port_configs:
        tx_dict = {str(tx_config.peer_port): []}
        dut_port_config["Tx"].append(tx_dict)

    for rx_config in rx_port_configs:
        rx_dict = {str(rx_config.peer_port): []}
        dut_port_config["Rx"].append(rx_dict)

    base_flow_config["dut_port_config"] = dut_port_config

    if num_tx_ports == 1:
        base_flow_config["tx_mac"] = tx_port_configs[0].mac
    else:
        base_flow_config["tx_mac"] = [config.mac for config in tx_port_configs]

    if num_rx_ports == 1:
        if tx_port_configs[0].gateway == rx_port_configs[0].gateway and \
           tx_port_configs[0].prefix_len == rx_port_configs[0].prefix_len:
            base_flow_config["rx_mac"] = rx_port_configs[0].mac
        else:
            base_flow_config["rx_mac"] = tx_port_configs[0].gateway_mac
    else:
        rx_macs = []
        for rx_config in rx_port_configs:
            if tx_port_configs[0].gateway == rx_config.gateway and \
               tx_port_configs[0].prefix_len == rx_config.prefix_len:
                rx_macs.append(rx_config.mac)
            else:
                rx_macs.append(tx_port_configs[0].gateway_mac)
        base_flow_config["rx_mac"] = rx_macs

    if num_tx_ports == 1:
        base_flow_config["tx_port_name"] = testbed_config.ports[tx_port_id_list[0]].name
    else:
        base_flow_config["tx_port_name"] = [testbed_config.ports[tx_id].name for tx_id in tx_port_id_list]

    if num_rx_ports == 1:
        base_flow_config["rx_port_name"] = testbed_config.ports[rx_port_id].name
    else:
        base_flow_config["rx_port_name"] = [testbed_config.ports[rx_id].name for rx_id in rx_port_id_list]

    return base_flow_config


def generate_test_flows(testbed_config,
                        test_flow_prio_list,
                        prio_dscp_map,
                        snappi_extra_params,
                        congested=False,
                        number_of_streams=1,
                        flow_index=None):
    """
    Generate configurations of test flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        test_flow_prio_list (list): list of test flow priorities
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        number_of_streams (int): number of UDP streams
        flow_index (int): Index to identify the base_flow_config. Default is None.
    """
    # If snappi_extra_params.base_flow_config_list exists,
    # assign it to base_flow_config using flow_index.
    if not snappi_extra_params.base_flow_config_list:
        base_flow_config = snappi_extra_params.base_flow_config
    else:
        base_flow_config = snappi_extra_params.base_flow_config_list[flow_index]

    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    pytest_assert(data_flow_config is not None, "Cannot find data flow configuration")
    test_flow_name_dut_rx_port_map = {}
    test_flow_name_dut_tx_port_map = {}

    # Check if flow_rate_percent is a dictionary
    if isinstance(data_flow_config["flow_rate_percent"], (int, float)):
        # Create a dictionary with priorities as keys and the flow rate percent as the value for each key
        data_flow_config["flow_rate_percent"] = {
            prio: data_flow_config["flow_rate_percent"] for prio in test_flow_prio_list
        }

    for prio in test_flow_prio_list:
        # If flow_index exists, then flow name uses it to identify Stream-name.
        if flow_index is None:
            test_flow_name = "{} Prio {}".format(data_flow_config["flow_name"], prio)
        else:
            test_flow_name = "{} Prio {} Stream {}".format(data_flow_config["flow_name"], prio, flow_index)
        test_flow = testbed_config.flows.flow(name=test_flow_name)[-1]
        ptype = "--snappi_macsec" in sys.argv
        # Assign TX and RX port names to the flow
        if ptype:
            test_flow.tx_rx.device.tx_names = [
                testbed_config.devices[len(testbed_config.devices)-1].ethernets[0].ipv4_addresses[0].name
            ]
            test_flow.tx_rx.device.rx_names = [
                testbed_config.devices[prio].ethernets[0].ipv4_addresses[0].name
            ]
            test_flow.tx_rx.device.mode = test_flow.tx_rx.device.ONE_TO_ONE
            test_flow.packet.ethernet().ipv4()
            ip = test_flow.packet[-1]
            eth = test_flow.packet[-2]
            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = prio
            else:
                eth.pfc_queue.value = pfcQueueValueDict[prio]
            ip.priority.choice = ip.priority.DSCP
            phb_value = [random.choice(prio_dscp_map[prio])]
            ip.priority.dscp.phb.values = phb_value
            ip.priority.dscp.ecn.value = (
                ip.priority.dscp.ecn.CONGESTION_ENCOUNTERED if congested else
                ip.priority.dscp.ecn.CAPABLE_TRANSPORT_1
            )
            snappi_extra_params.flow_name_prio_map[test_flow_name] = prio
        else:
            test_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
            test_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

            eth, ipv4, udp = test_flow.packet.ethernet().ipv4().udp()
            global UDP_PORT_START
            src_port = UDP_PORT_START
            UDP_PORT_START += number_of_streams
            udp.src_port.increment.start = src_port
            udp.src_port.increment.step = 1
            udp.src_port.increment.count = number_of_streams

            eth.src.value = base_flow_config["tx_mac"]
            eth.dst.value = base_flow_config["rx_mac"]
            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = prio
            else:
                eth.pfc_queue.value = pfcQueueValueDict[prio]

            ipv4.src.value = base_flow_config["tx_port_config"].ip
            ipv4.dst.value = gen_data_flow_dest_ip(base_flow_config["rx_port_config"].ip)
            ipv4.priority.choice = ipv4.priority.DSCP
            ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
            ipv4.priority.dscp.ecn.value = (ipv4.priority.dscp.ecn.CONGESTION_ENCOUNTERED if congested else
                                            ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        test_flow.size.fixed = data_flow_config["flow_pkt_size"]
        test_flow.rate.percentage = data_flow_config["flow_rate_percent"][prio]
        if data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
            test_flow.duration.fixed_seconds.seconds = data_flow_config["flow_dur_sec"]
            test_flow.duration.fixed_seconds.delay.nanoseconds = int(
                sec_to_nanosec(data_flow_config["flow_delay_sec"])
            )
        elif data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_PACKETS:
            test_flow.duration.fixed_packets.packets = data_flow_config["flow_pkt_count"]
            test_flow.duration.fixed_packets.delay.nanoseconds = int(
                sec_to_nanosec(data_flow_config["flow_delay_sec"])
            )

        test_flow.metrics.enable = True
        test_flow.metrics.loss = True

        """ Set flow port config values """
        dut_port_config = base_flow_config["dut_port_config"]

        # Find the TX port config entry and append priority
        tx_peer_port = str(base_flow_config["tx_port_config"].peer_port)
        for tx_port_dict in dut_port_config["Tx"]:
            if tx_peer_port in tx_port_dict:
                tx_port_dict[tx_peer_port].append(int(prio))
                break

        # Find the RX port config entry and append priority
        rx_peer_port = str(base_flow_config["rx_port_config"].peer_port)
        for rx_port_dict in dut_port_config["Rx"]:
            if rx_peer_port in rx_port_dict:
                rx_port_dict[rx_peer_port].append(int(prio))
                break

        base_flow_config["dut_port_config"] = dut_port_config

        # Save flow name to TX and RX port mapping for DUT
        test_flow_name_dut_rx_port_map[test_flow_name] = [base_flow_config["tx_port_config"].peer_port]
        test_flow_name_dut_tx_port_map[test_flow_name] = [base_flow_config["rx_port_config"].peer_port]

        base_flow_config["test_flow_name_dut_rx_port_map"] = test_flow_name_dut_rx_port_map
        base_flow_config["test_flow_name_dut_tx_port_map"] = test_flow_name_dut_tx_port_map

        # If base_flow_config_list, exists, re-assign updated base_flow_config to it using flow_index.
        if not snappi_extra_params.base_flow_config_list:
            snappi_extra_params.base_flow_config = base_flow_config
        else:
            snappi_extra_params.base_flow_config_list[flow_index] = base_flow_config


def generate_background_flows(testbed_config,
                              bg_flow_prio_list,
                              prio_dscp_map,
                              snappi_extra_params,
                              number_of_streams=1,
                              flow_index=None):
    """
    Generate background configurations of flows. Test flows and background flows are also known as data flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        bg_flow_prio_list (list): list of background flow priorities
        prio_dscp_map (dict): priority to DSCP mapping
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        flow_index (int): Index to identify the base_flow_config. Default is None.
    """
    # If snappi_extra_params.base_flow_config_list exists,
    # assign it to base_flow_config using flow_index.
    if not snappi_extra_params.base_flow_config_list:
        base_flow_config = snappi_extra_params.base_flow_config
    else:
        base_flow_config = snappi_extra_params.base_flow_config_list[flow_index]

    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config
    pytest_assert(bg_flow_config is not None, "Cannot find background flow configuration")

    for prio in bg_flow_prio_list:
        # If flow_index exists, then flow name uses it to identify Stream-name.
        if flow_index is None:
            bg_flow_name = '{} Prio {}'.format(bg_flow_config["flow_name"], prio)
        else:
            bg_flow_name = '{} Prio {} Stream {}'.format(bg_flow_config["flow_name"], prio, flow_index)
        bg_flow = testbed_config.flows.flow(name=bg_flow_name)[-1]
        ptype = "--snappi_macsec" in sys.argv
        # Assign TX and RX port names to the flow
        if ptype:
            bg_flow.tx_rx.device.tx_names = [
                testbed_config.devices[len(testbed_config.devices)-1].ethernets[0].ipv4_addresses[0].name
            ]
            bg_flow.tx_rx.device.rx_names = [
                testbed_config.devices[prio].ethernets[0].ipv4_addresses[0].name
            ]
            bg_flow.tx_rx.device.mode = bg_flow.tx_rx.device.ONE_TO_ONE
            bg_flow.packet.ethernet().ipv4()
            ip = bg_flow.packet[-1]
            eth = bg_flow.packet[-2]
            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = prio
            else:
                eth.pfc_queue.value = pfcQueueValueDict[prio]
            ip.priority.choice = ip.priority.DSCP
            phb_value = [random.choice(prio_dscp_map[prio])]
            ip.priority.dscp.phb.values = phb_value
            ip.priority.dscp.ecn.value = (
                ip.priority.dscp.ecn.CAPABLE_TRANSPORT_1)
            snappi_extra_params.flow_name_prio_map[bg_flow_name] = prio
        else:
            bg_flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"]
            bg_flow.tx_rx.port.rx_name = base_flow_config["rx_port_name"]

            eth, ipv4, udp = bg_flow.packet.ethernet().ipv4().udp()
            global UDP_PORT_START
            src_port = UDP_PORT_START
            UDP_PORT_START += number_of_streams
            udp.src_port.increment.start = src_port
            udp.src_port.increment.step = 1
            udp.src_port.increment.count = number_of_streams

            eth.src.value = base_flow_config["tx_mac"]
            eth.dst.value = base_flow_config["rx_mac"]
            if pfcQueueGroupSize == 8:
                eth.pfc_queue.value = prio
            else:
                eth.pfc_queue.value = pfcQueueValueDict[prio]

                ipv4.src.value = base_flow_config["tx_port_config"].ip
                ipv4.dst.value = gen_data_flow_dest_ip(base_flow_config["rx_port_config"].ip)
                ipv4.priority.choice = ipv4.priority.DSCP
                ipv4.priority.dscp.phb.values = prio_dscp_map[prio]
                ipv4.priority.dscp.ecn.value = (
                    ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1)

        bg_flow.size.fixed = bg_flow_config["flow_pkt_size"]
        bg_flow.rate.percentage = bg_flow_config["flow_rate_percent"]
        bg_flow.duration.fixed_seconds.seconds = bg_flow_config["flow_dur_sec"]
        bg_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec
                                                               (bg_flow_config["flow_delay_sec"]))

        bg_flow.metrics.enable = True
        bg_flow.metrics.loss = True


def generate_pause_flows(testbed_config,
                         pause_prio_list,
                         global_pause,
                         snappi_extra_params,
                         flow_index=None):
    """
    Generate configurations of pause flows.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        pause_prio_list (list): list of pause priorities
        global_pause (bool): global pause or per priority pause
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        flow_index (int): Index to identify the base_flow_config. Default is None.
    """
    # If snappi_extra_params.base_flow_config_list exists,
    # assign it to base_flow_config using flow_index.
    if not snappi_extra_params.base_flow_config_list:
        base_flow_config = snappi_extra_params.base_flow_config
    else:
        base_flow_config = snappi_extra_params.base_flow_config_list[flow_index]

    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    pause_flow_config = snappi_extra_params.traffic_flow_config.pause_flow_config
    pytest_assert(pause_flow_config is not None, "Cannot find pause flow configuration")

    # If flow_index exists, then flow name uses it to identify Stream-name.
    if flow_index is None:
        pause_flow = testbed_config.flows.flow(name=pause_flow_config["flow_name"])[-1]
    else:
        pause_flow = testbed_config.flows.flow(name='{} Stream {}'.
                                               format(pause_flow_config["flow_name"], flow_index))[-1]

    pause_flow.tx_rx.port.tx_name = testbed_config.ports[base_flow_config["rx_port_id"]].name
    pause_flow.tx_rx.port.rx_name = testbed_config.ports[base_flow_config["tx_port_id"]].name

    if global_pause:
        pause_pkt = pause_flow.packet.ethernetpause()[-1]
        pause_pkt.dst.value = "01:80:C2:00:00:01"
        pause_pkt.src.value = snappi_extra_params.pfc_pause_src_mac if snappi_extra_params.pfc_pause_src_mac \
            else "00:00:fa:ce:fa:ce"
    else:
        pause_time = []
        for x in range(8):
            if x in pause_prio_list:
                if "flow_quanta" in pause_flow_config:
                    pause_time.append(pause_flow_config["flow_quanta"])
                else:
                    pause_time.append(int('ffff', 16))
            else:
                pause_time.append(int('0000', 16))

        vector = pfc_class_enable_vector(pause_prio_list)
        pause_pkt = pause_flow.packet.pfcpause()[-1]
        pause_pkt.src.value = snappi_extra_params.pfc_pause_src_mac if snappi_extra_params.pfc_pause_src_mac \
            else "00:00:fa:ce:fa:ce"
        pause_pkt.dst.value = "01:80:C2:00:00:01"
        pause_pkt.class_enable_vector.value = vector if snappi_extra_params.set_pfc_class_enable_vec else 0
        pause_pkt.pause_class_0.value = pause_time[0]
        pause_pkt.pause_class_1.value = pause_time[1]
        pause_pkt.pause_class_2.value = pause_time[2]
        pause_pkt.pause_class_3.value = pause_time[3]
        pause_pkt.pause_class_4.value = pause_time[4]
        pause_pkt.pause_class_5.value = pause_time[5]
        pause_pkt.pause_class_6.value = pause_time[6]
        pause_pkt.pause_class_7.value = pause_time[7]

    # Pause frames are sent from the RX port of ixia
    pause_flow.rate.pps = pause_flow_config["flow_rate_pps"]
    pause_flow.size.fixed = pause_flow_config["flow_pkt_size"]
    pause_flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec(
        pause_flow_config["flow_delay_sec"]))

    if pause_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
        pause_flow.duration.fixed_seconds.seconds = pause_flow_config["flow_dur_sec"]
    elif pause_flow_config["flow_traffic_type"] == traffic_flow_mode.CONTINUOUS:
        pause_flow.duration.choice = pause_flow.duration.CONTINUOUS
    elif pause_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_PACKETS:
        pause_flow.duration.fixed_packets.packets = pause_flow_config["flow_pkt_count"]
        pause_flow.duration.fixed_packets.delay.nanoseconds = int(sec_to_nanosec
                                                                  (pause_flow_config["flow_delay_sec"]))

    pause_flow.metrics.enable = True
    pause_flow.metrics.loss = True


def _rand_ipv6():
    # 2007:db8::/32 is documentation range
    return "2007:db8:%x:%x:%x:%x:%x:%x" % tuple(getrandbits(16) for _ in range(6))


def generate_srv6_encap_flow(testbed_config,
                             snappi_test_params: SnappiTestParams):
    """
    Create a single or multiple SRv6 (IPv6-in-IPv6) encapsulated flow based
    on the snappi_test_params passed in.
    Outer IPv6 header encapsulates an inner IPv6 packet.

    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        snappi_test_params (SnappiTestParams obj): additional parameters for Snappi
                                                    traffic
    """

    base_flow_config = snappi_test_params.base_flow_config
    pytest_assert(base_flow_config is not None, "Cannot find base flow configuration")
    data_flow_config = snappi_test_params.traffic_flow_config.data_flow_config
    pytest_assert(data_flow_config is not None, "Cannot find data flow configuration")

    # Split flow rate equally amongst each dscp stream
    per_dscp_stream_flow_rate = data_flow_config['flow_rate_percent'] // len(snappi_test_params.tx_dscp_values)
    unique_tgen_rx_ports = set()

    if isinstance(base_flow_config["tx_port_id"], int):
        # If tx_port_id is an int, force a list type for easier access
        base_flow_config["tx_port_id"] = [base_flow_config["tx_port_id"]]
    if isinstance(base_flow_config["tx_port_config"], SnappiPortConfig):
        base_flow_config["tx_port_config"] = [base_flow_config["tx_port_config"]]

    for tx_config_idx in range(len(base_flow_config["tx_port_config"])):
        for tx_dscp in snappi_test_params.tx_dscp_values:
            tx_port_config = base_flow_config["tx_port_config"][tx_config_idx]
            flow_name = f"{tx_port_config.peer_port} SRv6 Flow DSCP {tx_dscp}"
            flow = testbed_config.flows.flow(name=flow_name)[-1]
            flow.tx_rx.port.tx_name = base_flow_config["tx_port_name"][tx_config_idx]
            rx_port_names = base_flow_config["rx_port_name"]
            if isinstance(rx_port_names, list):
                flow.tx_rx.port.rx_name = rx_port_names[tx_config_idx % len(rx_port_names)]
            else:
                flow.tx_rx.port.rx_name = rx_port_names

            eth, outer_ipv6, inner_ipv6 = flow.packet.ethernet().ipv6().ipv6()
            unique_tgen_rx_ports.add(flow.tx_rx.port.rx_name)

            # Ethernet addressing (reuse existing base flow macs)
            eth.src.value = base_flow_config["tx_mac"] if isinstance(base_flow_config["tx_mac"], str) else \
                base_flow_config["tx_mac"][tx_config_idx]
            eth.dst.value = base_flow_config["rx_mac"] if isinstance(base_flow_config["rx_mac"], str) else \
                base_flow_config["rx_mac"][tx_config_idx]

            # Outer IPv6 (SRv6 transport)
            outer_ipv6.src.value = tx_port_config.ipv6
            pytest_assert(outer_ipv6.src.value is not None, "Outer IPv6 source address is None")
            outer_ipv6.dst.value = base_flow_config["rx_port_config"].ipv6
            pytest_assert(outer_ipv6.dst.value is not None, "Outer IPv6 destination address is None")
            ecn = ECN_CAPABLE_TRANSPORT_1  # ECN ECT(1)=1 ECN-capable
            outer_ipv6.traffic_class.value = (tx_dscp << 2) | ecn
            outer_ipv6.flow_label.value = getrandbits(20)

            # Inner IPv6
            inner_ipv6.src.value = _rand_ipv6()
            inner_ipv6.dst.value = _rand_ipv6()
            inner_ipv6.traffic_class.value = 0
            inner_ipv6.flow_label.value = getrandbits(20)

            flow.size.fixed = data_flow_config["flow_pkt_size"]
            flow.rate.percentage = per_dscp_stream_flow_rate
            if data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_DURATION:
                flow.duration.fixed_seconds.seconds = data_flow_config["flow_dur_sec"]
                flow.duration.fixed_seconds.delay.nanoseconds = int(sec_to_nanosec
                                                                    (data_flow_config["flow_delay_sec"]))
            elif data_flow_config["flow_traffic_type"] == traffic_flow_mode.FIXED_PACKETS:
                flow.duration.fixed_packets.packets = data_flow_config["flow_pkt_count"]
                flow.duration.fixed_packets.delay.nanoseconds = int(sec_to_nanosec
                                                                    (data_flow_config["flow_delay_sec"]))
            flow.metrics.enable = True
            flow.metrics.loss = True

    if snappi_test_params.packet_capture_type != packet_capture.NO_CAPTURE:
        snappi_test_params.packet_capture_ports = list(unique_tgen_rx_ports)


def clear_dut_interface_counters(duthost):
    """
    Clears the dut interface counter.
    Args:
        duthost (obj): DUT host object
    """
    duthost.command("sonic-clear counters \n")


def clear_dut_que_counters(duthost):
    """
    Clears the dut que counter.
    Args:
        duthost (obj): DUT host object
    """
    duthost.command("sonic-clear queuecounters \n")


def clear_dut_pfc_counters(duthost):
    """
    Clears the dut pfc counter.
    Args:
        duthost (obj): DUT host object
    """
    duthost.command("sonic-clear pfccounters \n")
    duthost.command("sudo sonic-clear pfccounters \n")


def clear_pfc_counter_after_storm(dut, port, pri):
    """
    Clear PFC counter after PFC storm
    Args:
        dut (obj): DUT host object
        port (str): Port to check PFC storm
        pri (int): Priority to check PFC storm
    Returns:
        bool: True if PFC storm is detected, False otherwise
    """
    stats = get_pfcwd_stats(dut, port, pri)
    if stats['STATUS'] == 'stormed':
        logger.info("PFC storm detected on {}:{}".format(dut.hostname, port))
        # Adding sleep() for the pfc counter to refresh
        time.sleep(1)
        logger.info("Clearing PFC counter after PFC storm")
        clear_dut_pfc_counters(dut)
        return True
    return False


def check_for_crc_errors(api, snappi_extra_params):
    """
    Check for CRC errors in port statistics.
    Args:
        api (obj): snappi session
    Returns:
        None
    """
    ixnetwork = api._ixnetwork
    port_metrics = StatViewAssistant(ixnetwork, 'Port Statistics')
    for row in port_metrics.Rows:
        if int(row['CRC Errors']) > 0:
            for m_port in snappi_extra_params.multi_dut_params.multi_dut_ports:
                if row['Stat Name'] == m_port['location']:
                    pytest.fail("{} CRC Errors detected on Peer Port: {}, Peer Device: {}, snappi port: {}".format(
                                row['CRC Errors'], m_port['peer_port'], m_port['peer_device'], row['Port Name']))


def run_traffic(duthost,
                api,
                config,
                data_flow_names,
                all_flow_names,
                exp_dur_sec,
                snappi_extra_params):

    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        flow_metrics (snappi metrics object): per-flow statistics from TGEN (right after flows end)
        switch_device_results (dict): statistics from DUT on both TX and RX and per priority
        in_flight_flow_metrics (snappi metrics object): in-flight statistics per flow from TGEN
                                                        (right before flows end)
    """

    api.set_config(config)
    ptype = "--snappi_macsec" in sys.argv
    if ptype:
        ixnet = api._ixnetwork
        dp = ixnet.Topology.find().DeviceGroup.find().Ethernet.find().Mka.find().DelayProtect
        dp.Single(False)
        sci_id = ixnet.Topology.find()[1].DeviceGroup.find()[0].Ethernet.find()[0].StaticMacsec.find()[0].DutSciMac
        dut_port = snappi_extra_params.base_flow_config["tx_port_config"].peer_port
        sci_id.Single(duthost.get_dut_iface_mac(dut_port))
        for ti in ixnet.Traffic.TrafficItem.find():
            ti.EnableMacsecEgressOnlyAutoConfig = False
            ti.Tracking.find()[0].TrackBy = []
        ixnet.Traffic.EgressOnlyTracking.find().SignatureLengthType = 'twelveByte'
        mac_str = config.devices[0].ethernets[0].mac
        mac_bytes = mac_str.split(':')[-3:]
        final_bytes = ['00'] + mac_bytes + ['00'] * 6 + ['08', '00']
        for index, et in enumerate(ixnet.Traffic.EgressOnlyTracking.find()):
            et.SignatureValue = ' '.join(final_bytes)
            et.SignatureOffset = 2
            et.SignatureMask = 'FF 00 00 00 FF FF FF FF FF FF 00 00'
            if index == 0:
                et.Egress = [
                    {'arg1': 0, 'arg2': 'FF 00 FF FF'},
                    {'arg1': 52, 'arg2': 'FF FF FF FF'},
                    {'arg1': 52, 'arg2': 'FF FF FF FF'}
                ]
            else:
                et.Egress = [
                    {'arg1': 0, 'arg2': 'FF 03 FF FF'},
                    {'arg1': 52, 'arg2': 'FF FF FF FF'},
                    {'arg1': 52, 'arg2': 'FF FF FF FF'}
                ]

    clear_macsec_counters(duthost)
    """ Starting Protocols """
    logger.info("Starting all protocols ...")
    cs = api.control_state()
    cs.protocol.all.state = cs.protocol.all.START
    api.set_control_state(cs)
    wait(30, "For Protocols To start")

    if not ptype:
        logger.info("Wait for Arp to Resolve ...")
        wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    else:
        protocolsSummary = StatViewAssistant(ixnet, 'Protocols Summary')
        for row in protocolsSummary.Rows:
            if row['Sessions Not Started'] != '0' or row['Sessions Down'] != '0':
                pytest_assert(False, "Not all protocol sessions are up")
        rx_dut_port = snappi_extra_params.base_flow_config["rx_port_config"].peer_port
        for i in range(7):
            eth_stack = config.devices[i].ethernets[0]
            mac_address = eth_stack.mac
            ip_address = eth_stack.ipv4_addresses[0].address
            if duthost.facts["num_asic"] > 1:
                asic_value = duthost.get_port_asic_instance(rx_dut_port).namespace
                cmd = ("sudo ip netns exec {} arp -i {} -s {} {}".
                       format(asic_value, rx_dut_port, ip_address, mac_address))
            else:
                cmd = "sudo arp -i {} -s {} {}".format(rx_dut_port, ip_address, mac_address)
            logger.info(cmd)
            duthost.command(cmd)

    pcap_type = snappi_extra_params.packet_capture_type
    base_flow_config = snappi_extra_params.base_flow_config
    switch_tx_lossless_prios = sum(base_flow_config["dut_port_config"]["Tx"][0].values(), [])
    switch_rx_port = snappi_extra_params.base_flow_config["tx_port_config"].peer_port
    switch_tx_port = snappi_extra_params.base_flow_config["rx_port_config"].peer_port
    switch_device_results = None
    in_flight_flow_metrics = None

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Starting packet capture ...")
        cs = api.control_state()
        cs.port.capture.port_names = snappi_extra_params.packet_capture_ports
        cs.port.capture.state = cs.port.capture.START
        api.set_control_state(cs)

    for host in set([*snappi_extra_params.multi_dut_params.ingress_duthosts,
                     *snappi_extra_params.multi_dut_params.egress_duthosts, duthost]):
        clear_dut_interface_counters(host)
        clear_dut_que_counters(host)
        clear_dut_pfc_counters(host)

    if not ptype:
        logger.info("Starting transmit on all flows ...")
        cs = api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        api.set_control_state(cs)
    else:
        print('Generating Traffic Item')
        trafficItems = ixnet.Traffic.TrafficItem.find()
        for trafficItem in trafficItems:
            trafficItem.Generate()
        print('Applying Traffic')
        ixnet.Traffic.Apply()
        print('Starting Traffic')
        ixnet.Traffic.StartStatelessTrafficBlocking()

    if snappi_extra_params.reboot_type:
        logger.info(f"Issuing a {snappi_extra_params.reboot_type} reboot on the dut {duthost.hostname}")
        # The following reboot command waits until the DUT is accessible by SSH. It does not wait for
        # critical containers to be up. However, if the DUT's system clock is not set correctly after
        # the reboot, it will wait until the clock is synced.
        # The 'wait' parameter should ideally be set to 0, but since reboot overwrites 'wait' if it is 0, I have
        # set it to a very small positive value instead.
        reboot(duthost, snappi_extra_params.localhost, reboot_type=snappi_extra_params.reboot_type,
               delay=0, wait=0.01, return_after_reconnect=True)

    # Test needs to run for at least 10 seconds to allow successive device polling
    if snappi_extra_params.poll_device_runtime and exp_dur_sec > 10:
        logger.info("Polling DUT for traffic statistics for {} seconds ...".format(exp_dur_sec))
        switch_device_results = {}
        switch_device_results["tx_frames"] = {}
        switch_device_results["rx_frames"] = {}
        for lossless_prio in switch_tx_lossless_prios:
            switch_device_results["tx_frames"][lossless_prio] = []
            switch_device_results["rx_frames"][lossless_prio] = []
        exp_dur_sec = exp_dur_sec + ANSIBLE_POLL_DELAY_SEC  # extra time to allow for device polling
        poll_freq_sec = int(exp_dur_sec / 10)

        for poll_iter in range(10):
            for lossless_prio in switch_tx_lossless_prios:
                switch_device_results["tx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_tx_port,
                                                                                                lossless_prio)[0])
                switch_device_results["rx_frames"][lossless_prio].append(get_egress_queue_count(duthost, switch_rx_port,
                                                                                                lossless_prio)[0])
            time.sleep(poll_freq_sec)

            if poll_iter == 5:
                logger.info("Polling TGEN for in-flight traffic statistics...")
                if not ptype:
                    in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
                    flow_names = [
                        metric.name for metric in in_flight_flow_metrics if metric.name in data_flow_names
                    ]
                    tx_frames = [
                        metric.frames_tx for metric in in_flight_flow_metrics if metric.name in data_flow_names
                    ]
                    rx_frames = [
                        metric.frames_rx for metric in in_flight_flow_metrics if metric.name in data_flow_names
                    ]
                else:
                    flow_names, tx_frames, rx_frames = [], [], []
                    in_flight_flow_metrics = fetch_flow_metrics_for_macsec(api).Rows
                    for fs in in_flight_flow_metrics:
                        if int(fs['PGID']) in snappi_extra_params.flow_name_prio_map.values() and \
                           fs['Rx Port'] == snappi_extra_params.base_flow_config["rx_port_name"]:
                            flow_names.append(fs['Traffic Item'] + "-" + fs['PGID'])
                            tx_frames.append(fs['Tx Frames'])
                            rx_frames.append(fs['Rx Frames'])
                logger.info("In-flight traffic statistics for flows: {}".format(flow_names))
                logger.info("In-flight TX frames: {}".format(tx_frames))
                logger.info("In-flight RX frames: {}".format(rx_frames))
                in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
                flow_names = [metric.name for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                tx_frames = [metric.frames_tx for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                rx_frames = [metric.frames_rx for metric in in_flight_flow_metrics if metric.name in data_flow_names]
                rows = list(zip(flow_names, tx_frames, rx_frames))
                logger.info(
                    "In-flight traffic statistics for flows:\n%s",
                    tabulate(rows, headers=["Flow", "Tx", "Rx"], tablefmt="psql"),
                    )

        logger.info("DUT polling complete")
    else:
        time.sleep(exp_dur_sec*(2/5))  # no switch polling required, only TGEN polling
        logger.info("Polling TGEN for in-flight traffic statistics...")
        if not ptype:
            in_flight_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)  # fetch in-flight metrics from TGEN
        else:
            in_flight_flow_metrics = fetch_flow_metrics_for_macsec(api).Rows
        time.sleep(exp_dur_sec*(3/5))

    attempts = 0
    max_attempts = 20
    while attempts < max_attempts:
        logger.info("Checking if all flows have stopped. Attempt #{}".format(attempts + 1))
        if not ptype:
            flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)
            # If all the data flows have stopped
            transmit_states = [metric.transmit for metric in flow_metrics]
            if len(flow_metrics) == len(data_flow_names) and list(set(transmit_states)) == ['stopped']:
                logger.info("All test and background traffic flows stopped")
                time.sleep(SNAPPI_POLL_DELAY_SEC)
                break
            else:
                time.sleep(1)
                attempts += 1
        else:
            flow_metrics = fetch_flow_metrics_for_macsec(api).Rows
            transmit_states = [
                int(float(metric['Tx Frame Rate']))
                for metric in flow_metrics
                if int(metric['PGID']) in snappi_extra_params.flow_name_prio_map.values()
                and metric['Tx Port'] == snappi_extra_params.base_flow_config["tx_port_name"]
            ]
            if list(set(transmit_states)) == [0]:   # Issue encountered, workaround is != instead of ==
                logger.info("All test and background traffic flows stopped")
                time.sleep(SNAPPI_POLL_DELAY_SEC)
                break
            else:
                time.sleep(1)
                attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts))

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.control_state()
        cs.port.capture.state = cs.port.capture.STOP
        api.set_control_state(cs)
        logger.info("Retrieving and saving packet capture to {}.pcapng".format(snappi_extra_params.packet_capture_file))
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    if not ptype:
        flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
    else:
        flow_metrics = fetch_flow_metrics_for_macsec(api).Rows
    logger.info("Stopping transmit on all remaining flows")
    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
    api.set_control_state(cs)
    check_for_crc_errors(api, snappi_extra_params)
    return flow_metrics, switch_device_results, in_flight_flow_metrics


def verify_pause_flow_for_macsec(flow_metrics,
                                 pause_flow_tx_port_name):
    """
    Verify pause flow statistics i.e. all pause frames should be dropped

    Args:
        flow_metrics (list): per-flow statistics
        pause_flow_tx_port_name (str): Tx port name of the pause flow
    Returns:
    """
    pause_flow_row = next(fs for fs in flow_metrics if fs['Tx Port'] == pause_flow_tx_port_name)
    pause_flow_tx_frames = int(pause_flow_row['Tx Frames'])
    pause_flow_rx_frames = int(pause_flow_row['Rx Frames'])

    pytest_assert(pause_flow_tx_frames > 0 and pause_flow_rx_frames == 0,
                  "All the pause frames should be dropped")


def verify_background_flow_stats_for_macsec(flow_metrics,
                                            speed_gbps,
                                            tolerance,
                                            snappi_extra_params):
    """
    Verify if the background flows doesnt see any loss and all flows are received.
    Args:
        api (obj): snappi session
    Returns:

    """
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config
    for flow_name, prio in snappi_extra_params.flow_name_prio_map.items():
        if bg_flow_config["flow_name"] not in flow_name:
            logger.info("Skipping flow {} as it does not match background flow name {}".
                        format(flow_name, bg_flow_config["flow_name"]))
            continue
        for metric in flow_metrics:
            if int(metric['PGID']) == int(prio) and metric['Tx Port'] == \
               snappi_extra_params.base_flow_config["tx_port_name"]:
                tx_frames = int(metric['Tx Frames'])
                rx_frames = int(metric['Rx Frames'])

                exp_bg_flow_rx_pkts = bg_flow_config["flow_rate_percent"] / 100.0 * speed_gbps \
                    * 1e9 * bg_flow_config["flow_dur_sec"] / 8.0 / bg_flow_config["flow_pkt_size"]
                deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)

                pytest_assert(tx_frames == rx_frames,
                              "{} should not have any dropped packet".format(flow_name))

                pytest_assert(abs(deviation) < tolerance,
                              "{} should receive {} packets (actual {})".
                              format(flow_name, exp_bg_flow_rx_pkts, rx_frames))
            else:
                continue


def verify_test_flow_stats_for_macsec(flow_metrics,
                                      speed_gbps,
                                      tolerance,
                                      test_flow_pause,
                                      snappi_extra_params):
    """
    Verify if the background flows doesnt see any loss and all flows are received.
    Args:
        api (obj): snappi session
    Returns:

    """
    test_tx_frames = []
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    for flow_name, prio in snappi_extra_params.flow_name_prio_map.items():
        if data_flow_config["flow_name"] not in flow_name:
            continue
        for metric in flow_metrics:
            if int(metric['PGID']) == int(prio) and \
                    metric['Tx Port'] == snappi_extra_params.base_flow_config["tx_port_name"]:
                tx_frames = int(metric['Tx Frames'])
                rx_frames = int(metric['Rx Frames'])
                test_tx_frames.append(tx_frames)
                if test_flow_pause:
                    pytest_assert(tx_frames > 0 and rx_frames == 0,
                                  "{} should be paused".format(flow_name))
                else:
                    pytest_assert(tx_frames == rx_frames,
                                  "{} should not have any dropped packet".format(flow_name))

                    # Check if flow_rate_percent is a dictionary
                    if isinstance(data_flow_config["flow_rate_percent"], dict):
                        # Extract the priority number from metric.name
                        match = re.search(r'Prio (\d+)', flow_name)
                        prio = int(match.group(1)) if match else None
                        flow_rate_percent = data_flow_config["flow_rate_percent"].get(prio, 0)
                    else:
                        # Use the flow rate percent as is
                        flow_rate_percent = data_flow_config["flow_rate_percent"]

                    exp_test_flow_rx_pkts = flow_rate_percent / 100.0 * speed_gbps \
                        * 1e9 * data_flow_config["flow_dur_sec"] / 8.0 / data_flow_config["flow_pkt_size"]

                    deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
                    pytest_assert(abs(deviation) < tolerance,
                                  "{} should receive {} packets (actual {})".
                                  format(data_flow_config["flow_name"], exp_test_flow_rx_pkts, rx_frames))
            else:
                continue
    snappi_extra_params.test_tx_frames = test_tx_frames


def run_basic_traffic(
    duthost,
    api,
    config,
    data_flow_names,
    all_flow_names,
    exp_dur_sec,
    snappi_extra_params,
):
    """
    Run a basic traffic and return per-flow statistics, and capture packets if needed.
    Suitable for T0/T1 topologies.

    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background) flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        flow_metrics (snappi metrics object): per-flow statistics from TGEN (right after flows end)
        switch_device_results (dict): statistics from DUT on both TX and RX and per priority
        in_flight_flow_metrics (snappi metrics object): in-flight statistics per flow from TGEN
                                                        (right before flows end)
    """
    api.set_config(config)
    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)
    pcap_type = snappi_extra_params.packet_capture_type

    if pcap_type != packet_capture.NO_CAPTURE:
        if snappi_extra_params.ip_capture_filter:
            logger.info("Configuring packet capture filters with IP filter")
            config_capture_settings(api=api,
                                    port_names=snappi_extra_params.packet_capture_ports,
                                    capture_type=snappi_extra_params.packet_capture_type,
                                    ip_filter=snappi_extra_params.ip_capture_filter,
                                    )
        logger.info("Starting packet capture ...")
        cs = api.control_state()
        cs.port.capture.port_names = snappi_extra_params.packet_capture_ports
        cs.port.capture.state = cs.port.capture.START
        api.set_control_state(cs)

    logger.info("Starting transmit on all flows ...")
    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
    api.set_control_state(cs)

    time.sleep(exp_dur_sec * (2 / 5))
    logger.info("Polling TGEN for in-flight traffic statistics...")
    tgen_in_flight_flow_metrics = fetch_snappi_flow_metrics(
        api, all_flow_names
    )  # fetch in-flight metrics from TGEN
    time.sleep(exp_dur_sec * (3 / 5))

    attempts = 0
    max_attempts = 20

    while attempts < max_attempts:
        logger.info(
            "Checking if all flows have stopped. Attempt #{}".format(attempts + 1)
        )
        flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)

        # If all the data flows have stopped
        transmit_states = [metric.transmit for metric in flow_metrics]
        if len(flow_metrics) == len(data_flow_names) and list(set(transmit_states)) == [
            "stopped"
        ]:
            logger.info("All test and background traffic flows stopped")
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            time.sleep(1)
            attempts += 1

    pytest_assert(
        attempts < max_attempts, "Flows do not stop in {} seconds".format(max_attempts)
    )

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.control_state()
        cs.port.capture.state = cs.port.capture.STOP
        api.set_control_state(cs)
        logger.info(
            f"Retrieving and saving packet capture to {snappi_extra_params.packet_capture_file}.pcapng"
        )
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", "wb") as fid:
            fid.write(pcap_bytes.getvalue())

    # Dump per-flow statistics
    logger.info("Dumping per-flow statistics")
    tgen_flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
    logger.info("Stopping transmit on all remaining flows")
    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
    api.set_control_state(cs)

    return tgen_flow_metrics, tgen_in_flight_flow_metrics


def verify_pause_flow(flow_metrics,
                      pause_flow_name):
    """
    Verify pause flow statistics i.e. all pause frames should be dropped

    Args:
        flow_metrics (list): per-flow statistics
        pause_flow_name (str): name of the pause flow
    Returns:
    """
    pause_flow_row = next(metric for metric in flow_metrics if metric.name == pause_flow_name)
    pause_flow_tx_frames = pause_flow_row.frames_tx
    pause_flow_rx_frames = pause_flow_row.frames_rx

    pytest_assert(pause_flow_tx_frames > 0 and pause_flow_rx_frames == 0,
                  "All the pause frames should be dropped")


def verify_macsec_stats(
                        flow_metrics,
                        ingress_duthost,
                        egress_duthost,
                        ingress_port,
                        egress_port,
                        api,
                        snappi_extra_params):
    """
    Verify macsec statistics

    Args:
        flow_metrics (list): per-flow statistics
        ingress_duthost (obj): ingress DUT host object
        egress_duthost (obj): egress DUT host object
        ingress_port (list): list of ingress ports
        egress_port (list): list of egress ports
        api (obj): snappi session
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
    """
    macsec_stats = {}
    final_port_list = [ingress_port] + [egress_port]
    for item in final_port_list:
        macsec_stats.update(flatten_dict(get_dict_macsec_counters(item['duthost'], item['peer_port'])))
    logger.info("Macsec stats: {}".format(macsec_stats))
    # TODO: Need to add code to use macsec_stats(dictionary) and compare with flow metrics


def verify_background_flow(flow_metrics,
                           speed_gbps,
                           tolerance,
                           snappi_extra_params):
    """
    Verify background flow statistics. Background traffic on lossy priorities should not be dropped when there is no
    congestion, else some packets should be dropped if there is congestion.

    Args:
        flow_metrics (list): per-flow statistics
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for background flow deviation
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    bg_flow_config = snappi_extra_params.traffic_flow_config.background_flow_config

    for metric in flow_metrics:
        if bg_flow_config["flow_name"] not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx

        exp_bg_flow_rx_pkts = bg_flow_config["flow_rate_percent"] / 100.0 * speed_gbps \
            * 1e9 * bg_flow_config["flow_dur_sec"] / 8.0 / bg_flow_config["flow_pkt_size"]
        deviation = (rx_frames - exp_bg_flow_rx_pkts) / float(exp_bg_flow_rx_pkts)

        pytest_assert(tx_frames == rx_frames,
                      "{} should not have any dropped packet".format(metric.name))

        pytest_assert(abs(deviation) < tolerance,
                      "{} should receive {} packets (actual {})".format(metric.name, exp_bg_flow_rx_pkts, rx_frames))


def verify_basic_test_flow(flow_metrics,
                           speed_gbps,
                           tolerance,
                           test_flow_pause,
                           snappi_extra_params):
    """
    Verify basic test flow statistics from ixia. Test traffic on lossless priorities should not be dropped regardless
    of whether there is congestion or not.

    Args:
        flow_metrics (list): per-flow statistics
        speed_gbps (int): speed of the port in Gbps
        tolerance (float): tolerance for test flow deviation
        test_flow_pause (bool): whether test flow is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    test_tx_frames = []
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config

    for metric in flow_metrics:
        if data_flow_config["flow_name"] not in metric.name:
            continue

        tx_frames = metric.frames_tx
        rx_frames = metric.frames_rx
        test_tx_frames.append(tx_frames)

        if test_flow_pause:
            pytest_assert(tx_frames > 0 and rx_frames == 0,
                          "{} should be paused".format(metric.name))
        else:
            pytest_assert(tx_frames == rx_frames,
                          "{} should not have any dropped packet".format(metric.name))

            # Check if flow_rate_percent is a dictionary
            if isinstance(data_flow_config["flow_rate_percent"], dict):
                # Extract the priority number from metric.name
                match = re.search(r'Prio (\d+)', metric.name)
                prio = int(match.group(1)) if match else None
                flow_rate_percent = data_flow_config["flow_rate_percent"].get(prio, 0)
            else:
                # Use the flow rate percent as is
                flow_rate_percent = data_flow_config["flow_rate_percent"]

            exp_test_flow_rx_pkts = flow_rate_percent / 100.0 * speed_gbps \
                * 1e9 * data_flow_config["flow_dur_sec"] / 8.0 / data_flow_config["flow_pkt_size"]

            deviation = (rx_frames - exp_test_flow_rx_pkts) / float(exp_test_flow_rx_pkts)
            pytest_assert(abs(deviation) < tolerance,
                          "{} should receive {} packets (actual {})".
                          format(data_flow_config["flow_name"], exp_test_flow_rx_pkts, rx_frames))

    snappi_extra_params.test_tx_frames = test_tx_frames


def verify_in_flight_buffer_pkts(egress_duthost,
                                 ingress_duthost,
                                 flow_metrics,
                                 snappi_extra_params, asic_value=None):
    """
    Verify in-flight TX bytes of test flows should be held by switch buffer unless PFC delay is applied
    for when test traffic is expected to be paused

    Args:
        egress_duthost  (obj): DUT host object for egress.
        ingress_duthost (obj): DUT host object for ingress.
        flow_metrics (list): per-flow statistics
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    ptype = "--snappi_macsec" in sys.argv
    data_flow_config = snappi_extra_params.traffic_flow_config.data_flow_config
    if not ptype:
        tx_frames_total = sum(
            metric.frames_tx for metric in flow_metrics if data_flow_config["flow_name"] in metric.name
        )
    else:
        tx_frames_total = 0
        for flow_name, prio in snappi_extra_params.flow_name_prio_map.items():
            if data_flow_config["flow_name"] not in flow_name:
                continue
            for metric in flow_metrics:
                if (int(metric["PGID"]) == prio and
                   metric['Tx Port'] == snappi_extra_params.base_flow_config["tx_port_name"]):
                    tx_frames_total += int(metric['Tx Frames'])
    tx_bytes_total = tx_frames_total * data_flow_config["flow_pkt_size"]
    dut_buffer_size = get_lossless_buffer_size(host_ans=ingress_duthost)
    headroom_test_params = snappi_extra_params.headroom_test_params
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, "Flow port config is not provided")

    if headroom_test_params is None:
        exceeds_headroom = False
    elif headroom_test_params[1]:
        exceeds_headroom = False
    else:
        exceeds_headroom = True

    if exceeds_headroom:
        pytest_assert(tx_bytes_total > dut_buffer_size,
                      "Total TX bytes {} should exceed DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config["Tx"][0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(egress_duthost, peer_port, prio, asic_value)
                pytest_assert(dropped_packets > 0,
                              "Total TX dropped packets {} should be more than 0".
                              format(dropped_packets))
    else:
        pytest_assert(tx_bytes_total < dut_buffer_size,
                      "Total TX bytes {} should be smaller than DUT buffer size {}".
                      format(tx_bytes_total, dut_buffer_size))

        for peer_port, prios in dut_port_config["Tx"][0].items():
            for prio in prios:
                dropped_packets = get_pg_dropped_packets(egress_duthost, peer_port, prio, asic_value)
                pytest_assert(dropped_packets == 0,
                              "Total TX dropped packets {} should be 0".
                              format(dropped_packets))


def verify_pause_frame_count_dut(rx_dut,
                                 tx_dut,
                                 test_traffic_pause,
                                 global_pause,
                                 snappi_extra_params):
    """
    Verify correct frame count for pause frames when the traffic is expected to be paused or not
    on the DUT

    Args:
        rx_dut (obj): Ingress DUT host object receiving packets from IXIA transmitter.
        tx_dut (obj): Egress DUT host object sending packets to IXIA, hence also receiving PFCs from IXIA.
        test_traffic_pause (bool): whether test traffic is expected to be paused
        global_pause (bool): if pause frame is IEEE 802.3X pause i.e. global pause applied
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')

    for peer_port, prios in dut_port_config["Rx"][0].items():  # PFC pause frames received on DUT's egress port
        for prio in prios:
            pfc_pause_rx_frames = get_pfc_frame_count(tx_dut, peer_port, prio, is_tx=False)
            # For now, all PFC pause test cases send out PFC pause frames from the TGEN RX port to the DUT TX port,
            # except the case with global pause frames which SONiC does not count currently
            if global_pause:
                pytest_assert(pfc_pause_rx_frames == 0,
                              "Global pause frames should not be counted in RX PFC counters for priority {}"
                              .format(prio))
            elif not snappi_extra_params.set_pfc_class_enable_vec:
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames with no bit set in the class enable vector should be dropped")
            else:
                if ((len(prios) > 1 and is_cisco_device(tx_dut) and not test_traffic_pause) or
                    (len(prios) == 1 and is_cisco_device(tx_dut) and
                     "x86_64-8122" in tx_dut.facts['platform'] and not test_traffic_pause)):
                    pytest_assert(pfc_pause_rx_frames == 0,
                                  "PFC pause frames should not be counted in RX PFC counters for priority {}"
                                  .format(prios))
                else:
                    pytest_assert(pfc_pause_rx_frames > 0,
                                  "PFC pause frames should be received and counted in RX PFC counters for priority {}"
                                  .format(prio))
    for peer_port, prios in dut_port_config["Tx"][0].items():  # PFC pause frames sent by DUT's ingress port to TGEN
        for prio in prios:
            pfc_pause_tx_frames = get_pfc_frame_count(rx_dut, peer_port, prio, is_tx=True)
            if test_traffic_pause:
                pytest_assert(pfc_pause_tx_frames > 0,
                              "PFC pause frames should be transmitted and counted in TX PFC counters for priority {}"
                              .format(prio))
            else:
                # PFC pause frames should not be transmitted when test traffic is not paused
                pytest_assert(pfc_pause_tx_frames == 0,
                              "PFC pause frames should not be transmitted and counted in TX PFC counters")


def verify_tx_frame_count_dut(duthost,
                              api,
                              snappi_extra_params,
                              tx_frame_count_deviation=0.05,
                              tx_drop_frame_count_tol=5):
    """
    Verify correct frame count for tx frames on the DUT
    (OK and DROPS) when the traffic is expected to be paused on the DUT.
    DUT is polled after it stops receiving PFC pause frames from TGEN.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        tx_frame_count_deviation (float): deviation for tx frame count (default to 1%)
        tx_drop_frame_count_tol (int): tolerance for tx drop frame count
    Returns:

    """
    ptype = "--snappi_macsec" in sys.argv
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    test_flow_name_dut_tx_port_map = snappi_extra_params.base_flow_config["test_flow_name_dut_tx_port_map"]

    # RX frames on DUT must TX once DUT stops receiving PFC pause frames
    for peer_port, _ in dut_port_config["Rx"][0].items():
        # Collect metrics from TGEN once all flows have stopped
        test_flow_name = next((test_flow_name for test_flow_name, dut_tx_ports in test_flow_name_dut_tx_port_map.items()
                               if peer_port in dut_tx_ports), None)
        if not ptype:
            tgen_test_flow_metrics = fetch_snappi_flow_metrics(api, [test_flow_name])
        else:
            tgen_test_flow_metrics = fetch_flow_metrics_for_macsec(api).Rows
        pytest_assert(tgen_test_flow_metrics, "TGEN test flow metrics is not provided")
        if not ptype:
            tgen_tx_frames = tgen_test_flow_metrics[0].frames_tx
        else:
            for tgen_test_flow_metric in tgen_test_flow_metrics:
                if tgen_test_flow_metric['Tx Port'] == snappi_extra_params.base_flow_config["tx_port_name"] and \
                   int(tgen_test_flow_metric['PGID']) == snappi_extra_params.flow_name_prio_map[test_flow_name]:
                    tgen_tx_frames = tgen_test_flow_metric['Tx Frames']
                    break

        # Collect metrics from DUT once all flows have stopped
        tx_dut_frames, tx_dut_drop_frames = get_tx_frame_count(duthost, peer_port)

        # Verify metrics between TGEN and DUT
        pytest_assert(abs(tgen_tx_frames - tx_dut_frames)/tgen_tx_frames <= tx_frame_count_deviation,
                      "Additional frames are transmitted outside of deviation. Possible PFC frames are counted.")
        pytest_assert(tx_dut_drop_frames <= tx_drop_frame_count_tol, "No frames should be dropped")


def verify_rx_frame_count_dut(duthost,
                              api,
                              snappi_extra_params,
                              rx_frame_count_deviation=0.05,
                              rx_drop_frame_count_tol=5):
    """
    Verify correct frame count for rx frames on the DUT
    (OK and DROPS) when the traffic is expected to be paused on the DUT.
    Args:
        duthost (obj): DUT host object
        api (obj): snappi session
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        rx_frame_count_deviation (float): deviation for rx frame count (default to 1%)
        rx_drop_frame_count_tol (int): tolerance for tx drop frame count
    Returns:

    """
    ptype = "--snappi_macsec" in sys.argv
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    test_flow_name_dut_rx_port_map = snappi_extra_params.base_flow_config["test_flow_name_dut_rx_port_map"]

    # TX on TGEN is RX on DUT
    for peer_port, _ in dut_port_config["Tx"][0].items():
        # Collect metrics from TGEN once all flows have stopped
        test_flow_name = next((test_flow_name for test_flow_name, dut_rx_ports in test_flow_name_dut_rx_port_map.items()
                               if peer_port in dut_rx_ports), None)
        if not ptype:
            tgen_test_flow_metrics = fetch_snappi_flow_metrics(api, [test_flow_name])
        else:
            tgen_test_flow_metrics = fetch_flow_metrics_for_macsec(api).Rows
        pytest_assert(tgen_test_flow_metrics, "TGEN test flow metrics is not provided")
        if not ptype:
            tgen_rx_frames = tgen_test_flow_metrics[0].frames_rx
        else:
            for tgen_test_flow_metric in tgen_test_flow_metrics:
                if tgen_test_flow_metric['Tx Port'] == snappi_extra_params.base_flow_config["tx_port_name"] and \
                   int(tgen_test_flow_metric['PGID']) == snappi_extra_params.flow_name_prio_map[test_flow_name]:
                    tgen_rx_frames = tgen_test_flow_metric['Rx Frames']
                    break

        # Collect metrics from DUT once all flows have stopped
        rx_frames, rx_drop_frames = get_rx_frame_count(duthost, peer_port)

        # Verify metrics between TGEN and DUT
        pytest_assert(abs(tgen_rx_frames - rx_frames)/tgen_rx_frames <= rx_frame_count_deviation,
                      "Additional frames are received outside of deviation. Possible PFC frames are counted.")
        pytest_assert(rx_drop_frames <= rx_drop_frame_count_tol, "No frames should be dropped")


def verify_unset_cev_pause_frame_count(duthost,
                                       snappi_extra_params):
    """
    Verify zero pause frames are counted when the PFC class enable vector is not set

    Args:
        duthost (obj): DUT host object
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:

    """
    dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec

    if not set_class_enable_vec:
        for peer_port, prios in dut_port_config["Rx"][0].items():
            for prio in prios:
                pfc_pause_rx_frames = get_pfc_frame_count(duthost, peer_port, prio)
                pytest_assert(pfc_pause_rx_frames == 0,
                              "PFC pause frames with no bit set in the class enable vector should be dropped")


def verify_egress_queue_frame_count(duthost,
                                    switch_flow_stats,
                                    test_traffic_pause,
                                    snappi_extra_params,
                                    egress_queue_frame_count_tol=10):
    """
    Verify correct frame count for regular traffic from DUT egress queue

    Args:
        duthost (obj): DUT host object
        switch_flow_stats (dict): switch flow statistics
        test_traffic_pause (bool): whether test traffic is expected to be paused
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
        egress_queue_frame_count_tol (int): tolerance for egress queue frame count when traffic is expected
                                            to be paused
    Returns:

    """
    # If snappi_extra_params.base_flow_config_list exists,
    # assign base_flow_config[0]["dut_port_config"] to dut_port_config.
    if not snappi_extra_params.base_flow_config_list:
        dut_port_config = snappi_extra_params.base_flow_config["dut_port_config"]
    else:
        dut_port_config = snappi_extra_params.base_flow_config_list[0]["dut_port_config"]

    pytest_assert(dut_port_config is not None, 'Flow port config is not provided')
    set_class_enable_vec = snappi_extra_params.set_pfc_class_enable_vec
    test_tx_frames = snappi_extra_params.test_tx_frames

    if test_traffic_pause:
        pytest_assert(switch_flow_stats, "Switch flow statistics is not provided")
        for prio, poll_data in switch_flow_stats["tx_frames"].items():
            mid_poll_index = int(len(poll_data)/2)
            next_poll_index = mid_poll_index + 1
            mid_poll_egress_queue_count = switch_flow_stats["tx_frames"][prio][mid_poll_index]
            next_poll_egress_queue_count = switch_flow_stats["tx_frames"][prio][next_poll_index]
            pytest_assert(next_poll_egress_queue_count - mid_poll_egress_queue_count <= egress_queue_frame_count_tol,
                          "Egress queue frame count should not increase when test traffic is paused")

    if not set_class_enable_vec and not test_traffic_pause:
        for peer_port, prios in dut_port_config["Rx"][0].items():
            for prio in range(len(prios)):
                total_egress_packets, _ = get_egress_queue_count(duthost, peer_port, prios[prio])
                pytest_assert(total_egress_packets == test_tx_frames[prio],
                              "Queue counters should increment for invalid PFC pause frames")


def tgen_curr_stats(traf_metrics, flow_metrics, data_flow_names):
    """
    Print the current tgen metrics

    Arg:
        traf_metrics (obj): Current traffic item stats on IXIA.
        curr_flow_metrics (obj): Current tgen stats.
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic.
    Returns:
        stats (dictionary): Dictionary of DUTs statistics

    """
    stats = {}
    for metric in traf_metrics:
        if metric['Traffic Item'] not in data_flow_names:
            continue
        rx_rate_gbps = 0
        tx_rate_gbps = 0
        if (int(metric['Rx Rate (Mbps)'] != 0)):
            rx_rate_gbps = round(float(metric['Rx Rate (Mbps)'])*1024/(10**6), 2)
        if (int(metric['Tx Rate (Mbps)'] != 0)):
            tx_rate_gbps = round(float(metric['Tx Rate (Mbps)'])*1024/(10**6), 2)

        metric_name = metric['Traffic Item'].replace(' ', '_').lower()
        stats[metric_name+'_txrate_fps'] = float(metric['Tx Frame Rate'])
        stats[metric_name+'_txrate_Gbps'] = tx_rate_gbps
        stats[metric_name+'_rxrate_fps'] = float(metric['Rx Frame Rate'])
        stats[metric_name+'_rxrate_Gbps'] = rx_rate_gbps
        stats[metric_name+'_Rx_L1_Rate_bps'] = float(metric['Rx L1 Rate (bps)'])

    for metric in flow_metrics:
        if metric.name not in data_flow_names:
            continue
        metric_name = metric.name.replace(' ', '_').lower()
        stats[metric_name+'_rx_pkts'] = metric.frames_rx
        stats[metric_name+'_tx_pkts'] = metric.frames_tx
        stats[metric_name+'_loss'] = metric.loss
        stats[metric_name+'_avg_latency_ns'] = metric.latency.average_ns
        stats[metric_name+'_max_latency_ns'] = metric.latency.maximum_ns
        stats[metric_name+'_min_latency_ns'] = metric.latency.minimum_ns
    return stats


def run_traffic_and_collect_stats(rx_duthost,
                                  tx_duthost,
                                  api,
                                  config,
                                  data_flow_names,
                                  all_flow_names,
                                  exp_dur_sec,
                                  port_map,
                                  fname,
                                  stats_interval,
                                  imix,
                                  snappi_extra_params,
                                  enable_pfcwd_drop=None):

    """
    Run traffic and return per-flow statistics, and capture packets if needed.
    Args:
        rx_duthost (obj): Traffic receiving DUT host object - Ingress DUT
        tx_duthost (obj): Traffic transmitting DUT host object - Egress DUT
        api (obj): snappi session
        config (obj): experiment config (testbed config + flow config)
        data_flow_names (list): list of names of data (test and background flows
        all_flow_names (list): list of names of all the flows
        exp_dur_sec (int): experiment duration in second
        snappi_extra_params (SnappiTestParams obj): additional parameters for Snappi traffic
    Returns:
        per-flow statistics (list)
    """
    # Returns true if any value in prio_list contains the flow_name.
    def check_presence(flow_name, prio_list):
        return any(m in flow_name for m in prio_list)

    # Returns true if string is absent in all prio_list.
    def check_absence(flow_name, prio_list):
        return all(m not in flow_name for m in prio_list)

    api.set_config(config)

    logger.info("Wait for Arp to Resolve ...")
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    pcap_type = snappi_extra_params.packet_capture_type

    dutport_list = []

    for m in snappi_extra_params.multi_dut_params.multi_dut_ports:
        if m['peer_device'] == snappi_extra_params.multi_dut_params.duthost1.hostname:
            dutport_list.append([snappi_extra_params.multi_dut_params.duthost1, m['peer_port']])
        else:
            dutport_list.append([snappi_extra_params.multi_dut_params.duthost2, m['peer_port']])

    rx_port_config_values = snappi_extra_params.base_flow_config_list[0]["dut_port_config"]["Rx"][0].values()
    switch_tx_lossless_prios = sum(rx_port_config_values, [])
    # Generating list with lossless priorities starting with keyword 'prio_'
    prio_list = ['prio_{}'.format(num) for num in switch_tx_lossless_prios]

    # Clearing stats before starting the test
    # PFC, counters, queue-counters and dropcounters
    # logger.debug('Clearing PFC, dropcounters, queuecounters and stats')
    for dut, port in dutport_list:
        clear_counters(dut, port)

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Starting packet capture ...")
        cs = api.control_state()
        cs.port.capture.port_names = snappi_extra_params.packet_capture_ports
        cs.port.capture.state = cs.port.capture.START
        api.set_control_state(cs)

    # Returns the rest API object for features not present in Snappi
    ixnet_rest_api = api._ixnetwork

    # If imix flag is set, IMIX packet-profile is enabled.
    if (imix):
        logger.info('Test packet-profile setting to IMIX')
        for traff_item in ixnet_rest_api.Traffic.TrafficItem.find():
            config_ele = traff_item.ConfigElement.find()[0].FrameSize
            config_ele.PresetDistribution = "imix"
            config_ele.Type = "weightedPairs"
            config_ele.WeightedPairs = ["128", "7", "570", "4", "1518", "1"]

        ixnet_rest_api.Traffic.TrafficItem.find().Generate()
        ixnet_rest_api.Traffic.Apply()

    logger.info("Starting transmit on all flows ...")
    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
    api.set_control_state(cs)

    stormed = False
    if tx_duthost.facts["platform_asic"] == 'cisco-8000' and enable_pfcwd_drop:
        retry = 3
        while retry > 0 and not stormed:
            for dut, port in dutport_list:
                for pri in switch_tx_lossless_prios:
                    stormed = clear_pfc_counter_after_storm(dut, port, pri)
                    if stormed:
                        clear_dut_pfc_counters(rx_duthost)
                        clear_dut_pfc_counters(tx_duthost)
                        logger.info("PFC storm detected on {}:{}".format(dut.hostname, port))
                        break  # break inner for
                if stormed:
                    break  # break outer for
            retry = retry - 1
            if retry and not stormed:
                time.sleep(2)
        pytest_assert(stormed, "PFC storm not detected")

    time.sleep(5)
    iter_count = round((int(exp_dur_sec) - stats_interval)/stats_interval)

    f_stats = {}
    logger.info('Polling DUT and tool for traffic statistics for {} iterations and {} seconds'.
                format(iter_count, exp_dur_sec))
    switch_device_results = {}
    switch_device_results["tx_frames"] = {}
    switch_device_results["rx_frames"] = {}
    for lossless_prio in switch_tx_lossless_prios:
        switch_device_results["tx_frames"][lossless_prio] = []
        switch_device_results["rx_frames"][lossless_prio] = []

    exp_dur_sec = exp_dur_sec + ANSIBLE_POLL_DELAY_SEC

    for m in range(int(iter_count)):
        now = datetime.now()
        logger.info('----------- Collecting Stats for Iteration : {} ------------'.format(m+1))
        f_stats[m] = {'Date': datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}
        flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)
        traf_metrics = StatViewAssistant(ixnet_rest_api, 'Traffic Item Statistics').Rows
        tx_frame = sum([metric.frames_tx for metric in flow_metrics if metric.name in data_flow_names])
        f_stats[m]['tgen_tx_frames'] = tx_frame
        rx_frame = sum([metric.frames_rx for metric in flow_metrics if metric.name in data_flow_names])
        f_stats[m]['tgen_rx_frames'] = rx_frame
        f_stats = update_dict(m, f_stats, tgen_curr_stats(traf_metrics, flow_metrics, data_flow_names))
        for dut, port in dutport_list:
            f_stats = update_dict(m, f_stats, flatten_dict(get_interface_stats(dut, port)))
            f_stats = update_dict(m, f_stats, flatten_dict(get_interface_counters_detailed(dut, port)))
            f_stats = update_dict(m, f_stats, flatten_dict(get_pfc_count(dut, port)))
            f_stats = update_dict(m, f_stats, flatten_dict(get_queue_count_all_prio(dut, port)))

        logger.info("Polling DUT for Egress Queue statistics")

        for lossless_prio in switch_tx_lossless_prios:
            count_frames = 0
            for n in range(port_map[0]):
                dut, port = dutport_list[n]
                count_frames = count_frames + (get_egress_queue_count(dut, port, lossless_prio)[0])
                logger.info(
                    'Egress Queue Count for DUT:{}, Port:{}, Priority:{} - {}'.format(
                        dut.hostname, port, lossless_prio, count_frames
                        )
                    )
            switch_device_results["tx_frames"][lossless_prio].append(count_frames)
            count_frames = 0
            for n in range(port_map[2]):
                dut, port = dutport_list[-(n+1)]
                count_frames = count_frames + (get_egress_queue_count(dut, port, lossless_prio)[0])
            switch_device_results["rx_frames"][lossless_prio].append(count_frames)
        later = datetime.now()
        time.sleep(abs(round(stats_interval - ((later - now).total_seconds()))))
        logger.info('------------------------------------------------------------')

    attempts = 0
    max_attempts = 10

    while attempts < max_attempts:
        logger.info("Checking if all flows have stopped. Attempt #{}".format(attempts + 1))
        flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)

        # If all the data flows have stopped
        transmit_states = [metric.transmit for metric in flow_metrics]
        if len(flow_metrics) == len(data_flow_names) and\
           list(set(transmit_states)) == ['stopped']:
            logger.info("All test and background traffic flows stopped")
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        else:
            if (attempts == 4):
                logger.info("Stopping transmit on all remaining flows")
                cs = api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
                api.set_control_state(cs)
            time.sleep(stats_interval/4)
            attempts += 1

    pytest_assert(attempts < max_attempts,
                  "Flows do not stop in {} seconds".format(max_attempts*stats_interval))

    if pcap_type != packet_capture.NO_CAPTURE:
        logger.info("Stopping packet capture ...")
        request = api.capture_request()
        request.port_name = snappi_extra_params.packet_capture_ports[0]
        cs = api.control_state()
        cs.port.capture.state = cs.port.capture.STOP
        api.set_control_state(cs)
        logger.info("Retrieving and saving packet capture to {}.pcapng".format(snappi_extra_params.packet_capture_file))
        pcap_bytes = api.get_capture(request)
        with open(snappi_extra_params.packet_capture_file + ".pcapng", 'wb') as fid:
            fid.write(pcap_bytes.getvalue())

    time.sleep(5)
    # Counting egress queue frames at the end of the test.
    for lossless_prio in switch_tx_lossless_prios:
        count_frames = 0
        for n in range(port_map[0]):
            dut, port = dutport_list[n]
            count_frames = count_frames + (get_egress_queue_count(dut, port, lossless_prio)[0])
            logger.info(
                'Final egress Queue Count for DUT:{},Port:{}, Priority:{} - {}'.format(
                    dut.hostname, port, lossless_prio, count_frames
                    )
                )
        switch_device_results["tx_frames"][lossless_prio].append(count_frames)
        count_frames = 0
        for n in range(port_map[2]):
            dut, port = dutport_list[-(n+1)]
            count_frames = count_frames + (get_egress_queue_count(dut, port, lossless_prio)[0])
        switch_device_results["rx_frames"][lossless_prio].append(count_frames)

    # Dump per-flow statistics for final rows
    logger.info("Dumping per-flow statistics for final row")
    m = iter_count
    f_stats[m] = {'Date': datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}
    flow_metrics = fetch_snappi_flow_metrics(api, data_flow_names)
    traf_metrics = StatViewAssistant(ixnet_rest_api, 'Traffic Item Statistics').Rows
    tx_frame = sum([metric.frames_tx for metric in flow_metrics if metric.name in data_flow_names])
    rx_frame = sum([metric.frames_rx for metric in flow_metrics if metric.name in data_flow_names])
    f_stats[m]['tgen_tx_frames'] = tx_frame
    f_stats[m]['tgen_rx_frames'] = rx_frame
    f_stats = update_dict(m, f_stats, tgen_curr_stats(traf_metrics, flow_metrics, data_flow_names))
    for dut, port in dutport_list:
        f_stats = update_dict(m, f_stats, flatten_dict(get_interface_stats(dut, port)))
        f_stats = update_dict(m, f_stats, flatten_dict(get_pfc_count(dut, port)))
        f_stats = update_dict(m, f_stats, flatten_dict(get_queue_count_all_prio(dut, port)))

    flow_metrics = fetch_snappi_flow_metrics(api, all_flow_names)
    time.sleep(10)

    df = pd.DataFrame(f_stats)
    df_t = df.T
    df_t = df_t.reindex(sorted(df_t.columns), axis=1)
    flow_list = []
    all_flow_names = [flow.name for flow in config.flows]
    for item in all_flow_names:
        flow_list.append(item.replace(' ', '_').lower())
    results = list(df_t.columns)
    fname = fname + '-' + datetime.now().strftime('%Y-%m-%d-%H-%M')
    with open(fname+'.txt', 'w') as f:
        f.write('Captured data for {} iterations at {} seconds interval \n'.format(m, stats_interval))
        test_stats = {}
        test_stats['tgen_loss_pkts'] = 0
        test_stats['tgen_lossy_rx_pkts'] = 0
        test_stats['tgen_lossy_tx_pkts'] = 0
        test_stats['tgen_lossless_rx_pkts'] = 0
        test_stats['tgen_lossless_tx_pkts'] = 0
        test_stats['tgen_rx_rate'] = 0
        test_stats['tgen_tx_rate'] = 0
        for flow in flow_list:
            rx_rate = 0
            tx_rate = 0
            for item in results:
                if (flow in item and item.split(flow)[1] == '_avg_latency_ns'):
                    avg_latency = round(df_t[item].mean(), 2)
                if (flow in item and item.split(flow)[1] == '_rx_pkts'):
                    rx_pkts = df_t[item].max()
                # Incrementing TGEN lossless priority Rx packets.
                if (flow in item and item.split(flow)[1] == '_rx_pkts' and (check_presence(flow, prio_list))):
                    test_stats['tgen_lossless_rx_pkts'] += rx_pkts
                # Incrementing TGEN lossy priority Rx packets.
                if (flow in item and item.split(flow)[1] == '_rx_pkts'
                        and (check_absence(flow, prio_list))):
                    test_stats['tgen_lossy_rx_pkts'] += rx_pkts
                if (flow in item and item.split(flow)[1] == '_tx_pkts'):
                    tx_pkts = df_t[item].max()
                # Incrementing lossless priority Tx packets.
                if ((flow in item and item.split(flow)[1] == '_tx_pkts')
                        and (check_presence(flow, prio_list))):
                    test_stats['tgen_lossless_tx_pkts'] += tx_pkts
                # Incrementing lossy priority Tx packets.
                if ((flow in item and item.split(flow)[1] == '_tx_pkts')
                        and (check_absence(flow, prio_list))):
                    test_stats['tgen_lossy_tx_pkts'] += tx_pkts
                if (flow in item and item.split(flow)[1] == '_rxrate_Gbps'):
                    if (df_t[item].sum() != 0):
                        rx_rate = round(df_t.loc[df_t[item] != 0, item].mean(), 2)
                    else:
                        rx_rate = 0
                    test_stats['tgen_rx_rate'] += round(rx_rate, 2)
                if (flow in item and item.split(flow)[1] == '_txrate_Gbps'):
                    tx_rate = round(df_t.loc[df_t[item] != 0, item].mean(), 2)
                    test_stats['tgen_tx_rate'] += round(tx_rate, 2)
                if (flow in item and item.split(flow)[1] == '_loss'):
                    loss = df_t[item].max()
            if ('pause' not in flow):
                test_stats['tgen_loss_pkts'] += (int(tx_pkts) - int(rx_pkts))
            f.write('For {} - Avg_Latency:{}, rx_pkts:{}, tx_pkts:{}, rx_thrput:{}, tx_thrput:{} and loss prcnt:{} \n'
                    .format(flow, avg_latency, rx_pkts, tx_pkts, rx_rate, tx_rate, loss))
        f.write('Total Lossless Rx pkts:{} and Tx pkts:{} \n'.
                format(test_stats['tgen_lossless_rx_pkts'], test_stats['tgen_lossless_tx_pkts']))
        f.write('Total Lossy Rx pkts:{} and Tx pkts:{} \n'.
                format(test_stats['tgen_lossy_rx_pkts'], test_stats['tgen_lossy_tx_pkts']))
        f.write('Total TGEN Loss Pkts:{} \n'.format(test_stats['tgen_loss_pkts']))
        # Computing DUT Tx-Rx throughput, packets and failures via interface stats.
        test_stats['dut_loss_pkts'] = 0
        for dut, port in dutport_list:
            new_key = (dut.hostname + '_' + port).lower()
            rx_thrput = 0
            tx_thrput = 0
            for item in results:
                if (new_key in item and item.split(new_key)[1] == '_rx_thrput_Mbps'):
                    rx_thrput = round(df_t.loc[df_t[item] != 0, item].mean(), 2)
                if (new_key in item and item.split(new_key)[1] == '_tx_thrput_Mbps'):
                    tx_thrput = round(df_t.loc[df_t[item] != 0, item].mean(), 2)
                if (new_key in item and item.split(new_key)[1] == '_rx_pkts'):
                    rx_pkts = df_t[item].max()
                if (new_key in item and item.split(new_key)[1] == '_tx_pkts'):
                    tx_pkts = df_t[item].max()
                if (new_key in item and item.split(new_key)[1] == '_tx_fail'):
                    tx_fail = df_t[item].max()
                if (new_key in item and item.split(new_key)[1] == '_rx_fail'):
                    rx_fail = df_t[item].max()
            test_stats['dut_loss_pkts'] += (int(tx_fail) + int(rx_fail))
            f.write('For {} - rx_pkts:{}, tx_pkts:{}, rx_thrput:{}, tx_thrput:{} and rx_loss:{}, tx_loss:{} \n'.
                    format(new_key, rx_pkts, tx_pkts, rx_thrput, tx_thrput, rx_fail, tx_fail))
        f.write('Total DUT Loss Pkts:{} \n'.format(test_stats['dut_loss_pkts']))
        test_stats['dut_lossless_pkts'] = 0
        test_stats['dut_lossy_pkts'] = 0
        for dut, port in dutport_list:
            new_key = (dut.hostname + '_' + port).lower() + '_prio_'
            prio_dict = {}
            for item in results:
                if (new_key in item):
                    prio_dict[item] = df_t[item].max()
            f.write('Egress Queue Count for {} : \n'.format((dut.hostname + '_' + port).lower()))
            for key, val in prio_dict.items():
                if val != 0:
                    # Checking for lossless priorities in the key.
                    if check_presence(key, prio_list):
                        test_stats['dut_lossless_pkts'] += val
                    else:
                        test_stats['dut_lossy_pkts'] += val
                    f.write('{}:{} \n'.format(key, val))

        test_stats['lossless_tx_pfc'] = 0
        test_stats['lossless_rx_pfc'] = 0
        test_stats['lossy_rx_tx_pfc'] = 0
        f.write('Received or Transmitted PFC counts: \n')
        tx_pfc_list = ['tx_pfc_{}'.format(num) for num in switch_tx_lossless_prios]
        rx_pfc_list = ['rx_pfc_{}'.format(num) for num in switch_tx_lossless_prios]
        for item in results:
            if ('pfc' in item):
                if (df_t[item].max() != 0):
                    f.write('{} : {} \n'.format(item, df_t[item].max()))
                    # Lossless priority PFCs transmitted.
                    if (check_presence(item, tx_pfc_list)):
                        test_stats['lossless_tx_pfc'] += int(df_t[item].max())
                    # Lossless priority PFCs received.
                    elif (check_presence(item, rx_pfc_list)):
                        test_stats['lossless_rx_pfc'] += int(df_t[item].max())
                    else:
                        # Lossy PFCs received or transmitted.
                        test_stats['lossy_rx_tx_pfc'] += int(df_t[item].max())

    fname = fname + '.csv'
    logger.info('Writing statistics to file : {}'.format(fname))
    df_t.to_csv(fname, index=False)
    check_for_crc_errors(api, snappi_extra_params)
    return flow_metrics, switch_device_results, test_stats


def update_dict(m,
                orig_dict,
                new_dict):
    """
    Merges the info from new_dict into orig_dict at index of m
    Args:
        m (int): index of the orig_dict
        orig_dict (dict): original dictionary to be updated
        new_dict (dict): dictionary that needs to be fitted in orig_dict
    Returns:
        orig_dict (dict): Updated orig_dict with new values of new_dict
    """
    for key, value in new_dict.items():
        orig_dict[m][key] = value

    return orig_dict


def multi_base_traffic_config(testbed_config,
                              port_config_list,
                              rx_port_id,
                              tx_port_id):
    """
    Generate base configurations of flows, including test flows, background flows and
    pause storm. Test flows and background flows are also known as data flows.
    Args:
        testbed_config (obj): testbed L1/L2/L3 configuration
        port_config_list (list): list of port configuration
        rx_port_id (int): Rx ID of DUT port to test
        tx_port_id (int): Tx ID of DUT port to test

    Returns:
        base_flow_config (dict): base flow configuration containing dut_port_config, tx_mac,
            rx_mac, tx_port_config, rx_port_config, tx_port_name, rx_port_name
            dict key-value pairs (all keys are strings):
                tx_port_id (int): ID of ixia TX port ex. 1
                rx_port_id (int): ID of ixia RX port ex. 2
                tx_port_config (SnappiPortConfig): port config obj for ixia TX port
                rx_port_config (SnappiPortConfig): port config obj for ixia RX port
                tx_mac (str): MAC address of ixia TX port ex. '00:00:fa:ce:fa:ce'
                rx_mac (str): MAC address of ixia RX port ex. '00:00:fa:ce:fa:ce'
                tx_port_name (str): name of ixia TX port ex. 'Port 1'
                rx_port_name (str): name of ixia RX port ex. 'Port 2'
                dut_port_config (list): a list of two dictionaries of tx and rx ports on the peer (switch) side,
                                        and the associated test priorities
                                        ex. [{'Ethernet4':[3, 4]}, {'Ethernet8':[3, 4]}]
                test_flow_name_dut_rx_port_map (dict): Mapping of test flow name to DUT RX port(s)
                                                  ex. {'flow1': [Ethernet4, Ethernet8]}
                test_flow_name_dut_tx_port_map (dict): Mapping of test flow name to DUT TX port(s)
                                                  ex. {'flow1': [Ethernet4, Ethernet8]}
    """
    base_flow_config = {}
    base_flow_config["rx_port_id"] = rx_port_id
    base_flow_config["tx_port_id"] = tx_port_id

    tx_port_config = next((x for x in port_config_list if x.id == tx_port_id), None)
    rx_port_config = next((x for x in port_config_list if x.id == rx_port_id), None)
    base_flow_config["tx_port_config"] = tx_port_config
    base_flow_config["rx_port_config"] = rx_port_config

    # Instantiate peer ports in dut_port_config
    dut_port_config = []
    tx_dict = {str(tx_port_config.peer_port): []}
    rx_dict = {str(rx_port_config.peer_port): []}
    dut_port_config.append(tx_dict)
    dut_port_config.append(rx_dict)
    base_flow_config["dut_port_config"] = dut_port_config

    base_flow_config["tx_mac"] = tx_port_config.mac
    if tx_port_config.gateway == rx_port_config.gateway and \
       tx_port_config.prefix_len == rx_port_config.prefix_len:
        """ If soruce and destination port are in the same subnet """
        base_flow_config["rx_mac"] = rx_port_config.mac
    else:
        base_flow_config["rx_mac"] = tx_port_config.gateway_mac

    base_flow_config["tx_port_name"] = testbed_config.ports[tx_port_id].name
    base_flow_config["rx_port_name"] = testbed_config.ports[rx_port_id].name

    return base_flow_config


def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = (str(parent_key) + sep + str(k)).lower() if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
