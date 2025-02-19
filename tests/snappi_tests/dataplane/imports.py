# imports.py
import logging
import pytest
import time
from scapy.all import *
import scapy.contrib.mac_control
import pandas as pd
import struct
import json
import yaml
import collections
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

from copy import deepcopy
from rich import print as pr
from tabulate import tabulate
#*******

#*******
from tests.snappi_tests.pfc.files.helper import run_pfc_test
from tests.common.config_reload import config_reload

from tests.common.reboot import reboot
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.snappi_tests.files.helper import skip_warm_reboot
from tests.snappi_tests.variables import pfcQueueGroupSize, pfcQueueValueDict
from tests.snappi_tests.files.helper import skip_ecn_tests

from tests.common.snappi_tests.read_pcap import validate_pfc_frame, is_ecn_marked, get_ipv4_pkts
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts  # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

from tests.common.snappi_tests.snappi_fixtures import (
    snappi_api_serv_ip, 
    snappi_api_serv_port,
    snappi_api,
    snappi_testbed_config
    )
from tests.common.snappi_tests.qos_fixtures import (
    prio_dscp_map, 
    all_prio_list, 
    lossless_prio_list,
    lossy_prio_list,
    all_prio_list
    )

from tests.common.snappi_tests.snappi_helpers import (
    get_dut_port_id,
    wait_for_arp,
    fetch_snappi_flow_metrics,
    )
from tests.common.snappi_tests.port import (
    select_ports,
    select_tx_port,
    )

from tests.common.snappi_tests.traffic_generation import (
    generate_background_flows,
    generate_pause_flows,
    generate_test_flows,
    run_traffic,
    setup_base_traffic_config,
    verify_background_flow,
    verify_basic_test_flow,
    verify_egress_queue_frame_count,
    verify_in_flight_buffer_pkts,
    verify_pause_flow,
    verify_pause_frame_count_dut,
    verify_rx_frame_count_dut,
    verify_tx_frame_count_dut,
    verify_unset_cev_pause_frame_count,
)

from tests.common.snappi_tests.common_helpers import (
    calc_pfc_pause_flow_rate,
    config_capture_pkt,
    disable_packet_aging,
    get_lossless_buffer_size,
    get_pg_dropped_packets,
    get_pfc_frame_count,
    packet_capture,
    pfc_class_enable_vector,
    sec_to_nanosec,
    stop_pfcwd,
    traffic_flow_mode,
    get_tx_frame_count,
    get_rx_frame_count,
    get_egress_queue_count,
    config_wred,
    enable_ecn,
    config_ingress_lossless_buffer_alpha, 

)

