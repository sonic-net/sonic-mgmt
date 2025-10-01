# ==============================
#  Standard Library Imports
# ==============================
import os
import sys
import time
import struct
import json
import yaml
import collections
import logging
import snappi
import numpy as np

# ==============================
#  Third-Party Libraries
# ==============================
import pytest
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import seaborn as sns
from copy import deepcopy
from rich import print as pr
from tabulate import tabulate
from natsort import natsorted
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
import ipaddress
from ipaddress import ip_address, IPv4Address, IPv6Address
from datetime import datetime
from netaddr import IPNetwork

# ==============================
#  Packet Processing & Networking
# ==============================
from scapy.all import *   # noqa: F403, F401, F405
import scapy.contrib.mac_control    # noqa: F403, F401, F405

# ==============================
#  IxNetwork Traffic Testing
# ==============================
from ixnetwork_restpy.testplatform.testplatform import TestPlatform
from ixnetwork_restpy import SessionAssistant, BatchUpdate, BatchAdd
from ixnetwork_restpy.assistants.statistics.statviewassistant import (
    StatViewAssistant,
)   # noqa: F403, F401, F405

# ==============================
#  Common Test Utilities
# ==============================
from tests.common.config_reload import config_reload       # noqa: F403, F401, F405
from tests.common.reboot import reboot        # noqa: F403, F401, F405
from tests.common.platform.processes_utils import wait_critical_processes    # noqa: F403, F401, F405
from tests.common.utilities import wait_until, wait            # noqa: F403, F401, F405
from tests.common.helpers.assertions import pytest_assert, pytest_require      # noqa: F403, F401, F405

# ==============================
#  SONiC & Fanout Topology
# ==============================
from tests.common.fixtures.conn_graph_facts import (
    conn_graph_facts,
    fanout_graph_facts,
    fanout_graph_facts_multidut,
)  # noqa: F403, F401, F405

# ==============================
#  Snappi Test Framework
# ==============================
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

#  Snappi Fixtures (Testbed, Ports, API)
from tests.common.snappi_tests.snappi_fixtures import (
    snappi_api_serv_ip,
    snappi_api_serv_port,
    snappi_api,
    snappi_testbed_config,
    get_snappi_ports_single_dut,
    get_snappi_ports_multi_dut,
    get_snappi_ports,
    cleanup_config,
    is_snappi_multidut,
    create_ip_list,
    __gen_mac,
)   # noqa: F403, F401, F405

#  QoS (Priority Flow Control, ECN, Traffic Classes)
from tests.common.snappi_tests.qos_fixtures import (
    prio_dscp_map,
    all_prio_list,
    lossless_prio_list,
    lossy_prio_list,
)      # noqa: F403, F401, F405

#  Snappi Helpers & Metrics
from tests.common.snappi_tests.snappi_helpers import (
    get_dut_port_id,
    wait_for_arp,
    fetch_snappi_flow_metrics,
    SnappiFanoutManager,
    get_snappi_port_location,
)     # noqa: F403, F401, F405

#  Port Management (Selection, Configuration)
from tests.common.snappi_tests.port import (
    select_ports,
    select_tx_port,
    SnappiPortConfig,
    SnappiPortType,
)    # noqa: F403, F401, F405

#  Traffic Generation & Verification
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
)    # noqa: F403, F401, F405

#  Common Snappi Helpers (QoS, Packet Capture, Buffer)
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
    get_peer_snappi_chassis,
    get_addrs_in_subnet,
    get_other_hosts_from_ipv6_host,
)      # noqa: F403, F401, F405

# ==============================
#  PFC & ECN Test Helpers
# ==============================
from tests.snappi_tests.pfc.files.helper import run_pfc_test        # noqa: F403, F401, F405
from tests.snappi_tests.files.helper import skip_warm_reboot, skip_ecn_tests   # noqa: F403, F401, F405

# ==============================
#  Packet Analysis (PCAP, PFC, ECN)
# ==============================
from tests.common.snappi_tests.read_pcap import (
    validate_pfc_frame,
    is_ecn_marked,
    get_ipv4_pkts,
)     # noqa: F403, F401, F405

# ==============================
#  Test Variables (IP Ranges, QoS Groups)
# ==============================
from tests.common.snappi_tests.variables import (
    dut_ip_start,
    snappi_ip_start,
    prefix_length,
    dut_ipv6_start,
    snappi_ipv6_start,
    v6_prefix_length,
    pfcQueueGroupSize,
    pfcQueueValueDict,
)   # noqa: F403, F401, F405

# ==============================
# MAC Management
# ==============================
from snappi_tests.reboot.files.reboot_helper import get_macs    # noqa: F403, F401, F405
