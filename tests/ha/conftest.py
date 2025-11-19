import pytest
import time
import json

from pathlib import Path
from collections import defaultdict
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from common.ha.smartswitch_ha_helper import PtfTcpTestAdapter
from common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest
from common.ha.smartswitch_ha_helper import (
    add_port_to_namespace,
    remove_namespace,
    add_static_route_to_ptf,
    add_static_route_to_dut
)


@pytest.fixture(scope="module")
def copy_files(ptfhost):
    current_path = Path(__file__).resolve()
    tcp_server_path = current_path.parent.parent.joinpath("common", "ha", "tcp_server.py")
    tcp_client_path = current_path.parent.parent.joinpath("common", "ha", "tcp_client.py")

    ptfhost.copy(src=str(tcp_server_path), dest='/root')
    ptfhost.copy(src=str(tcp_client_path), dest='/root')


@pytest.fixture(scope='module')
def tcp_adapter(ptfadapter):
    return PtfTcpTestAdapter(ptfadapter)


@pytest.fixture(scope="module")
def setup_SmartSwitchHaTrafficTest(duthosts, ptfhost, ptfadapter, vmhost, tbinfo):
    activehost = duthosts[0]
    standbyhost = duthosts[1]
    io_ready = None

    ha_io = SmartSwitchHaTrafficTest(activehost, standbyhost, ptfhost,
                                     ptfadapter, vmhost, tbinfo, io_ready, namespace="ns1")
    return ha_io


@pytest.fixture(scope="module")
def get_t2_info(duthosts, tbinfo):
    # Get the list of upstream ports for each DUT
    upstream_ports = {}
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        upstream_port_ids = defaultdict(list)

        for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
            namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') \
                  else DEFAULT_NAMESPACE
            if duthost.sonichost.is_multi_asic and namespace == DEFAULT_NAMESPACE:
                continue
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo, namespace)

            for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
                port_id = mg_facts["minigraph_ptf_indices"][interface]
                if "T2" in neighbor["name"]:
                    upstream_port_ids[duthost.hostname].append(port_id)

        upstream_ports.update(upstream_port_ids)

    return upstream_ports


@pytest.fixture(scope="module")
def setup_namespaces_with_routes(ptfhost, duthosts, get_t2_info):
    ns_ifaces = []

    t2_ports = get_t2_info
    # Example split ports arbitrarily for namespace assignment
    dut1_ports = t2_ports[duthosts[0].hostname]
    dut2_ports = t2_ports[duthosts[1].hostname]
    ns1_ports = dut1_ports[0], dut2_ports[0]
    ns2_ports = dut1_ports[1], dut2_ports[1]

    for idx, port_idx in enumerate(ns1_ports, start=1):
        iface_name = f"eth{port_idx}"
        ns_ifaces.append({
            "namespace": "ns1",
            "iface": iface_name,
            "ip": f"172.16.2.{idx}/24",
            "next_hop": "172.16.2.254",
            "dut": duthosts[0]  # Add DUT for static route
        })

    for idx, port_idx in enumerate(ns2_ports, start=1):
        iface_name = f"eth{port_idx}"
        ns_ifaces.append({
            "namespace": "ns2",
            "iface": iface_name,
            "ip": f"172.16.1.{idx}/24",
            "next_hop": "172.16.1.254",
            "dut": duthosts[1]  # Add DUT
        })

    # Setup namespaces and static routes
    visited_namespaces = set()

    for ns in ns_ifaces:
        add_port_to_namespace(ptfhost, ns["namespace"], ns["iface"], ns["ip"])

        # Add static route to PTF only once per namespace
        if ns["namespace"] not in visited_namespaces:
            add_static_route_to_ptf(
                ptfhost,
                f"192.168.{ns['namespace'][-1]}.0/24",
                ns["next_hop"],
                name_of_namespace=ns["namespace"]
            )
            visited_namespaces.add(ns["namespace"])

        # Add static route on DUT
        add_static_route_to_dut(
            ns["dut"], "192.168.0.0/16", ns["ip"].split('/')[0]
        )

    yield
    visited_namespaces = set()
    for ns in ns_ifaces:
        if ns["namespace"] not in visited_namespaces:
            remove_namespace(ptfhost, ns["namespace"])
            visited_namespaces.add(ns["namespace"])
###############################################################################
# DUT01 CONFIG GENERATORS
###############################################################################


def generate_dpu_config(
    dpu_count=8,
    pa_prefix="20.0.200.",
    vip_prefix="3.2.1.",
    midplane_prefix="169.254.200.",
    swbus_start=23606,
):
    dpu = {}
    for idx in range(dpu_count):
        pa_idx = idx + 1
        dpu[f"dpu0_{idx}"] = {
            "dpu_id": str(idx),
            "gnmi_port": "50051",
            "local_port": "8080",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": f"{pa_prefix}{pa_idx}",
            "state": "up",
            "swbus_port": str(swbus_start + idx),
            "vdpu_id": f"vdpu0_{idx}",
            "vip_ipv4": f"{vip_prefix}{idx}",
            "midplane_ipv4": f"{midplane_prefix}{idx+1}",
        }
    return dpu


def generate_remote_dpu_config(
    cluster_id=1,
    npu_ipv4="10.1.1.32",
    pa_prefix="20.0.201.",
    pa_start=1,
    dpu_count=8,
    swbus_start=23606,
):
    remote = {}
    for dpu_id in range(dpu_count):
        remote[f"dpu{cluster_id}_{dpu_id}"] = {
            "dpu_id": str(dpu_id),
            "npu_ipv4": npu_ipv4,
            "pa_ipv4": f"{pa_prefix}{pa_start + dpu_id}",
            "swbus_port": str(swbus_start + dpu_id),
            "type": "cluster",
        }
    return remote


def generate_full_config():
    return {
        "DPU": generate_dpu_config(),
        "REMOTE_DPU": generate_remote_dpu_config(),
        "VDPU": {
            "vdpu0_0": {"main_dpu_ids": "dpu0_0"},
            "vdpu1_0": {"main_dpu_ids": "dpu1_0"}
        },
        "DASH_HA_GLOBAL_CONFIG": {
            "GLOBAL": {
                "dpu_bfd_probe_interval_in_ms": "1000",
                "dpu_bfd_probe_multiplier": "3",
                "cp_data_channel_port": "6000",
                "dp_channel_dst_port": "7000",
                "dp_channel_src_port_min": "7001",
                "dp_channel_src_port_max": "7010",
                "dp_channel_probe_interval_ms": "500",
                "vnet_name": "Vnet_55",
                "dp_channel_probe_fail_threshold": "5"
            }
        },
        "INTERFACE": {
            "Ethernet216": {},
            "Ethernet216|192.168.200.2/24": {}
        },
        "LOOPBACK_INTERFACE": {
            "Loopback0": {},
            "Loopback0|10.1.0.32/32": {},
            "Loopback0|FC00:1::32/128": {}
        },
        "FEATURE": {
            "dash-ha": {
                "auto_restart": "disabled",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "False",
                "has_per_dpu_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            }
        },
        "VNET": {
            "Vnet_55": {"scope": "default", "vni": "10000", "vxlan_tunnel": "t4"}
        },
        "VXLAN_TUNNEL": {"t4": {"src_ip": "10.1.0.32"}}
    }


###############################################################################
# DUT02 CONFIG GENERATOR
###############################################################################


def generate_dut2_dpu_config(
    dpu_count=8,
    pa_prefix="20.0.201.",
    vip_prefix="3.2.1.",
    midplane_prefix="169.254.200.",
    swbus_start=23606,
):
    dpu = {}

    for idx in range(dpu_count):
        pa_idx = idx + 1
        dpu[f"dpu1_{idx}"] = {
            "dpu_id": str(idx),
            "gnmi_port": "50051",
            "local_port": "8080",
            "midplane_ipv4": f"{midplane_prefix}{idx+1}",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": f"{pa_prefix}{pa_idx}",
            "state": "up",
            "swbus_port": str(swbus_start + idx),
            "vdpu_id": f"vdpu1_{idx}",
            "vip_ipv4": f"{vip_prefix}{idx}",
        }

    return dpu


def generate_dut2_remote_dpu_config():

    remote = {}

    # Remote DUT01 (dpu0_x)
    for i in range(2):
        remote[f"dpu0_{i}"] = {
            "dpu_id": str(i),
            "npu_ipv4": "10.1.0.32",
            "pa_ipv4": f"20.0.200.{i}",
            "swbus_port": str(23606 + i),
            "type": "cluster",
        }

    # Remote DUT03 (dpu2_x)
    for i in range(2):
        remote[f"dpu2_{i}"] = {
            "dpu_id": str(i),
            "npu_ipv4": "10.1.2.32",
            "pa_ipv4": f"20.0.202.{i}",
            "swbus_port": str(23606 + i),
            "type": "cluster",
        }

    return remote


def generate_dut2_full_config():

    return {
        "DPU": generate_dut2_dpu_config(),

        "REMOTE_DPU": generate_dut2_remote_dpu_config(),

        "VDPU": {
            "vdpu0_0": {"main_dpu_ids": "dpu0_0"},
            "vdpu1_0": {"main_dpu_ids": "dpu1_0"}
        },

        "DASH_HA_GLOBAL_CONFIG": {
            "GLOBAL": {
                "dpu_bfd_probe_interval_in_ms": "1000",
                "dpu_bfd_probe_multiplier": "3",
                "cp_data_channel_port": "6000",
                "dp_channel_dst_port": "7000",
                "dp_channel_src_port_min": "7001",
                "dp_channel_src_port_max": "7010",
                "dp_channel_probe_interval_ms": "500",
                "vnet_name": "Vnet_55",
                "dp_channel_probe_fail_threshold": "5"
            }
        },

        "LOOPBACK_INTERFACE": {
            "Loopback0": {},
            "Loopback0|10.1.1.32/32": {},
            "Loopback0|FC00:1::32/128": {}
        },

        "FEATURE": {
            "dash-ha": {
                "auto_restart": "disabled",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "False",
                "has_per_dpu_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            }
        },

        "VNET": {
            "Vnet_55": {
                "scope": "default",
                "vni": "10000",
                "vxlan_tunnel": "t4"
            }
        },

        "VXLAN_TUNNEL": {
            "t4": {"src_ip": "10.1.1.32"}
        }
    }


###############################################################################
# PYTEST FIXTURE (UPDATED WITH config load + config save)
###############################################################################

@pytest.fixture(scope="module")
def setup_ha_config(duthosts):
    """
    Load DASH-HA CONFIG_DB.json on BOTH DUT01 and DUT02 using:
        config load -j <file>
        config save -y

    No hostname logic.
    No parameters.
    Always configures:
        - duthosts[0] = DUT01
        - duthosts[1] = DUT02
    """

    # -------------------------------
    # DUT01: duthosts[0]
    # -------------------------------
    dut1 = duthosts[0]
    cfg1 = generate_full_config()
    tmp1 = "/tmp/dut1_ha_config.json"
    dut1.copy(content=json.dumps(cfg1, indent=4), dest=tmp1)
    dut1.shell(f"cat {tmp1} | jq .")
    dut1.shell(f"sudo config load -y {tmp1}")
    dut1.shell("sudo config save -y")

    # Wait for processes to stabilize
    time.sleep(10)

    # Validate DUT01 DPU keys (dpu0_*)
    out1 = dut1.shell("redis-cli -n 4 KEYS 'DPU|dpu0_*'")["stdout"]
    assert out1.strip(), "ERROR: DUT01 missing DPU|dpu0_* entries"

    # -------------------------------
    # DUT02: duthosts[1]
    # -------------------------------
    dut2 = duthosts[1]
    cfg2 = generate_dut2_full_config()
    tmp2 = "/tmp/dut2_ha_config.json"

    dut2.copy(content=json.dumps(cfg2, indent=4), dest=tmp2)
    dut2.shell(f"cat {tmp2} | jq .")
    dut2.shell(f"sudo config load -y {tmp2}")
    dut2.shell("sudo config save -y")

    # Wait for processes to settle
    time.sleep(10)

    # Validate DUT02 DPU keys (dpu1_*)
    out2 = dut2.shell("redis-cli -n 4 KEYS 'DPU|dpu1_*'")["stdout"]
    assert out2.strip(), "ERROR: DUT02 missing DPU|dpu1_* entries"

    # -------------------------------
    # RETURN both configs
    # -------------------------------
    return {
        "dut1_config": cfg1,
        "dut2_config": cfg2
    }
