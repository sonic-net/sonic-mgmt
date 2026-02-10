import pytest
import time
import json

from tests.common.config_reload import config_reload
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
# VLAN CONFIG (COMMON)
###############################################################################


def generate_vlan_config(
    svi_ip,
    vlan_id=55,
    vlan_description="DPU Management VLAN",
    member_start=224,
    member_count=8,
    member_step=8
):
    vlan_name = f"Vlan{vlan_id}"

    members = [f"Ethernet{member_start + i * member_step}" for i in range(member_count)]

    vlan = {
        vlan_name: {
            "description": vlan_description,
            "vlanid": str(vlan_id)
        }
    }

    vlan_interface = {
        vlan_name: {},
        f"{vlan_name}|{svi_ip}": {}
    }

    vlan_member = {
        f"{vlan_name}|{member}": {"tagging_mode": "untagged"}
        for member in members
    }

    return vlan, vlan_interface, vlan_member


###############################################################################
# LOCAL DPU GENERATOR (DUT01 & DUT02)
###############################################################################

def generate_local_dpu_config(
    switch_id: int,
    dpu_count=8,
    swbus_start=23606
):
    """
    switch_id:
        0 FOR DUT01 FOR dpu0_x prefix, pa_ipv4 = 20.0.200.x
        1 FOR DUT02 FOR dpu1_x prefix, pa_ipv4 = 20.0.201.x
    """
    prefix = f"dpu{switch_id}_"
    pa_prefix = f"20.0.20{switch_id}."
    vip_prefix = "3.2.1."
    midplane_prefix = "169.254.200."

    dpu = {}
    for idx in range(dpu_count):
        dpu[f"{prefix}{idx}"] = {
            "dpu_id": str(idx),
            "gnmi_port": "50051",
            "local_port": "8080",
            "orchagent_zmq_port": "8100",
            "pa_ipv4": f"{pa_prefix}{idx + 1}",
            "state": "up",
            "swbus_port": str(swbus_start + idx),
            "vdpu_id": f"vdpu{switch_id}_{idx}",
            "vip_ipv4": f"{vip_prefix}{idx}",
            "midplane_ipv4": f"{midplane_prefix}{idx + 1}",
        }

    return dpu


def generate_vdpu_config(dpu_count=8):
    """
    Generate VDPU table for BOTH clusters:
        vdpu0_0 ... vdpu0_7  --> dpu0_0 ... dpu0_7
        vdpu1_0 ... vdpu1_7  --> dpu1_0 ... dpu1_7
    """
    vdpu = {}

    # cluster0 (switch 0)
    for idx in range(dpu_count):
        vdpu[f"vdpu0_{idx}"] = {"main_dpu_ids": f"dpu0_{idx}"}

    # cluster1 (switch 1)
    for idx in range(dpu_count):
        vdpu[f"vdpu1_{idx}"] = {"main_dpu_ids": f"dpu1_{idx}"}

    return vdpu


###############################################################################
# REMOTE DPU GENERATOR (UNIFIED)
###############################################################################

def generate_remote_dpu_config_for_dut(
    switch_id: int,
    dpu_count=8,
    swbus_start=23606
):
    """
    Both DUT01 and DUT02 belong to the same cluster.

    DUT01 (switch_id=0) sees remote DPUs as dpu1_x
    DUT02 (switch_id=1) sees remote DPUs as dpu0_x
    """

    remote_switch_id = 1 - switch_id

    remote_npu_ip = f"10.1.{remote_switch_id}.32"
    pa_prefix = f"20.0.20{remote_switch_id}."

    remote = {}
    for idx in range(dpu_count):
        remote[f"dpu{remote_switch_id}_{idx}"] = {
            "dpu_id": str(idx),
            "npu_ipv4": remote_npu_ip,
            "pa_ipv4": f"{pa_prefix}{idx + 1}",
            "swbus_port": str(swbus_start + idx),
            "type": "cluster"
        }
    return remote


###############################################################################
# UNIFIED FULL CONFIG GENERATOR (DUT01 + DUT02)
###############################################################################

def generate_ha_config_for_dut(switch_id: int):
    """
    switch_id 0 FOR  DUT01
    switch_id 1 FOR  DUT02
    """

    # VLAN SVI per DUT
    svi_ip = "20.0.200.14/28" if switch_id == 0 else "20.0.201.14/28"
    vlan, vlan_intf, vlan_member = generate_vlan_config(svi_ip)

    # Loopbacks per DUT
    loopback_ip = "10.1.0.32/32" if switch_id == 0 else "10.1.1.32/32"
    loopback_v6 = "FC00:1::32/128"

    # VXLAN source IP per DUT
    vxlan_src_ip = "10.1.0.32" if switch_id == 0 else "10.1.1.32"
    if switch_id == 0:
        hostname = "swicth1"
    else:
        hostname = "switch2"

    return {
        "DPU": generate_local_dpu_config(switch_id),
        "REMOTE_DPU": generate_remote_dpu_config_for_dut(switch_id),
        "VDPU": generate_vdpu_config(),
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
            f"Loopback0|{loopback_ip}": {},
            f"Loopback0|{loopback_v6}": {}
        },

        # VLAN sections included
        "VLAN": vlan,
        "VLAN_INTERFACE": vlan_intf,
        "VLAN_MEMBER": vlan_member,

        # IMPORTANT: INTERFACE REMOVED (Reviewer request)
        # No INTERFACE section.

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
        "DEVICE_METADATA": {
            "localhost": {
                "region": "west",
                "cluster": "cluster1",
                "hostname": f"{hostname}"
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
            "t4": {"src_ip": vxlan_src_ip}
        }
    }


def remove_loopback_ips(dut):
    # Remove IPv4 addresses
    out_v4 = dut.shell("show ip interfaces | grep Loopback0 || true")["stdout"].strip().splitlines()
    for line in out_v4:
        parts = line.split()
        # Expected: ["Loopback0", "10.1.0.33/32", "up", "up"]
        if len(parts) >= 2:
            ip = parts[1]
            dut.shell(f"sudo config interface ip remove Loopback0 {ip} || true")

    # Remove IPv6 addresses
    out_v6 = dut.shell("show ipv6 interfaces | grep Loopback0 || true")["stdout"].strip().splitlines()
    for line in out_v6:
        parts = line.split()
        # Expected: ["Loopback0", "fc00:1::32/128", "up", "up"]
        if len(parts) >= 2:
            ip = parts[1]
            dut.shell(f"sudo config interface ip remove Loopback0 {ip} || true")


###############################################################################
# PYTEST FIXTURE — APPLY CONFIG ON BOTH DUTS
###############################################################################

@pytest.fixture(scope="module")
def setup_ha_config(duthosts):
    """
    Load unified DASH-HA config onto BOTH DUT01 and DUT02 using:
        config load -y <file>
        config save -y
    """

    final_cfg = {}

    for switch_id in (0, 1):
        dut = duthosts[switch_id]
        cfg = generate_ha_config_for_dut(switch_id)
        tmpfile = f"/tmp/dut{switch_id}_ha_config.json"

        # Copy JSON
        dut.copy(content=json.dumps(cfg, indent=4), dest=tmpfile)

        # Verify syntax
        dut.shell(f"cat {tmpfile} | jq .")

        # DELETE old Loopback0 IPs
        remove_loopback_ips(dut)

        # Load and persist
        dut.shell(f"sudo config load -y {tmpfile}")
        dut.shell("sudo config save -y")
        config_reload(dut, safe_reload=True)

        # Allow processes to settle
        time.sleep(10)

        # Validate DPU entries
        prefix = f"dpu{switch_id}_"
        out = dut.shell(f"redis-cli -n 4 KEYS 'DPU|{prefix}*'")["stdout"]
        assert out.strip(), f"ERROR: DUT{switch_id} missing DPU entries"

        final_cfg[f"DUT{switch_id}"] = cfg

    return final_cfg
