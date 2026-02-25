import pytest
import logging
import time
import random
import json
from pathlib import Path
from collections import defaultdict
import os

from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.ha.smartswitch_ha_helper import PtfTcpTestAdapter
from tests.common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest
from tests.common.ha.smartswitch_ha_helper import (
    add_port_to_namespace,
    remove_namespace,
    add_static_route_to_ptf,
    add_static_route_to_dut
)
from ipaddress import ip_interface
from constants import LOCAL_CA_IP, \
    DUT_MAC, LOCAL_PTF_INTF, LOCAL_PTF_MAC, \
    REMOTE_PTF_INTF, REMOTE_PTF_MAC, \
    LOCAL_DUT_INTF, REMOTE_DUT_INTF, \
    REMOTE_PTF_SEND_INTF, REMOTE_PTF_RECV_INTF, VXLAN_UDP_BASE_SRC_PORT, VXLAN_UDP_SRC_PORT_MASK, \
    NPU_DATAPLANE_IP, NPU_DATAPLANE_MAC, NPU_DATAPLANE_PORT, DPU_DATAPLANE_IP, DPU_DATAPLANE_MAC, DPU_DATAPLANE_PORT
from tests.common.dash_utils import render_template_to_host, apply_swssconfig_file
from gnmi_utils import generate_gnmi_cert, apply_gnmi_cert, recover_gnmi_cert, apply_gnmi_file
from tests.common import config_reload
import configs.privatelink_config as pl
from tests.common.helpers.assertions import pytest_require as pt_require
from tests.ha.ha_utils import (

    build_dash_ha_scope_args,
    wait_for_pending_operation_id,
    build_dash_ha_scope_activate_args,
    wait_for_ha_state,
    build_dash_ha_set_args,
    proto_utils_hset
)
ENABLE_GNMI_API = True
logger = logging.getLogger(__name__)


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


def get_interface_ip(duthost, interface):
    cmd = f"ip addr show {interface} | grep -w inet | awk '{{print $2}}'"
    output = duthost.shell(cmd)["stdout"].strip()
    return ip_interface(output)


@pytest.fixture(scope="module")
def config_only(request):
    return request.config.getoption("--config_only")


@pytest.fixture(scope="module")
def skip_config(request):
    return request.config.getoption("--skip_config")


@pytest.fixture(scope="module")
def skip_cleanup(request):
    return request.config.getoption("--skip_cleanup")


@pytest.fixture(scope="module")
def skip_cert_cleanup(request):
    return request.config.getoption("--skip_cert_cleanup")


@pytest.fixture(scope="module")
def config_facts(duthost):
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


def get_intf_from_ip(local_ip, config_facts):
    for intf, config in list(config_facts["INTERFACE"].items()):
        for ip in config:
            intf_ip = ip_interface(ip)
            if str(intf_ip.ip) == local_ip:
                return intf, intf_ip

    for intf, config in list(config_facts["PORTCHANNEL_INTERFACE"].items()):
        for ip in config:
            intf_ip = ip_interface(ip)
            if str(intf_ip.ip) == local_ip:
                return intf, intf_ip


@pytest.fixture(params=["no-underlay-route", "with-underlay-route"])
def use_underlay_route(request):
    return request.param == "with-underlay-route"


@pytest.fixture(scope="function")
def dash_pl_config(duthosts, dpuhosts, dpu_index, duts_minigraph_facts):
    dash_info = [{
        LOCAL_CA_IP: "10.2.2.2",
    } for _ in range(2)]

    for i in range(len(duthosts)):
        config_facts = duthosts[i].get_running_config_facts()
        minigraph_facts = duts_minigraph_facts[duthosts[i].hostname]
        neigh_table = duthosts[i].switch_arptable()['ansible_facts']['arptable']
        dash_info[i][DUT_MAC] = config_facts["DEVICE_METADATA"]["localhost"]["mac"]
        for neigh_ip, config in list(config_facts["BGP_NEIGHBOR"].items()):
            if ip_interface(neigh_ip).version == 4:
                if LOCAL_PTF_INTF not in dash_info[i] and config["name"].endswith("T0"):
                    intf, _ = get_intf_from_ip(config['local_addr'], config_facts)
                    dash_info[i][LOCAL_PTF_INTF] = minigraph_facts[0][1]["minigraph_ptf_indices"][intf]
                    dash_info[i][LOCAL_DUT_INTF] = intf
                    dash_info[i][LOCAL_PTF_MAC] = neigh_table["v4"][neigh_ip]["macaddress"]
                if REMOTE_PTF_SEND_INTF not in dash_info[i] and config["name"].endswith("T2"):
                    intf, _ = get_intf_from_ip(config['local_addr'], config_facts)
                    intfs = list(config_facts["PORTCHANNEL_MEMBER"][intf].keys())
                    dash_info[i][REMOTE_PTF_SEND_INTF] = minigraph_facts[0][1]["minigraph_ptf_indices"][intfs[0]]
                    dash_info[i][REMOTE_PTF_RECV_INTF] = \
                        [minigraph_facts[0][1]["minigraph_ptf_indices"][j] for j in intfs]
                    dash_info[i][REMOTE_DUT_INTF] = intf
                    dash_info[i][REMOTE_PTF_MAC] = neigh_table["v4"][neigh_ip]["macaddress"]

                if REMOTE_PTF_INTF in dash_info and LOCAL_PTF_INTF in dash_info[i]:
                    break
        if len(dpuhosts) == 1:
            dpuhost = dpuhosts[0]
        else:
            dpuhost = dpuhosts[i]
        dash_info[i][DPU_DATAPLANE_PORT] = dpuhost.dpu_dataplane_port
        dash_info[i][DPU_DATAPLANE_IP] = dpuhost.dpu_data_port_ip
        dash_info[i][DPU_DATAPLANE_MAC] = dpuhost.dpu_dataplane_mac

        dash_info[i][NPU_DATAPLANE_PORT] = dpuhost.npu_dataplane_port
        dash_info[i][NPU_DATAPLANE_IP] = dpuhost.npu_data_port_ip
        dash_info[i][NPU_DATAPLANE_MAC] = dpuhost.npu_dataplane_mac

    return dash_info


@pytest.fixture(scope="function")
def apply_config(localhost, duthost, ptfhost, skip_config, skip_cleanup):
    configs = []
    op = "SET"

    def _apply_config(config_info):
        if skip_config:
            return
        if config_info not in configs:
            configs.append(config_info)

        config = "dash_basic_config"
        template_name = "{}.j2".format(config)
        dest_path = "/tmp/{}.json".format(config)
        render_template_to_host(template_name, duthost, dest_path, config_info, op=op)
        if ENABLE_GNMI_API:
            apply_gnmi_file(localhost, duthost, ptfhost, dest_path)
        else:
            apply_swssconfig_file(duthost, dest_path)

    yield _apply_config

    op = "DEL"
    if not skip_cleanup:
        for config_info in reversed(configs):
            _apply_config(config_info)


@pytest.fixture(scope="function")
def setup_gnmi_server(duthosts, localhost, ptfhost, skip_cert_cleanup):
    if not ENABLE_GNMI_API:
        yield
        return
    for duthost in duthosts:
        generate_gnmi_cert(localhost, duthost)
        apply_gnmi_cert(duthost, ptfhost)
    yield
    for duthost in duthosts:
        recover_gnmi_cert(localhost, duthost, skip_cert_cleanup)


@pytest.fixture(scope="function", params=['udp', 'tcp', 'echo_request', 'echo_reply'])
def inner_packet_type(request):
    return request.param


def config_vxlan_udp_dport(duthost, port):
    vxlan_port_config = [
        {
            "SWITCH_TABLE:switch": {"vxlan_port": f"{port}"},
            "OP": "SET"
        }
    ]
    config_path = "/tmp/vxlan_port_config.json"
    duthost.copy(content=json.dumps(vxlan_port_config, indent=4), dest=config_path, verbose=False)
    apply_swssconfig_file(duthost, config_path)


@pytest.fixture(scope="function")
def vxlan_udp_dport(request, duthost):
    """
    Test the traffic with specified or randomly generated VxLAN UDP dst port.
    Configuration is applied by swssconfig.
    """
    UDP_PORT_RANGE = range(0, 65536)
    WELL_KNOWN_UDP_PORT_RANGE = range(0, 1024)
    vxlan_udp_dport = request.config.getoption("--vxlan_udp_dport")
    if vxlan_udp_dport == "random":
        port_candidate_list = ["default", 4789, 13330, 1024, 65535]
        while True:
            random_port = random.choice(UDP_PORT_RANGE)
            if random_port not in WELL_KNOWN_UDP_PORT_RANGE and random_port not in port_candidate_list:
                port_candidate_list.append(random_port)
                break
        vxlan_udp_dport = random.choice(port_candidate_list)
    if vxlan_udp_dport != "default":
        logger.info(f"Configure the VXLAN UDP dst port {vxlan_udp_dport} to DPU")
        vxlan_udp_dport = int(vxlan_udp_dport)
        config_vxlan_udp_dport(duthost, vxlan_udp_dport)
    else:
        logger.info("Use the default VXLAN UDP dst port 4789")
        vxlan_udp_dport = 4789

    yield vxlan_udp_dport

    logger.info("Restore the VXLAN UDP dst port to 4789")
    config_vxlan_udp_dport(duthost, 4789)


@pytest.fixture(scope="function")
def set_vxlan_udp_sport_range(dpuhosts, dpu_index):
    """
    Configure VXLAN UDP source port range in dpu configuration.

    """
    dpuhost = dpuhosts[dpu_index]
    vxlan_sport_config = [
        {
            "SWITCH_TABLE:switch": {
                "vxlan_sport": VXLAN_UDP_BASE_SRC_PORT,
                "vxlan_mask": VXLAN_UDP_SRC_PORT_MASK
            },
            "OP": "SET"
        }
    ]

    logger.info(f"Setting VXLAN source port config: {vxlan_sport_config}")
    config_path = "/tmp/vxlan_sport_config.json"
    dpuhost.copy(content=json.dumps(vxlan_sport_config, indent=4), dest=config_path, verbose=False)
    apply_swssconfig_file(dpuhost, config_path)
    if 'pensando' in dpuhost.facts['asic_type']:
        logger.warning("Applying Pensando DPU VXLAN sport workaround")
        dpuhost.shell("pdsctl debug update device --vxlan-port 4789 --vxlan-src-ports 5120-5247")
    yield
    if str(VXLAN_UDP_BASE_SRC_PORT) in dpuhost.shell("redis-cli -n 0 hget SWITCH_TABLE:switch vxlan_sport")['stdout']:
        config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.fixture(scope="module")
def dpu_index(request):
    return request.config.getoption("--dpu_index")


@pytest.fixture
def dpu_setup(duthosts, dpuhosts, dpu_index, skip_config):
    if skip_config:
        return

    """
    Prior to this, HA configuration will set the route from DPU to NPU
    """
    for i in range(len(duthosts)):
        # we run the DUT and DPU index in parallel because they are forming the HA pair
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]
        # explicitly add mgmt IP route so the default route doesn't disrupt SSH access
        dpuhost.shell(f'ip route replace {duthost.mgmt_ip}/32 via 169.254.200.254')
        intfs = dpuhost.shell("show ip int")["stdout"]
        dpu_cmds = list()
        if "Loopback0" not in intfs:
            dpu_cmds.append("config loopback add Loopback0")
            dpu_cmds.append(f"config int ip add Loopback0 {pl.APPLIANCE_VIP}/32")


@pytest.fixture(scope="function")
def add_npu_static_routes(
    duthosts, dash_pl_config, skip_config, skip_cleanup, dpu_index, dpuhosts
):
    if not skip_config:
        for i in range(len(duthosts)):
            duthost = duthosts[i]
            dpuhost = dpuhosts[i]

            cmds = []
            vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][LOCAL_DUT_INTF]).ip + 1
            pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1

            pt_require(vm_nexthop_ip, "VM nexthop interface does not have an IP address")
            pt_require(pe_nexthop_ip, "PE nexthop interface does not have an IP address")

            cmds.append(f"ip route replace {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
            cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")

            cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
            logger.info(f"Adding static routes: {cmds} on {duthost}")
            duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        for i in range(len(duthosts)):
            duthost = duthosts[i]
            dpuhost = dpuhosts[i]

            cmds = []
            vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][LOCAL_DUT_INTF]).ip + 1
            pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1

            cmds.append(f"ip route del {pl.APPLIANCE_VIP}/32 via {dpuhost.dpu_data_port_ip}")
            cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
            cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
            logger.info(f"Removing static routes: {cmds} from {duthost}")
            duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="function")
def setup_npu_dpu(dpu_setup, add_npu_static_routes):
    yield
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


@pytest.fixture(scope="module")
def setup_dash_ha_from_json(duthosts):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, "..", "common", "ha")
    ha_set_file = os.path.join(base_dir, "dash_ha_set_dpu_config_table.json")

    with open(ha_set_file) as f:
        ha_set_data = json.load(f)["DASH_HA_SET_CONFIG_TABLE"]

    # -------------------------------------------------
    # Step 1: Program HA SET on BOTH DUTs
    # -------------------------------------------------
    for duthost in duthosts:
        for key, fields in ha_set_data.items():
            proto_utils_hset(
                duthost,
                table="DASH_HA_SET_CONFIG_TABLE",
                key=key,
                args=build_dash_ha_set_args(fields),
            )

    # -------------------------------------------------
    # Step 2: Initial HA SCOPE per DUT
    # -------------------------------------------------
    ha_scope_per_dut = [
        (
            "vdpu0_0:haset0_0",
            {
                "version": "1",
                "disabled": "true",
                "desired_ha_state": "active",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
        (
            "vdpu1_0:haset0_0",
            {
                "version": "1",
                "disabled": "true",
                "desired_ha_state": "unspecified",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
    ]

    for duthost, (key, fields) in zip(duthosts, ha_scope_per_dut):
        proto_utils_hset(
            duthost,
            table="DASH_HA_SCOPE_CONFIG_TABLE",
            key=key,
            args=build_dash_ha_scope_args(fields),
        )


@pytest.fixture(scope="module")
def activate_dash_ha_from_json(duthosts):
    # -------------------------------------------------
    # Step 4: Activate Role (using pending_operation_ids)
    # -------------------------------------------------
    activate_scope_per_dut = [
        (
            "vdpu0_0:haset0_0",
            {
                "version": "1",
                "disabled": False,
                "desired_ha_state": "active",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
        (
            "vdpu1_0:haset0_0",
            {
                "version": "1",
                "disabled": False,
                "desired_ha_state": "unspecified",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
    ]
    for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut):
        proto_utils_hset(
            duthost,
            table="DASH_HA_SCOPE_CONFIG_TABLE",
            key=key,
            args=build_dash_ha_scope_args(fields),
        )
    for idx, (duthost, (key, fields)) in enumerate(zip(duthosts, activate_scope_per_dut)):
        pending_id = wait_for_pending_operation_id(
            duthost,
            scope_key=key,
            expected_op_type="activate_role",
            timeout=120,
            interval=2
        )
        assert pending_id, (
            f"Timed out waiting for active pending_operation_id "
            f"for {duthost.hostname} scope {key}"
        )

        logger.info(f"DASH HA {duthost.hostname} found pending id {pending_id}")
        proto_utils_hset(
            duthost,
            table="DASH_HA_SCOPE_CONFIG_TABLE",
            key=key,
            args=build_dash_ha_scope_activate_args(fields, pending_id),
        )
        # Verify HA state using fields
        expected_state = "active" if idx == 0 else "standby"
        assert wait_for_ha_state(
            duthost,
            scope_key=key,
            expected_state=expected_state,
            timeout=120,
            interval=5,
        ), f"HA did not reach expected state {expected_state} for {key} on {duthost.hostname}"
        logger.info(f"DASH HA Step-4 Activate Role completed for {duthost.hostname}")
    logger.info("DASH HA Step-4 Activate Role completed")
    yield
