import pytest
import logging
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
from tests.common.helpers.smartswitch_util import correlate_dpu_info_with_dpuhost, get_data_port_on_dpu, get_dpu_dataplane_port # noqa F401
from tests.ha.gnmi_utils import generate_gnmi_cert, apply_gnmi_cert, recover_gnmi_cert, apply_gnmi_file, apply_messages
from tests.ha.ha_gnmi import apply_ha_messages, ha_scope_config, ha_set_config
from tests.common import config_reload
import configs.privatelink_config as pl
from tests.common.helpers.assertions import pytest_require as pt_require
from tests.ha.ha_utils import (
    wait_for_pending_operation_id,
    verify_ha_state,
    set_dead_dash_ha_scope
)

ENABLE_GNMI_API = True
logger = logging.getLogger(__name__)

ha_scope_per_dut = [
    (
        "vdpu0_0:haset0_0",
        {
            "version": "1",
            "disabled": True,
            "desired_ha_state": "active",
            "owner": "dpu",
        },
    ),
    (
        "vdpu1_0:haset0_0",
        {
            "version": "1",
            "disabled": True,
            "desired_ha_state": "unspecified",
            "owner": "dpu",
        },
    ),
]

activate_scope_per_dut = [
    (
        "vdpu0_0:haset0_0",
        {
            "version": "1",
            "disabled": False,
            "desired_ha_state": "active",
            "owner": "dpu",
        },
    ),
    (
        "vdpu1_0:haset0_0",
        {
            "version": "1",
            "disabled": False,
            "desired_ha_state": "unspecified",
            "owner": "dpu",
        },
    ),
]


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


@pytest.fixture(scope="module")
def primary_vdpu_key(dpuhosts):
    return f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"


@pytest.fixture(scope="module")
def standby_vdpu_key(dpuhosts):
    return f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"


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


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
def set_vxlan_udp_sport_range(dpuhosts):
    """
    Configure VXLAN UDP source port range in dpu configuration.

    """
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
    for dpuhost in dpuhosts:
        dpuhost.copy(content=json.dumps(vxlan_sport_config, indent=4), dest=config_path, verbose=False)
        apply_swssconfig_file(dpuhost, config_path)
        if 'pensando' in dpuhost.facts['asic_type']:
            logger.warning("Applying Pensando DPU VXLAN sport workaround")
            dpuhost.shell("pdsctl debug update device --vxlan-port 4789 --vxlan-src-ports 5120-5247")
    yield
    for dpuhost in dpuhosts:
        if str(VXLAN_UDP_BASE_SRC_PORT) in dpuhost.shell("redis-cli -n 0"
                                                         " hget SWITCH_TABLE:switch vxlan_sport")['stdout']:
            config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.fixture(scope="module")
def dpu_index(request):
    return request.config.getoption("--dpu_index")


@pytest.fixture(scope="module")
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
            dpuhost.shell_cmds(cmds=dpu_cmds)


@pytest.fixture(scope="module")
def add_npu_static_routes(
    duthosts, dash_pl_config, skip_config, skip_cleanup, dpu_index
):
    if not skip_config:
        for i in range(len(duthosts)):
            duthost = duthosts[i]

            cmds = []
            vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][LOCAL_DUT_INTF]).ip + 1
            pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1

            pt_require(vm_nexthop_ip, "VM nexthop interface does not have an IP address")
            pt_require(pe_nexthop_ip, "PE nexthop interface does not have an IP address")

            cmds.append(f"ip route replace {pl.VM1_PA}/32 via {vm_nexthop_ip}")

            cmds.append(f"ip route replace {pl.PE_PA}/32 via {pe_nexthop_ip}")
            logger.info(f"Adding static routes: {cmds} on {duthost}")
            duthost.shell_cmds(cmds=cmds)

    yield

    if not skip_config and not skip_cleanup:
        for i in range(len(duthosts)):
            duthost = duthosts[i]

            cmds = []
            vm_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][LOCAL_DUT_INTF]).ip + 1
            pe_nexthop_ip = get_interface_ip(duthost, dash_pl_config[i][REMOTE_DUT_INTF]).ip + 1

            cmds.append(f"ip route del {pl.VM1_PA}/32 via {vm_nexthop_ip}")
            cmds.append(f"ip route del {pl.PE_PA}/32 via {pe_nexthop_ip}")
            logger.info(f"Removing static routes: {cmds} from {duthost}")
            duthost.shell_cmds(cmds=cmds)


@pytest.fixture(scope="module")
def setup_npu_dpu(dpu_setup, add_npu_static_routes):
    yield


###############################################################################
# PYTEST FIXTURE — APPLY CONFIG ON BOTH DUTS
###############################################################################

@pytest.fixture(scope="module")
def setup_ha_config(duthosts, tbinfo):
    """
    DASH-HA config (DPU, REMOTE_DPU, VDPU, DASH_HA_GLOBAL_CONFIG,
    LOOPBACK_INTERFACE, FEATURE, VNET, VXLAN_TUNNEL) is now generated
    as part of the golden_config_db during testbed setup via
    generate_golden_config_db (ansible/library/generate_golden_config_db.py).

    This fixture is kept as a no-op for ordering purposes — tests
    that depend on it will continue to work without changes.
    """
    logger.info("HA config is applied via golden_config_db during testbed setup; nothing to do here.")
    return


@pytest.fixture(scope="module")
def ha_owner(dpuhosts):
    """
    Fixture to parametrize HA owner type (dpu or switch) for the test.
    """
    if 'pensando' in dpuhosts[0].facts['asic_type']:
        owner = "dpu"
    else:
        owner = "switch"
    yield owner


def setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, "..", "common", "ha")
    ha_set_file = os.path.join(base_dir, "dash_ha_set_config_table.json")
    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    ha_scope_per_dut_modified = []
    for index, (name, data) in enumerate(ha_scope_per_dut):
        if name == "vdpu0_0:haset0_0":
            name = primary_vdpu_key
        elif name == "vdpu1_0:haset0_0":
            name = standby_vdpu_key
        ha_scope_per_dut_modified.append((name, data))

    for index, (name, data) in enumerate(ha_scope_per_dut_modified):
        # Update the 'owner' key in the dictionary
        ha_scope_per_dut_modified[index][1]['owner'] = ha_owner

    logger.info("HA: setup from json for Primary and Standby")

    # Workaround for the neigh resolve issue
    # To be removed after fixes are merged: PR 147, 148 in sonic-dash-ha
    for i in range(len(duthosts)):
        logger.info(f"Sending ping to DPU{dpuhosts[i].dpu_index} for {duthosts[i].hostname}")
        ip_part = 200 + i
        ip_last = dpuhosts[i].dpu_index + 1
        ping_result = duthosts[i].shell(f"ping -c 3 20.0.{ip_part}.{ip_last}", module_ignore_errors=True)["stdout"]
        logger.info(f"{duthosts[i].hostname} ping_result [{ping_result}]")

    with open(ha_set_file) as f:
        ha_set_data = json.load(f)["DASH_HA_SET_CONFIG_TABLE"]

    # Update the entry for "haset0_0"
    ha_set_entry = ha_set_data.get("haset0_0", {})

    ha_set_entry["vdpu_ids"] = [f"vdpu0_{dpuhosts[0].dpu_index}", f"vdpu1_{dpuhosts[1].dpu_index}"]
    ha_set_entry["preferred_vdpu_id"] = f"vdpu0_{dpuhosts[0].dpu_index}"

    # Save the modified data back into the dictionary
    ha_set_data["haset0_0"] = ha_set_entry

    # -------------------------------------------------
    # Step 1: Program HA SET on BOTH DUTs
    # -------------------------------------------------
    for duthost in duthosts:
        for key, fields in ha_set_data.items():
            ha_set_messages = ha_set_config(ha_set_id=key, **fields)
            apply_ha_messages(
                localhost=localhost,
                duthost=duthost,
                ptfhost=ptfhost,
                messages=ha_set_messages,
            )

    # -------------------------------------------------
    # Step 2: Initial HA SCOPE per DUT
    # -------------------------------------------------

    for duthost, (key, fields) in zip(duthosts, ha_scope_per_dut_modified):
        vdpu_id, ha_set_id = key.split(":", 1)
        ha_scope_messages = ha_scope_config(
            vdpu_id=vdpu_id,
            ha_set_id=ha_set_id,
            **fields,
        )
        apply_ha_messages(
            localhost=localhost,
            duthost=duthost,
            ptfhost=ptfhost,
            messages=ha_scope_messages,
        )


def remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(current_dir, "..", "common", "ha")
    ha_set_file = os.path.join(base_dir, "dash_ha_set_config_table.json")

    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    ha_scope_per_dut_modified = []
    for index, (name, data) in enumerate(ha_scope_per_dut):
        if name == "vdpu0_0:haset0_0":
            name = primary_vdpu_key
        elif name == "vdpu1_0:haset0_0":
            name = standby_vdpu_key
        ha_scope_per_dut_modified.append((name, data))

    for index, (name, data) in enumerate(ha_scope_per_dut_modified):
        # Update the 'owner' key in the dictionary
        ha_scope_per_dut_modified[index][1]['owner'] = ha_owner

    logger.info("HA: remove SCOPE for Primary and Standby")
    for duthost, (key, fields) in zip(duthosts, ha_scope_per_dut_modified):
        vdpu_id, ha_set_id = key.split(":", 1)
        ha_scope_messages = ha_scope_config(
            vdpu_id=vdpu_id,
            ha_set_id=ha_set_id,
            **fields,
        )
        apply_ha_messages(
            localhost=localhost,
            duthost=duthost,
            ptfhost=ptfhost,
            messages=ha_scope_messages,
            set_db=False
        )

    logger.info("HA: remove SET for Primary and Standby")
    with open(ha_set_file) as f:
        ha_set_data = json.load(f)["DASH_HA_SET_CONFIG_TABLE"]

    for duthost in duthosts:
        for key, fields in ha_set_data.items():
            ha_set_messages = ha_set_config(ha_set_id=key, **fields)
            apply_ha_messages(
                localhost=localhost,
                duthost=duthost,
                ptfhost=ptfhost,
                messages=ha_set_messages,
                set_db=False
            )


@pytest.fixture(scope="module")
def setup_dash_ha_from_json(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
    yield
    remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)


@pytest.fixture(scope="function")
def setup_dash_ha_from_json_func_scope(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
    yield
    remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)


def activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):

    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    activate_scope_per_dut_modified = []
    for index, (name, data) in enumerate(activate_scope_per_dut):
        if name == "vdpu0_0:haset0_0":
            name = primary_vdpu_key
        elif name == "vdpu1_0:haset0_0":
            name = standby_vdpu_key
        activate_scope_per_dut_modified.append((name, data))

    for index, (name, data) in enumerate(activate_scope_per_dut_modified):
        activate_scope_per_dut_modified[index][1]['owner'] = ha_owner

    # -------------------------------------------------
    # Step 4: Activate Role (using pending_operation_ids)
    # -------------------------------------------------
    logger.info("HA: activate Primary and Standby")
    for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut_modified):
        is_active = verify_ha_state(duthost, scope_key=key, expected_state="active", timeout=10, interval=5)
        if not is_active:
            break

    if is_active:
        logger.info("HA: Primary and Standby already active")
        return
    else:
        for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut_modified):
            vdpu_id, ha_set_id = key.split(":", 1)
            ha_scope_messages = ha_scope_config(
                vdpu_id=vdpu_id,
                ha_set_id=ha_set_id,
                **fields,
            )
            apply_ha_messages(
                localhost=localhost,
                duthost=duthost,
                ptfhost=ptfhost,
                messages=ha_scope_messages,
            )
        for idx, (duthost, (key, fields)) in enumerate(zip(duthosts, activate_scope_per_dut_modified)):
            # Wait up to 300s — after a process-crash test the HA state machine
            # may need significant time to re-enter the activate_role flow.
            pending_id = wait_for_pending_operation_id(
                duthost,
                scope_key=key,
                expected_op_type="activate_role",
                timeout=300,
                interval=2
            )
            assert pending_id, (
                f"Timed out waiting for active pending_operation_id "
                f"for {duthost.hostname} scope {key}"
            )

            logger.info(f"DASH HA {duthost.hostname} found pending id {pending_id}")
            vdpu_id, ha_set_id = key.split(":", 1)
            ha_scope_messages = ha_scope_config(
                vdpu_id=vdpu_id,
                ha_set_id=ha_set_id,
                approved_pending_operation_ids=[pending_id],
                **fields,
            )
            apply_ha_messages(
                localhost=localhost,
                duthost=duthost,
                ptfhost=ptfhost,
                messages=ha_scope_messages,
            )
            # Verify HA state using fields
            if ha_owner == "dpu":
                expected_state = "active"
            else:
                # Expect standby state on vDPU1
                if key == standby_vdpu_key:
                    expected_state = "standby"
                else:
                    expected_state = "active"
            assert verify_ha_state(
                duthost,
                scope_key=key,
                expected_state=expected_state,
                timeout=120,
                interval=5,
            ), f"HA did not reach expected state {expected_state} for {key} on {duthost.hostname}"
            logger.info(f"Activate completed for {duthost.hostname}")
        logger.info("HA: activate completed for Primary and Standby")


def deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server):

    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    logger.info("HA: de-activate Primary and Standby - set dead")
    set_dead_dash_ha_scope(localhost, duthosts[0], ptfhost, primary_vdpu_key)
    set_dead_dash_ha_scope(localhost, duthosts[1], ptfhost, standby_vdpu_key)


@pytest.fixture(scope="function")
def activate_dash_ha_from_json(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner):
    activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
    yield
    deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server)


@pytest.fixture(scope="function")
def setup_dash_pl_pipeline(
    localhost, duthosts, ptfhost, dpu_index, skip_config,
    dpuhosts, setup_npu_dpu, set_vxlan_udp_sport_range
):
    """
    Apply DASH Private Link pipeline config (appliance, routing type, VNET,
    ENI, routes, meters) on all DPUs. Required by any test that sends PL
    traffic and does not already pull in the steady-state common_setup_teardown.
    """
    if skip_config:
        yield
        return

    for i in range(len(duthosts)):
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]

        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG,
        }
        logger.info(
            f"setup_dash_pl_pipeline: applying base config on "
            f"{duthost.hostname} dpu {dpuhost.dpu_index}"
        )
        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_CONFIG,
        }
        if "bluefield" in dpuhost.facts["asic_type"]:
            route_and_mapping_messages.update({**pl.INBOUND_VNI_ROUTE_RULE_CONFIG})
        apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

        meter_rule_messages = {
            **pl.METER_RULE1_V4_CONFIG,
            **pl.METER_RULE2_V4_CONFIG,
        }
        apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)

        apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    logger.info("setup_dash_pl_pipeline: cleanup.")
    for dpuhost in dpuhosts:
        config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.fixture(scope="module")
def setup_dash_pl_pipeline_module_scope(
    localhost, duthosts, ptfhost, dpu_index, skip_config,
    dpuhosts, setup_npu_dpu, set_vxlan_udp_sport_range
):
    """
    Apply DASH Private Link pipeline config (appliance, routing type, VNET,
    ENI, routes, meters) on all DPUs. Required by any test that sends PL
    traffic and does not already pull in the steady-state common_setup_teardown.
    """
    if skip_config:
        yield
        return

    for i in range(len(duthosts)):
        duthost = duthosts[i]
        dpuhost = dpuhosts[i]

        base_config_messages = {
            **pl.APPLIANCE_CONFIG,
            **pl.ROUTING_TYPE_PL_CONFIG,
            **pl.VNET_CONFIG,
            **pl.ROUTE_GROUP1_CONFIG,
            **pl.METER_POLICY_V4_CONFIG,
        }
        logger.info(
            f"setup_dash_pl_pipeline: applying base config on "
            f"{duthost.hostname} dpu {dpuhost.dpu_index}"
        )
        apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

        route_and_mapping_messages = {
            **pl.PE_VNET_MAPPING_CONFIG,
            **pl.PE_SUBNET_ROUTE_CONFIG,
            **pl.VM_SUBNET_ROUTE_CONFIG,
        }
        if "bluefield" in dpuhost.facts["asic_type"]:
            route_and_mapping_messages.update({**pl.INBOUND_VNI_ROUTE_RULE_CONFIG})
        apply_messages(localhost, duthost, ptfhost, route_and_mapping_messages, dpuhost.dpu_index)

        meter_rule_messages = {
            **pl.METER_RULE1_V4_CONFIG,
            **pl.METER_RULE2_V4_CONFIG,
        }
        apply_messages(localhost, duthost, ptfhost, meter_rule_messages, dpuhost.dpu_index)

        apply_messages(localhost, duthost, ptfhost, pl.ENI_CONFIG, dpuhost.dpu_index)
        apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)

    yield

    logger.info("setup_dash_pl_pipeline: cleanup.")
    for dpuhost in dpuhosts:
        config_reload(dpuhost, safe_reload=True, yang_validate=False)
