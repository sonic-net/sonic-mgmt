import logging
from pathlib import Path
from collections import defaultdict
import re
import os
import json

import pytest

from tests.common.helpers.constants import DEFAULT_NAMESPACE

from common.ha.smartswitch_ha_helper import (
    PtfTcpTestAdapter,
    add_port_to_namespace,
    remove_namespace,
    add_static_route_to_ptf,
    add_static_route_to_dut,
)

from common.ha.smartswitch_ha_io import SmartSwitchHaTrafficTest


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


def build_dash_ha_set_args(fields):
    """
    Build args for DASH_HA_SET_CONFIG_TABLE
    EXACTLY following the working CLI
    """

    version = str(fields["version"])
    if version.endswith(".0"):
        version = version[:-2]

    return (
        f'version \\"{version}\\" '
        f'vip_v4 "{fields["vip_v4"]}" '
        f'vip_v6 "{fields["vip_v6"]}" '
        f'scope "{fields["scope"]}" '
        f'preferred_vdpu_id "{fields["preferred_vdpu_id"]}" '
        f'preferred_standalone_vdpu_index 0 '
        f'vdpu_ids \'["vdpu0_0","vdpu1_0"]\''
    )


def build_dash_ha_scope_args(fields):
    """
    Build args for DASH_HA_SCOPE_CONFIG_TABLE
    EXACTLY following the working CLI
    """

    version = str(fields["version"])
    if version.endswith(".0"):
        version = version[:-2]

    return (
        f'version \\"{version}\\" '
        f'disabled "true" '
        f'desired_ha_state "{fields["desired_ha_state"]}" '
        f'ha_set_id "{fields["ha_set_id"]}" '
        f'owner "dpu"'
    )


def extract_pending_operation_id(text):
    """
    Extract pending_operation_ids UUID from swbus-cli output
    """
    match = re.search(
        r'pending_operation_ids\s+\|\s+([0-9a-fA-F-]+)',
        text
    )
    return match.group(1) if match else None


def get_pending_operation_id(duthost, scope_key):
    """
    scope_key example: vdpu0_0:haset0_0
    """
    cmd = (
        "docker exec dash-hadpu0 swbus-cli show hamgrd actor "
        f"/hamgrd/0/ha-scope/{scope_key}"
    )
    res = duthost.shell(cmd)
    return extract_pending_operation_id(res["stdout"])


def build_dash_ha_scope_activate_args(fields, pending_id):
    return (
        f'version \\"{fields["version"]}\\" '
        f'disabled "{fields["disabled"]}" '
        f'desired_ha_state "{fields["desired_ha_state"]}" '
        f'ha_set_id "{fields["ha_set_id"]}" '
        f'owner "{fields["owner"]}" '
        f'approved_pending_operation_ids '
        f'[\"{pending_id}\"]'
    )


@pytest.fixture(scope="module")
def setup_dash_ha_from_json(duthosts):
    base_dir = "/data/tests/common/ha"
    ha_set_file = os.path.join(base_dir, "dash_ha_set_dpu_config_table.json")

    with open(ha_set_file) as f:
        ha_set_data = json.load(f)["DASH_HA_SET_CONFIG_TABLE"]

    # -------------------------------------------------
    # Step 1: Program HA SET on BOTH DUTs
    # -------------------------------------------------
    for duthost in duthosts:
        for key, fields in ha_set_data.items():
            cmd = (
                "docker exec swss python /etc/sonic/proto_utils.py hset "
                f"DASH_HA_SET_CONFIG_TABLE:{key} "
                f"{build_dash_ha_set_args(fields)}"
            )
            duthost.shell(cmd)

    # -------------------------------------------------
    # Step 2: Initial HA SCOPE per DUT
    # -------------------------------------------------
    ha_scope_per_dut = [
        (
            "vdpu0_0:haset0_0",
            {
                "version": "1",
                "disabled": "false",
                "desired_ha_state": "active",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
        (
            "vdpu1_0:haset0_0",
            {
                "version": "1",
                "disabled": "false",
                "desired_ha_state": "unspecified",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
    ]

    for duthost, (key, fields) in zip(duthosts, ha_scope_per_dut):
        cmd = (
            "docker exec swss python /etc/sonic/proto_utils.py hset "
            f'"DASH_HA_SCOPE_CONFIG_TABLE:{key}" '
            f"{build_dash_ha_scope_args(fields)}"
        )
        duthost.shell(cmd)

    # -------------------------------------------------
    # Step 4: Activate Role (using pending_operation_ids)
    # -------------------------------------------------
    activate_scope_per_dut = [
        # DUT-1
        (
            "vdpu0_0:haset0_0",
            {
                "version": "3",
                "disabled": "false",
                "desired_ha_state": "active",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
        # DUT-2
        (
            "vdpu1_0:haset0_0",
            {
                "version": "3",
                "disabled": "false",
                "desired_ha_state": "unspecified",
                "ha_set_id": "haset0_0",
                "owner": "dpu",
            },
        ),
    ]

    for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut):
        pending_id = get_pending_operation_id(duthost, key)
        assert pending_id, f"No pending_operation_id found for {key}"

        cmd = (
            "docker exec swss python /etc/sonic/proto_utils.py hset "
            f'"DASH_HA_SCOPE_CONFIG_TABLE:{key}" '
            f"{build_dash_ha_scope_activate_args(fields, pending_id)}"
        )
        duthost.shell(cmd)

    print("DASH HA Step-4 Activate Role completed")
    yield
