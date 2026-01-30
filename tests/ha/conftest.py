import logging
from pathlib import Path
from collections import defaultdict
import re
import os
import json
import ast

import pytest

from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until


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


def extract_pending_operations(text):
    """
    Extract pending_operation_ids and pending_operation_types
    and return list of (type, id) tuples.
    """
    ids_match = re.search(
        r'pending_operation_ids\s+\|\s+(\[.*?\])',
        text,
        re.DOTALL,
    )
    types_match = re.search(
        r'pending_operation_types\s+\|\s+(\[.*?\])',
        text,
        re.DOTALL,
    )

    if not ids_match or not types_match:
        logging.warning(f"Regex match failed - ids_match: {bool(ids_match)}, types_match: {bool(types_match)}")
        return []

    try:
        ids = ast.literal_eval(f"{ids_match.group(1)}")
        types = ast.literal_eval(f"{types_match.group(1)}")
    except Exception as e:
        logging.error(
            f"Failed to parse ids or types: {e}. "
            f"ids_match: {ids_match.group(1) if ids_match else None}, "
            f"types_match: {types_match.group(1) if types_match else None}"
        )
        return []

    return list(zip(types, ids))


def get_pending_operation_id(duthost, scope_key, expected_op_type):
    """
    scope_key example: vdpu0_0:haset0_0
    expected_op_type example: ACTIVATE_ROLE
    """
    cmd = (
        "docker exec dash-hadpu0 swbus-cli show hamgrd actor "
        f"/hamgrd/0/ha-scope/{scope_key}"
    )
    res = duthost.shell(cmd)

    pending_ops = extract_pending_operations(res["stdout"])

    for op_type, op_id in pending_ops:
        if op_type == expected_op_type:
            return op_id

    return None


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


def proto_utils_hset(duthost, table, key, args):
    """
    Wrapper around proto_utils.py hset

    Args:
        duthost: pytest duthost fixture
        table (str): Redis table name
        key (str): Redis key
        args (str): Already-built proto args string
    """
    cmd = (
        "docker exec swss python /etc/sonic/proto_utils.py hset "
        f'"{table}:{key}" {args}'
    )
    duthost.shell(cmd)


def wait_for_pending_operation_id(
    duthost,
    scope_key,
    expected_op_type,
    timeout=60,
    interval=2,
):
    """
    Wait until the expected pending_operation_id appears.
    """
    pending_id = None

    def _condition():
        nonlocal pending_id
        pending_id = get_pending_operation_id(
            duthost,
            scope_key,
            expected_op_type,
        )
        return pending_id is not None

    success = wait_until(
        timeout,
        interval,
        0,           # REQUIRED delay argument
        _condition,  # condition callable
    )

    return pending_id if success else None


def expected_ha_state_from_fields(fields):
    desired = fields.get("desired_ha_state")

    if desired == "active":
        return "active"
    if desired == "unspecified":
        return "unspecified"

    raise ValueError(f"Unknown desired_ha_state: {desired}")


def extract_ha_state(text):
    """
    Extract ha_state from swbus-cli output
    """
    match = re.search(r'ha_state\s+\|\s+(\w+)', text)
    return match.group(1) if match else None


def wait_for_ha_state(
    duthost,
    scope_key,
    expected_state,
    timeout=120,
    interval=5,
):
    """
    Wait until HA reaches the expected state
    """
    def _check_ha_state():
        cmd = (
            "docker exec dash-hadpu0 swbus-cli show hamgrd actor "
            f"/hamgrd/0/ha-scope/{scope_key}"
        )
        res = duthost.shell(cmd)
        return extract_ha_state(res["stdout"]) == expected_state

    success, _ = wait_until(
        timeout,
        interval,
        _check_ha_state,
        delay=0,
    )

    return success


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
                "disabled": "false",
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
    # Step 3: Activate Role (using pending_operation_ids)
    # -------------------------------------------------
    activate_scope_per_dut = [
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
        proto_utils_hset(
            duthost,
            table="DASH_HA_SCOPE_CONFIG_TABLE",
            key=key,
            args=build_dash_ha_scope_args(fields),
        )

    for duthost, (key, fields) in zip(duthosts, activate_scope_per_dut):
        pending_id = wait_for_pending_operation_id(
            duthost,
            scope_key=key,
            expected_op_type="active",
            timeout=60,
            interval=2
        )
        assert pending_id, (
            f"Timed out waiting for active pending_operation_id "
            f"for scope {key}"
        )

        proto_utils_hset(
            duthost,
            table="DASH_HA_SCOPE_CONFIG_TABLE",
            key=key,
            args=build_dash_ha_scope_activate_args(fields, pending_id),
        )
        expected_state = expected_ha_state_from_fields(fields)
        # Verify HA state using fields
        assert wait_for_ha_state(
            duthost,
            scope_key=key,
            expected_state=expected_state,
            timeout=120,
            interval=5,
        ), f"HA did not reach ACTIVE state for {key}"
    logger.info("DASH HA Step-4 Activate Role completed")
    yield
