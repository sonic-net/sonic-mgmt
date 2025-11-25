import json
import logging
from pathlib import Path
from collections import defaultdict

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

from common.ha.smartswitch_ha_gnmi_utils import (
    ha_gnmi_apply_config,
    generate_gnmi_cert,
    apply_gnmi_cert,
)

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


@pytest.fixture(scope="module")
def apply_ha_config(duthosts, localhost, ptfhost):
    """
    Independent fixture that:

    1. Generates GNMI certs
    2. Applies them to DUT + PTF
    3. Restarts GNMI server
    4. Loads HA-SET and HA-SCOPE JSON files
    5. Applies HA config (Option 1 GNMI UPDATE)
    6. Makes HA configuration available before tests start

    Usage:
        def test_ha_example(apply_ha_config):
            pass
    """

    duthost = duthosts[0]

    logger.info("========== HA GNMI CERT GENERATION ==========")
    generate_gnmi_cert(localhost, duthost)

    logger.info("========== APPLY GNMI CERTS TO DUT + PTF ==========")
    apply_gnmi_cert(duthost, ptfhost)

    logger.info("========== LOADING HA JSON CONFIG FILES ==========")
    tests_root = Path(__file__).parents[1]
    base_path = tests_root / "common" / "ha"
    ha_set_path = base_path / "dash_ha_set_dpu_config_table.json"
    ha_scope_path = base_path / "dash_ha_scope_config_table.json"

    if not ha_set_path.exists() or not ha_scope_path.exists():
        raise FileNotFoundError(f"Missing HA config JSONs under: {base_path}")

    with open(ha_set_path) as f:
        ha_set_json = json.load(f)

    with open(ha_scope_path) as f:
        ha_scope_json = json.load(f)

    logger.info("========== APPLYING HA CONFIG VIA GNMI ==========")

    ha_gnmi_apply_config(
        duthost=duthost,
        ptfhost=ptfhost,
        ha_set_json=ha_set_json,
        ha_scope_json=ha_scope_json,
    )

    logger.info("========== HA CONFIG APPLIED SUCCESSFULLY ==========")

    # Return something only if needed by future tests
    return {
        "ha_set": ha_set_json,
        "ha_scope": ha_scope_json,
    }
