"""
Snappi coverage for 100G -> 400G port speed upgrade through GCU.

The test selects at least one 400G Snappi port connected to the downlink line
card, downgrades the selected target DUT port to 100G with a PORT-only GCU
patch, upgrades it back to 400G with the selected-port cluster restore data,
then runs Snappi all-to-all traffic when a downlink traffic peer is available.
It intentionally does not alter minigraph.
"""

import logging
import random
import time
from copy import deepcopy
from collections import defaultdict

import pytest

from tests.common.config_reload import config_reload
from tests.common.fixtures.conn_graph_facts import (  # noqa: F401
    conn_graph_facts,
    fanout_graph_facts,
    fanout_graph_facts_multidut,
)
from tests.common.gcu_port_speed_utils import (
    _get_external_portchannel_members,
    _get_portchannel_for_member,
    apply_patch_port_configs,
    verify_port_show_interface_status,
)
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.snappi_tests.port import select_ports
from tests.common.snappi_tests.qos_fixtures import (  # noqa: F401
    lossless_prio_list,
    prio_dscp_map,
)
from tests.common.snappi_tests.snappi_fixtures import (  # noqa: F401
    gen_data_flow_dest_ip,
    get_snappi_ports,
    get_snappi_ports_for_rdma,
    get_snappi_ports_multi_dut,
    get_snappi_ports_single_dut,
    is_snappi_multidut,
    setup_dut_ports,
    snappi_api,
    snappi_api_serv_ip,
    snappi_api_serv_port,
    snappi_dut_base_config,
    snappi_multi_base_config,
)
from tests.common.snappi_tests.snappi_helpers import wait_for_arp
from tests.conftest import generate_skeleton_port_info, parse_override
from tests.snappi_tests.gcu.gcu_port_speed_platform_config import (
    get_fec_modes_for_speed,
    get_num_lanes_for_speed,
)


pytestmark = [pytest.mark.topology("multidut-tgen")]

logger = logging.getLogger(__name__)

SPEED_100G = "100000"
SPEED_400G = "400000"
SNAPPI_SPEED_400G = "speed_400_gbps"
SNAPPI_POLL_DELAY_SEC = 2
GCU_SPEED_PATCH_SETTLE_DELAY_SEC = 100
MIN_DOWNLINK_SNAPPIPORTS = 1
GCU_TARGET_PORT_FIELD = "gcu_target"
SNAPPI_CATEGORY_SINGLE_LC_SINGLE_ASIC = "single_linecard_single_asic"
SNAPPI_CATEGORY_SINGLE_LC_MULTIPLE_ASIC = "single_linecard_multiple_asic"
SNAPPI_CATEGORY_MULTIPLE_LC_MULTIPLE_ASIC = "multiple_linecard_multiple_asic"

LOGANALYZER_IGNORE_REGEX = [
    ".*ERR sonic_yang.*",
    ".*doPortTask: Unsupported port .* speed.*",
    ".*createEntry: Failed to start PFC Watchdog on port.*",
    ".*Unable to find key NPU_SI_SETTINGS_SYNC_STATUS.*",
    ".*ERR pmon#.*CmisManagerTask.*no suitable app for the port appl.*",
    (
        ".*ERR syncd[0-9]*#syncd: SAI_LOG\\|SAI_API_QUEUE: "
        "Invalid queue counter.*"
    ),
    (
        ".*ERR swss[0-9]*#orchagent: :- processPriorityGroup: "
        "Port with alias:.* not found"
    ),
    (
        ".*ERR swss[0-9]*#orchagent: :- doTask: "
        "Failed to process invalid buffer task"
    ),
]


def pytest_generate_tests(metafunc):
    """
    Parameterize from the same Snappi metadata used by tgen_port_info.
    """
    if "snappi_gcu_port_param" not in metafunc.fixturenames:
        return

    params = generate_skeleton_port_info(metafunc)
    port_params = []
    for param in params:
        if not isinstance(param, str):
            port_params.append(param)
            continue
        speed = param.split("-", 1)[0]
        try:
            if int(float(speed)) == 400:
                port_params.append(param)
        except ValueError:
            continue

    if not port_params:
        port_params = [
            "400.0-{}".format(SNAPPI_CATEGORY_SINGLE_LC_SINGLE_ASIC)
        ]

    metafunc.parametrize("snappi_gcu_port_param", port_params, indirect=True)


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    """
    Use the same minimal 1 Tx / 1 Rx shape as the basic multidut Snappi test.
    """
    yield (1, 1)


@pytest.fixture(scope="function")
def snappi_gcu_port_param(request):
    """
    Return the current Snappi port-selection parameter.
    """
    return request.param


def _cli_namespace_prefix(namespace):
    """
    Return the sonic-db-cli namespace prefix for an ASIC namespace.
    """
    return "" if namespace is None else "-n {}".format(namespace)


def _get_num_lanes_per_speed(duthost, speed):
    """
    Return the number of lanes required for a speed on the DUT platform.
    """
    return get_num_lanes_for_speed(duthost.facts["platform"], speed)


def _get_port_lanes(duthost, cli_namespace_prefix, port):
    """
    Read port lanes from CONFIG_DB.
    """
    cmd = "sonic-db-cli {} CONFIG_DB hget 'PORT|{}' lanes".format(
        cli_namespace_prefix, port
    )
    output = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(
        output["stdout_lines"],
        "No lanes in CONFIG_DB for port {}: {}".format(port, output),
    )
    return output["stdout_lines"][0].split(",")


def _wait_before_gcu_speed_patch(stage, contexts, ports_by_context):
    """
    Add spacing before a GCU speed patch.
    """
    selected = [
        "{}:{}:{}".format(
            contexts[key]["duthost"].hostname,
            contexts[key]["namespace"] or "default",
            ",".join(ports),
        )
        for key, ports in ports_by_context.items()
    ]
    logger.info(
        "Waiting %s seconds before %s GCU speed patch for %s",
        GCU_SPEED_PATCH_SETTLE_DELAY_SEC,
        stage,
        selected,
    )
    time.sleep(GCU_SPEED_PATCH_SETTLE_DELAY_SEC)


def _get_supported_port_fecs(duthost, cli_namespace_prefix, port):
    """
    Read supported FEC values for a port from STATE_DB.
    """
    cmd = (
        'sonic-db-cli {} STATE_DB HGET "PORT_TABLE|{}" '
        '"supported_fecs"'
    ).format(cli_namespace_prefix, port)
    output = duthost.shell(cmd, module_ignore_errors=True)["stdout"]
    valid_fecs = [fec for fec in output.split(",") if fec]
    pytest_assert(valid_fecs, "Failed to get valid FEC modes for {}".format(
        port))
    return valid_fecs


def _get_target_fec(duthost, cli_namespace_prefix, port, target_speed):
    """
    Pick a FEC mode for target speed using Snappi platform config data.
    """
    supported_state_fecs = _get_supported_port_fecs(
        duthost, cli_namespace_prefix, port)
    supported_fecs_per_speed = get_fec_modes_for_speed(target_speed)
    pytest_assert(
        supported_fecs_per_speed,
        "No FEC data for speed {} in Snappi platform config".format(
            target_speed),
    )
    for fec in supported_fecs_per_speed:
        if fec in supported_state_fecs:
            return fec
    return random.choice(supported_fecs_per_speed)


def _build_port_config_for_speed(
        duthost, base_port_config, target_speed, cli_namespace_prefix, port):
    """
    Build a full CONFIG_DB PORT entry for the target speed.
    """
    target_num_lanes = _get_num_lanes_per_speed(duthost, target_speed)
    pytest_assert(
        target_num_lanes is not None,
        "No lane-count data for platform {} speed {}".format(
            duthost.facts["platform"], target_speed),
    )

    port_config = dict(base_port_config)
    current_lanes = _get_port_lanes(duthost, cli_namespace_prefix, port)
    start_lane = int(current_lanes[0])
    port_config["lanes"] = ",".join(
        str(i) for i in range(start_lane, start_lane + target_num_lanes))
    port_config["speed"] = target_speed

    target_fec = _get_target_fec(
        duthost, cli_namespace_prefix, port, target_speed)
    if target_fec == "N/A":
        port_config.pop("fec", None)
    elif target_fec:
        port_config["fec"] = target_fec

    return port_config


def _build_port_config_for_400g_upgrade(
        duthost, cli_namespace_prefix, port,
        port_config_100g, original_port_config):
    """
    Build a full 400G PORT entry from the current 100G PORT config.
    """
    port_config_400g = dict(port_config_100g)
    for field in ["speed", "lanes"]:
        if field in original_port_config:
            port_config_400g[field] = original_port_config[field]
        else:
            port_config_400g.pop(field, None)

    target_fec = _get_target_fec(
        duthost, cli_namespace_prefix, port, SPEED_400G)
    if target_fec == "N/A":
        port_config_400g.pop("fec", None)
    elif target_fec:
        port_config_400g["fec"] = target_fec

    return port_config_400g


def _restore_duts(duthosts_to_restore, loganalyzer):
    """
    Restore touched DUTs through minigraph reload.
    """
    for duthost in duthosts_to_restore:
        config_reload(
            duthost,
            config_source="minigraph",
            safe_reload=True,
            wait_for_bgp=True,
            ignore_loganalyzer=loganalyzer,
        )


def _ignore_expected_speed_change_logs(duthosts_to_restore, loganalyzer):
    """
    Add loganalyzer ignores for expected transient speed-change messages.
    """
    if not loganalyzer:
        return
    for duthost in duthosts_to_restore:
        if duthost.hostname in loganalyzer:
            loganalyzer[duthost.hostname].ignore_regex.extend(
                LOGANALYZER_IGNORE_REGEX)


def _get_frontend_hostnames(duthosts):
    """
    Return DUT hostnames that have front-panel ports.
    """
    frontend_nodes = getattr(duthosts, "frontend_nodes", None)
    if frontend_nodes:
        return [duthost.hostname for duthost in frontend_nodes]

    frontend_hostnames = []
    for duthost in duthosts:
        if hasattr(duthost, "is_frontend_node"):
            if duthost.is_frontend_node():
                frontend_hostnames.append(duthost.hostname)
        else:
            frontend_hostnames.append(duthost.hostname)
    return frontend_hostnames


def _get_downlink_lc_hostname(duthosts, tbinfo):
    """
    Return the downlink line-card hostname for the current T2 chassis testbed.
    """
    topo_name = tbinfo.get("topo", {}).get("name", "")
    pytest_require(
        "t2" in topo_name.lower(),
        "Downlink LC GCU speed upgrade requires T2 topology; got {}".format(
            topo_name),
    )

    testbed_duts = tbinfo.get("duts", [])
    pytest_require(
        len(testbed_duts) >= 2,
        "Failed to determine downlink LC from testbed DUT list {}".format(
            testbed_duts),
    )

    downlink_lc_hostname = testbed_duts[1]
    frontend_hostnames = _get_frontend_hostnames(duthosts)
    pytest_require(
        any(
            downlink_lc_hostname in hostname
            for hostname in frontend_hostnames
        ),
        "Downlink LC {} is not available in current frontend DUTs {}".format(
            downlink_lc_hostname, frontend_hostnames),
    )
    logger.info(
        "Detected T2 topology %s downlink LC %s from testbed DUT order %s",
        topo_name,
        downlink_lc_hostname,
        testbed_duts,
    )
    return downlink_lc_hostname


def _port_matches_peer_device(port, peer_device):
    """
    Return whether a Snappi port is connected to the requested DUT hostname.
    """
    return (
        _normalize_hostname(port.get("peer_device")) ==
        _normalize_hostname(peer_device)
    )


def _normalize_hostname(hostname):
    """
    Return a lower-case short hostname for exact peer matching.
    """
    if hostname is None:
        return ""
    return str(hostname).strip().split(".")[0].lower()


def _format_snappi_port_names(snappi_ports):
    """
    Return compact DUT/interface labels for assertion and skip messages.
    """
    return [
        "{}/{}({})".format(
            port.get("peer_device"),
            port.get("peer_port"),
            port.get("speed"),
        )
        for port in snappi_ports
    ]


def _snappi_port_identity(port):
    """
    Return the DUT-side identity for a Snappi port.
    """
    return port.get("peer_device"), port.get("peer_port")


def _snappi_port_context_identity(port):
    """
    Return a DUT/ASIC/port identity for a Snappi port.
    """
    duthost = port.get("duthost")
    hostname = getattr(duthost, "hostname", port.get("peer_device"))
    return (
        _normalize_hostname(hostname),
        port.get("asic_value"),
        port.get("peer_port"),
    )


def _find_available_snappi_port(
        available_snappi_ports, duthost, namespace, dut_port):
    """
    Return the Snappi port connected to a DUT/ASIC port, if available.
    """
    hostname = _normalize_hostname(duthost.hostname)
    for snappi_port in available_snappi_ports:
        if _normalize_hostname(snappi_port.get("peer_device")) != hostname:
            continue
        if snappi_port.get("peer_port") != dut_port:
            continue
        if snappi_port.get("asic_value") != namespace:
            continue
        return dict(snappi_port)
    return None


def _mark_gcu_target_ports(snappi_ports, is_gcu_target):
    """
    Return copied Snappi ports tagged as GCU targets or traffic peers.
    """
    tagged_ports = []
    for port in snappi_ports:
        tagged_port = dict(port)
        tagged_port[GCU_TARGET_PORT_FIELD] = is_gcu_target
        tagged_ports.append(tagged_port)
    return tagged_ports


def _mark_400g_ports_as_gcu_targets(snappi_ports):
    """
    Return copied Snappi ports with only 400G ports tagged as GCU targets.
    """
    tagged_ports = []
    for port in snappi_ports:
        tagged_port = dict(port)
        tagged_port[GCU_TARGET_PORT_FIELD] = (
            str(port.get("speed")) == SPEED_400G)
        tagged_ports.append(tagged_port)
    return tagged_ports


def _get_gcu_restore_mg_facts(mg_facts, ports):
    """
    Return minigraph facts safe for selected Snappi ports without neighbors.
    """
    restore_mg_facts = deepcopy(mg_facts)
    vm_neighbors = restore_mg_facts.setdefault("minigraph_neighbors", {})
    missing_neighbors = []
    for port in ports:
        dut_interface = port
        port_channel = restore_mg_facts.get(
            "minigraph_portchannels", {}).get(dut_interface)
        if port_channel and port_channel.get("members"):
            dut_interface = port_channel["members"][0]
        if dut_interface in vm_neighbors:
            continue

        vm_neighbors[dut_interface] = {
            "name": "__snappi_no_minigraph_neighbor_{}__".format(
                dut_interface)
        }
        missing_neighbors.append(dut_interface)

    if missing_neighbors:
        logger.info(
            "Snappi ports %s have no minigraph neighbors; using placeholder "
            "neighbor names so GCU restore patch can include selected-port "
            "non-BGP config only",
            missing_neighbors,
        )
    return restore_mg_facts


def _select_downlink_traffic_peer_ports(
        available_snappi_ports, downlink_lc_hostname, selected_ports,
        needed_ports):
    """
    Select extra downlink Snappi ports for traffic without changing speed.
    """
    if needed_ports <= 0:
        return []

    selected_identities = {
        _snappi_port_identity(port) for port in selected_ports
    }
    candidate_ports = [
        port for port in available_snappi_ports
        if (_port_matches_peer_device(port, downlink_lc_hostname) and
            _snappi_port_identity(port) not in selected_identities)
    ]
    candidate_ports.sort(
        key=lambda port: 0 if str(port.get("speed")) == SPEED_100G else 1)
    peer_ports = candidate_ports[:needed_ports]
    if peer_ports:
        logger.info(
            "Selected non-GCU downlink LC traffic peer ports %s",
            _format_snappi_port_names(peer_ports),
        )
    return _mark_gcu_target_ports(peer_ports, False)


def _add_downlink_traffic_peer_ports(
        gcu_target_ports, available_snappi_ports, downlink_lc_hostname,
        preferred_ports):
    """
    Add downlink traffic peers when fewer 400G GCU targets are available.
    """
    selected_ports = _mark_gcu_target_ports(gcu_target_ports, True)
    peer_ports = _select_downlink_traffic_peer_ports(
        available_snappi_ports,
        downlink_lc_hostname,
        selected_ports,
        preferred_ports - len(selected_ports),
    )
    if len(selected_ports) + len(peer_ports) < preferred_ports:
        logger.info(
            "Only %s downlink LC Snappi ports selected; traffic requires %s",
            len(selected_ports) + len(peer_ports),
            preferred_ports,
        )
    return selected_ports + peer_ports


def _select_same_asic_downlink_ports(downlink_ports, total_ports):
    """
    Select enough 400G downlink ports from a single ASIC.
    """
    ports_by_asic = defaultdict(list)
    for port in downlink_ports:
        ports_by_asic[port.get("asic_value")].append(port)

    for asic_value, ports in ports_by_asic.items():
        if len(ports) >= total_ports:
            logger.info(
                "Selected downlink LC ASIC %s ports %s",
                asic_value,
                _format_snappi_port_names(ports[:total_ports]),
            )
            return ports[:total_ports]
    return []


def _select_multi_asic_downlink_ports(
        downlink_ports, number_of_tx_rx_ports):
    """
    Select enough 400G downlink ports across two ASICs.
    """
    tx_port_count, rx_port_count = number_of_tx_rx_ports
    total_ports = tx_port_count + rx_port_count
    ports_by_asic = defaultdict(list)
    for port in downlink_ports:
        ports_by_asic[port.get("asic_value")].append(port)

    if len(ports_by_asic) < 2:
        return []

    selected_ports = []
    selected_asics = set()
    for asic_value, ports in ports_by_asic.items():
        if len(ports) >= tx_port_count:
            selected_ports.extend(ports[:tx_port_count])
            selected_asics.add(asic_value)
            break

    for asic_value, ports in ports_by_asic.items():
        if asic_value in selected_asics:
            continue
        if len(ports) >= rx_port_count:
            selected_ports.extend(ports[:rx_port_count])
            break

    if len(selected_ports) == total_ports:
        logger.info(
            "Selected downlink LC multi-ASIC ports %s",
            _format_snappi_port_names(selected_ports),
        )
        return selected_ports
    return []


def _select_downlink_ports_for_category(
        downlink_ports, category, number_of_tx_rx_ports):
    """
    Select 400G downlink ports for one dynamic Snappi category.
    """
    total_ports = sum(number_of_tx_rx_ports)
    if category == SNAPPI_CATEGORY_SINGLE_LC_SINGLE_ASIC:
        return _select_same_asic_downlink_ports(downlink_ports, total_ports)

    if category == SNAPPI_CATEGORY_SINGLE_LC_MULTIPLE_ASIC:
        return _select_multi_asic_downlink_ports(
            downlink_ports, number_of_tx_rx_ports)

    if category == SNAPPI_CATEGORY_MULTIPLE_LC_MULTIPLE_ASIC:
        pytest.skip(
            "{} is not applicable because this test is restricted to the "
            "downlink LC".format(SNAPPI_CATEGORY_MULTIPLE_LC_MULTIPLE_ASIC)
        )
        return []

    pytest.skip("Unsupported downlink LC Snappi category {}".format(category))
    return []


def _validate_static_downlink_selection(
        selected_ports, downlink_lc_hostname, min_ports):
    """
    Verify static Snappi overrides selected downlink LC ports with 400G target.
    """
    non_downlink_ports = [
        port for port in selected_ports
        if not _port_matches_peer_device(port, downlink_lc_hostname)
    ]
    pytest_require(
        not non_downlink_ports,
        "Static Snappi selection must use only downlink LC {}; selected "
        "non-downlink ports {}".format(
            downlink_lc_hostname,
            _format_snappi_port_names(non_downlink_ports),
        ),
    )
    pytest_require(
        len(selected_ports) >= min_ports,
        "Need minimum of {} downlink LC Snappi ports, got {}".format(
            min_ports, len(selected_ports)),
    )

    gcu_target_ports = [
        port for port in selected_ports
        if str(port.get("speed")) == SPEED_400G
    ]
    pytest_require(
        len(gcu_target_ports) >= min_ports,
        "Need minimum of {} 400G GCU target ports on downlink LC {}; "
        "selected ports {}".format(
            min_ports,
            downlink_lc_hostname,
            _format_snappi_port_names(selected_ports),
        ),
    )


def _select_snappi_ports_from_param(
        request, param, available_snappi_ports,
        number_of_tx_rx_ports, duthosts, tbinfo):
    """
    Select 400G GCU targets and optional traffic peers on the downlink LC.
    """
    downlink_lc_hostname = _get_downlink_lc_hostname(duthosts, tbinfo)
    logger.info("Restricting GCU speed upgrade to downlink LC %s",
                downlink_lc_hostname)

    testbed = request.config.getoption("--testbed")
    is_override, _ = parse_override(testbed, "multidut_port_info")
    preferred_ports = sum(number_of_tx_rx_ports)
    if is_override:
        testbed_subtype, rdma_ports = next(iter(param.items()))
        tx_port_count, rx_port_count = number_of_tx_rx_ports

        pytest_require(
            len(available_snappi_ports) >= tx_port_count + rx_port_count,
            "Need minimum of {} Snappi ports, got {}".format(
                tx_port_count + rx_port_count, len(available_snappi_ports)
            ),
        )
        if is_snappi_multidut(duthosts):
            selected_ports = get_snappi_ports_for_rdma(
                available_snappi_ports,
                rdma_ports,
                tx_port_count,
                rx_port_count,
                testbed,
            )
            _validate_static_downlink_selection(
                selected_ports,
                downlink_lc_hostname,
                MIN_DOWNLINK_SNAPPIPORTS,
            )
            return _mark_400g_ports_as_gcu_targets(selected_ports)
        logger.info(
            "Using override subtype %s on single-DUT Snappi setup",
            testbed_subtype,
        )
        pytest.skip(
            "Downlink LC GCU speed upgrade requires multidut Snappi setup"
        )

    pytest_require(
        isinstance(param, str),
        "Unsupported Snappi port parameter {}".format(param),
    )
    speed, category = param.split("-", 1)
    pytest_require(
        int(float(speed)) == 400,
        "Skipping non-400G Snappi port parameter {}".format(param),
    )
    if category == "no_available_400g_ports":
        pytest.skip("No 400G Snappi port metadata is available")

    downlink_400g_ports = [
        port for port in available_snappi_ports
        if (_port_matches_peer_device(port, downlink_lc_hostname) and
            str(port.get("speed")) == SPEED_400G)
    ]
    if len(downlink_400g_ports) < MIN_DOWNLINK_SNAPPIPORTS:
        pytest.skip(
            "Need minimum of {} 400G Snappi ports on downlink LC {}, got "
            "{}".format(
                MIN_DOWNLINK_SNAPPIPORTS,
                downlink_lc_hostname,
                len(downlink_400g_ports),
            )
        )

    if len(downlink_400g_ports) < preferred_ports:
        selected_ports = downlink_400g_ports[:MIN_DOWNLINK_SNAPPIPORTS]
        logger.info(
            "Only one 400G downlink LC port is available; selecting %s "
            "as GCU target and looking for downlink traffic peers",
            _format_snappi_port_names(selected_ports),
        )
        return _add_downlink_traffic_peer_ports(
            selected_ports,
            available_snappi_ports,
            downlink_lc_hostname,
            preferred_ports,
        )

    selected_ports = _select_downlink_ports_for_category(
        downlink_400g_ports, category, number_of_tx_rx_ports)
    if not selected_ports:
        pytest.skip(
            "Unsupported downlink LC combination {} on {}".format(
                param, downlink_lc_hostname)
        )
    return _add_downlink_traffic_peer_ports(
        selected_ports,
        available_snappi_ports,
        downlink_lc_hostname,
        preferred_ports,
    )


@pytest.fixture(scope="function")
def gcu_100g_to_400g_snappi_testbed(
        request,
        duthosts,
        tbinfo,
        snappi_api,  # noqa: F811
        snappi_gcu_port_param,
        get_snappi_ports,  # noqa: F811
        number_of_tx_rx_ports,
        loganalyzer):
    """
    Convert selected Snappi DUT ports 400G -> 100G -> 400G with GCU.

    Yields:
        tuple: (testbed_config, port_config_list, selected_snappi_ports)
    """
    selected_snappi_ports = [
        dict(port)
        for port in _select_snappi_ports_from_param(
            request,
            snappi_gcu_port_param,
            get_snappi_ports,
            number_of_tx_rx_ports,
            duthosts,
            tbinfo,
        )
    ]

    pytest_require(
        selected_snappi_ports,
        "No Snappi ports selected for GCU speed upgrade test",
    )

    for port in selected_snappi_ports:
        port.setdefault(
            GCU_TARGET_PORT_FIELD, str(port.get("speed")) == SPEED_400G)
    gcu_target_ports = [
        port for port in selected_snappi_ports
        if port.get(GCU_TARGET_PORT_FIELD)
    ]
    pytest_require(
        gcu_target_ports,
        "No 400G downlink LC Snappi port selected as GCU target",
    )

    contexts = {}
    touched_duts = {}
    ports_by_context = defaultdict(list)
    selected_snappi_port_by_identity = {
        _snappi_port_context_identity(port): port
        for port in selected_snappi_ports
    }
    selected_gcu_identities = {
        _snappi_port_context_identity(port) for port in gcu_target_ports
    }

    port_index = 0
    while port_index < len(gcu_target_ports):
        port = gcu_target_ports[port_index]
        port_index += 1
        duthost = port["duthost"]
        namespace = port.get("asic_value")
        peer_port = port["peer_port"]
        key = (duthost.hostname, namespace)
        touched_duts[duthost.hostname] = duthost

        if key not in contexts:
            contexts[key] = {
                "duthost": duthost,
                "namespace": namespace,
                "config_facts": duthost.config_facts(
                    host=duthost.hostname,
                    source="running",
                    namespace=namespace,
                )["ansible_facts"],
                "mg_facts": duthost.get_extended_minigraph_facts(
                    tbinfo, namespace=namespace),
            }

        portchannel = _get_portchannel_for_member(
            contexts[key]["config_facts"], peer_port)
        if portchannel:
            member_ports = _get_external_portchannel_members(
                contexts[key]["config_facts"], portchannel)
            missing_member_ports = []
            for member_port in member_ports:
                member_snappi_port = _find_available_snappi_port(
                    get_snappi_ports, duthost, namespace, member_port)
                if (member_snappi_port is None or
                        str(member_snappi_port.get("speed")) != SPEED_400G):
                    missing_member_ports.append(member_port)
                    continue

                member_identity = _snappi_port_context_identity(
                    member_snappi_port)
                existing_member_port = selected_snappi_port_by_identity.get(
                    member_identity)
                if existing_member_port is None:
                    member_snappi_port[GCU_TARGET_PORT_FIELD] = True
                    selected_snappi_port_by_identity[
                        member_identity] = member_snappi_port
                    selected_snappi_ports.append(member_snappi_port)
                    existing_member_port = member_snappi_port
                else:
                    existing_member_port[GCU_TARGET_PORT_FIELD] = True

                if member_identity not in selected_gcu_identities:
                    selected_gcu_identities.add(member_identity)
                    gcu_target_ports.append(existing_member_port)

            pytest_require(
                not missing_member_ports,
                "Selected 400G port {} is member of {}, but not all external "
                "members have 400G Snappi links: missing/non-400G {}".format(
                    peer_port, portchannel, missing_member_ports),
            )

        if peer_port not in ports_by_context[key]:
            ports_by_context[key].append(peer_port)

        port_config = (
            contexts[key]["config_facts"].get("PORT", {}).get(peer_port)
        )
        pytest_require(
            port_config is not None,
            "PORT table entry for {} missing on {}".format(
                peer_port, duthost.hostname),
        )
        pytest_require(
            str(port_config.get("speed")) == SPEED_400G and
            str(port.get("speed")) == SPEED_400G,
            (
                "Selected Snappi port {} on {} must start as 400G; "
                "DUT speed={}, Snappi speed={}"
            ).format(
                peer_port,
                duthost.hostname,
                port_config.get("speed"),
                port.get("speed"),
            ),
        )
        pytest_require(
            _get_num_lanes_per_speed(duthost, SPEED_100G) is not None,
            "Platform {} has no 100G lane-count data".format(
                duthost.facts["platform"]),
        )

        port["speed"] = SPEED_400G
        port["snappi_speed_type"] = SNAPPI_SPEED_400G

    _ignore_expected_speed_change_logs(
        list(touched_duts.values()), loganalyzer)

    testbed_config = None
    port_config_list = None
    try:
        configs_100g = defaultdict(dict)
        for key, ports in ports_by_context.items():
            ctx = contexts[key]
            for peer_port in ports:
                original_port_config = ctx["config_facts"]["PORT"][peer_port]
                configs_100g[key][peer_port] = _build_port_config_for_speed(
                    ctx["duthost"],
                    original_port_config,
                    SPEED_100G,
                    _cli_namespace_prefix(ctx["namespace"]),
                    peer_port,
                )

        _wait_before_gcu_speed_patch(
            "400G->100G downgrade", contexts, ports_by_context)

        for key, port_configs in configs_100g.items():
            ctx = contexts[key]
            apply_patch_port_configs(
                ctx["duthost"],
                ctx["namespace"],
                port_configs,
            )

        for key, port_configs in configs_100g.items():
            ctx = contexts[key]
            for peer_port, port_config_100g in port_configs.items():
                verify_port_show_interface_status(
                    ctx["duthost"],
                    peer_port,
                    ctx["namespace"],
                    SPEED_100G,
                    port_config_100g["lanes"],
                    port_config_100g.get("fec"),
                    require_oper_up=False,
                )

        _wait_before_gcu_speed_patch(
            "100G->400G restore", contexts, ports_by_context)

        configs_400g = defaultdict(dict)
        for key, ports in ports_by_context.items():
            ctx = contexts[key]
            for peer_port in ports:
                configs_400g[key][peer_port] = (
                    _build_port_config_for_400g_upgrade(
                        ctx["duthost"],
                        _cli_namespace_prefix(ctx["namespace"]),
                        peer_port,
                        configs_100g[key][peer_port],
                        ctx["config_facts"]["PORT"][peer_port],
                    )
                )

        for key, port_configs in configs_400g.items():
            ctx = contexts[key]
            restore_mg_facts = _get_gcu_restore_mg_facts(
                ctx["mg_facts"], port_configs.keys())
            apply_patch_port_configs(
                ctx["duthost"],
                ctx["namespace"],
                port_configs,
                config_facts=ctx["config_facts"],
                mg_facts=restore_mg_facts,
            )

        for key, port_configs in configs_400g.items():
            ctx = contexts[key]
            for peer_port, port_config_400g in port_configs.items():
                verify_port_show_interface_status(
                    ctx["duthost"],
                    peer_port,
                    ctx["namespace"],
                    SPEED_400G,
                    port_config_400g["lanes"],
                    port_config_400g.get("fec"),
                    require_oper_up=True,
                )

        snappi_config_builder = snappi_dut_base_config
        selected_speeds = {
            str(port.get("speed")) for port in selected_snappi_ports
        }
        if len(selected_speeds) > 1:
            logger.info(
                "Using mixed-speed Snappi base config for selected speeds %s",
                selected_speeds,
            )
            snappi_config_builder = snappi_multi_base_config

        (
            testbed_config,
            port_config_list,
            selected_snappi_ports,
        ) = snappi_config_builder(
                duthosts,
                selected_snappi_ports,
                snappi_api,
                setup=True,
        )
        yield testbed_config, port_config_list, selected_snappi_ports
    finally:
        try:
            if testbed_config is not None and port_config_list is not None:
                setup_dut_ports(
                    False,
                    duthosts,
                    testbed_config,
                    port_config_list,
                    selected_snappi_ports,
                )
        finally:
            _restore_duts(list(touched_duts.values()), loganalyzer)


def _gen_all_to_all_traffic(
        testbed_config, duthosts, port_config_list, priority, dscp_map):
    """
    Generate the same all-to-all IPv4 traffic used by test_multidut_snappi.
    """
    line_rate = 100
    if duthosts[0].facts["asic_type"] == "cisco-8000":
        line_rate = 50
    flow_count_per_tx = len(port_config_list) - 1
    rate_percent = line_rate / flow_count_per_tx
    speed_by_port_name = _get_snappi_port_speed_gbps_by_name(testbed_config)

    duration_sec = 2
    pkt_size = 1024
    tx_port_id_list, rx_port_id_list = select_ports(
        port_config_list=port_config_list,
        pattern="all to all",
        rx_port_id=0,
    )

    for tx_port_id in tx_port_id_list:
        for rx_port_id in rx_port_id_list:
            if tx_port_id == rx_port_id:
                continue

            tx_port_config = next(
                (x for x in port_config_list if x.id == tx_port_id), None)
            rx_port_config = next(
                (x for x in port_config_list if x.id == rx_port_id), None)
            tx_mac = tx_port_config.mac
            if (tx_port_config.gateway == rx_port_config.gateway and
                    tx_port_config.prefix_len == rx_port_config.prefix_len):
                rx_mac = rx_port_config.mac
            else:
                rx_mac = tx_port_config.gateway_mac

            flow = testbed_config.flows.flow(
                name="Flow {} -> {}".format(tx_port_id, rx_port_id)
            )[-1]
            tx_port_name = testbed_config.ports[tx_port_id].name
            rx_port_name = testbed_config.ports[rx_port_id].name
            flow.tx_rx.port.tx_name = tx_port_name
            flow.tx_rx.port.rx_name = rx_port_name

            eth, ipv4, udp = flow.packet.ethernet().ipv4().udp()
            udp.src_port.increment.start = random.randint(5000, 6000)
            udp.src_port.increment.step = 1
            udp.src_port.increment.count = 1

            eth.src.value = tx_mac
            eth.dst.value = rx_mac
            eth.pfc_queue.value = priority

            ipv4.src.value = tx_port_config.ip
            ipv4.dst.value = gen_data_flow_dest_ip(rx_port_config.ip)
            ipv4.priority.choice = ipv4.priority.DSCP
            ipv4.priority.dscp.phb.values = dscp_map[priority]
            ipv4.priority.dscp.ecn.value = (
                ipv4.priority.dscp.ecn.CAPABLE_TRANSPORT_1
            )

            flow.size.fixed = pkt_size
            flow.rate.percentage = _get_snappi_flow_rate_percent(
                speed_by_port_name,
                tx_port_name,
                rx_port_name,
                line_rate,
                flow_count_per_tx,
                rate_percent,
            )
            flow.duration.fixed_seconds.seconds = duration_sec
            flow.metrics.enable = True
            flow.metrics.loss = True

    return testbed_config


def _parse_snappi_speed_gbps(speed):
    """
    Parse Snappi L1 speed strings such as speed_400_gbps.
    """
    words = speed.split("_")
    pytest_assert(
        len(words) == 3 and words[1].isdigit(),
        "Fail to get port speed from {}".format(speed),
    )
    return int(words[1])


def _get_snappi_port_speed_gbps_by_name(config):
    """
    Return Snappi port-name to line-rate mapping from L1 profiles.
    """
    speed_by_port_name = {}
    for layer1_config in config.layer1:
        speed_gbps = _parse_snappi_speed_gbps(layer1_config.speed)
        for port_name in layer1_config.port_names:
            speed_by_port_name[port_name] = speed_gbps
    return speed_by_port_name


def _get_snappi_flow_rate_percent(
        speed_by_port_name, tx_port_name, rx_port_name, line_rate,
        flow_count_per_tx, default_rate_percent):
    """
    Return per-flow rate percent capped by the slower side in mixed-speed runs.
    """
    tx_speed = speed_by_port_name.get(tx_port_name)
    rx_speed = speed_by_port_name.get(rx_port_name)
    if not tx_speed or not rx_speed:
        return default_rate_percent

    return line_rate * min(tx_speed, rx_speed) / tx_speed / flow_count_per_tx


def _run_snappi_traffic(api, config):
    """
    Apply Snappi config, run traffic, and return final flow metrics.
    """
    api.set_config(config)
    wait_for_arp(api, max_attempts=30, poll_interval_sec=2)

    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
    api.set_control_state(cs)

    duration_sec = config.flows[0].duration.fixed_seconds.seconds
    time.sleep(duration_sec)

    attempts = 0
    max_attempts = 20
    all_flow_names = [flow.name for flow in config.flows]
    rows = []
    while attempts < max_attempts:
        request = api.metrics_request()
        request.flow.flow_names = all_flow_names
        rows = api.get_metrics(request).flow_metrics
        transmit_states = [row.transmit for row in rows]
        if (len(rows) == len(all_flow_names) and
                list(set(transmit_states)) == ["stopped"]):
            time.sleep(SNAPPI_POLL_DELAY_SEC)
            break
        time.sleep(1)
        attempts += 1

    pytest_assert(
        attempts < max_attempts,
        "Flows do not stop in {} seconds".format(max_attempts),
    )

    request = api.metrics_request()
    request.flow.flow_names = all_flow_names
    rows = api.get_metrics(request).flow_metrics

    cs = api.control_state()
    cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
    api.set_control_state(cs)

    return rows


def _assert_snappi_flow_metrics(config, rows):
    """
    Assert zero loss and expected frame count for generated traffic.
    """
    single_speed_config = len(config.layer1) == 1
    port_speed_gbps = None
    if single_speed_config:
        port_speed_gbps = _parse_snappi_speed_gbps(config.layer1[0].speed)
    else:
        logger.info(
            "Skipping expected frame-count check for mixed-speed Snappi "
            "config with %s L1 profiles",
            len(config.layer1),
        )

    for row in rows:
        rx_frames = row.frames_rx
        tx_frames = row.frames_tx
        pytest_assert(
            rx_frames == tx_frames,
            "Packet loss for {}: Tx {}, Rx {}".format(
                row.name, tx_frames, rx_frames),
        )
        pytest_assert(
            rx_frames > 0,
            "No packets received for flow {}".format(row.name),
        )

        if not single_speed_config:
            continue

        pkt_size = config.flows[0].size.fixed
        rate_percent = config.flows[0].rate.percentage
        duration_sec = config.flows[0].duration.fixed_seconds.seconds
        tput_bps = port_speed_gbps * 1e9 * rate_percent / 100.0
        exp_rx_frames = tput_bps * duration_sec / 8 / pkt_size
        deviation = abs(float(exp_rx_frames) / rx_frames - 1)
        pytest_assert(
            deviation <= 0.05,
            "Expected / Actual # of pkts for flow {}: {} / {}".format(
                row.name, exp_rx_frames, rx_frames
            ),
        )


def test_snappi_gcu_port_speed_upgrade_100g_to_400g(
        duthosts,
        snappi_api,  # noqa: F811
        lossless_prio_list,  # noqa: F811
        prio_dscp_map,  # noqa: F811
        gcu_100g_to_400g_snappi_testbed):
    """
    Verify Snappi traffic after DUT ports convert 100G -> 400G by GCU.
    """
    (
        testbed_config,
        port_config_list,
        selected_snappi_ports,
    ) = gcu_100g_to_400g_snappi_testbed

    for port in selected_snappi_ports:
        logger.info(
            "Snappi GCU test selected port: %s:%s speed=%s gcu_target=%s",
            port["peer_device"],
            port["peer_port"],
            port.get("speed"),
            port.get(GCU_TARGET_PORT_FIELD),
        )

    if len(port_config_list) < 2:
        logger.info(
            "Only one Snappi port selected; applying config and ARP check "
            "without traffic"
        )
        snappi_api.set_config(testbed_config)
        wait_for_arp(snappi_api, max_attempts=30, poll_interval_sec=2)
        return

    pytest_require(
        lossless_prio_list,
        "No lossless priorities available for Snappi traffic",
    )
    lossless_prio = int(random.sample(lossless_prio_list, 1)[0])
    config = _gen_all_to_all_traffic(
        testbed_config=testbed_config,
        duthosts=duthosts,
        port_config_list=port_config_list,
        priority=lossless_prio,
        dscp_map=prio_dscp_map,
    )
    pytest_require(
        len(config.flows) > 0,
        "No eligible Snappi traffic flows generated for selected ports",
    )

    rows = _run_snappi_traffic(snappi_api, config)
    _assert_snappi_flow_metrics(config, rows)
