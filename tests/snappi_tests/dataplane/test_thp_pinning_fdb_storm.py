import logging

import pytest

from tests.common.fixtures.conn_graph_facts import (  # noqa: F401
    conn_graph_facts,
    fanout_graph_facts,
    fanout_graph_facts_multidut,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.snappi_fixtures import (  # noqa: F401
    cleanup_config,
    get_snappi_ports,
    get_snappi_ports_multi_dut,
    get_snappi_ports_single_dut,
    snappi_api,
    snappi_api_serv_ip,
    snappi_api_serv_port,
    snappi_port_selection,
    tgen_port_info,
)
from tests.snappi_tests.dataplane.files.helper import start_stop
from tests.snappi_tests.dataplane.files.thp_pinning_helper import (
    DEFAULT_PINNING_DURATION_SEC,
    cleanup_thp_pinning_objects,
    configure_dut_for_fdb_storm,
    find_unused_vlan_id,
    generate_fdb_storm_config,
    get_thp_enabled_mode,
    monitor_dut_health,
    render_thp_pinning_script,
    select_pinning_ports,
    select_snappi_test_ports,
    set_thp_enabled_mode,
    start_thp_pinning_workload,
    stop_thp_pinning_workload,
    verify_fdb_storm_traffic,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("multidut-tgen", "tgen"),
    pytest.mark.disable_memory_utilization,
]


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (1, 2)


@pytest.mark.disable_loganalyzer
def test_thp_pinning_fdb_storm_direct_snappi(duthosts,             # noqa: F811
                                             snappi_api,           # noqa: F811
                                             tgen_port_info,       # noqa: F811
                                             get_snappi_ports):    # noqa: F811
    """
    Verify THP pinning under madvise does not grow orchagent AnonHugePages by more than 500 MB in 15 minutes.
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    pytest_assert(port_config_list, "Direct Snappi setup did not provide port configuration")
    duthost, ingress_ports, egress_port = select_snappi_test_ports(snappi_ports)
    excluded_ports = [
        port["peer_port"]
        for port in ingress_ports + [egress_port]
        if port["peer_device"] == duthost.hostname
    ]
    pinning_ports = select_pinning_ports(
        duthost,
        excluded_ports,
        required_ports=1
    )
    vlan_id = find_unused_vlan_id(duthost)
    workload_pid = None
    traffic_started = False
    original_thp_mode = None

    logger.info("FDB storm ingress ports: %s", [port["peer_port"] for port in ingress_ports])
    logger.info("FDB storm routed egress port: %s", egress_port["peer_port"])
    logger.info("THP pinning ports: %s", pinning_ports)

    try:
        original_thp_mode = get_thp_enabled_mode(duthost)
        logger.info("Original THP enabled mode: %s", original_thp_mode)
        set_thp_enabled_mode(duthost, "madvise")
        configure_dut_for_fdb_storm(duthost, ingress_ports, egress_port, pinning_ports, vlan_id)
        config = generate_fdb_storm_config(
            testbed_config,
            ingress_ports,
            egress_port,
            duration_sec=DEFAULT_PINNING_DURATION_SEC
        )
        snappi_api.set_config(config)

        start_stop(snappi_api, operation="start", op_type="traffic")
        traffic_started = True
        verify_fdb_storm_traffic(snappi_api)

        workload_pid = start_thp_pinning_workload(
            duthost,
            render_thp_pinning_script(pinning_ports)
        )
        final_sample = monitor_dut_health(duthost, workload_pid, pinning_ports)
        logger.info("Final memory sample: %s", final_sample)
    finally:
        if traffic_started:
            start_stop(snappi_api, operation="stop", op_type="traffic")
        stop_thp_pinning_workload(duthost, workload_pid)
        cleanup_thp_pinning_objects(duthost, pinning_ports)
        if original_thp_mode is not None:
            set_thp_enabled_mode(duthost, original_thp_mode)
        cleanup_config(duthosts, snappi_ports)
