import logging

import pytest

from tests.common.config_reload import config_reload
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut  # noqa: F401
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
from tests.snappi_tests.dataplane.files.thp_pinning_helper import (
    DEFAULT_PINNING_DURATION_SEC,
    cleanup_thp_pinning_objects,
    configure_dut_for_fdb_storm,
    find_unused_vlan_id,
    generate_fdb_storm_config,
    monitor_dut_health,
    render_thp_pinning_script,
    select_pinning_ports,
    select_snappi_test_ports,
    start_thp_pinning_workload,
    stop_thp_pinning_workload,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("multidut-tgen", "tgen")]

CONFIG_DB_BACKUP = "/tmp/thp_pinning_fdb_storm_config_db.json"


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (1, 4)


@pytest.mark.disable_loganalyzer
def test_thp_pinning_fdb_storm_direct_snappi(duthosts,             # noqa: F811
                                             snappi_api,           # noqa: F811
                                             tgen_port_info,       # noqa: F811
                                             get_snappi_ports):    # noqa: F811
    """
    Verify THP pinning does not drive orchagent AnonHugePages above 1 GB within 10 minutes.
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    pytest_assert(port_config_list, "PFC/PFCWD direct Snappi setup did not provide port configuration")
    duthost, ingress_ports, egress_port = select_snappi_test_ports(snappi_ports)
    excluded_ports = [
        port["peer_port"]
        for port in get_snappi_ports
        if port["peer_device"] == duthost.hostname
    ]
    pinning_ports = select_pinning_ports(duthost, excluded_ports)
    vlan_id = find_unused_vlan_id(duthost)
    workload_pid = None
    traffic_started = False

    logger.info("FDB storm ingress ports: %s", [port["peer_port"] for port in ingress_ports])
    logger.info("FDB storm routed egress port: %s", egress_port["peer_port"])
    logger.info("THP pinning ports: %s", pinning_ports)

    duthost.shell("sudo cp /etc/sonic/config_db.json {}".format(CONFIG_DB_BACKUP))

    try:
        configure_dut_for_fdb_storm(duthost, ingress_ports, egress_port, pinning_ports, vlan_id)
        config = generate_fdb_storm_config(
            testbed_config,
            ingress_ports,
            egress_port,
            duration_sec=DEFAULT_PINNING_DURATION_SEC
        )
        snappi_api.set_config(config)

        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        snappi_api.set_control_state(cs)
        traffic_started = True

        workload_pid = start_thp_pinning_workload(
            duthost,
            render_thp_pinning_script(pinning_ports)
        )
        final_sample = monitor_dut_health(duthost, workload_pid, pinning_ports)
        logger.info("Final memory sample: %s", final_sample)
    finally:
        if traffic_started:
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
        stop_thp_pinning_workload(duthost, workload_pid)
        cleanup_thp_pinning_objects(duthost, pinning_ports)
        duthost.shell("sudo cp {} /etc/sonic/config_db.json".format(CONFIG_DB_BACKUP),
                      module_ignore_errors=True)
        config_reload(duthost)
        cleanup_config(duthosts, snappi_ports)
