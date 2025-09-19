import logging
import pytest

from tests.snappi_tests.packet_trimming.files.packet_trimming_helper import run_packet_trimming_test
from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config, is_pfc_enabled  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map  # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.packet_trim_helpers import TrimMode

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]

SINGLE_QUEUE_STREAM = [0]
MULTI_QUEUE_STREAM = [0, 1, 2]


@pytest.mark.parametrize(
    "tx_dscp_values, description",
    [
        (SINGLE_QUEUE_STREAM, "single queue stream"),
        (MULTI_QUEUE_STREAM, "multi queue stream"),
    ]
)
def test_four_to_one_asymmetric_dscp_trimming(snappi_api,  # noqa: F811
                                              snappi_testbed_config,  # noqa: F811
                                              conn_graph_facts,  # noqa: F811
                                              fanout_graph_facts,  # noqa: F811
                                              duthosts,
                                              rand_one_dut_hostname,
                                              rand_one_dut_portname_oper_up,
                                              prio_dscp_map,  # noqa: F811
                                              tx_dscp_values,
                                              description,  # noqa: F811
                                              ):
    """
    Validate packet trimming with 4 to 1 asymmetric traffic single/multiple data queue

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.num_tx_links = 4
    snappi_extra_params.num_rx_links = 1
    snappi_extra_params.tx_dscp_values = tx_dscp_values

    run_packet_trimming_test(api=snappi_api,
                             testbed_config=testbed_config,
                             port_config_list=port_config_list,
                             conn_data=conn_graph_facts,
                             fanout_data=fanout_graph_facts,
                             duthost=duthost,
                             dut_port=dut_port,
                             prio_dscp_map=prio_dscp_map,
                             snappi_test_params=snappi_extra_params,
                             trim_mode=TrimMode.ASYMMETRIC,
                             )


@pytest.mark.parametrize(
    "tx_dscp_values, description",
    [
        (SINGLE_QUEUE_STREAM, "single queue stream"),
        (MULTI_QUEUE_STREAM, "multi queue stream"),
    ]
)
def test_eight_to_one_asymmetric_dscp_trimming(snappi_api,  # noqa: F811
                                               snappi_testbed_config,  # noqa: F811
                                               conn_graph_facts,  # noqa: F811
                                               fanout_graph_facts,  # noqa: F811
                                               duthosts,
                                               rand_one_dut_hostname,
                                               rand_one_dut_portname_oper_up,
                                               prio_dscp_map,  # noqa: F811
                                               tx_dscp_values,
                                               description,  # noqa: F811
                                               ):
    """
    Validate packet trimming with 8 to 1 asymmetric traffic single/multiple data queue

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.num_tx_links = 8
    snappi_extra_params.num_rx_links = 1
    snappi_extra_params.tx_dscp_values = tx_dscp_values

    run_packet_trimming_test(api=snappi_api,
                             testbed_config=testbed_config,
                             port_config_list=port_config_list,
                             conn_data=conn_graph_facts,
                             fanout_data=fanout_graph_facts,
                             duthost=duthost,
                             dut_port=dut_port,
                             prio_dscp_map=prio_dscp_map,
                             snappi_test_params=snappi_extra_params,
                             trim_mode=TrimMode.ASYMMETRIC,
                             )


@pytest.mark.parametrize(
    "tx_dscp_values, description",
    [
        (SINGLE_QUEUE_STREAM, "single queue stream"),
        (MULTI_QUEUE_STREAM, "multi queue stream"),
    ]
)
def test_ten_to_one_asymmetric_dscp_trimming(snappi_api,  # noqa: F811
                                            snappi_testbed_config,  # noqa: F811
                                            conn_graph_facts,  # noqa: F811
                                            fanout_graph_facts,  # noqa: F811
                                            duthosts,
                                            rand_one_dut_hostname,
                                            rand_one_dut_portname_oper_up,
                                            prio_dscp_map,  # noqa: F811
                                            tx_dscp_values,
                                            description,  # noqa: F811
                                            ):
    """
    Validate packet trimming with 10 to 1 asymmetric traffic single data queue

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.num_tx_links = 10
    snappi_extra_params.num_rx_links = 1
    snappi_extra_params.tx_dscp_values = tx_dscp_values

    run_packet_trimming_test(api=snappi_api,
                             testbed_config=testbed_config,
                             port_config_list=port_config_list,
                             conn_data=conn_graph_facts,
                             fanout_data=fanout_graph_facts,
                             duthost=duthost,
                             dut_port=dut_port,
                             prio_dscp_map=prio_dscp_map,
                             snappi_test_params=snappi_extra_params,
                             trim_mode=TrimMode.ASYMMETRIC,
                             )


@pytest.mark.parametrize(
    "tx_dscp_values, description",
    [
        (SINGLE_QUEUE_STREAM, "single queue stream"),
        (MULTI_QUEUE_STREAM, "multi queue stream"),
    ]
)
def test_twelve_to_one_asymmetric_dscp_trimming(snappi_api,  # noqa: F811
                                                snappi_testbed_config,  # noqa: F811
                                                conn_graph_facts,  # noqa: F811
                                                fanout_graph_facts,  # noqa: F811
                                                duthosts,
                                                rand_one_dut_hostname,
                                                rand_one_dut_portname_oper_up,
                                                prio_dscp_map,  # noqa: F811
                                                tx_dscp_values,
                                                description,  # noqa: F811
                                                ):
    """
    Validate packet trimming with 12 to 1 asymmetric traffic single/multiple data queue

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.num_tx_links = 12
    snappi_extra_params.num_rx_links = 1
    snappi_extra_params.tx_dscp_values = tx_dscp_values

    run_packet_trimming_test(api=snappi_api,
                             testbed_config=testbed_config,
                             port_config_list=port_config_list,
                             conn_data=conn_graph_facts,
                             fanout_data=fanout_graph_facts,
                             duthost=duthost,
                             dut_port=dut_port,
                             prio_dscp_map=prio_dscp_map,
                             snappi_test_params=snappi_extra_params,
                             trim_mode=TrimMode.ASYMMETRIC,
                             )
