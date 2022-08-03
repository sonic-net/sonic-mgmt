import pytest
import time
import datetime

from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed_config
from tests.common.ixia.qos_fixtures import prio_dscp_map, lossless_prio_list
from ixia.ptf_utils import get_sai_attributes

from files.helper import run_ecn_test
from common.cisco_data import setup_ecn_markings_dut, get_ecn_markings_dut

# percent linerate to use in the test.
TRAFFIC_RATE = 51

pytestmark = [pytest.mark.topology('tgen')]

@pytest.fixture(autouse=True, scope="module")
def store_ecn_markings_dut(duthost, localhost):
    original_ecn_markings = get_ecn_markings_dut(duthost)

    yield

    setup_ecn_markings_dut(duthost, localhost, **original_ecn_markings)

def stop_debug_shell(duthost):
    duthost.shell("docker exec -t syncd supervisorctl stop dshell_client")

@pytest.mark.parametrize("number_of_transmit_ports", [1, 3])
@pytest.mark.parametrize("pmax", [5, 100])
@pytest.mark.parametrize("xoff_quanta", [500, 10000, 20000, 30000, 40000, 50000, 60000])
@pytest.mark.parametrize("kmin", [50000])
@pytest.mark.parametrize("kmax", [500000])
@pytest.mark.parametrize("pkt_size", [1024])
@pytest.mark.parametrize("dequeue_marking,latency_marking", [(True, True), (False, True)])
def test_ecn_markings(request,
                      ixia_api,
                      ixia_testbed_config,
                      conn_graph_facts,
                      fanout_graph_facts,
                      duthosts,
                      ptfhost,
                      localhost,
                      rand_one_dut_hostname,
                      rand_one_dut_portname_oper_up,
                      rand_one_dut_lossless_prio,
                      prio_dscp_map,
                      store_ecn_markings_dut,
                      dequeue_marking,
                      latency_marking,
                      number_of_transmit_ports,
                      kmin,
                      kmax,
                      pkt_size,
                      pmax,
                      xoff_quanta):
    """
    Measure ECN marking accuracy of the device under test (DUT).
    ECN marking results into a file.

    Args:
        request (pytest fixture): pytest request object
        ixia_api (pytest fixture): IXIA session
        ixia_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    disable_test = request.config.getoption("--disable_ecn_test")
    if disable_test:
        pytest.skip("test_ecn_markings is disabled")

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = ixia_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    lossless_prio = int(lossless_prio)

    setup_ecn_markings_dut(duthost, localhost, 
                           ecn_dequeue_marking=dequeue_marking,
                           ecn_latency_marking=latency_marking)
    stop_debug_shell(duthost)

    csv_file_name = 'mark_data.csv'

    duthost.shell("sonic-clear pfccounters")
    duthost.shell("sonic-clear queuecounters")
    # TODO: This will be enabled when the PR for get_sai_attributes is approved:
    # https://github.com/Azure/sonic-mgmt/pull/6040
    #get_sai_attributes(duthost, ptfhost, dut_port, [], clear_only=True)
    traffic_rate = TRAFFIC_RATE/number_of_transmit_ports

    run_ecn_test(api=ixia_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 kmin=kmin,
                 kmax=kmax,
                 pmax=pmax,
                 pkt_size=pkt_size,
                 lossless_prio=lossless_prio,
                 prio_dscp_map=prio_dscp_map,
                 iters=1,
                 xoff_quanta=xoff_quanta,
                 traffic_rate=traffic_rate,
                 number_of_transmit_ports=number_of_transmit_ports,
                 single_pause=True)

    time.sleep(8)
    sai_values = None
    total = "N/A"
    marked_pkts = "N/A"

    # TODO:This will be enabled when the PR for get_sai_attributes is approved:
    # https://github.com/Azure/sonic-mgmt/pull/6040
    #sai_values = get_sai_attributes(duthost, ptfhost, dut_port,
    #                    ["SAI_QUEUE_STAT_PACKETS","SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS"])
    if sai_values:
        value_list = eval(sai_values[0])
        total = value_list[lossless_prio][0]
        marked_pkts = value_list[lossless_prio][1]

    print("The SAI attributes in the DUT:{}".format(sai_values))
    print("Xoff = {}".format(xoff_quanta))
    print("pmax = {}".format(pmax))

    with open(csv_file_name, "a") as fd:
        fd.write("{tx_ports},{rate},{deq},{lat},{kmax},{kmin},{pmax},{xoff_quanta},{total},{marked},{time_stamp}\n".format(
            time_stamp=str(datetime.datetime.now()),
            rate=traffic_rate,
            deq=dequeue_marking,
            lat=latency_marking,
            tx_ports=number_of_transmit_ports,
            kmax=kmax,
            kmin=kmin,
            pmax=pmax,
            xoff_quanta=xoff_quanta,
            total=total,
            marked=marked_pkts))

    print("test done")
