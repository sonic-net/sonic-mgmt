"""
    Tests the COPP feature in SONiC.

    Notes:
        These test cases require that a special RPC syncd image is installed on the
        DUT. You can either pre-install this image and run the test normally, or
        specify the `--swap-syncd` flag from the command line to have the test fetch
        the RPC image and install it before the test runs.

        These test cases limit the PPS of all trap groups to 600. This is done to ensure
        that the PTF can send traffic fast enough to trigger the policer. In order to validate
        higher rate limits, a physical traffic generator is needed, which is beyond the scope
        of these test cases.

    Parameters:
        --nn_target_port <port> (int): Which port you want the test to send traffic
            to. Default is 3.

            Note that this is not the same as the interface name. For example, Ethernet12
            may not be the 12th port in your system depending on the HWSKU under test.

        --pkt_tx_count <n> (int): How many packets to send during each individual test case.
            Default is 100000.

        --copp_swap_syncd: Used to install the RPC syncd image before running the tests. Default
            is enabled.
"""

import logging
import pytest
from collections import namedtuple

from tests.copp import copp_utils
from tests.ptf_runner import ptf_runner
from tests.common import config_reload
from tests.common.system_utils import docker

# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology("t1")
]

_COPPTestParameters = namedtuple("_COPPTestParameters",
                                 ["nn_target_port",
                                  "pkt_tx_count",
                                  "swap_syncd",
                                  "topo",
                                  "bgp_graph"])
_SUPPORTED_PTF_TOPOS = ["ptf32", "ptf64"]
_SUPPORTED_T1_TOPOS = ["t1", "t1-lag"]
_T1_NO_COPP_PROTOCOL = ["DHCP"]
_TEST_RATE_LIMIT = 600

class TestCOPP(object):
    """
        Tests basic COPP functionality in SONiC.
    """

    @pytest.mark.parametrize("protocol", ["ARP",
                                          "IP2ME",
                                          "SNMP",
                                          "SSH"])
    def test_policer(self, protocol, duthost, ptfhost, copp_testbed):
        """
            Validates that rate-limited COPP groups work as expected.

            Checks that the policer enforces the rate limit for protocols
            that have a set rate limit.
        """
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed)

    @pytest.mark.parametrize("protocol", ["BGP",
                                          "DHCP",
                                          "LACP",
                                          "LLDP",
                                          "UDLD"])
    def test_no_policer(self, protocol, duthost, ptfhost, copp_testbed):
        """
            Validates that non-rate-limited COPP groups work as expected.

            Checks that the policer does not enforce a rate limit for protocols
            that do not have any set rate limit.
        """
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed)

@pytest.fixture(scope="class")
def copp_testbed(duthost, creds, ptfhost, testbed, request):
    """
        Pytest fixture to handle setup and cleanup for the COPP tests.
    """
    test_params = _gather_test_params(testbed, duthost, request)

    if test_params.topo not in (_SUPPORTED_PTF_TOPOS + _SUPPORTED_T1_TOPOS):
        pytest.skip("Topology not supported by COPP tests")

    _setup_testbed(duthost, creds, ptfhost, test_params)
    yield test_params
    _teardown_testbed(duthost, creds, ptfhost, test_params)

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        We disable LLDP during the test, so we expect to see "lldp not running"
        messages in the logs. All other errors should be treated as errors.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*ERR monit.*'lldpd_monitor' process is not running",
        ".*ERR monit.*'lldp_syncd' process is not running",
        ".*snmp#snmp-subagent.*",
    ]
    loganalyzer.ignore_regex.extend(ignoreRegex)

    yield

def _copp_runner(dut, ptf, protocol, test_params):
    """
        Configures and runs the PTF test cases.
    """

    params = {"verbose": False,
              "pkt_tx_count": test_params.pkt_tx_count,
              "target_port": test_params.nn_target_port,
              "minig_bgp": test_params.bgp_graph}

    dut_ip = dut.setup()["ansible_facts"]["ansible_eth0"]["ipv4"]["address"]
    device_sockets = ["0-{}@tcp://127.0.0.1:10900".format(test_params.nn_target_port),
                      "1-{}@tcp://{}:10900".format(test_params.nn_target_port, dut_ip)]

    # NOTE: debug_level can actually slow the PTF down enough to fail the test cases
    # that are not rate limited. Until this is addressed, do not use this flag as part of
    # nightly test runs.
    ptf_runner(host=ptf,
               testdir="ptftests",
               # Special Handling for DHCP if we are using T1 Topo
               testname="copp_tests.{}Test".format((protocol+"TopoT1")
                         if test_params.topo in _SUPPORTED_T1_TOPOS and protocol in _T1_NO_COPP_PROTOCOL else protocol),
               platform="nn",
               qlen=100000,
               params=params,
               relax=None,
               debug_level=None,
               device_sockets=device_sockets)

def _gather_test_params(testbed, duthost, request):
    """
        Fetches the test parameters from pytest.
    """

    nn_target_port = request.config.getoption("--nn_target_port")
    pkt_tx_count = request.config.getoption("--pkt_tx_count")
    swap_syncd = request.config.getoption("--copp_swap_syncd")
    topo = testbed["topo"]["name"]
    bgp_graph = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]["minigraph_bgp"]

    return _COPPTestParameters(nn_target_port=nn_target_port,
                               pkt_tx_count=pkt_tx_count,
                               swap_syncd=swap_syncd,
                               topo=topo,
                               bgp_graph=bgp_graph)

def _setup_testbed(dut, creds, ptf, test_params):
    """
        Sets up the testbed to run the COPP tests.
    """

    logging.info("Disable LLDP for COPP tests")
    dut.command("docker exec lldp supervisorctl stop lldp-syncd")
    dut.command("docker exec lldp supervisorctl stop lldpd")

    logging.info("Set up the PTF for COPP tests")
    copp_utils.configure_ptf(ptf, test_params.nn_target_port)

    logging.info("Update the rate limit for the COPP policer")
    copp_utils.limit_policer(dut, _TEST_RATE_LIMIT)

    if test_params.swap_syncd:
        logging.info("Swap out syncd to use RPC image...")
        docker.swap_syncd(dut, creds)
    else:
        # NOTE: Even if the rpc syncd image is already installed, we need to restart
        # SWSS for the COPP changes to take effect.
        logging.info("Reloading config and restarting swss...")
        config_reload(dut)

    logging.info("Configure syncd RPC for testing")
    copp_utils.configure_syncd(dut, test_params.nn_target_port)

def _teardown_testbed(dut, creds, ptf, test_params):
    """
        Tears down the testbed, returning it to its initial state.
    """

    logging.info("Restore PTF post COPP test")
    copp_utils.restore_ptf(ptf)

    logging.info("Restore COPP policer to default settings")
    copp_utils.restore_policer(dut)

    if test_params.swap_syncd:
        logging.info("Restore default syncd docker...")
        docker.restore_default_syncd(dut, creds)
    else:
        logging.info("Reloading config and restarting swss...")
        config_reload(dut)

    logging.info("Restore LLDP")
    dut.command("docker exec lldp supervisorctl start lldpd")
    dut.command("docker exec lldp supervisorctl start lldp-syncd")
