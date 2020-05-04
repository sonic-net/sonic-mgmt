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

        --swap_syncd: Used to install the RPC syncd image before running the tests. Default
            is disabled.
"""

import time
from collections import namedtuple

import pytest
from copp import copp_utils
from ptf_runner import ptf_runner
from common.system_utils import docker
from common.broadcom_data import is_broadcom_device

_COPPTestParameters = namedtuple("_COPPTestParameters",
                                 ["nn_target_port",
                                  "pkt_tx_count",
                                  "swap_syncd",
                                  "topo"])
_SUPPORTED_TOPOS = ["ptf32", "ptf64", "t1", "t1-lag"]
_TEST_RATE_LIMIT = 600

class TestCOPP(object):
    """
        Tests basic COPP functionality in SONiC.
    """

    @pytest.mark.parametrize("protocol", ["ARP",
                                          "IP2ME",
                                          "SNMP",
                                          "SSH"])
    def test_policer(self, protocol, duthost, ptfhost, _copp_testbed):
        """
            Validates that rate-limited COPP groups work as expected.

            Checks that the policer enforces the rate limit for protocols
            that have a set rate limit.
        """

        if protocol == "ARP" \
                and is_broadcom_device(duthost) \
                and "201811" not in duthost.get_version():
            pytest.xfail("ARP policy disabled on BRCM devices due to SAI bug")

        if protocol in ["IP2ME", "SNMP", "SSH"] and _copp_testbed.topo == "t1-lag":
            pytest.xfail("Packets not received due to faulty DIP, see #1171")

        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     _copp_testbed)

    @pytest.mark.parametrize("protocol", ["BGP",
                                          "DHCP",
                                          "LACP",
                                          "LLDP",
                                          "UDLD"])
    def test_no_policer(self, protocol, duthost, ptfhost, _copp_testbed):
        """
            Validates that non-rate-limited COPP groups work as expected.

            Checks that the policer does not enforce a rate limit for protocols
            that do not have any set rate limit.
        """

        if protocol == "BGP" and _copp_testbed.topo == "t1-lag":
            pytest.xfail("Packets not received due to faulty DIP, see #1171")

        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     _copp_testbed)

@pytest.fixture(scope="class")
def _copp_testbed(duthost, ptfhost, testbed, request):
    """
        Pytest fixture to handle setup and cleanup for the COPP tests.
    """

    test_params = _gather_test_params(testbed, request)

    if test_params.topo not in _SUPPORTED_TOPOS:
        pytest.skip("Topology not supported by COPP tests")

    _setup_testbed(duthost, ptfhost, test_params)
    yield test_params
    _teardown_testbed(duthost, ptfhost, test_params)

def _copp_runner(dut, ptf, protocol, test_params):
    """
        Configures and runs the PTF test cases.
    """

    params = {"verbose": False,
              "pkt_tx_count": test_params.pkt_tx_count,
              "target_port": test_params.nn_target_port}

    dut_ip = dut.setup()["ansible_facts"]["ansible_eth0"]["ipv4"]["address"]
    device_sockets = ["0-{}@tcp://127.0.0.1:10900".format(test_params.nn_target_port),
                      "1-{}@tcp://{}:10900".format(test_params.nn_target_port, dut_ip)]

    # NOTE: debug_level can actually slow the PTF down enough to fail the test cases
    # that are not rate limited. Until this is addressed, do not use this flag as part of
    # nightly test runs.
    ptf_runner(host=ptf,
               testdir="ptftests",
               testname="copp_tests.{}Test".format(protocol),
               platform="nn",
               qlen=100000,
               params=params,
               relax=None,
               debug_level=None,
               device_sockets=device_sockets)

def _gather_test_params(testbed, request):
    """
        Fetches the test parameters from pytest.
    """

    nn_target_port = request.config.getoption("--nn_target_port")
    pkt_tx_count = request.config.getoption("--pkt_tx_count")
    swap_syncd = request.config.getoption("--swap_syncd")
    topo = testbed["topo"]["name"]

    return _COPPTestParameters(nn_target_port=nn_target_port,
                               pkt_tx_count=pkt_tx_count,
                               swap_syncd=swap_syncd,
                               topo=topo)

def _setup_testbed(dut, ptf, test_params):
    """
        Sets up the testbed to run the COPP tests.
    """

    # We don't want LLDP to throw off our test results, so we disable it first.
    dut.command("docker exec lldp supervisorctl stop lldp-syncd")
    dut.command("docker exec lldp supervisorctl stop lldpd")

    copp_utils.configure_ptf(ptf, test_params.nn_target_port)

    copp_utils.limit_policer(dut, _TEST_RATE_LIMIT)

    if test_params.swap_syncd:
        docker.swap_syncd(dut)
    else:
        # NOTE: Even if the rpc syncd image is already installed, we need to restart
        # SWSS for the COPP changes to take effect.
        _restart_swss(dut)

    copp_utils.configure_syncd(dut, test_params.nn_target_port)

def _teardown_testbed(dut, ptf, test_params):
    """
        Tears down the testbed, returning it to its initial state.
    """

    copp_utils.restore_ptf(ptf)

    copp_utils.restore_policer(dut)

    if test_params.swap_syncd:
        docker.restore_default_syncd(dut)
    else:
        _restart_swss(dut)

    dut.command("docker exec lldp supervisorctl start lldpd")
    dut.command("docker exec lldp supervisorctl start lldp-syncd")

def _restart_swss(dut):
    """
        Restarts SWSS and waits for the system to stabilize.
    """

    # The failure counter may be incremented by other test cases, so we clear it
    # first to avoid crashing the testbed.
    dut.command("systemctl reset-failed swss")
    dut.command("systemctl restart swss")
    time.sleep(60)
