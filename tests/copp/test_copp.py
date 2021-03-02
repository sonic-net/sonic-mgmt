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
        --copp_swap_syncd: Used to install the RPC syncd image before running the tests. Default
            is disabled.

"""

import ipaddr
import logging
import pytest
import json
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
                                  "swap_syncd",
                                  "topo",
                                  "myip",
                                  "peerip",
                                  "nn_target_interface"])
_SUPPORTED_PTF_TOPOS = ["ptf32", "ptf64"]
_SUPPORTED_T1_TOPOS = ["t1", "t1-lag", "t1-64-lag"]
_TOR_ONLY_PROTOCOL = ["DHCP"]
_TEST_RATE_LIMIT = 600


class TestCOPP(object):
    """
        Tests basic COPP functionality in SONiC.
    """

    @pytest.mark.parametrize("protocol", ["ARP",
                                          "IP2ME",
                                          "SNMP",
                                          "SSH"])
    def test_policer(self, protocol, duthosts, rand_one_dut_hostname, ptfhost, copp_testbed, dut_type):
        """
            Validates that rate-limited COPP groups work as expected.

            Checks that the policer enforces the rate limit for protocols
            that have a set rate limit.
        """
        duthost = duthosts[rand_one_dut_hostname]
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed,
                     dut_type)

    @pytest.mark.parametrize("protocol", ["BGP",
                                          "DHCP",
                                          "LACP",
                                          "LLDP",
                                          "UDLD"])
    def test_no_policer(self, protocol, duthosts, rand_one_dut_hostname, ptfhost, copp_testbed, dut_type):
        """
            Validates that non-rate-limited COPP groups work as expected.

            Checks that the policer does not enforce a rate limit for protocols
            that do not have any set rate limit.
        """
        duthost = duthosts[rand_one_dut_hostname]
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed,
                     dut_type)

@pytest.fixture(scope="class")
def dut_type(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])  # return config db contents(running-config)
    dut_type = None

    if "DEVICE_METADATA" in cfg_facts:
        if "localhost" in cfg_facts["DEVICE_METADATA"]:
            if "type" in cfg_facts["DEVICE_METADATA"]["localhost"]:
                dut_type = cfg_facts["DEVICE_METADATA"]["localhost"]["type"]

    return dut_type

@pytest.fixture(scope="class")
def copp_testbed(
    duthosts,
    rand_one_dut_hostname,
    creds,
    ptfhost,
    tbinfo,
    request,
    disable_lldp_for_testing  # usefixtures not supported on fixtures
):
    """
        Pytest fixture to handle setup and cleanup for the COPP tests.
    """
    duthost = duthosts[rand_one_dut_hostname]
    test_params = _gather_test_params(tbinfo, duthost, request)

    if test_params.topo not in (_SUPPORTED_PTF_TOPOS + _SUPPORTED_T1_TOPOS):
        pytest.skip("Topology not supported by COPP tests")

    try:
        _setup_testbed(duthost, creds, ptfhost, test_params)
        yield test_params
    finally:
        _teardown_testbed(duthost, creds, ptfhost, test_params)

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        We disable LLDP during the test, so we expect to see "lldp not running"
        messages in the logs. All other errors should be treated as errors.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*ERR monit.*'lldpd_monitor' process is not running.*",
        ".*ERR monit.* 'lldp\|lldpd_monitor' status failed.*-- 'lldpd:' is not running.*",
        ".*ERR monit.*'lldp_syncd' process is not running.*",
        ".*ERR monit.*'lldp\|lldp_syncd' status failed.*'python2 -m lldp_syncd' is not running.*",
        ".*snmp#snmp-subagent.*",
        ".*kernel reports TIME_ERROR: 0x4041: Clock Unsynchronized.*"
    ]

    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

def _copp_runner(dut, ptf, protocol, test_params, dut_type):
    """
        Configures and runs the PTF test cases.
    """

    params = {"verbose": False,
              "target_port": test_params.nn_target_port,
              "myip": test_params.myip,
              "peerip": test_params.peerip}

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
                         if protocol in _TOR_ONLY_PROTOCOL and dut_type != "ToRRouter" else protocol),
               platform="nn",
               qlen=100000,
               params=params,
               relax=None,
               debug_level=None,
               device_sockets=device_sockets)

def _gather_test_params(tbinfo, duthost, request):
    """
        Fetches the test parameters from pytest.
    """

    swap_syncd = request.config.getoption("--copp_swap_syncd")
    topo = tbinfo["topo"]["name"]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_index_map = {
        k: v
        for k, v in mg_facts["minigraph_port_indices"].items()
        if k in mg_facts["minigraph_ports"]
    }
    nn_target_port = port_index_map[random.choice(port_index_map.keys())]
    nn_target_interface = copp_utils._map_port_number_to_interface(duthost, nn_target_port)
    myip = None
    peerip = None

    for bgp_peer in mg_facts["minigraph_bgp"]:
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][nn_target_interface]["name"] and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
            myip = bgp_peer["addr"]
            peerip = bgp_peer["peer_addr"]
            break

    logging.info("nn_target_port {} nn_target_interface {}".format(nn_target_port, nn_target_interface))

    return _COPPTestParameters(nn_target_port=nn_target_port,
                               swap_syncd=swap_syncd,
                               topo=topo,
                               myip=myip,
                               peerip = peerip,
                               nn_target_interface=nn_target_interface)

def _setup_testbed(dut, creds, ptf, test_params):
    """
        Sets up the testbed to run the COPP tests.
    """

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
    copp_utils.configure_syncd(dut, test_params.nn_target_port, test_params.nn_target_interface, creds)

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


@pytest.fixture(scope="class")
def disable_lldp_for_testing(
    duthosts,
    rand_one_dut_hostname,
    disable_container_autorestart,
    enable_container_autorestart
):
    """Disables LLDP during testing so that it doesn't interfere with the policer."""
    duthost = duthosts[rand_one_dut_hostname]

    logging.info("Disabling LLDP for the COPP tests")

    feature_list = ['lldp']
    disable_container_autorestart(duthost, testcase="test_copp", feature_list=feature_list)

    duthost.command("docker exec lldp supervisorctl stop lldp-syncd")
    duthost.command("docker exec lldp supervisorctl stop lldpd")

    yield

    logging.info("Restoring LLDP after the COPP tests")

    duthost.command("docker exec lldp supervisorctl start lldpd")
    duthost.command("docker exec lldp supervisorctl start lldp-syncd")

    enable_container_autorestart(duthost, testcase="test_copp", feature_list=feature_list)
