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
        --send_rate_limit: Used to set custom server send rate-limit pps. Default is 2000 pps

"""

import ipaddr
import logging
import pytest
import json
import random
import threading
import time
from collections import namedtuple

from tests.copp import copp_utils
from tests.ptf_runner import ptf_runner
from tests.common import config_reload, constants
from tests.common.system_utils import docker
from tests.common.utilities import wait_until

# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology("t1", "t2")
]

_COPPTestParameters = namedtuple("_COPPTestParameters",
                                 ["nn_target_port",
                                  "swap_syncd",
                                  "topo",
                                  "myip",
                                  "peerip",
                                  "nn_target_interface",
                                  "nn_target_namespace",
                                  "send_rate_limit",
                                  "nn_target_vlanid"])
_SUPPORTED_PTF_TOPOS = ["ptf32", "ptf64"]
_SUPPORTED_T0_TOPOS = ["t0", "t0-64", "t0-52", "t0-116"]
_SUPPORTED_T1_TOPOS = ["t1", "t1-lag", "t1-64-lag", "t1-backend"]
_SUPPORTED_T2_TOPOS = ["t2"]
_TOR_ONLY_PROTOCOL = ["DHCP"]
_TEST_RATE_LIMIT = 600
_SEND_PACKET_NUMBER = 1500
_SEND_DURATION = 30


class TestCOPP(object):
    """
        Tests basic COPP functionality in SONiC.
    """

    @pytest.mark.parametrize("protocol", ["ARP",
                                          "IP2ME",
                                          "SNMP",
                                          "SSH"])
    def test_policer(self, protocol, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, copp_testbed, dut_type):
        """
            Validates that rate-limited COPP groups work as expected.

            Checks that the policer enforces the rate limit for protocols
            that have a set rate limit.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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
    def test_no_policer(self, protocol, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, copp_testbed, dut_type):
        """
            Validates that non-rate-limited COPP groups work as expected.

            Checks that the policer does not enforce a rate limit for protocols
            that do not have any set rate limit.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed,
                     dut_type)

    @pytest.mark.parametrize("protocol", ["LACP",
                                          "LLDP",
                                          "UDLD",
                                          "IP2ME"])
    def test_counter(self, protocol, duthosts, rand_one_dut_hostname, ptfhost, copp_testbed, dut_type, counter_test):
        duthost = duthosts[rand_one_dut_hostname]
        trap_type = protocol.lower()

        # wait until the trap counter is enabled
        assert wait_until(10, 1, 0, _check_trap_counter_enabled, duthost, trap_type), 'counter is not created for {}'.format(trap_type)

        # clean previous counter value
        duthost.command('sonic-clear flowcnt-trap')

        # start a thread to collect the max PPS value
        actual_rate = []
        t = threading.Thread(target=_collect_counter_rate, args=(duthost, trap_type, actual_rate))
        t.start()

        # init and start PTF
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed,
                     dut_type,
                     True)

        # wait for thread finish
        t.join()

        # get final packet count from CLI
        expect_rate = float(_SEND_PACKET_NUMBER / _SEND_DURATION)
        actual_packet_number = None
        cli_data = duthost.show_and_parse('show flowcnt-trap stats')
        for line in cli_data:
            if 'trap name' in line and line['trap name'] == trap_type:
                actual_packet_number = int(line['packets'].replace(',', ''))
                break

        assert actual_packet_number == _SEND_PACKET_NUMBER, 'Trap {} expect send packet number: {}, but actual: {}'.format(trap_type, _SEND_PACKET_NUMBER, actual_packet_number)
        assert len(actual_rate) == 1, 'Failed to collect PPS value for trap {}'.format(trap_type)
        # Allow a 10 percent threshold for trap rate
        assert (expect_rate * 0.9) < actual_rate[0] < (expect_rate * 1.1), 'Trap {} expect send packet rate: {}, but actual: {}'.format(trap_type, expect_rate, actual_rate)


@pytest.fixture(scope="class")
def dut_type(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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
    enum_rand_one_per_hwsku_frontend_hostname,
    creds,
    ptfhost,
    tbinfo,
    request
):
    """
        Pytest fixture to handle setup and cleanup for the COPP tests.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    test_params = _gather_test_params(tbinfo, duthost, request)

    if test_params.topo not in (_SUPPORTED_PTF_TOPOS + _SUPPORTED_T0_TOPOS + _SUPPORTED_T1_TOPOS + _SUPPORTED_T2_TOPOS):
        pytest.skip("Topology not supported by COPP tests")

    try:
        _setup_multi_asic_proxy(duthost, creds, test_params, tbinfo)
        _setup_testbed(duthost, creds, ptfhost, test_params, tbinfo)
        yield test_params
    finally:
        _teardown_multi_asic_proxy(duthost, creds, test_params, tbinfo)
        _teardown_testbed(duthost, creds, ptfhost, test_params, tbinfo)

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        We disable LLDP during the test, so we expect to see "lldp not running"
        messages in the logs. All other errors should be treated as errors.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*snmp#snmp-subagent.*",
        ".*kernel reports TIME_ERROR: 0x4041: Clock Unsynchronized.*"
    ]

    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)

@pytest.fixture(scope="function")
def counter_test(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command('counterpoll flowcnt-trap enable')

    yield

    duthost.command('counterpoll flowcnt-trap disable')

def _copp_runner(dut, ptf, protocol, test_params, dut_type, counter_test=False):
    """
        Configures and runs the PTF test cases.
    """
    if not counter_test:
        params = {"verbose": False,
                "target_port": test_params.nn_target_port,
                "myip": test_params.myip,
                "peerip": test_params.peerip,
                "send_rate_limit": test_params.send_rate_limit}
    else:
        params = {"verbose": False,
                "target_port": test_params.nn_target_port,
                "myip": test_params.myip,
                "peerip": test_params.peerip,
                "send_rate_limit": test_params.send_rate_limit,
                "sent_pkt_number": _SEND_PACKET_NUMBER,
                "send_duration": _SEND_DURATION}
    dut_ip = dut.mgmt_ip
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
    send_rate_limit = request.config.getoption("--send_rate_limit")
    topo = tbinfo["topo"]["name"]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)
    # filter out server peer port and only bgp peer ports remain, to support T0 topologies
    bgp_peer_name_set = set([bgp_peer["name"] for bgp_peer in mg_facts["minigraph_bgp"]])
    # get the port_index_map using the ptf_indicies to support multi DUT topologies
    port_index_map = {
        k: v
        for k, v in mg_facts["minigraph_ptf_indices"].items()
        if k in mg_facts["minigraph_ports"] and mg_facts["minigraph_neighbors"][k]["name"] in bgp_peer_name_set
    }
    # use randam sonic interface for testing
    nn_target_interface = random.choice(port_index_map.keys())
    #get the  ptf port for choosen port
    nn_target_port = port_index_map[nn_target_interface]
    myip = None
    peerip = None

    for bgp_peer in mg_facts["minigraph_bgp"]:
        if bgp_peer["name"] == mg_facts["minigraph_neighbors"][nn_target_interface]["name"] and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
            myip = bgp_peer["addr"]
            peerip = bgp_peer["peer_addr"]
            break

    nn_target_namespace = mg_facts["minigraph_neighbors"][nn_target_interface]['namespace']
    if is_backend_topology and len(mg_facts["minigraph_vlan_sub_interfaces"]) > 0:
        nn_target_vlanid = mg_facts["minigraph_vlan_sub_interfaces"][0]["vlan"]
    else:
        nn_target_vlanid = None


    logging.info("nn_target_port {} nn_target_interface {} nn_target_namespace {} nn_target_vlanid {}".format(nn_target_port, nn_target_interface, nn_target_namespace, nn_target_vlanid))

    return _COPPTestParameters(nn_target_port=nn_target_port,
                               swap_syncd=swap_syncd,
                               topo=topo,
                               myip=myip,
                               peerip=peerip,
                               nn_target_interface=nn_target_interface,
                               nn_target_namespace=nn_target_namespace,
                               send_rate_limit=send_rate_limit,
                               nn_target_vlanid=nn_target_vlanid)

def _setup_testbed(dut, creds, ptf, test_params, tbinfo):
    """
        Sets up the testbed to run the COPP tests.
    """
    mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)

    logging.info("Set up the PTF for COPP tests")
    copp_utils.configure_ptf(ptf, test_params, is_backend_topology)

    logging.info("Update the rate limit for the COPP policer")
    copp_utils.limit_policer(dut, _TEST_RATE_LIMIT, test_params.nn_target_namespace)

    # Multi-asic will not support this mode as of now.
    if test_params.swap_syncd and not dut.is_multi_asic:
        logging.info("Swap out syncd to use RPC image...")
        docker.swap_syncd(dut, creds)
    else:
        # Set sysctl RCVBUF parameter for tests
        dut.command("sysctl -w net.core.rmem_max=609430500")

        # Set sysctl SENDBUF parameter for tests
        dut.command("sysctl -w net.core.wmem_max=609430500")

        # NOTE: Even if the rpc syncd image is already installed, we need to restart
        # SWSS for the COPP changes to take effect.
        logging.info("Reloading config and restarting swss...")
        config_reload(dut)

    logging.info("Configure syncd RPC for testing")
    copp_utils.configure_syncd(dut, test_params.nn_target_port, test_params.nn_target_interface,
                               test_params.nn_target_namespace, test_params.nn_target_vlanid, creds)

def _teardown_testbed(dut, creds, ptf, test_params, tbinfo):
    """
        Tears down the testbed, returning it to its initial state.
    """
    logging.info("Restore PTF post COPP test")
    copp_utils.restore_ptf(ptf)

    logging.info("Restore COPP policer to default settings")
    copp_utils.restore_policer(dut, test_params.nn_target_namespace)

    if test_params.swap_syncd and not dut.is_multi_asic:
        logging.info("Restore default syncd docker...")
        docker.restore_default_syncd(dut, creds)
    else:
        copp_utils.restore_syncd(dut, test_params.nn_target_namespace)
        logging.info("Reloading config and restarting swss...")
        config_reload(dut)

def _setup_multi_asic_proxy(dut, creds, test_params, tbinfo):
    """
        Sets up the testbed to run the COPP tests on multi-asic platfroms via setting proxy.
    """
    if not dut.is_multi_asic:
        return

    logging.info("Adding iptables rules and enabling eth0 port forwarding")
    http_proxy, https_proxy = copp_utils._get_http_and_https_proxy_ip(creds)
    # Add IP Table rule for http and ptf nn_agent traffic.
    dut.command("sudo sysctl net.ipv4.conf.eth0.forwarding=1")
    mgmt_ip = dut.host.options["inventory_manager"].get_host(dut.hostname).vars["ansible_host"]
    # Add Rule to communicate to http/s proxy from namespace
    dut.command("sudo iptables -t nat -A POSTROUTING -p tcp --dport 8080 -j SNAT --to-source {}".format(mgmt_ip))
    dut.command("sudo ip -n {} rule add from all to {} pref 1 lookup default".format(test_params.nn_target_namespace, http_proxy))
    if http_proxy != https_proxy:
        dut.command("sudo ip -n {} rule add from all to {} pref 2 lookup default".format(test_params.nn_target_namespace, https_proxy))
    # Add Rule to communicate to ptf nn agent client from namespace
    ns_ip = dut.shell("sudo ip -n {} -4 -o addr show eth0".format(test_params.nn_target_namespace) + " | awk '{print $4}' | cut -d'/' -f1")["stdout"]
    dut.command("sudo iptables -t nat -A PREROUTING -p tcp --dport 10900 -j DNAT --to-destination {}".format(ns_ip))
    dut.command("sudo ip -n {} rule add from {} to {} pref 3 lookup default".format(test_params.nn_target_namespace, ns_ip, tbinfo["ptf_ip"]))

def _teardown_multi_asic_proxy(dut, creds, test_params, tbinfo):
    """
        Tears down multi asic proxy settings, returning it to its initial state.
    """
    if not dut.is_multi_asic:
        return

    logging.info("Removing iptables rules and disabling eth0 port forwarding")
    http_proxy, https_proxy = copp_utils._get_http_and_https_proxy_ip(creds)
    dut.command("sudo sysctl net.ipv4.conf.eth0.forwarding=0")
    # Delete IP Table rule for http and ptf nn_agent traffic.
    mgmt_ip = dut.host.options["inventory_manager"].get_host(dut.hostname).vars["ansible_host"]
    # Delete Rule to communicate to http/s proxy from namespace
    dut.command("sudo iptables -t nat -D POSTROUTING -p tcp --dport 8080 -j SNAT --to-source {}".format(mgmt_ip))
    dut.command("sudo ip -n {} rule delete from all to {} pref 1 lookup default".format(test_params.nn_target_namespace, http_proxy))
    if http_proxy != https_proxy:
        dut.command("sudo ip -n {} rule delete from all to {} pref 2 lookup default".format(test_params.nn_target_namespace, https_proxy))
    # Delete Rule to communicate to ptf nn agent client from namespace
    ns_ip = dut.shell("sudo ip -n {} -4 -o addr show eth0".format(test_params.nn_target_namespace) + " | awk '{print $4}' | cut -d'/' -f1")["stdout"]
    dut.command("sudo iptables -t nat -D PREROUTING -p tcp --dport 10900 -j DNAT --to-destination {}".format(ns_ip))
    dut.command("sudo ip -n {} rule delete from {} to {} pref 3 lookup default".format(test_params.nn_target_namespace, ns_ip, tbinfo["ptf_ip"]))

def _check_trap_counter_enabled(duthost, trap_type):
    lines = duthost.command('show flowcnt-trap stats')['stdout']
    return trap_type in lines

def _collect_counter_rate(duthost, trap_type, actual_rate):
    rate_values = []
    # Wait up to _SEND_DURATION + 5 seconds for PTF to stop sending packet,
    # as it might take some time for PTF to initialize itself
    max_wait = _SEND_DURATION + 5
    packets = None
    while max_wait > 0:
        cli_data = duthost.show_and_parse('show flowcnt-trap stats')
        for line in cli_data:
            if 'trap name' in line and line['trap name'] == trap_type:
                packets = line['packets']
                if packets == 'N/A':
                    # Packets value is not available yet
                    logging.debug('Trap {} packets value is not available yet'.format(trap_type))
                    break

                pps_value = line['pps']
                if pps_value == 'N/A':
                    # PPS value is not available yet
                    logging.debug('Trap {} PPS value is not available yet'.format(trap_type))
                    break

                packets = int(packets.replace(',', ''))
                if packets == 0:
                    # PTF has not started yet
                    logging.debug('Trap {} packets value is still 0, PTF has not started yet'.format(trap_type))
                    break

                logging.info('Trap {} current PPS value is {}, packets value is {}'.format(trap_type, pps_value, packets))
                rate_values.append(float(pps_value[:-2]))
                break
        if packets == _SEND_PACKET_NUMBER:
            # Enough packets are sent, stop
            break
        time.sleep(0.5)
        max_wait -= 0.5

    if rate_values:
        # Calculate max PPS
        max_pps = max(rate_values)
        logging.info('Trap {} max PPS is {}'.format(trap_type, max_pps))
        actual_rate.append(max_pps)

