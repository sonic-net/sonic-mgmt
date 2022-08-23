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
from collections import namedtuple

from tests.copp import copp_utils
from tests.ptf_runner import ptf_runner
from tests.common import config_reload, constants
from tests.common.system_utils import docker
from tests.common.reboot import reboot
from tests.common.utilities import skip_release
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology("t0", "t1", "t2")
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

_TOR_ONLY_PROTOCOL = ["DHCP", "DHCP6"]
_TEST_RATE_LIMIT = 600

logger = logging.getLogger(__name__)


class TestCOPP(object):
    """
        Tests basic COPP functionality in SONiC.
    """
    trap_id = "bgp"
    feature_name = "bgp"

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
                                          "DHCP6",
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

    @pytest.mark.disable_loganalyzer
    def test_add_new_trap(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, check_image_version, copp_testbed, dut_type, backup_restore_config_db):
        """
        Validates that one new trap(bgp) can be installed

        1. The trap(bgp) should be uninstalled
        2. Set always_enabled of bgp to true
        3. Verify the trap status is installed by sending traffic
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        logger.info("Uninstall trap {}".format(self.trap_id))
        copp_utils.uninstall_trap(duthost, self.feature_name, self.trap_id)

        logger.info("Verify {} trap status is uninstalled by sending traffic".format(self.trap_id))
        _copp_runner(duthost,
                     ptfhost,
                     self.trap_id.upper(),
                     copp_testbed,
                     dut_type,
                     has_trap=False)

        logger.info("Set always_enabled of {} to true".format(self.trap_id))
        copp_utils.configure_always_enabled_for_trap(duthost, self.trap_id, "true")

        logger.info("Verify {} trap status is installed by sending traffic".format(self.trap_id))
        pytest_assert(
            wait_until(60, 20, 0, _copp_runner, duthost, ptfhost, self.trap_id.upper(), copp_testbed, dut_type),
            "Installing {} trap fail".format(self.trap_id))

    @pytest.mark.disable_loganalyzer
    @pytest.mark.parametrize("remove_trap_type", ["delete_feature_entry",
                                                  "disable_feature_status"])
    def test_remove_trap(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, check_image_version, copp_testbed, dut_type, backup_restore_config_db, remove_trap_type):
        """
        Validates that The trap(bgp) can be uninstalled after deleting the corresponding entry from the feature table

        1. Pre condition: make the tested trap installed and always_enable is false
        2. Remove trap according to remove trap type
        4. Verify the trap status is uninstalled by sending traffic
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        logger.info("Pre condition: make trap {} is installed".format(self.feature_name))
        pre_condition_install_trap(ptfhost, duthost, copp_testbed, self.trap_id, self.feature_name)

        if remove_trap_type == "delete_feature_entry":
            logger.info("Remove feature entry: {}".format(self.feature_name))
            copp_utils.remove_feature_entry(duthost, self.feature_name)
        else:
            logger.info("Disable {} in feature table".format(self.feature_name))
            copp_utils.disable_feature_entry(duthost, self.feature_name)

        logger.info("Verify {} trap status is uninstalled by sending traffic".format(self.trap_id))
        pytest_assert(
            wait_until(100, 20, 0, _copp_runner, duthost, ptfhost, self.trap_id.upper(), copp_testbed, dut_type, has_trap=False),
            "uninstalling {} trap fail".format(self.trap_id))

    @pytest.mark.disable_loganalyzer
    def test_trap_config_save_after_reboot(self, duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,check_image_version, copp_testbed, dut_type, backup_restore_config_db, request):
        """
        Validates that the trap configuration is saved or not after reboot(reboot, fast-reboot, warm-reboot)

        1. Set always_enabled of a trap(e.g. bgp) to true
        2. Config save -y
        3. Do reboot according to the specified parameter of copp_reboot_type (reboot/warm-reboot/fast-reboot/soft-reboot)
        4. Verify configuration are saved successfully
        5. Verify the trap status is installed by sending traffic
        """

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        logger.info("Set always_enabled of {} to true".format(self.trap_id))
        copp_utils.configure_always_enabled_for_trap(duthost, self.trap_id, "true")

        logger.info("Config save")
        duthost.command("sudo config save -y")

        reboot_type = request.config.getoption("--copp_reboot_type")
        logger.info("Do {}".format(reboot_type))
        reboot(duthost, localhost, reboot_type=reboot_type, reboot_helper=None, reboot_kwargs=None)

        logger.info("Verify always_enable of {} == {} in config_db".format(self.trap_id, "true"))
        copp_utils.verify_always_enable_value(duthost, self.trap_id, "true")
        logger.info("Verify {} trap status is installed by sending traffic".format(self.trap_id))
        pytest_assert(
            wait_until(100, 20, 0, _copp_runner, duthost, ptfhost, self.trap_id.upper(), copp_testbed, dut_type),
            "Installing {} trap fail".format(self.trap_id))


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


def _copp_runner(dut, ptf, protocol, test_params, dut_type, has_trap=True):
    """
        Configures and runs the PTF test cases.
    """

    params = {"verbose": False,
              "target_port": test_params.nn_target_port,
              "myip": test_params.myip,
              "peerip": test_params.peerip,
              "send_rate_limit": test_params.send_rate_limit,
              "has_trap": has_trap}

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
    return True


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
        config_reload(dut, safe_reload=True, check_intf_up_ports=True)

    logging.info("Configure syncd RPC for testing")
    copp_utils.configure_syncd(dut, test_params.nn_target_port, test_params.nn_target_interface,
                               test_params.nn_target_namespace, test_params.nn_target_vlanid,
                               test_params.swap_syncd, creds)

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
        config_reload(dut, safe_reload=True, check_intf_up_ports=True)

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


@pytest.fixture(scope="function", autouse=False)
def backup_restore_config_db(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    copp_utils.backup_config_db(duthost)

    yield
    copp_utils.restore_config_db(duthost)


def pre_condition_install_trap(ptfhost, duthost, copp_testbed, trap_id, feature_name):
    copp_utils.install_trap(duthost, feature_name)
    logger.info("Set always_enabled of {} to false".format(trap_id))
    copp_utils.configure_always_enabled_for_trap(duthost, trap_id, "false")

    logger.info("Verify {} trap status is installed by sending traffic in pre_condition".format(trap_id))
    pytest_assert(
        wait_until(100, 20, 0, _copp_runner, duthost, ptfhost, trap_id.upper(), copp_testbed, dut_type),
        "Installing {} trap fail".format(trap_id))


@pytest.fixture(autouse=False, scope="class")
def check_image_version(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Skips this test because new copp management logic works on 202012 branch and above

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(duthosts[enum_rand_one_per_hwsku_frontend_hostname], ["201911"])
