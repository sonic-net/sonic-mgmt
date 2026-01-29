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
import time
from collections import namedtuple

from tests.copp import copp_utils
from tests.ptf_runner import ptf_runner
from tests.common import config_reload, constants
from tests.common.system_utils import docker
from tests.common.reboot import reboot
from tests.common.utilities import skip_release
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import find_duthost_on_role
from tests.common.utilities import get_upstream_neigh_type

# Module-level fixtures
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa: F401

pytestmark = [
    pytest.mark.topology("t0", "t1", "t2", "m0", "mx", "m1", "lt2", "ft2")
]

_COPPTestParameters = namedtuple("_COPPTestParameters",
                                 ["nn_target_port",
                                  "swap_syncd",
                                  "topo",
                                  "myip",
                                  "myip6",
                                  "peerip",
                                  "peerip6",
                                  "nn_target_interface",
                                  "nn_target_namespace",
                                  "send_rate_limit",
                                  "nn_target_vlanid",
                                  "topo_type",
                                  "neighbor_miss_trap_supported"])

_TOR_ONLY_PROTOCOL = ["DHCP", "DHCP6"]
_TEST_RATE_LIMIT_DEFAULT = 600
_TEST_RATE_LIMIT_MARVELL = 625

# Protocol to trap ID mapping indicating which trap
# being for which protocol. Trap ID is used to verify
# the trap installation status.
PROTOCOL_TO_TRAP_ID = {
    "ARP": ["arp_req", "arp_resp", "neigh_discovery"],
    "IP2ME": ["ip2me"],
    "SNMP": ["ip2me"],
    "SSH": ["ip2me"],
    "DHCP": ["dhcp"],
    "DHCP6": ["dhcpv6"],
    "BGP": ["bgp", "bgpv6"],
    "LACP": ["lacp"],
    "LLDP": ["lldp"],
    "UDLD": ["udld"],
    "Default": ["default"]
}

logger = logging.getLogger(__name__)


class TestCOPP(object):
    """
        Tests basic COPP functionality in SONiC.
    """
    trap_id = "bgp"
    feature_name = "bgp"

    @pytest.mark.parametrize("protocol", ["ARP",
                                          "DHCP",
                                          "DHCP6",
                                          "LACP",
                                          "LLDP",
                                          "UDLD",
                                          "Default"])
    def test_policer(self, protocol, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                     ptfhost, copp_testbed, dut_type, fanouthosts):
        """
            Validates that rate-limited COPP groups work as expected.

            Checks that the policer enforces the rate limit for protocols
            that have a set rate limit.
        """
        # If fanout is running 7060x6 and running SONiC, the only supported action for UDLD is trap, which means
        # UDLD packet will not be forwarded to DUT
        if 'UDLD' == protocol:
            for fanouthost in list(fanouthosts.values()):
                if fanouthost.get_fanout_os() == 'sonic' and "arista_7060x6_64pe_b" in fanouthost.facts["platform"]:
                    pytest.skip("Skip UDLD test for Arista-7060x6 fanout without UDLD forward support")

        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        namespace = DEFAULT_NAMESPACE
        if duthost.is_multi_asic:
            namespace = random.choice(duthost.asics)

        # Skip the check if the protocol is "Default"
        if protocol != "Default":
            trap_ids = PROTOCOL_TO_TRAP_ID.get(protocol)
            is_always_enabled, feature_name = copp_utils.get_feature_name_from_trap_id(duthost, trap_ids[0])
            if is_always_enabled:
                pytest_assert(copp_utils.is_trap_installed(duthost, trap_ids[0], namespace),
                              f"Trap {trap_ids[0]} for protocol {protocol} is not installed")
            else:
                feature_list, _ = duthost.get_feature_status()
                trap_installed = copp_utils.is_trap_installed(duthost, trap_ids[0], namespace)
                if feature_name in feature_list and feature_list[feature_name] == "enabled":
                    pytest_assert(trap_installed,
                                  f"Trap {trap_ids[0]} for protocol {protocol} is not installed")
                else:
                    pytest_assert(not trap_installed,
                                  f"Trap {trap_ids[0]} for protocol {protocol} is unexpectedly installed")

        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed,
                     dut_type)

    @pytest.mark.parametrize("protocol", ["IP2ME",
                                          "SNMP",
                                          "SSH",
                                          "BGP"])
    def test_policer_mtu(self, protocol, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                         ptfhost, copp_testbed, dut_type, packet_size):
        """
            Validates that rate-limited COPP groups work as expected.

            Checks that the policer enforces the rate limit for protocols
            that can receive packets with different sizes and have a set rate
            limit.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        _copp_runner(duthost,
                     ptfhost,
                     protocol,
                     copp_testbed,
                     dut_type,
                     packet_size=packet_size)

    @pytest.mark.disable_loganalyzer
    def test_trap_neighbor_miss(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                ptfhost, check_image_version, copp_testbed, dut_type,
                                ip_versions, packet_type):    # noqa: F811
        """
        Validates that neighbor miss (subnet hit) packets are rate-limited

        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        # Access test_params from the class-level variable
        test_params = self.test_params

        trap_status = copp_utils.is_trap_installed(duthost, "neighbor_miss")
        if test_params.neighbor_miss_trap_supported:
            logger.info("neighbor_miss trap is supported by DUT")
            pytest_assert(trap_status,
                          "neighbor_miss trap is supported but not installed")
        else:
            logger.info("neighbor_miss trap is not supported by DUT")
            pytest_assert(not trap_status,
                          "neighbor_miss trap is not supported but installed")

        logger.info("Verify IPV{} {} packets are rate limited".format(ip_versions, packet_type))
        pytest_assert(
            wait_until(60, 20, 0, _copp_runner, duthost, ptfhost, packet_type, copp_testbed, dut_type,
                       ip_version=ip_versions),
            "Traffic check for {} packets failed".format(packet_type))

    @pytest.mark.disable_loganalyzer
    def test_add_new_trap(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                          ptfhost, check_image_version, copp_testbed, dut_type, backup_restore_config_db):
        """
        Validates that one new trap(bgp) can be installed

        1. The trap(bgp) should be uninstalled
        2. Set always_enabled of bgp to true
        3. Verify the trap status is installed by sending traffic
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        logger.info("Uninstall trap {}".format(self.trap_id))
        copp_utils.uninstall_trap(duthost, self.feature_name, self.trap_id)
        pytest_assert(not copp_utils.is_trap_installed(duthost, self.trap_id),
                      "Trap {} is still installed, expected to be uninstalled".format(self.trap_id))

        # remove ip2me because bgp traffic can fall back to ip2me trap then interfere following traffic tests
        if self.trap_id == "bgp":
            logger.info("Uninstall trap ip2me")
            copp_utils.uninstall_trap(duthost, "ip2me", "ip2me")

        logger.info("Verify {} trap status is uninstalled by sending traffic".format(self.trap_id))
        _copp_runner(duthost,
                     ptfhost,
                     self.trap_id.upper(),
                     copp_testbed,
                     dut_type,
                     has_trap=False)

        logger.info("Set always_enabled of {} to true".format(self.trap_id))
        copp_utils.configure_always_enabled_for_trap(duthost, self.trap_id, "true")

        logging.info("Verify trap installed through CLI")
        pytest_assert(copp_utils.is_trap_installed(duthost, self.trap_id),
                      "Trap {} is not installed, expected to be installed".format(self.trap_id))

        logger.info("Verify {} trap status is installed by sending traffic".format(self.trap_id))
        pytest_assert(
            wait_until(60, 20, 0, _copp_runner, duthost, ptfhost, self.trap_id.upper(), copp_testbed, dut_type),
            "Installing {} trap fail".format(self.trap_id))

    @pytest.mark.disable_loganalyzer
    @pytest.mark.parametrize("remove_trap_type", ["delete_feature_entry",
                                                  "disable_feature_status"])
    def test_remove_trap(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                         ptfhost, check_image_version, copp_testbed, dut_type,
                         backup_restore_config_db, remove_trap_type):
        """
        Validates that The trap(bgp) can be uninstalled after deleting the corresponding entry from the feature table

        1. Pre condition: make the tested trap installed and always_enable is false
        2. Remove trap according to remove trap type
        4. Verify the trap status is uninstalled by sending traffic
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        if (duthost.facts["asic_type"] == "cisco-8000"):
            logger.info("Sleep 120 seconds for Cisco platform")
            time.sleep(120)

        if self.trap_id == "bgp":
            logger.info("Uninstall trap ip2me")
            copp_utils.uninstall_trap(duthost, "ip2me", "ip2me")

        logger.info("Pre condition: make trap {} is installed".format(self.feature_name))
        pre_condition_install_trap(ptfhost, duthost, copp_testbed, self.trap_id, self.feature_name)

        if remove_trap_type == "delete_feature_entry":
            logger.info("Remove feature entry: {}".format(self.feature_name))
            copp_utils.remove_feature_entry(duthost, self.feature_name)
        else:
            logger.info("Disable {} in feature table".format(self.feature_name))
            copp_utils.disable_feature_entry(duthost, self.feature_name)

        logging.info("Verify {} trap is uninstalled through CLI".format(self.trap_id))
        pytest_assert(wait_until(30, 2, 0, copp_utils.is_trap_uninstalled, duthost, self.trap_id),
                      "Trap {} is not uninstalled".format(self.trap_id))
        logger.info("Verify {} trap status is uninstalled by sending traffic".format(self.trap_id))
        pytest_assert(
            wait_until(100, 20, 0, _copp_runner, duthost, ptfhost, self.trap_id.upper(),
                       copp_testbed, dut_type, has_trap=False),
            "uninstalling {} trap fail".format(self.trap_id))

    @pytest.mark.disable_loganalyzer
    def test_trap_config_save_after_reboot(self, duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname,
                                           ptfhost, check_image_version, copp_testbed, dut_type,
                                           backup_restore_config_db, request):   # noqa: F811
        """
        Validates that the trap configuration is saved or not after reboot(reboot, fast-reboot, warm-reboot)

        1. Set always_enabled of a trap(e.g. bgp) to true
        2. Config save -y
        3. Do reboot according to the specified parameter of
               copp_reboot_type (reboot/warm-reboot/fast-reboot/soft-reboot)
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

        time.sleep(180)
        logger.info("Verify always_enable of {} == {} in config_db".format(self.trap_id, "true"))
        copp_utils.verify_always_enable_value(duthost, self.trap_id, "true")

        logging.info("Verify {} trap is installed through CLI".format(self.trap_id))
        pytest_assert(copp_utils.is_trap_installed(duthost, self.trap_id),
                      "Trap {} is not installed, expected to be installed".format(self.trap_id))

        logger.info("Verify {} trap status is installed by sending traffic".format(self.trap_id))
        pytest_assert(
            wait_until(200, 20, 0, _copp_runner, duthost, ptfhost, self.trap_id.upper(), copp_testbed, dut_type),
            "Installing {} trap fail".format(self.trap_id))


@pytest.mark.disable_loganalyzer
def test_verify_copp_configuration_cli(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Verifies the `show copp configuration` output with copp_cfg.json and hw_status in STATE_DB.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    namespace = DEFAULT_NAMESPACE
    if duthost.is_multi_asic:
        namespace = random.choice(duthost.asics)

    trap, trap_group, copp_group_cfg = copp_utils.get_random_copp_trap_config(duthost)
    hw_status = copp_utils.get_trap_hw_status(duthost, namespace)
    show_copp_config = copp_utils.parse_show_copp_configuration(duthost, namespace)

    pytest_assert(trap in show_copp_config,
                  f"Trap {trap} not found in show copp configuration output")
    pytest_assert(trap_group == show_copp_config[trap]["trap_group"],
                  f"Trap group mismatch for trap {trap} (expected: \
                  {trap_group}, actual: {show_copp_config[trap]['trap_group']})")

    logging.info("Verifying trap {} configuration with CLI".format(trap))
    for field in ["trap_action", "cbs", "cir", "meter_type", "mode"]:
        expected_value = copp_group_cfg.get(field, "").strip()
        actual_value = show_copp_config[trap].get(field, "").strip()
        pytest_assert(expected_value == actual_value,
                      f"Field {field} mismatch for trap {trap} (expected: {expected_value}, actual: {actual_value})")

    logging.info("Verifying trap {} installation status between CLI and STATE_DB".format(trap))
    expected_hw_status = hw_status.get(trap, "not-installed")
    actual_hw_status = show_copp_config[trap]["hw_status"]
    pytest_assert(expected_hw_status == actual_hw_status,
                  f"hw_status mismatch for trap {trap} (expected: {expected_hw_status}, actual: {actual_hw_status})")


@pytest.fixture(scope="class")
def dut_type(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # return config db contents(running-config)
    cfg_facts = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
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
    duts_minigraph_facts,
    request,
    is_backend_topology
):
    """
        Pytest fixture to handle setup and cleanup for the COPP tests.
    """
    upStreamDuthost = None
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    test_params = _gather_test_params(tbinfo, duthost, request, duts_minigraph_facts)

    # Store test_params in the TestCOPP class
    TestCOPP.test_params = test_params

    if not is_backend_topology:
        # There is no upstream neighbor in T1 backend topology. Test is skipped on T0 backend.
        # For Non T2 topologies, setting upStreamDuthost as duthost to cover dualTOR and MLAG scenarios.
        if 't2' in tbinfo["topo"]["type"]:
            upStreamDuthost = find_duthost_on_role(duthosts, get_upstream_neigh_type(tbinfo), tbinfo)
        else:
            upStreamDuthost = duthost

    try:
        _setup_multi_asic_proxy(duthost, creds, test_params, tbinfo)
        _setup_testbed(duthost, creds, ptfhost, test_params, tbinfo, upStreamDuthost, is_backend_topology)
        yield test_params
    finally:
        _teardown_multi_asic_proxy(duthost, creds, test_params, tbinfo)
        _teardown_testbed(duthost, creds, ptfhost, test_params, tbinfo, upStreamDuthost, is_backend_topology)


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


def _copp_runner(dut, ptf, protocol, test_params, dut_type, has_trap=True,
                 ip_version="4", packet_size=100):    # noqa: F811
    """
        Configures and runs the PTF test cases.
    """

    is_ipv4 = True if ip_version == "4" else False

    params = {"verbose": False,
              "target_port": test_params.nn_target_port,
              "myip": test_params.myip if is_ipv4 else test_params.myip6,
              "peerip": test_params.peerip if is_ipv4 else test_params.peerip6,
              "vlanip": copp_utils.get_vlan_ip(dut, ip_version),
              "loopbackip": copp_utils.get_lo_ipv4(dut),
              "send_rate_limit": test_params.send_rate_limit,
              "has_trap": has_trap,
              "hw_sku": dut.facts["hwsku"],
              "asic_type": dut.facts["asic_type"],
              "is_smartswitch": dut.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_smartswitch"),
              "platform": dut.facts["platform"],
              "topo_type": test_params.topo_type,
              "ip_version": ip_version,
              "packet_size": packet_size,
              "neighbor_miss_trap_supported": test_params.neighbor_miss_trap_supported}

    dut_ip = dut.mgmt_ip
    device_sockets = ["0-{}@tcp://127.0.0.1:10900".format(test_params.nn_target_port),
                      "1-{}@tcp://{}:10900".format(test_params.nn_target_port, dut_ip)]

    # Check the dut reachability from ptf host, this is to make sure the socket for ptf_nn_agent
    # can be established successfully. If the socket cannot be established, the ptf test command
    # could hang there forever.
    ptf.shell(f"ping {dut_ip} -c 5 -i 0.2")

    # NOTE: debug_level can actually slow the PTF down enough to fail the test cases
    # that are not rate limited. Until this is addressed, do not use this flag as part of
    # nightly test runs.
    ptf_runner(host=ptf,
               testdir="ptftests",
               # Special Handling for DHCP if we are using T1 Topo
               testname="copp_tests.{}Test".format((protocol+"TopoT1") if protocol in _TOR_ONLY_PROTOCOL and
                                                   dut_type not in ["ToRRouter", "MgmtToRRouter", "BmcMgmtToRRouter"]
                                                   else protocol),
               platform="nn",
               qlen=100000,
               params=params,
               relax=None,
               debug_level=None,
               device_sockets=device_sockets,
               is_python3=True)
    return True


def _gather_test_params(tbinfo, duthost, request, duts_minigraph_facts):
    """
        Fetches the test parameters from pytest.
    """

    swap_syncd = request.config.getoption("--copp_swap_syncd")
    send_rate_limit = request.config.getoption("--send_rate_limit")
    topo = tbinfo["topo"]["name"]
    topo_type = tbinfo["topo"]["type"]
    mg_fact = duts_minigraph_facts[duthost.hostname]

    port_index_map = {}
    for mg_facts_tuple in mg_fact:
        index, mg_facts = mg_facts_tuple
        # filter out server peer port and only bgp peer ports remain, to support T0 topologies
        bgp_peer_name_set = set([bgp_peer["name"] for bgp_peer in mg_facts["minigraph_bgp"]])
        # get the port_index_map using the ptf_indicies to support multi DUT topologies
        port_index_map.update({
           k: v
           for k, v in list(mg_facts["minigraph_ptf_indices"].items())
           if k in mg_facts["minigraph_ports"] and
           not duthost.is_backend_port(k, mg_facts) and
           mg_facts["minigraph_neighbors"][k]["name"] in bgp_peer_name_set
        })
    # use randam sonic interface for testing
    nn_target_interface = random.choice(list(port_index_map.keys()))
    # get the  ptf port for choosen port
    nn_target_port = port_index_map[nn_target_interface]
    myip = None
    peerip = None
    nn_target_vlanid = None

    for mg_facts_tuple in mg_fact:
        index, mg_facts = mg_facts_tuple
        if nn_target_interface not in mg_facts["minigraph_neighbors"]:
            continue
        for bgp_peer in mg_facts["minigraph_bgp"]:
            if myip is None and \
                    bgp_peer["name"] == mg_facts["minigraph_neighbors"][nn_target_interface]["name"] \
                    and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
                myip = bgp_peer["addr"]
                peerip = bgp_peer["peer_addr"]
                nn_target_namespace = mg_facts["minigraph_neighbors"][nn_target_interface]['namespace']
                is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)
                if is_backend_topology and len(mg_facts["minigraph_vlan_sub_interfaces"]) > 0:
                    nn_target_vlanid = mg_facts["minigraph_vlan_sub_interfaces"][0]["vlan"]
            elif bgp_peer["name"] == mg_facts["minigraph_neighbors"][nn_target_interface]["name"] \
                    and ipaddr.IPAddress(bgp_peer["addr"]).version == 6:
                myip6 = bgp_peer["addr"]
                peerip6 = bgp_peer["peer_addr"]
                break

    neighbor_miss_trap_supported = "neighbor_miss" in copp_utils.get_copp_trap_capabilities(duthost)

    logging.info("nn_target_port {} nn_target_interface {} nn_target_namespace {} nn_target_vlanid {}"
                 .format(nn_target_port, nn_target_interface, nn_target_namespace, nn_target_vlanid))

    return _COPPTestParameters(nn_target_port=nn_target_port,
                               swap_syncd=swap_syncd,
                               topo=topo,
                               myip=myip,
                               myip6=myip6,
                               peerip=peerip,
                               peerip6=peerip6,
                               nn_target_interface=nn_target_interface,
                               nn_target_namespace=nn_target_namespace,
                               send_rate_limit=send_rate_limit,
                               nn_target_vlanid=nn_target_vlanid,
                               topo_type=topo_type,
                               neighbor_miss_trap_supported=neighbor_miss_trap_supported)


def _setup_testbed(dut, creds, ptf, test_params, tbinfo, upStreamDuthost, is_backend_topology):
    """
        Sets up the testbed to run the COPP tests.
    """
    logging.info("Set up the PTF for COPP tests")
    copp_utils.configure_ptf(ptf, test_params, is_backend_topology)

    rate_limit = _TEST_RATE_LIMIT_DEFAULT
    if dut.facts["asic_type"] in ["marvell-prestera", "marvell"]:
        rate_limit = _TEST_RATE_LIMIT_MARVELL

    logging.info("Update the rate limit for the COPP policer")
    copp_utils.limit_policer(dut, rate_limit, test_params.nn_target_namespace, test_params.neighbor_miss_trap_supported)

    if not is_backend_topology:
        # make sure traffic goes over management port by shutdown bgp toward upstream neigh that gives default route
        upStreamDuthost.command("sudo config bgp shutdown all")
        # save BGP shutdown into config, so backup_restore_config_db won't bring it back up
        # without shutting down, background BGP traffic can consume significant COPP bandwidth on large topos
        if dut == upStreamDuthost:
            dut.command("sudo config save -y")

    # Multi-asic will not support this mode as of now.
    if test_params.swap_syncd:
        logging.info("Swap out syncd to use RPC image...")
        docker.swap_syncd(dut, creds, test_params.nn_target_namespace)
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


def _teardown_testbed(dut, creds, ptf, test_params, tbinfo, upStreamDuthost, is_backend_topology):
    """
        Tears down the testbed, returning it to its initial state.
    """
    logging.info("Restore PTF post COPP test")
    copp_utils.restore_ptf(ptf)

    logging.info("Restore COPP policer to default settings")
    copp_utils.restore_policer(dut, test_params.nn_target_namespace)

    if not is_backend_topology:
        # Testbed is not a T1 backend device, so bring up bgp session to upstream device
        upStreamDuthost.command("sudo config bgp startup all")
        if dut == upStreamDuthost:
            dut.command("sudo config save -y")

    if test_params.swap_syncd:
        logging.info("Restore default syncd docker...")
        docker.restore_default_syncd(dut, creds, test_params.nn_target_namespace)
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
    # Add IP Table rule for http and ptf nn_agent traffic.
    dut.command("sudo sysctl net.ipv4.conf.eth0.forwarding=1")

    if not test_params.swap_syncd:
        mgmt_ip = dut.host.options["inventory_manager"].get_host(dut.hostname).vars["ansible_host"]
        # Add Rule to communicate to http/s proxy from namespace
        dut.command("sudo iptables -t nat -A POSTROUTING -p tcp --dport 8080 -j SNAT --to-source {}".format(mgmt_ip))
    # Add Rule to communicate to ptf nn agent client from namespace
    ns_ip = dut.shell("sudo ip -n {} -4 -o addr show eth0".format(test_params.nn_target_namespace)
                      + " | awk '{print $4}' | cut -d'/' -f1")["stdout"]
    dut.command("sudo iptables -t nat -A PREROUTING -p tcp --dport 10900 -j DNAT --to-destination {}".format(ns_ip))


def _teardown_multi_asic_proxy(dut, creds, test_params, tbinfo):
    """
        Tears down multi asic proxy settings, returning it to its initial state.
    """
    if not dut.is_multi_asic:
        return

    logging.info("Removing iptables rules and disabling eth0 port forwarding")
    dut.command("sudo sysctl net.ipv4.conf.eth0.forwarding=0")
    if not test_params.swap_syncd:
        # Delete IP Table rule for http and ptf nn_agent traffic.
        mgmt_ip = dut.host.options["inventory_manager"].get_host(dut.hostname).vars["ansible_host"]
        # Delete Rule to communicate to http/s proxy from namespace
        dut.command("sudo iptables -t nat -D POSTROUTING -p tcp --dport 8080 -j SNAT --to-source {}".format(mgmt_ip))
    # Delete Rule to communicate to ptf nn agent client from namespace
    ns_ip = dut.shell("sudo ip -n {} -4 -o addr show eth0".format(test_params.nn_target_namespace)
                      + " | awk '{print $4}' | cut -d'/' -f1")["stdout"]
    dut.command("sudo iptables -t nat -D PREROUTING -p tcp --dport 10900 -j DNAT --to-destination {}".format(ns_ip))


@pytest.fixture(scope="function", autouse=False)
def backup_restore_config_db(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    copp_utils.backup_config_db(duthost)

    yield
    copp_utils.restore_config_db(duthost)


def pre_condition_install_trap(ptfhost, duthost, copp_testbed, trap_id, feature_name):   # noqa: F811
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
