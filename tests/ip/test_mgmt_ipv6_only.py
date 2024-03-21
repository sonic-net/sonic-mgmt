import os
import time
import pytest
import logging
from scapy.all import rdpcap

from tests.common.fixtures.duthost_utils import convert_and_restore_config_db_to_ipv6_only  # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.syslog.test_syslog import check_dummy_addr_and_default_route, _check_pcap, check_default_route

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

DUT_PCAP_FILEPATH = "/tmp/test_syslog_tcpdump.pcap"
DOCKER_TMP_PATH = "/tmp/"


def test_bgp_facts_ipv6_only(duthosts, enum_frontend_dut_hostname, enum_asic_index,
                             convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """compare the bgp facts between observed states and target state"""

    duthost = duthosts[enum_frontend_dut_hostname]

    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    config_facts = duthost.config_facts(host=duthost.hostname, source="running", namespace=namespace)['ansible_facts']
    sonic_db_cmd = "sonic-db-cli {}".format("-n " + namespace if namespace else "")
    for k, v in list(bgp_facts['bgp_neighbors'].items()):
        # Verify bgp sessions are established
        assert v['state'] == 'established'
        # Verify local ASNs in bgp sessions
        assert v['local AS'] == int(config_facts['DEVICE_METADATA']['localhost']['bgp_asn'].encode().decode("utf-8"))
        # Check bgpmon functionality by validate STATE DB contains this neighbor as well
        state_fact = duthost.shell('{} STATE_DB HGET "NEIGH_STATE_TABLE|{}" "state"'
                                   .format(sonic_db_cmd, k), module_ignore_errors=False)['stdout_lines']
        peer_type = duthost.shell('{} STATE_DB HGET "NEIGH_STATE_TABLE|{}" "peerType"'
                                  .format(sonic_db_cmd, k),
                                  module_ignore_errors=False)['stdout_lines']
        assert state_fact[0] == "Established"
        assert peer_type[0] == "i-BGP" if v['remote AS'] == v['local AS'] else "e-BGP"

    # In multi-asic, would have 'BGP_INTERNAL_NEIGHBORS' and possibly no 'BGP_NEIGHBOR' (ebgp) neighbors.
    nbrs_in_cfg_facts = {}
    nbrs_in_cfg_facts.update(config_facts.get('BGP_NEIGHBOR', {}))
    nbrs_in_cfg_facts.update(config_facts.get('BGP_INTERNAL_NEIGHBOR', {}))
    # In VoQ Chassis, we would have BGP_VOQ_CHASSIS_NEIGHBOR as well.
    nbrs_in_cfg_facts.update(config_facts.get('BGP_VOQ_CHASSIS_NEIGHBOR', {}))
    for k, v in list(nbrs_in_cfg_facts.items()):
        # Compare the bgp neighbors name with config db bgp neighbors name
        assert v['name'] == bgp_facts['bgp_neighbors'][k]['description']
        # Compare the bgp neighbors ASN with config db
        assert int(v['asn'].encode().decode("utf-8")) == bgp_facts['bgp_neighbors'][k]['remote AS']


def test_show_features_ipv6_only(duthosts, enum_dut_hostname, convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """Verify show features command output against CONFIG_DB
    """

    duthost = duthosts[enum_dut_hostname]
    features_dict, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "failed to obtain feature status")
    for cmd_key, cmd_value in list(features_dict.items()):
        redis_value = duthost.shell('/usr/bin/redis-cli -n 4 --raw hget "FEATURE|{}" "state"'
                                    .format(cmd_key), module_ignore_errors=False)['stdout']
        pytest_assert(redis_value.lower() == cmd_value.lower(),
                      "'{}' is '{}' which does not match with config_db".format(cmd_key, cmd_value))


def test_image_download_ipv6_only(creds, duthosts, enum_dut_hostname,
                                  convert_and_restore_config_db_to_ipv6_only): # noqa F811
    """
    Test image download in mgmt ipv6 only scenario
    """
    duthost = duthosts[enum_dut_hostname]
    image_url = creds.get("test_image_url", {}).get("ipv6", "")
    pytest_require(len(image_url) != 0, "Cannot get image url")
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    mgmt_interfaces = cfg_facts.get("MGMT_INTERFACE", {}).keys()
    for mgmt_interface in mgmt_interfaces:
        output = duthost.shell("curl --fail --interface {} {}".format(mgmt_interface, image_url),
                               module_ignore_errors=True)
        if output["rc"] == 0:
            break
    else:
        pytest.fail("Failed to download image from image_url {} via any of {}"
                    .format(image_url, list(mgmt_interfaces)))


@pytest.mark.parametrize("dummy_syslog_server_ip_a, dummy_syslog_server_ip_b",
                         [("fd82:b34f:cc99::100", None),
                          ("fd82:b34f:cc99::100", "fd82:b34f:cc99::200")])
def test_syslog(rand_selected_dut, dummy_syslog_server_ip_a, dummy_syslog_server_ip_b,
                check_default_route, convert_and_restore_config_db_to_ipv6_only):
    duthost = rand_selected_dut
    logger.info("Starting syslog tests")
    test_message = "Basic Test Message"

    check_dummy_addr_and_default_route(dummy_syslog_server_ip_a, dummy_syslog_server_ip_b,
                                       check_default_route['IPv4'], check_default_route['IPv6'])

    if dummy_syslog_server_ip_a:
        duthost.command("sudo ip -6 rule add from all to {} pref 1 lookup default".format(dummy_syslog_server_ip_a))

    if dummy_syslog_server_ip_b:
        duthost.command("sudo ip -6 rule add from all to {} pref 2 lookup default".format(dummy_syslog_server_ip_b))

    logger.info("Configuring the DUT")
    # Add dummy rsyslog destination for testing
    if dummy_syslog_server_ip_a is not None:
        if "201911" in duthost.os_version and ":" in dummy_syslog_server_ip_a:
            pytest.skip("IPv6 syslog server IP not supported on 201911")
        duthost.shell("sudo config syslog add {}".format(dummy_syslog_server_ip_a))
        logger.debug("Added new rsyslog server IP {}".format(dummy_syslog_server_ip_a))
    if dummy_syslog_server_ip_b is not None:
        if "201911" in duthost.os_version and ":" in dummy_syslog_server_ip_b:
            pytest.skip("IPv6 syslog server IP not supported on 201911")
        duthost.shell("sudo config syslog add {}".format(dummy_syslog_server_ip_b))
        logger.debug("Added new rsyslog server IP {}".format(dummy_syslog_server_ip_b))

    logger.info("Start tcpdump")
    # Make sure that the DUT_PCAP_FILEPATH dose not exist
    duthost.shell("sudo rm -f {}".format(DUT_PCAP_FILEPATH))
    # Scapy doesn't support LINUX_SLL2 (Linux cooked v2), and tcpdump on Bullseye
    # defaults to writing in that format when listening on any interface. Therefore,
    # have it use LINUX_SLL (Linux cooked) instead.
    tcpdump_task, tcpdump_result = duthost.shell(
        "sudo timeout 20 tcpdump -y LINUX_SLL -i any -s0 -A -w {} \"udp and port 514\""
        .format(DUT_PCAP_FILEPATH), module_async=True)
    # wait for starting tcpdump
    time.sleep(5)

    logger.debug("Generating log message from DUT")
    # Generate a syslog from the DUT
    duthost.shell("logger --priority INFO {}".format(test_message))

    # wait for stoping tcpdump
    tcpdump_task.close()
    tcpdump_task.join()

    # Remove the syslog configuration
    if dummy_syslog_server_ip_a is not None:
        duthost.shell("sudo config syslog del {}".format(dummy_syslog_server_ip_a))
        duthost.command("sudo ip -6 rule del from all to {} pref 1 lookup default".format(dummy_syslog_server_ip_a))

    if dummy_syslog_server_ip_b is not None:
        duthost.shell("sudo config syslog del {}".format(dummy_syslog_server_ip_b))
        duthost.command("sudo ip -6 rule del from all to {} pref 2 lookup default".format(dummy_syslog_server_ip_b))

    duthost.fetch(src=DUT_PCAP_FILEPATH, dest=DOCKER_TMP_PATH)
    filepath = os.path.join(DOCKER_TMP_PATH, duthost.hostname, DUT_PCAP_FILEPATH.lstrip(os.path.sep))

    if not _check_pcap(dummy_syslog_server_ip_a, dummy_syslog_server_ip_b, filepath):
        default_route_v6 = duthost.shell("ip -6 route show default table default")['stdout']
        logger.debug("DUT's IPv6 default route:\n%s" % default_route_v6)
        syslog_config = duthost.shell("grep 'remote syslog server' -A 7 /etc/rsyslog.conf")['stdout']
        logger.debug("DUT's syslog server IPs:\n%s" % syslog_config)

        pytest.fail("Dummy syslog server IP not seen in the pcap file")
