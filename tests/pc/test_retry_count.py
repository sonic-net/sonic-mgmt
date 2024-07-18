import pytest

import time
import logging
import tempfile

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until
from scapy.all import Packet, ByteField, ShortField, MACField, XStrFixedLenField, ConditionalField, MultipleTypeField
from scapy.all import split_layers, bind_layers, rdpcap
import scapy.contrib.lacp
import scapy.layers.l2

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0", "t1")
]


class LACPRetryCount(Packet):
    name = "LACPRetryCount"
    fields_desc = [
        ByteField("version", 0xf1),
        ByteField("actor_type", 1),
        ByteField("actor_length", 20),
        ShortField("actor_system_priority", 0),
        MACField("actor_system", None),
        ShortField("actor_key", 0),
        ShortField("actor_port_priority", 0),
        ShortField("actor_port_number", 0),
        ByteField("actor_state", 0),
        XStrFixedLenField("actor_reserved", "", 3),
        ByteField("partner_type", 2),
        ByteField("partner_length", 20),
        ShortField("partner_system_priority", 0),
        MACField("partner_system", None),
        ShortField("partner_key", 0),
        ShortField("partner_port_priority", 0),
        ShortField("partner_port_number", 0),
        ByteField("partner_state", 0),
        XStrFixedLenField("partner_reserved", "", 3),
        ByteField("collector_type", 3),
        ByteField("collector_length", 16),
        ShortField("collector_max_delay", 0),
        XStrFixedLenField("collector_reserved", "", 12),
        ConditionalField(ByteField("actor_retry_count_type", 0x80), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("actor_retry_count_length", 4), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("actor_retry_count", 0), lambda pkt:pkt.version == 0xf1),
        ConditionalField(XStrFixedLenField("actor_retry_count_reserved", "", 1), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("partner_retry_count_type", 0x81), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("partner_retry_count_length", 4), lambda pkt:pkt.version == 0xf1),
        ConditionalField(ByteField("partner_retry_count", 0), lambda pkt:pkt.version == 0xf1),
        ConditionalField(XStrFixedLenField("partner_retry_count_reserved", "", 1), lambda pkt:pkt.version == 0xf1),
        ByteField("terminator_type", 0),
        ByteField("terminator_length", 0),
        MultipleTypeField([(XStrFixedLenField("reserved", "", 42), lambda pkt:pkt.version == 0xf1)],
                          XStrFixedLenField("reserved", "", 50)),
    ]


def verify_retry_count(hosts, expected_retry_count):
    for host in hosts:
        cfg_facts = host.config_facts(host=host.hostname, source="running")["ansible_facts"]
        port_channels = cfg_facts["PORTCHANNEL"].keys()
        for port_channel in port_channels:
            port_channel_status = host.get_port_channel_status(port_channel)
            for _, status in list(port_channel_status["ports"].items()):
                if status["runner"]["partner_retry_count"] != expected_retry_count:
                    return False

    return True


@pytest.fixture(scope="class")
def higher_retry_count_on_peers(request, duthost, nbrhosts):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Only supported with SONiC neighbor")

    featureCheckResult = nbrhosts[list(nbrhosts.keys())[0]]['host'].shell(
            "sudo config portchannel retry-count get PortChannel1", module_ignore_errors=True)
    if featureCheckResult["rc"] != 0:
        pytest.skip("SONiC neighbor isn't running supported version of SONiC")

    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("sudo config portchannel retry-count set PortChannel1 5")

    # Wait for retry count info to be updated
    pytest_assert(wait_until(5, 1, 0, verify_retry_count, [duthost], 5),
                  "Retry count on DUT has not been changed to 5.")

    yield

    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("sudo config portchannel retry-count set PortChannel1 3")

    # Wait for retry count info to be updated
    pytest_assert(wait_until(90, 5, 0, verify_retry_count, [duthost], 3),
                  "Retry count on DUT has not been changed to 3.")


@pytest.fixture(scope="class")
def higher_retry_count_on_dut(request, duthost, nbrhosts):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Only supported with SONiC neighbor")

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]

    featureCheckResult = duthost.shell("sudo config portchannel retry-count get {}".format(
        list(cfg_facts["PORTCHANNEL"].keys())[0]), module_ignore_errors=True)
    if featureCheckResult["rc"] != 0:
        pytest.skip("SONiC DUT isn't running supported version of SONiC")

    for port_channel in list(cfg_facts["PORTCHANNEL"].keys()):
        duthost.shell("sudo config portchannel retry-count set {} 5".format(port_channel))

    # Wait for retry count info to be updated
    pytest_assert(wait_until(5, 1, 0, verify_retry_count, [nbrhosts[nbr]['host'] for nbr in nbrhosts], 5),
                  "Retry count on neighbors has not been changed to 5.")

    yield

    for port_channel in list(cfg_facts["PORTCHANNEL"].keys()):
        duthost.shell("sudo config portchannel retry-count set {} 3".format(port_channel))

    # Wait for retry count info to be updated
    pytest_assert(wait_until(90, 5, 0, verify_retry_count, [nbrhosts[nbr]['host'] for nbr in nbrhosts], 3),
                  "Retry count on neighbors has not been changed to 3.")


@pytest.fixture(scope="function")
def config_reload_on_cleanup(request, nbrhosts, duthost):
    if request.config.getoption("enable_macsec"):
        pytest.skip("Skip for now, since config reload will disable macsec for future test cases")

    yield

    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("sudo config reload -y")
    config_reload(duthost, safe_reload=True)


def log_lacpdu_packets(duthost, save_path):
    """Capture LACPDU packets to file."""
    # Support for LINUX_SLL2 was added in Scapy 2.5.0. We're using 2.4.5 currently.
    start_pcap = "tcpdump -i any -y LINUX_SLL -w %s ether proto 0x8809" % (save_path)
    stop_pcap = "sudo pkill -f '{}'".format(start_pcap)
    start_pcap = "sudo nohup {} &".format(start_pcap)
    duthost.shell(start_pcap)

    time.sleep(30)

    duthost.shell(stop_pcap, module_ignore_errors=True)


@pytest.fixture(scope="function")
def scapy_lacp_layer():
    split_layers(scapy.contrib.lacp.SlowProtocol, scapy.contrib.lacp.LACP, subtype=1)
    bind_layers(scapy.contrib.lacp.SlowProtocol, LACPRetryCount, subtype=1)
    bind_layers(scapy.layers.l2.CookedLinux, scapy.contrib.lacp.SlowProtocol, proto=0x8809)

    yield

    split_layers(scapy.layers.l2.CookedLinux, scapy.contrib.lacp.SlowProtocol, proto=0x8809)
    split_layers(scapy.contrib.lacp.SlowProtocol, LACPRetryCount, subtype=1)
    bind_layers(scapy.contrib.lacp.SlowProtocol, scapy.contrib.lacp.LACP, subtype=1)


def check_lacpdu_packet_version(duthost):
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    log_lacpdu_packets(duthost, "lacpdu.pcap")
    lacpduPackets = None
    with tempfile.NamedTemporaryFile() as tmp_pcap:
        duthost.fetch(src="lacpdu.pcap", dest=tmp_pcap.name, flat=True)
        lacpduPackets = rdpcap(tmp_pcap.name)
    for port_channel in port_channels:
        port_channel_status = duthost.get_port_channel_status(port_channel)
        for port, status in list(port_channel_status["ports"].items()):
            sendVersionVerified = False
            receiveVersionVerified = False
            actorInfo = status["runner"]["actor_lacpdu_info"]
            partnerInfo = status["runner"]["partner_lacpdu_info"]
            for pkt in lacpduPackets:
                if pkt["LACPRetryCount"].version == 0xf1:
                    if pkt["LACPRetryCount"].actor_system == actorInfo["system"] \
                            and pkt["LACPRetryCount"].actor_port_number == actorInfo["port"] \
                            and pkt["LACPRetryCount"].partner_system == partnerInfo["system"] \
                            and pkt["LACPRetryCount"].partner_port_number == partnerInfo["port"]:
                        sendVersionVerified = True
                    elif pkt["LACPRetryCount"].actor_system == partnerInfo["system"] \
                            and pkt["LACPRetryCount"].actor_port_number == partnerInfo["port"] \
                            and pkt["LACPRetryCount"].partner_system == actorInfo["system"] \
                            and pkt["LACPRetryCount"].partner_port_number == actorInfo["port"]:
                        receiveVersionVerified = True
            pytest_assert(sendVersionVerified, "unable to verify that LACPDU packets sent were the right version")
            pytest_assert(receiveVersionVerified,
                          "unable to verify that LACPDU packets received were the right version")


@pytest.fixture(scope="function")
def disable_retry_count_on_peer(duthost, nbrhosts, higher_retry_count_on_peers):
    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("teamdctl PortChannel1 state item set runner.enable_retry_count_feature false")

    # Wait 90 seconds for retry count to get updated on the DUT
    pytest_assert(wait_until(90, 5, 0, verify_retry_count, [duthost], 3),
                  "Retry count on neighbors has not been reset to 3.")

    yield

    for nbr in list(nbrhosts.keys()):
        nbrhosts[nbr]['host'].shell("teamdctl PortChannel1 state item set runner.enable_retry_count_feature true")


@pytest.fixture(scope="function")
def disable_retry_count_on_dut(duthost, nbrhosts, higher_retry_count_on_dut):
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    for port_channel in list(cfg_facts["PORTCHANNEL"].keys()):
        duthost.shell("teamdctl {} state item set runner.enable_retry_count_feature false".format(port_channel))

    # Wait 90 seconds for retry count to get updated on the peers
    pytest_assert(wait_until(90, 5, 0, verify_retry_count, [nbrhosts[nbr]['host'] for nbr in nbrhosts], 3),
                  "Retry count on neighbors has not been reset to 3.")

    yield

    for port_channel in list(cfg_facts["PORTCHANNEL"].keys()):
        duthost.shell("teamdctl {} state item set runner.enable_retry_count_feature true".format(port_channel))


class TestNeighborRetryCount:
    def test_peer_retry_count(self, duthost, nbrhosts, higher_retry_count_on_peers):
        """
        Test that DUT sees new retry count when peers update retry count.
        """
        for nbr in list(nbrhosts.keys()):
            port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
            pytest_assert(port_channel_status["runner"]["retry_count"] == 5,
                          "retry count on neighbor is incorrect; expected 5, but is {}"
                          .format(port_channel_status["runner"]["retry_count"]))

        cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        port_channels = cfg_facts["PORTCHANNEL"].keys()
        for port_channel in port_channels:
            port_channel_status = duthost.get_port_channel_status(port_channel)
            number_of_lag_member = len(cfg_facts["PORTCHANNEL_MEMBER"][port_channel])
            pytest_assert("ports" in port_channel_status and number_of_lag_member == len(port_channel_status["ports"]),
                          "get port status error")
            for _, status in list(port_channel_status["ports"].items()):
                pytest_assert(status["runner"]["selected"], "lag member is not up")
                pytest_assert(status["runner"]["partner_retry_count"] == 5,
                              "partner retry count is incorrect; expected 5, but is {}"
                              .format(status["runner"]["partner_retry_count"]))

    def test_peer_retry_count_packet_version(self, duthost, nbrhosts, higher_retry_count_on_peers, scapy_lacp_layer):
        """
        Test that peers and DUT use new LACPDU version when peers use a non-standard retry count
        """
        check_lacpdu_packet_version(duthost)

    def test_kill_teamd_lag_up(self, duthost, nbrhosts, higher_retry_count_on_peers, config_reload_on_cleanup):
        """
        Test that the lag remains up for 150 seconds after killing teamd on the peer
        """
        for nbr in list(nbrhosts.keys()):
            nbrhosts[nbr]['host'].shell("sudo pkill -USR1 -x teamd")

        # Give ourselves 15 seconds to check before the LAG goes down.
        time.sleep(135)

        cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        port_channels = cfg_facts["PORTCHANNEL"].keys()
        for port_channel in port_channels:
            port_channel_status = duthost.get_port_channel_status(port_channel)
            for _, status in list(port_channel_status["ports"].items()):
                pytest_assert(status["runner"]["selected"], "lag member is not up")
                pytest_assert(status["runner"]["partner_retry_count"] == 5,
                              "partner retry count is incorrect; expected 5, but is {}"
                              .format(status["runner"]["partner_retry_count"]))

        # Wait 20 seconds (total of 155 seconds) to verify that the LAG did go down.
        time.sleep(20)

        cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        port_channels = cfg_facts["PORTCHANNEL"].keys()
        for port_channel in port_channels:
            port_channel_status = duthost.get_port_channel_status(port_channel)
            for _, status in list(port_channel_status["ports"].items()):
                pytest_assert(not status["runner"]["selected"], "lag member is still up")


def test_peer_retry_count_disabled(duthost, nbrhosts, higher_retry_count_on_peers, disable_retry_count_on_peer,
                                   collect_techsupport_all_nbrs):
    """
    Test that peers reset the retry count to 3 when the feature is disabled
    """

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    for port_channel in port_channels:
        port_channel_status = duthost.get_port_channel_status(port_channel)
        for _, status in list(port_channel_status["ports"].items()):
            pytest_assert(status["runner"]["partner_retry_count"] == 3,
                          "partner retry count is incorrect; expected 3, but is {}"
                          .format(status["runner"]["partner_retry_count"]))

    for nbr in list(nbrhosts.keys()):
        processRc = nbrhosts[nbr]['host'].shell("sudo config portchannel retry-count get PortChannel1",
                                                module_ignore_errors=True)
        pytest_assert(processRc["failed"], "Expected failure for getting retry count, but instead it succeeded")


class TestDutRetryCount:
    def test_retry_count(self, duthost, nbrhosts, higher_retry_count_on_dut):
        """
        Test that peers see new retry count when DUT updates retry count.
        """
        cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
        port_channels = cfg_facts["PORTCHANNEL"].keys()
        for port_channel in port_channels:
            port_channel_status = duthost.get_port_channel_status(port_channel)
            pytest_assert(port_channel_status["runner"]["retry_count"] == 5,
                          "retry count on DUT is incorrect; expected 5, but is {}"
                          .format(port_channel_status["runner"]["retry_count"]))

        for nbr in list(nbrhosts.keys()):
            port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
            for _, status in list(port_channel_status["ports"].items()):
                pytest_assert(status["runner"]["selected"], "lag member is not up")
                pytest_assert(status["runner"]["partner_retry_count"] == 5,
                              "partner retry count is incorrect; expected 5, but is {}"
                              .format(status["runner"]["partner_retry_count"]))

    def test_retry_count_packet_version(self, duthost, nbrhosts, higher_retry_count_on_dut, scapy_lacp_layer):
        """
        Test that peers and DUT use new LACPDU version when DUT uses a non-standard retry count
        """
        check_lacpdu_packet_version(duthost)

    def test_kill_teamd_peer_lag_up(self, duthost, nbrhosts, higher_retry_count_on_peers, config_reload_on_cleanup):
        """
        Test that the lag remains up for 150 seconds after killing teamd on the DUT
        """
        duthost.shell("docker exec teamd pkill -USR1 -x teamd")

        # Give ourselves 15 seconds to check before the LAG goes down.
        time.sleep(135)

        for nbr in list(nbrhosts.keys()):
            port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
            for _, status in list(port_channel_status["ports"].items()):
                pytest_assert(status["runner"]["selected"], "lag member is not up")
                pytest_assert(status["runner"]["partner_retry_count"] == 5,
                              "partner retry count is incorrect; expected 5, but is {}"
                              .format(status["runner"]["partner_retry_count"]))

        # Wait 20 seconds (total of 155 seconds) to verify that the LAG did go down.
        time.sleep(20)

        for nbr in list(nbrhosts.keys()):
            port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
            for _, status in list(port_channel_status["ports"].items()):
                pytest_assert(not status["runner"]["selected"], "lag member is still up")


def test_dut_retry_count_disabled(duthost, nbrhosts, higher_retry_count_on_dut, disable_retry_count_on_dut,
                                  collect_techsupport_all_nbrs):
    """
    Test that DUT resets the retry count to 3 when the feature is disabled
    """
    for nbr in list(nbrhosts.keys()):
        port_channel_status = nbrhosts[nbr]['host'].get_port_channel_status("PortChannel1")
        for _, status in list(port_channel_status["ports"].items()):
            pytest_assert(status["runner"]["partner_retry_count"] == 3,
                          "partner retry count is incorrect; expected 3, but is {}"
                          .format(status["runner"]["partner_retry_count"]))

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    port_channels = cfg_facts["PORTCHANNEL"].keys()
    for port_channel in port_channels:
        processRc = duthost.shell("sudo config portchannel retry-count get {}".format(port_channel),
                                  module_ignore_errors=True)
        pytest_assert(processRc["failed"], "Expected failure for getting retry count, but instead it succeeded")
