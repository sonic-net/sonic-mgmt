import pytest
import logging

from tests.common.utilities import wait_until
from macsec_helper import *
from macsec_config_helper import *
from macsec_platform_helper import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0"),
]


@pytest.fixture(scope="module", autouse=True)
def setup(duthost, ctrl_links, unctrl_links, enable_macsec_feature, profile_name, default_priority, cipher_suite,
          primary_cak, primary_ckn, policy, send_sci, request):
    if request.session.testsfailed > 0:
        return
    all_links = {}
    all_links.update(ctrl_links)
    all_links.update(unctrl_links)
    startup_all_ctrl_links(ctrl_links)
    cleanup_macsec_configuration(duthost, all_links, profile_name)
    setup_macsec_configuration(duthost, ctrl_links, profile_name,
                               default_priority, cipher_suite, primary_cak, primary_ckn, policy, send_sci)
    logger.info(
        "Setup MACsec configuration with arguments:\n{}".format(locals()))
    yield
    if request.session.testsfailed > 0:
        return
    cleanup_macsec_configuration(duthost, all_links, profile_name)


class TestControlPlane():
    def test_wpa_supplicant_processes(self, duthost, ctrl_links):
        def _test_wpa_supplicant_processes():
            for port_name, nbr in ctrl_links.items():
                check_wpa_supplicant_process(duthost, port_name)
                check_wpa_supplicant_process(nbr["host"], nbr["port"])
            return True
        assert wait_until(300, 1, 1, _test_wpa_supplicant_processes)

    def test_appl_db(self, duthost, ctrl_links, policy, cipher_suite, send_sci):
        def _test_appl_db():
            for port_name, nbr in ctrl_links.items():
                check_appl_db(duthost, port_name, nbr["host"],
                              nbr["port"], policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 6, 12, _test_appl_db)

    def test_mka_session(self, duthost, ctrl_links, policy, cipher_suite, send_sci):
        def _test_mka_session():
            # If the DUT isn't a virtual switch that cannot support "get mka session" by "ip macsec show"
            # So, skip this test for physical switch
            # TODO: Support "get mka session" in the physical switch
            if u"x86_64-kvm_x86_64" not in get_platform(duthost):
                logging.info(
                    "Skip to check mka session due to the DUT isn't a virtual switch")
                return True
            dut_mka_session = get_mka_session(duthost)
            assert len(dut_mka_session) == len(ctrl_links)
            for port_name, nbr in ctrl_links.items():
                nbr_mka_session = get_mka_session(nbr["host"])
                dut_macsec_port = get_macsec_ifname(duthost, port_name)
                nbr_macsec_port = get_macsec_ifname(
                    nbr["host"], nbr["port"])
                dut_macaddress = duthost.get_dut_iface_mac(port_name)
                nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
                dut_sci = get_sci(dut_macaddress, order="host")
                nbr_sci = get_sci(nbr_macaddress, order="host")
                check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                                  nbr_mka_session[nbr_macsec_port], nbr_sci,
                                  policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 1, 1, _test_mka_session)


class TestDataPlane():
    BATCH_COUNT = 100

    def test_server_to_neighbor(self, duthost, ctrl_links, downstream_links, upstream_links, nbr_device_numbers, nbr_ptfadapter):
        nbr_ptfadapter.dataplane.set_qlen(TestDataPlane.BATCH_COUNT * 10)

        down_link = downstream_links.values()[0]
        dut_macaddress = duthost.get_dut_iface_mac(ctrl_links.keys()[0])

        for portchannel in get_portchannel(duthost).values():
            members = portchannel["members"]

            if not members:
                continue

            is_protected_link = members[0] in ctrl_links
            peer_ports = []
            ptf_injected_ports = []
            for port_name in members:
                if is_protected_link:
                    assert port_name in ctrl_links
                    peer_ports.append(
                        int(re.search(r"(\d+)", ctrl_links[port_name]["port"]).group(1)))
                    ptf_injected_ports.append(
                        upstream_links[port_name]["ptf_port_id"])
                else:
                    assert port_name not in ctrl_links
            if not is_protected_link:
                continue

            up_link = upstream_links[members[0]]
            up_host_name = up_link["name"]
            up_host_ip = up_link["local_ipv4_addr"]
            payload = "{} -> {}".format(down_link["name"], up_host_name)
            logging.info(payload)
            # Source mac address is not useful in this test case and we use an arbitrary mac address as the source
            pkt = create_pkt(
                "00:01:02:03:04:05", dut_macaddress, "1.2.3.4", up_host_ip, bytes(payload))
            exp_pkt = create_exp_pkt(pkt, pkt[scapy.IP].ttl - 1)

            testutils.send_packet(
                nbr_ptfadapter, down_link["ptf_port_id"], pkt, TestDataPlane.BATCH_COUNT)
            testutils.verify_packet_any_port(
                nbr_ptfadapter, exp_pkt, ports=peer_ports, device_number=nbr_device_numbers[up_host_name], timeout=3)

            fail_message = ""
            for port_name in members:
                up_link = upstream_links[port_name]
                macsec_attr = get_macsec_attr(duthost, port_name)
                testutils.send_packet(
                    nbr_ptfadapter, down_link["ptf_port_id"], pkt, TestDataPlane.BATCH_COUNT)
                result = check_macsec_pkt(macsec_attr=macsec_attr, test=nbr_ptfadapter,
                                          ptf_port_id=up_link["ptf_port_id"],  exp_pkt=exp_pkt, timeout=3)
                if result is None:
                    return
                fail_message += result
            pytest.fail(fail_message)

    def test_neighbor_to_neighbor(self, duthost, ctrl_links, upstream_links, nbr_device_numbers, nbr_ptfadapter):
        portchannels = get_portchannel(duthost).values()
        for i in range(len(portchannels)):
            assert portchannels[i]["members"]
            requester = upstream_links[portchannels[i]["members"][0]]
            # Set DUT as the gateway of requester
            requester["host"].shell("ip route add 0.0.0.0/0 via {}".format(
                requester["peer_ipv4_addr"]), module_ignore_errors=True)
            for j in range(i + 1, len(portchannels)):
                if portchannels[i]["members"][0] not in ctrl_links and portchannels[j]["members"][0] not in ctrl_links:
                    continue
                responser = upstream_links[portchannels[j]["members"][0]]
                # Set DUT as the gateway of responser
                responser["host"].shell("ip route add 0.0.0.0/0 via {}".format(
                    responser["peer_ipv4_addr"]), module_ignore_errors=True)
                # Ping from requester to responser
                assert not requester["host"].shell(
                    "ping -c 6 -v {}".format(responser["local_ipv4_addr"]))["failed"]
                responser["host"].shell("ip route del 0.0.0.0/0 via {}".format(
                    responser["peer_ipv4_addr"]), module_ignore_errors=True)
            requester["host"].shell("ip route del 0.0.0.0/0 via {}".format(
                requester["peer_ipv4_addr"]), module_ignore_errors=True)


class TestFaultHandling():
    MKA_TIMEOUT = 6
    LACP_TIMEOUT = 90

    def test_link_flap(self, duthost, ctrl_links):
        # Only pick one link for link flap test
        assert ctrl_links
        port_name, nbr = ctrl_links.items()[0]
        _, _, _, dut_egress_sa_table_orig, dut_ingress_sa_table_orig = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])

        # Flap < 6 seconds
        nbr["host"].shell("ifconfig {} down && sleep 1 && ifconfig {} up".format(
            nbr_eth_port, nbr_eth_port))
        _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        assert dut_egress_sa_table_orig == dut_egress_sa_table_new
        assert dut_ingress_sa_table_orig == dut_ingress_sa_table_new

        # Flap > 6 seconds but < 90 seconds
        nbr["host"].shell("ifconfig {} down && sleep {} && ifconfig {} up".format(
            nbr_eth_port, TestFaultHandling.MKA_TIMEOUT, nbr_eth_port))

        def check_new_mka_session():
            _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            assert dut_egress_sa_table_new
            assert dut_ingress_sa_table_new
            assert dut_egress_sa_table_orig != dut_egress_sa_table_new
            assert dut_ingress_sa_table_orig != dut_ingress_sa_table_new
            return True
        assert wait_until(12, 1, 0, check_new_mka_session)

        # Flap > 90 seconds
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up")
        nbr["host"].shell("ifconfig {} down && sleep {}".format(
            nbr_eth_port, TestFaultHandling.LACP_TIMEOUT))
        assert wait_until(6, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Dw")
        nbr["host"].shell("ifconfig {} up".format(nbr_eth_port))
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up")

    def test_mismatch_macsec_configuration(self, duthost, unctrl_links,
                                           profile_name, default_priority, cipher_suite,
                                           primary_cak, primary_ckn, policy, send_sci, request):
        # Only pick one uncontrolled link for mismatch macsec configuration test
        assert unctrl_links
        port_name, nbr = unctrl_links.items()[0]

        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], profile_name)

        # Set a wrong cak to the profile
        primary_cak = "0" * len(primary_cak)
        enable_macsec_port(duthost, port_name, profile_name)
        set_macsec_profile(nbr["host"], profile_name, default_priority,
                           cipher_suite, primary_cak, primary_ckn, policy, send_sci)
        enable_macsec_port(nbr["host"], nbr["port"], profile_name)

        def check_mka_establishment():
            _, _, dut_ingress_sc_table, dut_egress_sa_table, dut_ingress_sa_table = get_appl_db(
                duthost, port_name, nbr["host"], nbr["port"])
            return dut_ingress_sc_table or dut_egress_sa_table or dut_ingress_sa_table
        # The mka should be establishing or established
        # To check whether the MKA establishment happened within 90 seconds
        assert not wait_until(90, 1, 12, check_mka_establishment)

        # Teardown
        disable_macsec_port(duthost, port_name)
        disable_macsec_port(nbr["host"], nbr["port"])
        delete_macsec_profile(nbr["host"], profile_name)
