from time import sleep
import pytest
import logging
import re
import scapy.all as scapy
import ptf.testutils as testutils
from collections import Counter

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common import config_reload
from macsec_helper import *
from macsec_config_helper import *
from macsec_platform_helper import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2"),
]


class TestControlPlane():
    def test_wpa_supplicant_processes(self, duthost, ctrl_links):
        def _test_wpa_supplicant_processes():
            for port_name, nbr in ctrl_links.items():
                check_wpa_supplicant_process(duthost, port_name)
                if isinstance(nbr["host"], EosHost):
                    continue
                check_wpa_supplicant_process(nbr["host"], nbr["port"])
            return True
        assert wait_until(300, 1, 1, _test_wpa_supplicant_processes)

    def test_appl_db(self, duthost, ctrl_links, policy, cipher_suite, send_sci):
        def _test_appl_db():
            for port_name, nbr in ctrl_links.items():
                if isinstance(nbr["host"], EosHost):
                    continue
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
                # TODO: add check mka session later, now wait some time for session ready
                sleep(30)
                logging.info(
                    "Skip to check mka session due to the DUT isn't a virtual switch")
                return True
            dut_mka_session = get_mka_session(duthost)
            assert len(dut_mka_session) == len(ctrl_links)
            for port_name, nbr in ctrl_links.items():
                if isinstance(nbr["host"], EosHost):
                    assert nbr["host"].iface_macsec_ok(nbr["port"])
                    continue
                nbr_mka_session = get_mka_session(nbr["host"])
                dut_macsec_port = get_macsec_ifname(duthost, port_name)
                nbr_macsec_port = get_macsec_ifname(
                    nbr["host"], nbr["port"])
                dut_macaddress = duthost.get_dut_iface_mac(port_name)
                nbr_macaddress = nbr["host"].get_dut_iface_mac(nbr["port"])
                dut_sci = get_sci(dut_macaddress)
                nbr_sci = get_sci(nbr_macaddress)
                check_mka_session(dut_mka_session[dut_macsec_port], dut_sci,
                                  nbr_mka_session[nbr_macsec_port], nbr_sci,
                                  policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 5, 3, _test_mka_session)

    def test_rekey_by_period(self, duthost, ctrl_links, upstream_links, rekey_period):
        if rekey_period == 0:
            pytest.skip("If the rekey period is 0 which means rekey by period isn't active.")
        assert len(ctrl_links) > 0
        # Only pick one link to test
        port_name, nbr = ctrl_links.items()[0]
        _, _, _, last_dut_egress_sa_table, last_dut_ingress_sa_table = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        up_link = upstream_links[port_name]
        output = duthost.command("ping {} -w {} -q -i 0.1".format(up_link["local_ipv4_addr"], rekey_period * 2))["stdout_lines"]
        _, _, _, new_dut_egress_sa_table, new_dut_ingress_sa_table = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])
        assert last_dut_egress_sa_table != new_dut_egress_sa_table
        assert last_dut_ingress_sa_table != new_dut_ingress_sa_table
        assert float(re.search(r"([\d\.]+)% packet loss", output[-2]).group(1)) < 1.0


class TestDataPlane():
    BATCH_COUNT = 10

    def test_server_to_neighbor(self, duthost, ctrl_links, downstream_links, upstream_links, ptfadapter):
        ptfadapter.dataplane.set_qlen(TestDataPlane.BATCH_COUNT * 10)

        down_link = downstream_links.values()[0]
        dut_macaddress = duthost.get_dut_iface_mac(ctrl_links.keys()[0])

        setattr(ptfadapter, "force_reload_macsec", True)

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

            fail_message = ""
            for port_name in members:
                up_link = upstream_links[port_name]
                testutils.send_packet(
                    ptfadapter, down_link["ptf_port_id"], pkt, TestDataPlane.BATCH_COUNT)
                result = check_macsec_pkt(test=ptfadapter,
                                          ptf_port_id=up_link["ptf_port_id"],  exp_pkt=exp_pkt, timeout=3)
                if result is None:
                    return
                fail_message += result
            pytest.fail(fail_message)

    def test_dut_to_neighbor(self, duthost, ctrl_links, upstream_links):
        for up_port, up_link in upstream_links.items():
            ret = duthost.command(
                "ping -c {} {}".format(4, up_link['local_ipv4_addr']))
            assert not ret['failed']

    def test_neighbor_to_neighbor(self, duthost, ctrl_links, upstream_links, nbr_device_numbers):
        portchannels = get_portchannel(duthost).values()
        for i in range(len(portchannels)):
            assert portchannels[i]["members"]
            requester = upstream_links[portchannels[i]["members"][0]]
            # Set DUT as the gateway of requester
            if isinstance(requester["host"], EosHost):
                requester["host"].eos_config(lines=["ip route 0.0.0.0/0 {}".format(
                    requester["peer_ipv4_addr"])], module_ignore_errors=True)
            else:
                requester["host"].shell("ip route add 0.0.0.0/0 via {}".format(
                    requester["peer_ipv4_addr"]), module_ignore_errors=True)
            for j in range(i + 1, len(portchannels)):
                if portchannels[i]["members"][0] not in ctrl_links and portchannels[j]["members"][0] not in ctrl_links:
                    continue
                responser = upstream_links[portchannels[j]["members"][0]]
                # Set DUT as the gateway of responser
                if isinstance(responser["host"], EosHost):
                    responser["host"].eos_config(lines=["ip route 0.0.0.0/0 {}".format(
                        responser["peer_ipv4_addr"])], module_ignore_errors=True)
                else:
                    responser["host"].shell("ip route add 0.0.0.0/0 via {}".format(
                        responser["peer_ipv4_addr"]), module_ignore_errors=True)
                # Ping from requester to responser
                assert not requester["host"].shell(
                    "ping -c 6 -v {}".format(responser["local_ipv4_addr"]))["failed"]
                if isinstance(responser["host"], EosHost):
                    responser["host"].eos_config(lines=["no ip route 0.0.0.0/0 {}".format(
                        responser["peer_ipv4_addr"])], module_ignore_errors=True)
                else:
                    responser["host"].shell("ip route del 0.0.0.0/0 via {}".format(
                        responser["peer_ipv4_addr"]), module_ignore_errors=True)
            if isinstance(requester["host"], EosHost):
                requester["host"].eos_config(lines=["no ip route 0.0.0.0/0 {}".format(
                    requester["peer_ipv4_addr"])], module_ignore_errors=True)
            else:
                requester["host"].shell("ip route del 0.0.0.0/0 via {}".format(
                    requester["peer_ipv4_addr"]), module_ignore_errors=True)

    def test_counters(self, duthost, ctrl_links, upstream_links, rekey_period):
        if rekey_period:
            pytest.skip("Counter increase is not guaranteed in case rekey is happening")
        EGRESS_SA_COUNTERS = (
                'SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED',
                'SAI_MACSEC_SA_STAT_OUT_PKTS_ENCRYPTED',
                )
        INGRESS_SA_COUNTERS = (
                'SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED',
                'SAI_MACSEC_SA_STAT_IN_PKTS_OK',
                )
        PKT_NUM = 5
        PKT_OCTET = 1024

        # Select some one macsec link
        port_name = list(ctrl_links)[0]
        nbr_ip_addr = upstream_links[port_name]['local_ipv4_addr']
        pc = find_portchannel_from_member(port_name, get_portchannel(duthost))
        if pc:
            assert pc["status"] == "Up"
            up_ports = pc["members"]
        else:
            up_ports = [port_name]

        # Sum up start counter
        egress_start_counters = Counter()
        ingress_start_counters = Counter()
        for up_port in up_ports:
            assert up_port in ctrl_links

            asic = duthost.get_port_asic_instance(up_port)
            egress_sa_name = get_macsec_sa_name(asic, up_port, True)
            ingress_sa_name = get_macsec_sa_name(asic, up_port, False)
            if not egress_sa_name or not ingress_sa_name:
                continue

            egress_start_counters += Counter(get_macsec_counters(asic, egress_sa_name))
            ingress_start_counters += Counter(get_macsec_counters(asic, ingress_sa_name))

        # Launch traffic
        ret = duthost.command(
            "ping -c {} -s {} {}".format(PKT_NUM, PKT_OCTET, nbr_ip_addr))
        assert not ret['failed']
        sleep(10) # wait 10s for polling counters

        # Sum up end counter
        egress_end_counters = Counter()
        ingress_end_counters = Counter()
        for up_port in up_ports:
            asic = duthost.get_port_asic_instance(up_port)
            egress_sa_name = get_macsec_sa_name(asic, up_port, True)
            ingress_sa_name = get_macsec_sa_name(asic, up_port, False)
            if not egress_sa_name or not ingress_sa_name:
                continue

            egress_end_counters += Counter(get_macsec_counters(asic, egress_sa_name))
            ingress_end_counters += Counter(get_macsec_counters(asic, ingress_sa_name))

        i = 'SAI_MACSEC_SA_ATTR_CURRENT_XPN'
        assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM
        assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM

        if duthost.facts["asic_type"] == "vs":
            # vsonic only has xpn counter
            return

        for i in EGRESS_SA_COUNTERS:
            if 'OCTETS' in i:
                assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM * PKT_OCTET
            else:
                assert egress_end_counters[i] - egress_start_counters[i] >= PKT_NUM

        for i in INGRESS_SA_COUNTERS:
            if 'OCTETS' in i:
                assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM * PKT_OCTET
            else:
                assert ingress_end_counters[i] - ingress_start_counters[i] >= PKT_NUM


class TestFaultHandling():
    MKA_TIMEOUT = 6
    LACP_TIMEOUT = 90

    def test_link_flap(self, duthost, ctrl_links):
        # Only pick one link for link flap test
        assert ctrl_links
        port_name, nbr = ctrl_links.items()[0]
        nbr_eth_port = get_eth_ifname(
            nbr["host"], nbr["port"])
        _, _, _, dut_egress_sa_table_orig, dut_ingress_sa_table_orig = get_appl_db(
            duthost, port_name, nbr["host"], nbr["port"])


        # Flap < 6 seconds
        # Not working on eos neighbour
        if not isinstance(nbr["host"], EosHost):
            # Rekey may happen during the following assertions, so we need to get the SA tables again
            retry = 3
            while retry > 0:
                retry -= 1
                try:
                    nbr["host"].shell("ifconfig {} down && sleep 1 && ifconfig {} up".format(
                        nbr_eth_port, nbr_eth_port))
                    _, _, _, dut_egress_sa_table_new, dut_ingress_sa_table_new = get_appl_db(
                        duthost, port_name, nbr["host"], nbr["port"])
                    assert dut_egress_sa_table_orig == dut_egress_sa_table_new
                    assert dut_ingress_sa_table_orig == dut_ingress_sa_table_new
                    break
                except AssertionError as e:
                    if retry == 0:
                        raise e
                dut_egress_sa_table_orig, dut_ingress_sa_table_orig = dut_egress_sa_table_new, dut_ingress_sa_table_new

        # Flap > 6 seconds but < 90 seconds
        if isinstance(nbr["host"], EosHost):
            nbr["host"].shutdown(nbr_eth_port)
            sleep(TestFaultHandling.MKA_TIMEOUT)
            nbr["host"].no_shutdown(nbr_eth_port)
        else:
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
        assert wait_until(30, 5, 2, check_new_mka_session)

        # Flap > 90 seconds
        assert wait_until(12, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Up")
        if isinstance(nbr["host"], EosHost):
            nbr["host"].shutdown(nbr_eth_port)
            sleep(TestFaultHandling.LACP_TIMEOUT)
        else:
            nbr["host"].shell("ifconfig {} down && sleep {}".format(
                nbr_eth_port, TestFaultHandling.LACP_TIMEOUT))
        assert wait_until(6, 1, 0, lambda: find_portchannel_from_member(
            port_name, get_portchannel(duthost))["status"] == "Dw")

        if isinstance(nbr["host"], EosHost):
            nbr["host"].no_shutdown(nbr_eth_port)
        else:
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
        delete_macsec_profile(nbr["host"], nbr["port"], profile_name)

        # Set a wrong cak to the profile
        primary_cak = "0" * len(primary_cak)
        enable_macsec_port(duthost, port_name, profile_name)
        set_macsec_profile(nbr["host"], nbr["port"], profile_name, default_priority,
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
        delete_macsec_profile(nbr["host"], nbr["port"], profile_name)


class TestInteropProtocol():
    '''
    Macsec interop with other protocols
    '''

    def test_port_channel(self, duthost, ctrl_links):
        '''Verify lacp
        '''
        ctrl_port, _ = ctrl_links.items()[0]
        pc = find_portchannel_from_member(ctrl_port, get_portchannel(duthost))
        assert pc["status"] == "Up"

        # Remove ethernet interface <ctrl_port> from PortChannel interface <pc>
        duthost.command("sudo config portchannel member del {} {}".format(
            pc["name"], ctrl_port))
        assert wait_until(20, 1, 0, lambda: get_portchannel(
            duthost)[pc["name"]]["status"] == "Dw")

        # Add ethernet interface <ctrl_port> back to PortChannel interface <pc>
        duthost.command("sudo config portchannel member add {} {}".format(
            pc["name"], ctrl_port))
        assert wait_until(20, 1, 0, lambda: find_portchannel_from_member(
            ctrl_port, get_portchannel(duthost))["status"] == "Up")

    def test_lldp(self, duthost, ctrl_links, profile_name):
        '''Verify lldp
        '''
        LLDP_ADVERTISEMENT_INTERVAL = 30  # default interval in seconds
        LLDP_HOLD_MULTIPLIER = 4  # default multiplier number
        LLDP_TIMEOUT = LLDP_ADVERTISEMENT_INTERVAL * LLDP_HOLD_MULTIPLIER

        # select one macsec link
        for ctrl_port, nbr in ctrl_links.items():
            assert wait_until(LLDP_TIMEOUT, LLDP_ADVERTISEMENT_INTERVAL, 0,
                            lambda: nbr["name"] in get_lldp_list(duthost))

            disable_macsec_port(duthost, ctrl_port)
            disable_macsec_port(nbr["host"], nbr["port"])
            wait_until(20, 3, 0,
                lambda: not duthost.iface_macsec_ok(ctrl_port) and
                        not nbr["host"].iface_macsec_ok(nbr["port"]))
            assert wait_until(LLDP_TIMEOUT, LLDP_ADVERTISEMENT_INTERVAL, 0,
                            lambda: nbr["name"] in get_lldp_list(duthost))

            enable_macsec_port(duthost, ctrl_port, profile_name)
            enable_macsec_port(nbr["host"], nbr["port"], profile_name)
            wait_until(20, 3, 0,
                lambda: duthost.iface_macsec_ok(ctrl_port) and
                        nbr["host"].iface_macsec_ok(nbr["port"]))
            assert wait_until(1, 1, LLDP_TIMEOUT,
                            lambda: nbr["name"] in get_lldp_list(duthost))

    def test_bgp(self, duthost, ctrl_links, upstream_links, profile_name):
        '''Verify BGP neighbourship
        '''
        bgp_config = duthost.get_running_config_facts()[
            "BGP_NEIGHBOR"].values()[0]
        BGP_KEEPALIVE = int(bgp_config["keepalive"])
        BGP_HOLDTIME = int(bgp_config["holdtime"])

        def check_bgp_established(up_link):
            command = "sonic-db-cli STATE_DB HGETALL 'NEIGH_STATE_TABLE|{}'".format(
                up_link["local_ipv4_addr"])
            fact = sonic_db_cli(duthost, command)
            logger.info("bgp state {}".format(fact))
            return fact["state"] == "Established"

        # Ensure the BGP sessions have been established
        for ctrl_port in ctrl_links.keys():
            assert wait_until(30, 5, 0,
                              check_bgp_established, upstream_links[ctrl_port])

        # Check the BGP sessions are present after port macsec disabled
        for ctrl_port, nbr in ctrl_links.items():
            disable_macsec_port(duthost, ctrl_port)
            disable_macsec_port(nbr["host"], nbr["port"])
            wait_until(20, 3, 0,
                lambda: not duthost.iface_macsec_ok(ctrl_port) and
                        not nbr["host"].iface_macsec_ok(nbr["port"]))
            # BGP session should keep established even after holdtime
            assert wait_until(BGP_HOLDTIME * 2, BGP_KEEPALIVE, BGP_HOLDTIME,
                              check_bgp_established, upstream_links[ctrl_port])

        # Check the BGP sessions are present after port macsec enabled
        for ctrl_port, nbr in ctrl_links.items():
            enable_macsec_port(duthost, ctrl_port, profile_name)
            enable_macsec_port(nbr["host"], nbr["port"], profile_name)
            wait_until(20, 3, 0,
                lambda: duthost.iface_macsec_ok(ctrl_port) and
                        nbr["host"].iface_macsec_ok(nbr["port"]))
            # Wait PortChannel up, which might flap if having one port member
            wait_until(20, 5, 5, lambda: find_portchannel_from_member(
                ctrl_port, get_portchannel(duthost))["status"] == "Up")
            # BGP session should keep established even after holdtime
            assert wait_until(BGP_HOLDTIME * 2, BGP_KEEPALIVE, BGP_HOLDTIME,
                              check_bgp_established, upstream_links[ctrl_port])

    def test_snmp(self, duthost, ctrl_links, upstream_links, creds):
        '''
        Verify SNMP request/response works across interface with macsec configuration
        '''
        if duthost.is_multi_asic:
            pytest.skip("The test is for Single ASIC devices")

        for ctrl_port, nbr in ctrl_links.items():
            if isinstance(nbr["host"], EosHost):
                result = nbr["host"].eos_command(
                    commands=['show snmp community | include name'])
                community = re.search(r'Community name: (\S+)',
                                      result['stdout'][0]).groups()[0]
            else:  # vsonic neighbour
                community = creds['snmp_rocommunity']

            up_link = upstream_links[ctrl_port]
            sysDescr = ".1.3.6.1.2.1.1.1.0"
            command = "docker exec snmp snmpwalk -v 2c -c {} {} {}".format(
                community, up_link["local_ipv4_addr"], sysDescr)
            assert not duthost.command(command)["failed"]


class TestDeployment():
    def test_config_reload(self, duthost, ctrl_links, policy, cipher_suite, send_sci):
        # Save the original config file
        duthost.shell("cp /etc/sonic/config_db.json config_db.json")
        # Save the current config file
        duthost.shell("sonic-cfggen -d --print-data > /etc/sonic/config_db.json")
        config_reload(duthost)
        def _test_appl_db():
            for port_name, nbr in ctrl_links.items():
                if isinstance(nbr["host"], EosHost):
                    continue
                check_appl_db(duthost, port_name, nbr["host"],
                              nbr["port"], policy, cipher_suite, send_sci)
            return True
        assert wait_until(300, 6, 12, _test_appl_db)
        # Recover the original config file
        duthost.shell("sudo cp config_db.json /etc/sonic/config_db.json")

