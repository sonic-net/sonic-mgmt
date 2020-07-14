import re
import copy
import time
import random

import pytest

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import POOL_RANGE_START_PORT
from nat_helpers import GLOBAL_UDP_NAPT_TIMEOUT
from nat_helpers import POOL_RANGE_END_PORT
from nat_helpers import check_rule_by_traffic
from nat_helpers import configure_dynamic_nat_rule
from nat_helpers import wait_timeout
from nat_helpers import get_dst_ip
from nat_helpers import get_src_ip
from nat_helpers import get_dst_port
from nat_helpers import get_src_port
from nat_helpers import expected_mask_nated_packet
from nat_helpers import set_l4_default_ports
from nat_helpers import exec_command
from nat_helpers import get_public_ip
from nat_helpers import nat_statistics
from nat_helpers import nat_translations
from nat_helpers import dut_interface_control
from nat_helpers import dut_nat_iptables_status
from nat_helpers import nat_zones_config
import ptf.testutils as testutils
from common.helpers.assertions import pytest_assert


class TestDynamicNat(object):
    """ TestDynamicNat class for testing dynamic nat """

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                               protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True,
                                   remove_bindings=False)
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction,
                                  interface_type, protocol_type, icmp_id=POOL_RANGE_START_PORT,
                                  negative=False, handshake=True, nat_type='dynamic', default=True)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_entry_persist(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                       protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Configure Dynamic NAT rules
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # Check if NAT entry stays persist due TCP/UDP timeout
        handshake = True
        for attempt in range(0, 4):
            if attempt == 1:
                handshake = False
            for direction in DIRECTION_PARAMS:
                if protocol_type == 'ICMP' and direction == 'leaf-tor':
                    continue
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                      protocol_type, icmp_id=POOL_RANGE_START_PORT, handshake=handshake,
                                      nat_type='dynamic', default=True)
            # Wait some time and send packet again
            wait = random.randint(1, GLOBAL_UDP_NAPT_TIMEOUT / 2)
            wait_timeout(protocol_type, wait_time=wait, default=False)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_disable_nat(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                     protocol_type, enable_nat_config):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Configure Dynamic NAT rules
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # Disable NAT feature
        duthost.command("config nat feature disable")
        # Send traffic and check that NAT does not happen
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                  protocol_type, exp_source_port=POOL_RANGE_START_PORT, icmp_id=POOL_RANGE_START_PORT,
                                  handshake=True, nat_type='dynamic', default=True, negative=True)
        # Enable NAT feature and send traffic to check that NAT happens
        duthost.command("config nat feature enable")
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction,
                                  interface_type, protocol_type, icmp_id=POOL_RANGE_START_PORT,
                                  negative=False, handshake=True, nat_type='dynamic', default=True)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_other_protocols(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # Create packet
        outer_ports = get_dst_port(setup_data, direction, interface_type)
        inner_ports = get_src_port(setup_data, direction, interface_type)
        # Set MAC addresses for packets to send
        eth_dst = setup_data['router_mac']
        eth_src = ptfadapter.dataplane.get_mac(0, inner_ports[0])
        # Set source and destination IPs for packets to send
        ip_src = get_src_ip(setup_data, direction, interface_type)
        ip_dst = get_dst_ip(setup_data, direction, interface_type)
        pkt = testutils.simple_gre_packet(eth_dst=eth_dst, eth_src=eth_src, ip_src=ip_src, ip_dst=ip_dst)
        exp_pkt = expected_mask_nated_packet(pkt, setup_data, interface_type, direction, "gre",
                                             exp_src_ip=ip_src, exp_dst_ip=ip_dst)
        # Check that packet was forwarded and not NAT
        testutils.send(ptfadapter, inner_ports[0], pkt, count=5)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=outer_ports)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_acl_rule_actions(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                          protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, acl_rules=acl_rules, default=True)
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                  protocol_type, exp_source_port=POOL_RANGE_START_PORT, icmp_id=POOL_RANGE_START_PORT,
                                  handshake=True, nat_type='dynamic', default=True, negative=True, action='do_not_nat')
        # Change rules ACL rule from "do_not_nat" to "forward" and check that NAT traffic was NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "forward"}]
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, acl_rules=acl_rules, default=True)
        # Verify the behaviour when the ACL binding action changed from "do_not_nat" to "forward"
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                  protocol_type, icmp_id=POOL_RANGE_START_PORT, handshake=True, nat_type='dynamic',
                                  default=True)
        # Change rules ACL rule from "forward" to "do_not_nat" and check that NAT traffic was not NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, acl_rules=acl_rules, default=True)
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                  protocol_type, exp_source_port=POOL_RANGE_START_PORT, icmp_id=POOL_RANGE_START_PORT,
                                  nat_type='dynamic', default=True, negative=True, action='do_not_nat')

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_acl_modify_rule(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                         protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                  protocol_type, icmp_id=POOL_RANGE_START_PORT, handshake=True, nat_type='dynamic',
                                  default=True)
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = "172.20.0.0/24"
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, acl_rules=acl_rules, default=True)
        # Send traffic from 172.20.0.0 subnet and verify that it was not NAT
        packet_source_ip = "172.20.19.2"
        # Check that packet is L3 forwarded after rule was chenged from forward to do_not_nat
        source_l4_port, dest_l4_port = set_l4_default_ports(protocol_type)
        check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, 'host-tor', interface_type,
                              protocol_type, ip_src=packet_source_ip, exp_src_ip=packet_source_ip,
                              source_l4_port=source_l4_port, dest_l4_port=dest_l4_port,
                              exp_source_port=source_l4_port,
                              exp_dst_port=dest_l4_port, icmp_id=POOL_RANGE_START_PORT,
                              negative=True if protocol_type == "ICMP" else False)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_enable_disable_nat_docker(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                                   protocol_type, enable_nat_docker):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # Check that NAT entries are present in iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        pattern = r"SNAT.*({0}:{1} fullcone)"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                             format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 3, "IP Tables rules were not created")
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type,
                                  protocol_type, icmp_id=POOL_RANGE_START_PORT, handshake=True, nat_type='dynamic',
                                  default=True)
        # Disable NAT docker
        exec_command(duthost, ["sudo docker stop nat"])
        # Check that NAT rules were removed from iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                             format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 0, "IP Tables rules were not removed")
        # Enable NAT docker
        exec_command(duthost, ["sudo docker start nat"])
        wait_timeout(protocol_type, wait_time=5, default=False)
        # Check that NAT rules were added to iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                             format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 3, "IP Tables rules were not added after enabled NAT docker")

    @pytest.mark.nat_dynamic
    def test_nat_clear_translations_dynamic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                            protocol_type_no_icmp):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # make sure static NAT translations don't exist
        cleared_translations = nat_translations(duthost, show=True)
        pytest_assert(not cleared_translations,
                      "Unexpected NAT translations output")
        # Traffic send and check
        check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type, protocol_type_no_icmp,
                              icmp_id=POOL_RANGE_START_PORT, handshake=True, nat_type='dynamic', default=True)
        source_l4_port, _ = set_l4_default_ports(protocol_type_no_icmp)
        nat_translated_source_ip = setup_data[interface_type]["public_ip"]
        nat_source_ip = setup_data[interface_type]["src_ip"]
        nat_source = "{}:{}".format(setup_data[interface_type]["src_ip"], source_l4_port)
        nat_translated_destination = nat_source
        nat_destination_ip = nat_translated_source_ip
        # make sure static NAT translations exist
        translations = nat_translations(duthost, show=True)
        for entry in translations:
            if nat_source_ip in entry:
                pytest_assert(nat_translated_source_ip in translations[entry]["Translated Source"],
                              "Unexpected source translation rule for {}: {}".format(entry, translations[entry]))
                pytest_assert(nat_source == translations[entry]["Source"],
                              "Unexpected source translation rule for {}: {}".format(entry, translations[entry]))
                translated_port = int(re.search(r'[0-9]{1,6}$', translations[entry]["Translated Source"]).group())
                pytest_assert(translated_port >= POOL_RANGE_START_PORT + 1,
                              "Unexpected translated l4 port in rule {}: {}".format(entry, translations[entry]))
            elif nat_destination_ip in entry:
                pytest_assert(nat_translated_destination == translations[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}: {}".format(entry, translations[entry]))
                pytest_assert(nat_destination_ip in translations[entry]["Destination"],
                              "Unexpected destination translation rule for {}: {}".format(entry, translations[entry]))
                translated_port = int(re.search(r'[0-9]{1,6}$', translations[entry]["Destination"]).group())
                pytest_assert(translated_port >= POOL_RANGE_START_PORT + 1,
                              "Unexpected translated l4 port in rule {}: {}".format(entry, translations[entry]))
            else:
                pytest_assert(False,
                              "Unexpected translation rule for {}: {}".format(entry, translations[entry]))
        # clear translations
        nat_translations(duthost, clear=True)
        # make sure static NAT translations don't exist
        cleared_translations = nat_translations(duthost, show=True)
        pytest_assert(not cleared_translations, "Unexpected NAT translations output")
        # wait for counters update
        time.sleep(5)
        # make sure NAT counters exist and have incremented
        nat_counters = nat_statistics(duthost, show=True)
        pytest_assert(not nat_counters, "Unexpected empty NAT counters output")

    @pytest.mark.nat_dynamic
    def test_nat_interfaces_flap_dynamic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                         protocol_type, enable_outer_interfaces):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True)
        # Traffic send and check
        check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type, protocol_type,
                              icmp_id=POOL_RANGE_START_PORT, handshake=True, nat_type='dynamic', default=True)
        # Disable outer interface
        ifname_to_disable = setup_data[interface_type]["outer_zone_interfaces"][0]
        dut_interface_control(duthost, "disable", setup_data["config_portchannels"][ifname_to_disable]['members'][0])
        # make sure trasnlations are not expired
        source_l4_port, _ = set_l4_default_ports(protocol_type)
        nat_translated_source_ip = setup_data[interface_type]["public_ip"]
        nat_source_ip = setup_data[interface_type]["src_ip"]
        nat_source = "{}:{}".format(setup_data[interface_type]["src_ip"], source_l4_port)
        nat_translated_destination = nat_source
        nat_destination_ip = nat_translated_source_ip
        # make sure static NAT translations exist
        translations = nat_translations(duthost, show=True)
        for entry in translations:
            if nat_source_ip in entry:
                pytest_assert(nat_translated_source_ip in translations[entry]["Translated Source"],
                              "Unexpected source translation rule for {}: {}".format(entry, translations[entry]))
                pytest_assert(nat_source == translations[entry]["Source"],
                              "Unexpected source translation rule for {}: {}".format(entry, translations[entry]))
                translated_port = int(re.search(r'[0-9]{1,6}$', translations[entry]["Translated Source"]).group())
                pytest_assert(translated_port >= POOL_RANGE_START_PORT + 1,
                              "Unexpected translated l4 port in rule {}: {}".format(entry, translations[entry]))
            elif nat_destination_ip in entry:
                pytest_assert(nat_translated_destination == translations[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}: {}".format(entry, translations[entry]))
                pytest_assert(nat_destination_ip in translations[entry]["Destination"],
                              "Unexpected destination translation rule for {}: {}".format(entry, translations[entry]))
                translated_port = int(re.search(r'[0-9]{1,6}$', translations[entry]["Destination"]).group())
                pytest_assert(translated_port >= POOL_RANGE_START_PORT + 1,
                              "Unexpected translated l4 port in rule {}: {}".format(entry, translations[entry]))
            else:
                pytest_assert(False,
                              "Unexpected translation rule for {}: {}".format(entry, translations[entry]))
        # make sure iptables rules are not expired
        portrange = "{}-{}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        public_ip = setup_data[interface_type]["public_ip"]
        iptables_ouput = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                          "postrouting": [
                              "SNAT tcp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{} fullcone".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT udp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{} fullcone".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT icmp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{} fullcone".format(acl_subnet, public_ip,
                                                                                                  portrange)]
                          }
        pytest_assert(iptables_rules == iptables_ouput,
                      "Unexpected iptables output for nat table")
        # Enable outer interface
        dut_interface_control(duthost, "enable", setup_data["config_portchannels"][ifname_to_disable]['members'][0])
        # Traffic send and check
        check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction, interface_type, protocol_type,
                              icmp_id=POOL_RANGE_START_PORT, nat_type='dynamic', default=True)

    @pytest.mark.nat_dynamic
    @pytest.mark.parametrize("zone_type", [0, 1])
    def test_nat_dynamic_zones(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                               protocol_type, zone_type):
        # Prepare configuration for NAT zones modify test
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = zone_type
        # Check dynamic NAT when all NAT interfaces zones are corect
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, default=True,
                                   remove_bindings=False)
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction,
                                  interface_type, protocol_type, icmp_id=POOL_RANGE_START_PORT,
                                  negative=False, handshake=True, nat_type='dynamic', default=True)
        # Check dynamic NAT when all NAT interfaces zones are 0
        nat_zones_config(duthost, setup_info_negative_zones, interface_type)
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_info_negative_zones, direction,
                                  interface_type, protocol_type, icmp_id=POOL_RANGE_START_PORT,
                                  negative=True, handshake=False, nat_type='dynamic')
        # Check dynamic NAT when all NAT interfaces zones are corect
        nat_zones_config(duthost, setup_data, interface_type)
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, direction,
                                  interface_type, protocol_type, icmp_id=POOL_RANGE_START_PORT,
                                  negative=False, handshake=True, nat_type='dynamic', default=True)
