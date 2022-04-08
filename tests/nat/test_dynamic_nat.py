import re
import copy
import time
import random

import pytest

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import POOL_RANGE_START_PORT
from nat_helpers import GLOBAL_UDP_NAPT_TIMEOUT
from nat_helpers import GLOBAL_TCP_NAPT_TIMEOUT
from nat_helpers import POOL_RANGE_END_PORT
from nat_helpers import TCP_GLOBAL_PORT
from nat_helpers import configure_dynamic_nat_rule
from nat_helpers import get_dynamic_l4_ports
from nat_helpers import wait_timeout
from nat_helpers import get_dst_ip
from nat_helpers import get_src_ip
from nat_helpers import get_dst_port
from nat_helpers import get_src_port
from nat_helpers import expected_mask_nated_packet
from nat_helpers import get_l4_default_ports
from nat_helpers import exec_command
from nat_helpers import get_public_ip
from nat_helpers import nat_statistics
from nat_helpers import nat_translations
from nat_helpers import dut_interface_control
from nat_helpers import dut_nat_iptables_status
from nat_helpers import nat_zones_config
from nat_helpers import perform_handshake
from nat_helpers import get_network_data
from nat_helpers import generate_and_verify_traffic
from nat_helpers import generate_and_verify_icmp_traffic
from nat_helpers import generate_and_verify_not_translated_traffic
from nat_helpers import generate_and_verify_not_translated_icmp_traffic
from nat_helpers import generate_and_verify_traffic_dropped
from nat_helpers import get_cli_show_nat_config_output
from nat_helpers import write_json
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0')
]

class TestDynamicNat(object):
    """ TestDynamicNat class for testing dynamic nat """

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_basic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                               protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_basic_icmp(self, tbinfo, duthost, ptfadapter, ptfhost, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=POOL_RANGE_START_PORT)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_entry_persist(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                       protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for _ in range(0, 4):
            for path in DIRECTION_PARAMS:
                generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
            # Wait some time and send packet again
            wait = random.randint(1, GLOBAL_UDP_NAPT_TIMEOUT / 2)
            wait_timeout(protocol_type, wait_time=wait, default=False)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_entry_persist_icmp(self, tbinfo, ptfhost, duthost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        for _ in range(0, 4):
            generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type=nat_type, icmp_id=POOL_RANGE_START_PORT)
            wait_timeout(protocol_type, wait_time=15, default=False)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_disable_nat(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                     protocol_type, enable_nat_feature):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_info, interface_type, protocol_type, default=True,
                                   remove_bindings=False, handshake=True)
        # Disable NAT feature
        duthost.command("config nat feature disable")
        # Send traffic and check that traffic was L3 forwarded
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)
        # Enable NAT feature and send traffic to check that NAT happens
        duthost.command("config nat feature enable")
        # Perform TCP handshake (host-tor -> leaf-tor)
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_disable_nat_icmp(self, tbinfo, duthost, ptfadapter, ptfhost, setup_test_env, enable_nat_feature):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True)
        # Disable NAT feature
        duthost.command("config nat feature disable")
        # Send ICMP traffic and check that NAT does not happen
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type=nat_type)
        # Enable NAT feature and send traffic to check that NAT happens
        duthost.command("config nat feature enable")
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type=nat_type, icmp_id=POOL_RANGE_START_PORT)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_bindings(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                  protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Configure default rules for Dynamic NAT, but change pool configuration
        pool = "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_START_PORT + 1)
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, port_range=pool, default=True, remove_bindings=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        generate_and_verify_traffic_dropped(ptfadapter, setup_info, interface_type, 'leaf-tor', protocol_type, nat_type,
                                            src_port=dst_port, dst_port=POOL_RANGE_START_PORT, exp_src_port=dst_port, exp_dst_port=src_port)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, 'host-tor', protocol_type, nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_bindings_icmp(self, tbinfo, duthost, ptfadapter, ptfhost, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, remove_bindings=True)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_info, interface_type, direction, nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_other_protocols(self, tbinfo, ptfhost, duthost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type="GRE", default=True)
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
        exp_pkt = expected_mask_nated_packet(pkt, "gre", ip_dst=ip_dst, ip_src=ip_src)
        # Check that packet was forwarded and not NAT
        testutils.send(ptfadapter, inner_ports[0], pkt, count=5)
        testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=outer_ports)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_acl_rule_actions(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                          protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        direction = 'host-tor'
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, acl_rules=acl_rules, handshake=True)
        # Send traffic and check that NAT does not happen
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)
        # Change rules ACL rule from "do_not_nat" to "forward" and check that NAT traffic was NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "forward"}]
        # Configure rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, acl_rules=acl_rules, handshake=True)
        # Verify the behaviour when the ACL binding action changed from "do_not_nat" to "forward"
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Change rules ACL rule from "forward" to "do_not_nat" and check that NAT traffic was not NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True,
                                   remove_bindings=False, acl_rules=acl_rules, handshake=True)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_acl_rule_actions_icmp(self, tbinfo, duthost, ptfhost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True)
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, acl_rules=acl_rules, default=True)
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_info, interface_type, direction, nat_type)
        # Change rules ACL rule from "do_not_nat" to "forward" and check that NAT traffic was NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "forward"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, acl_rules=acl_rules, default=True)
        # Verify the behaviour when the ACL binding action changed from "do_not_nat" to "forward"
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type=nat_type, icmp_id=POOL_RANGE_START_PORT)
        # Change rules ACL rule from "forward" to "do_not_nat" and check that NAT traffic was not NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, acl_rules=acl_rules, default=True)
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_acl_modify_rule(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                         protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = "172.20.0.0/24"
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, acl_rules=acl_rules, default=True, handshake=True)
        # Send traffic from 172.20.0.0 subnet and verify that it was not NAT
        packet_source_ip = "172.20.0.2"
        # Check that packet is L3 forwarded after rule was chenged from forward to do_not_nat
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type,
                                                   ip_src=packet_source_ip, exp_ip_src=packet_source_ip)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_acl_modify_rule_icmp(self, tbinfo, duthost, ptfhost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = "ICMP"
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, remove_bindings=False)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=POOL_RANGE_START_PORT)
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = "172.20.0.0/24"
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, acl_rules=acl_rules, default=True)
        # Send traffic from 172.20.0.0 subnet and verify that it was not NAT
        packet_source_ip = "172.20.19.2"
        # Check that packet is L3 forwarded after rule was chenged from forward to do_not_nat
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, ip_src=packet_source_ip, check_reply=False)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_pool_threshold(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                        protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Configure default rules for Dynamic NAT, but change pool configuration
        pool = "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_START_PORT + 1)
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, port_range=pool, default=True, handshake=True)
        # Define dynamic source port for expected packet
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        l4_ports = get_dynamic_l4_ports(duthost, protocol_type, direction, network_data.public_ip)
        if l4_ports.exp_src_port != POOL_RANGE_START_PORT:
            first_exp_src_port = POOL_RANGE_START_PORT + 1
            second_exp_src_port = POOL_RANGE_START_PORT
        else:
            first_exp_src_port = POOL_RANGE_START_PORT
            second_exp_src_port = POOL_RANGE_START_PORT + 1
        # Send traffic with different source L4 port and check that first two packets were NAT and 3-d one was dropped
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        # Check first translation entry
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type,
                                    src_port=src_port, dst_port=TCP_GLOBAL_PORT, exp_src_port=first_exp_src_port, exp_dst_port=TCP_GLOBAL_PORT)
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'leaf-tor', protocol_type, nat_type=nat_type,
                                    src_port=TCP_GLOBAL_PORT, dst_port=first_exp_src_port, exp_src_port=TCP_GLOBAL_PORT, exp_dst_port=src_port)
        # Check second translation entry
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port + 1,
                          network_data.public_ip)
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type,
                                    src_port=src_port + 1, dst_port=TCP_GLOBAL_PORT, exp_src_port=second_exp_src_port, exp_dst_port=TCP_GLOBAL_PORT)
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'leaf-tor', protocol_type, nat_type=nat_type,
                                    src_port=TCP_GLOBAL_PORT, dst_port=second_exp_src_port, exp_src_port=TCP_GLOBAL_PORT, exp_dst_port=src_port + 1)
        # Check that third translation entry was not created and packets are dropped
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port + 2,
                          network_data.public_ip)
        translation_rules = nat_translations(duthost, show=True)
        for entry in translation_rules:
            if network_data.ip_src in entry:
                translated_port = int(re.search(r'[0-9]{1,6}$', translation_rules[entry]["Source"]).group())
                pytest_assert(translated_port != src_port + 2,
                              "Unexpected translated l4 port in rule {}: {}".format(entry, translation_rules[entry]))
        generate_and_verify_traffic_dropped(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type,
                                            src_port=src_port + 2, dst_port=TCP_GLOBAL_PORT, exp_src_port=first_exp_src_port, exp_dst_port=TCP_GLOBAL_PORT)
        generate_and_verify_traffic_dropped(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type,
                                            src_port=src_port + 2, dst_port=TCP_GLOBAL_PORT, exp_src_port=second_exp_src_port, exp_dst_port=TCP_GLOBAL_PORT)
        # Wait until entry expired
        wait_timeout(protocol_type)
        # Check that NAT entries were deleted
        translation_rules = nat_translations(duthost, show=True)
        pytest_assert(not translation_rules,
                      "Unexpected NAT translations output")
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port + 2,
                          network_data.public_ip)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        # Check new translation entry
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type,
                                    src_port=src_port + 2, dst_port=TCP_GLOBAL_PORT, exp_src_port=first_exp_src_port, exp_dst_port=TCP_GLOBAL_PORT)
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'leaf-tor', protocol_type, nat_type=nat_type,
                                    src_port=TCP_GLOBAL_PORT, dst_port=first_exp_src_port, exp_src_port=TCP_GLOBAL_PORT, exp_dst_port=src_port + 2)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_crud(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                              protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Change NAT pool range and name
        start_port, end_port = 6000, 6500
        port_range = "{0}-{1}".format(start_port, end_port)
        # Configure rules with new port range for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, port_range=port_range, default=True)
        wait_timeout(protocol_type)
        # Check that new pool configuration was applied to NAT
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Get rules and check than new entry was added with new port range
        output = exec_command(duthost, ["show nat translation"])['stdout']
        # Find expected source port
        pattern = r"tcp.+{}:(\d+)" if protocol_type == "TCP" else r"udp.+{}:(\d+)"
        exp_source_port = sorted(re.search(pattern.format(get_public_ip(setup_data, interface_type)), output).
                                 groups())[-1]
        pytest_assert(start_port <= int(exp_source_port) <= end_port, "New entry was not added with l4 port from new port range")
        # Delete NAT rules
        wait_timeout(protocol_type, default=True)
        # Check that NAT entries were deleted
        translation_rules = nat_translations(duthost, show=True)
        pytest_assert(not translation_rules,
                      "Unexpected NAT translations output")

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_crud_icmp(self, tbinfo, duthost, ptfhost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=POOL_RANGE_START_PORT)
        # Change NAT pool range and name
        start_port, end_port = 6000, 7000
        port_range = "{0}-{1}".format(start_port, end_port)
        # Configure rules with new port range for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, port_range=port_range, default=True)
        wait_timeout(protocol_type)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=start_port)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_full_cone(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                   protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Configure rules with port range what will be including source port for protocols
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, port_range="100-5000", default=True, handshake=True)
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type,
                                    dst_port=dst_port, exp_dst_port=dst_port)
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, 'leaf-tor', protocol_type, nat_type=nat_type,
                                    src_port=dst_port, exp_dst_port=src_port, exp_src_port=dst_port)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_enable_disable_nat_docker(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                                   protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True,
                                   handshake=True)
        # Check that NAT entries are present in iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        pattern = r"SNAT.*({0}:{1})"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type),
                                            "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 3, "IP Tables rules were not created")
        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Disable NAT docker
        exec_command(duthost, ["sudo docker stop nat"])
        # Check that NAT rules were removed from iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type),
                                            "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 0, "IP Tables rules were not removed")
        # Enable NAT docker
        exec_command(duthost, ["sudo docker start nat"])
        wait_timeout(protocol_type, wait_time=5, default=False)
        # Check that NAT rules were added to iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type),
                                            "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 3, "IP Tables rules were not added after enabled NAT docker")

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_enable_disable_nat_docker_icmp(self, tbinfo, duthost, ptfhost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        protocol_type = 'ICMP'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Check that NAT entries are present in iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        pattern = r"SNAT.*({0}:{1})"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type),
                                            "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 3, "IP Tables rules were not created")
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=POOL_RANGE_START_PORT)
        # Disable NAT docker
        exec_command(duthost, ["sudo docker stop nat"])
        # Check that NAT rules were removed from iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type),
                                            "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 0, "IP Tables rules were not removed")
        # Enable NAT docker
        exec_command(duthost, ["sudo docker start nat"])
        wait_timeout(protocol_type, wait_time=5, default=False)
        # Check that NAT rules were added to iptables
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type),
                                            "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 3, "IP Tables rules were not added after enabled NAT docker")

    @pytest.mark.nat_dynamic
    def test_nat_clear_statistics_dynamic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                          protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        # Traffic send and check
        cleared_counters = nat_statistics(duthost, show=True)
        # make sure NAT counters do not exist
        pytest_assert(not cleared_counters,
                      "Unexpected NAT counters output")
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # wait for counters update
        time.sleep(5)
        # make sure NAT counters have incremented
        nat_counters = nat_statistics(duthost, show=True)
        pytest_assert(nat_counters,
                      "Unexpected empty NAT counters output")
        for entry in nat_counters:
            pytest_assert(int(nat_counters[entry]["Packets"]) > 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(nat_counters[entry]["Packets"]))
            pytest_assert(int(nat_counters[entry]["Bytes"]) > 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(nat_counters[entry]["Bytes"]))
        # Clear NAT counters
        nat_statistics(duthost, clear=True)
        # wait for counters update
        time.sleep(5)
        # make sure NAT counters have cleared
        cleared_counters = nat_statistics(duthost, show=True)
        pytest_assert(cleared_counters,
                      "Unexpected empty NAT counters output")
        for entry in cleared_counters:
            pytest_assert(int(cleared_counters[entry]["Packets"]) == 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(cleared_counters[entry]["Packets"]))
            pytest_assert(int(cleared_counters[entry]["Bytes"]) == 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(cleared_counters[entry]["Bytes"]))

    @pytest.mark.nat_dynamic
    def test_nat_clear_translations_dynamic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                            protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        # make sure static NAT translations don't exist
        cleared_translations = nat_translations(duthost, show=True)
        pytest_assert(not cleared_translations,
                      "Unexpected NAT translations output")
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send traffic
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        source_l4_port, _ = get_l4_default_ports(protocol_type)
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
    def test_nat_interfaces_flap_dynamic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                         protocol_type, enable_outer_interfaces):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send traffic
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Disable outer interface
        ifname_to_disable = setup_data[interface_type]["outer_zone_interfaces"][0]
        dut_interface_control(duthost, "disable", setup_data["config_portchannels"][ifname_to_disable]['members'][0])
        # make sure trasnlations are not expired
        source_l4_port, _ = get_l4_default_ports(protocol_type)
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
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": [
                              "SNAT tcp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT udp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT icmp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                  portrange)]
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Enable outer interface
        dut_interface_control(duthost, "enable", setup_data["config_portchannels"][ifname_to_disable]['members'][0])
        # Send traffic
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_zones(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                               protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = 1
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Send traffic
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Check dynamic NAT when all NAT interfaces zones are 0
        nat_zones_config(duthost, setup_info_negative_zones, interface_type)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)
        # Check dynamic NAT when all NAT interfaces zones are corect
        nat_zones_config(duthost, setup_data, interface_type)
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send traffic
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_zones_icmp(self, tbinfo, duthost, ptfhost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = 1
        direction = 'host-tor'
        nat_type = 'dynamic'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, "ICMP", default=True)
        # Send ICMP traffic(host-tor -> leaf-tor) and check
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=POOL_RANGE_START_PORT)
        # Check dynamic NAT when all NAT interfaces zones are 0
        nat_zones_config(duthost, setup_info_negative_zones, interface_type)
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type)
        # Check dynamic NAT when all NAT interfaces zones are corect
        nat_zones_config(duthost, setup_data, interface_type)
        generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type, icmp_id=POOL_RANGE_START_PORT)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_extremal_ports(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        # L4 ports to be examined
        ex_ports = [7, 23, 65535]
        # Port 22 is used by ssh daemon for tcp
        if protocol_type == 'udp':
            ex_ports.append(22)
        exp_entries = len(ex_ports) + 1
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Perform series of TCP handshakes (host-tor -> leaf-tor)
        source_port, dst_port = get_l4_default_ports(protocol_type)
        for src_port in ex_ports:
            perform_handshake(ptfhost, setup_data, protocol_type, direction,
                              network_data.ip_dst, dst_port,
                              network_data.ip_src, src_port,
                              network_data.public_ip)
        # Checking numbers
        output = exec_command(duthost, ['show nat translations | grep DNAPT'])['stdout']
        entries_no = [int(s) for s in output.split() if s.isdigit()]
        fail_msg = "Unexpected number of translations. Got {} while {} expected".format(entries_no[0], exp_entries)
        pytest_assert(exp_entries == entries_no[0], fail_msg)
        duthost.command("sudo sonic-clear nat translations")

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_single_host(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        n_c = 10
        dst_port = get_l4_default_ports(protocol_type)[1]
        scale_range = [dst_port, dst_port + n_c]
        p_range_conf = "{}-{}".format(scale_range[0], scale_range[1])
        exp_entries = scale_range[1] - scale_range[0] + 1
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, port_range=p_range_conf, default=True, handshake=True)
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set timeouts to max
        duthost.command('sudo config nat set tcp-timeout 432000')
        duthost.command('sudo config nat set udp-timeout 600')
        # Perform series of TCP handshakes (host-tor -> leaf-tor)
        for src_port in range(scale_range[0], scale_range[1]):
            perform_handshake(ptfhost, setup_data, protocol_type, direction,
                              network_data.ip_dst, dst_port,
                              network_data.ip_src, src_port,
                              network_data.public_ip)
        # Checking numbers
        output = exec_command(duthost, ['show nat translations | grep DNAPT'])['stdout']
        entries_no = [int(s) for s in output.split() if s.isdigit()]
        fail_msg = "Unexpected number of translations. Got {} while {} expected".format(entries_no[0], exp_entries)
        pytest_assert(exp_entries == entries_no[0], fail_msg)
        # Restore default config
        duthost.command('sudo config nat set tcp-timeout {}'.format(GLOBAL_TCP_NAPT_TIMEOUT))
        duthost.command('sudo config nat set udp-timeout {}'.format(GLOBAL_UDP_NAPT_TIMEOUT))
        duthost.command("sudo sonic-clear nat translations")

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_binding_remove(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                        protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_info, interface_type, protocol_type, default=True, handshake=True)
        # Confirm that binding is added
        output = get_cli_show_nat_config_output(duthost, "bindings")
        nat_pools_dump = get_cli_show_nat_config_output(duthost, "pool")
        pattern = r"test_binding"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                                            format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output[0]['binding name'])
        pytest_assert(len(entries) == 1, "Binding has not been added properly, binding count: {} \n {} ; {}".format(len(entries),
                                                                                                                    output[0]['binding name'],
                                                                                                                    nat_pools_dump[0]['pool name']))
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Check that NAT entries are present in iptables after adding
        portrange = "{}-{}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        public_ip = setup_data[interface_type]["public_ip"]
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": [
                              "SNAT tcp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT udp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT icmp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                  portrange)]
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Delete NAT bindings
        exec_command(duthost, ["config nat remove bindings"])
        # Confirm that binding has been removed
        output = exec_command(duthost, ["show nat config bindings"])['stdout']
        nat_pools_dump = get_cli_show_nat_config_output(duthost, "pool")
        pattern = r"test_binding"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                                            format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 0, "Binding has not been deleted properly, binding count: {} \n {} ; {}".format(len(entries),
                                                                                                                      output,
                                                                                                                      nat_pools_dump[0]['pool name']))
        # Send TCP/UDP traffic and check
        wait_timeout(protocol_type)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)
        # Check that NAT entries are not present in iptables after removing binding
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_iptable_snat(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                      protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_info, interface_type, protocol_type, default=True, handshake=True)
        # Confirm that pool is added
        output = get_cli_show_nat_config_output(duthost, "pool")
        nat_bindings_dump = get_cli_show_nat_config_output(duthost, "bindings")
        pattern = r"pool"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                                            format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output[0]['pool name'])
        pytest_assert(len(entries) == 1, "Pool has not been added properly, pool count: {} \n {} ; {}".format(len(entries),
                                                                                                              output[0]['pool name'],
                                                                                                              nat_bindings_dump[0]['binding name']))
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Check that IP table rules are programmed as SNAT rules for TCP/UDP/ICMP IP protocol type
        output = exec_command(duthost, ["iptables -n -L -t nat"])['stdout']
        pattern = r"SNAT.*tcp.*\n.*SNAT.*udp.*\n.*SNAT.*icmp"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                                            format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        nat_pools_dump = get_cli_show_nat_config_output(duthost, "pool")
        nat_bindings_dump = get_cli_show_nat_config_output(duthost, "bindings")
        nat_translations_dump = nat_translations(duthost, show=True)
        pytest_assert(len(entries) == 1, "IP Tables rules are not properly programmed: {} \n {} \n {} \n {} \n {}".format(len(entries),
                                                                                                                          output,
                                                                                                                          nat_pools_dump[0]['pool name'],
                                                                                                                          nat_bindings_dump[0]['binding name'],
                                                                                                                          nat_translations_dump))

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_outside_interface_delete(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                                  protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        direction = 'host-tor'
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_info, interface_type, protocol_type, default=True, handshake=True)

        # Confirm that pool is added
        output = get_cli_show_nat_config_output(duthost, "pool")
        nat_bindings_dump = get_cli_show_nat_config_output(duthost, "bindings")
        pattern = r"pool"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                                            format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output[0]['pool name'])
        pytest_assert(len(entries) == 1, "Pool has not been added properly, pool count: {} \n {} ; {}".format(len(entries),
                                                                                                              output[0]['pool name'],
                                                                                                              nat_bindings_dump[0]['binding name']))
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Check that NAT entries are present in iptables after adding
        portrange = "{}-{}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        public_ip = setup_data[interface_type]["public_ip"]
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {
            "prerouting": [
                'DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
            "postrouting": [
                "SNAT tcp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip, portrange),
                "SNAT udp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip, portrange),
                "SNAT icmp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip, portrange)]
            }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Remove outside interface IP
        interface_ip = "{} {}/{}".format(setup_data[interface_type]["vrf_conf"]["red"]["dut_iface"],
                                         setup_data[interface_type]["vrf_conf"]["red"]["gw"],
                                         setup_data[interface_type]["vrf_conf"]["red"]["mask"])
        ifname_to_disable = setup_data[interface_type]["outer_zone_interfaces"][0]
        dut_interface_control(duthost, "ip remove", setup_data["config_portchannels"][ifname_to_disable]['members'][0], interface_ip)
        # Check that NAT entries are not present in iptables after removing interface IP
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Restore previous configuration
        dut_interface_control(duthost, "ip add", setup_data["config_portchannels"][ifname_to_disable]['members'][0], interface_ip)
        # Send TCP/UDP traffic and confirm that restoring previous configuration went well
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        perform_handshake(ptfhost, setup_info, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_nat_pools(self, tbinfo, duthost, ptfhost, ptfadapter, setup_test_env, protocol_type):
        # Prepare test environment
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Declare variables
        direction = 'host-tor'
        nat_type = 'dynamic'
        inner_interface = dict(setup_data["indices_to_ports_config"])[get_src_port(setup_info, direction, interface_type)[0]]
        port_range = "{}-{}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        public_ip = setup_data[interface_type]["public_ip"]

        # Get network informations
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)

        # Check, if iptables is empty
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))

        # Prepare and add configuration json file
        nat_session = {
            'public_ip' : public_ip,
            'port_range' : port_range,
            'inner_interface' : inner_interface,
            'acl_subnet' : acl_subnet
        }
        write_json(duthost, nat_session, 'dynamic_binding')
        # Check iptables
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": [
                              "SNAT tcp -- {} 0.0.0.0/0 mark match 0x1 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 port_range),
                              "SNAT udp -- {} 0.0.0.0/0 mark match 0x1 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 port_range),
                              "SNAT icmp -- {} 0.0.0.0/0 mark match 0x1 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                  port_range)]
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Check traffic. Zone 1 is not configured, not NAT translations expected
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)

        # Setup zones
        nat_zones_config(duthost, setup_data, interface_type)
        # Check iptables
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": [
                              "SNAT tcp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 port_range),
                              "SNAT udp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 port_range),
                              "SNAT icmp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                  port_range)]
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))

        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send traffic and check the frame
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)

        # Wait until nat translations will expire and check one more time
        wait_timeout(protocol_type)
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send traffic and check the frame
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_dynamic
    def test_nat_dynamic_modify_bindings(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                         protocol_type):

        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'dynamic'
        direction = 'host-tor'
        network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type='dynamic')
        src_port, dst_port = get_l4_default_ports(protocol_type)

        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)

        # Check iptables
        portrange = "{}-{}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)
        acl_subnet = setup_data[interface_type]["acl_subnet"]
        public_ip = setup_data[interface_type]["public_ip"]
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": [
                              "SNAT tcp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT udp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                 portrange),
                              "SNAT icmp -- {} 0.0.0.0/0 mark match 0x2 to:{}:{}".format(acl_subnet, public_ip,
                                                                                                  portrange)]
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)

        # Remove bindings
        nat_binding = get_cli_show_nat_config_output(duthost, "bindings")
        duthost.command("config nat remove bindings")
        # Check, if nat bindings is empty
        pytest_assert(len(get_cli_show_nat_config_output(duthost, "bindings")) == 0, "Nat bindings is not empty")
        # Check, if iptables is empty
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        wait_timeout(protocol_type)
        # Send TCP/UDP traffic and check without NAT
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)

        # Add the binding again
        acl_subnet = "empty"
        duthost.command("sudo config nat add binding {0} {1} {2}".format(nat_binding[0]['binding name'],
                                                                         nat_binding[0]["pool name"], acl_subnet))
        public_ip = setup_data[interface_type]["public_ip"]
        portrange = "{}-{}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1'],
                          "postrouting": [
                              "SNAT tcp -- 0.0.0.0/0 0.0.0.0/0 mark match 0x2 to:{}:{}".format(public_ip,
                                                                                                        portrange),
                              "SNAT udp -- 0.0.0.0/0 0.0.0.0/0 mark match 0x2 to:{}:{}".format(public_ip,
                                                                                                        portrange),
                              "SNAT icmp -- 0.0.0.0/0 0.0.0.0/0 mark match 0x2 to:{}:{}".format(public_ip,
                                                                                                         portrange)]
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table. \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))

        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_info, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send TCP/UDP traffic and check without NAT
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type)
