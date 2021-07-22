import copy
import time
import json

import pytest

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import STATIC_NAT_TABLE_NAME
from nat_helpers import STATIC_NAPT_TABLE_NAME
from nat_helpers import REBOOT_MAP
from nat_helpers import apply_static_nat_config
from nat_helpers import check_peers_by_ping
from nat_helpers import nat_zones_config
from nat_helpers import nat_statistics
from nat_helpers import nat_translations
from nat_helpers import crud_operations_basic
from nat_helpers import crud_operations_napt
from nat_helpers import exec_command
from nat_helpers import perform_handshake
from nat_helpers import get_network_data
from nat_helpers import generate_and_verify_traffic
from nat_helpers import get_l4_default_ports
from nat_helpers import generate_and_verify_traffic_dropped
from nat_helpers import generate_and_verify_icmp_traffic
from nat_helpers import generate_and_verify_not_translated_traffic
from nat_helpers import generate_and_verify_not_translated_icmp_traffic
from nat_helpers import POOL_RANGE_START_PORT
from nat_helpers import POOL_RANGE_END_PORT
from nat_helpers import GLOBAL_NAT_TIMEOUT
from nat_helpers import GLOBAL_UDP_NAPT_TIMEOUT
from nat_helpers import GLOBAL_TCP_NAPT_TIMEOUT
from nat_helpers import get_redis_val
from nat_helpers import get_db_rules
from nat_helpers import configure_nat_over_cli
from nat_helpers import configure_dynamic_nat_rule
from nat_helpers import dut_nat_iptables_status
from nat_helpers import dut_interface_control
from nat_helpers import get_public_ip
import tests.common.reboot as common_reboot
from tests.common.helpers.assertions import pytest_assert
from tests.nat.conftest import nat_global_config


pytestmark = [
    pytest.mark.topology('t0')
]


class TestStaticNat(object):
    """ TestStaticNat class for testing static nat """

    @pytest.mark.nat_static
    def test_nat_static_basic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send bidirectional traffic and check if NAT translation happens
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Send traffic and check that NAT translation does not happen for another inner IP-address
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type, second_port=True)

    @pytest.mark.nat_static
    def test_nat_static_basic_icmp(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, nat_entry=nat_type)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, path, nat_type)
        # Send bidirectional traffic and check that NAT translation does not happen for other inner IP-address
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_info, interface_type, direction, nat_type, second_port=True)

    @pytest.mark.nat_static
    def test_nat_static_napt(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Send traffic and check that NAPT translation does not happen for another port
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # wait till the PTF's buffer become cleared
        time.sleep(5)
        generate_and_verify_traffic_dropped(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type, src_port=dst_port,
                                            dst_port=dst_port + 1, exp_src_port=dst_port, exp_dst_port=src_port)

    @pytest.mark.nat_static
    def test_nat_clear_statistics_static_basic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send bidirectional traffic
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
                          "Unexpected value {} for NAT counter 'Packets'".format(
                              nat_counters[entry]["Packets"]))
            pytest_assert(int(nat_counters[entry]["Bytes"]) > 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(
                              nat_counters[entry]["Bytes"]))
        # Clear NAt counters
        nat_statistics(duthost, clear=True)
        # make sure NAT counters have cleared
        cleared_counters = nat_statistics(duthost, show=True)
        pytest_assert(cleared_counters,
                      "NAT counters output are not empty")
        for entry in cleared_counters:
            pytest_assert(int(cleared_counters[entry]["Packets"]) == 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(
                              cleared_counters[entry]["Packets"]))
            pytest_assert(int(cleared_counters[entry]["Bytes"]) == 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(
                              cleared_counters[entry]["Bytes"]))

    @pytest.mark.nat_static
    def test_nat_clear_statistics_static_napt(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send bidirectional traffic
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
                          "Unexpected value {} for NAT counter 'Packets'".format(
                              nat_counters[entry]["Packets"]))
            pytest_assert(int(nat_counters[entry]["Bytes"]) > 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(
                              nat_counters[entry]["Bytes"]))
        # Clear NAt counters
        nat_statistics(duthost, clear=True)
        # make sure NAT counters have cleared
        cleared_counters = nat_statistics(duthost, show=True)
        pytest_assert(cleared_counters,
                      "NAT counters output are not empty")
        for entry in cleared_counters:
            pytest_assert(int(cleared_counters[entry]["Packets"]) == 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(
                              cleared_counters[entry]["Packets"]))
            pytest_assert(int(cleared_counters[entry]["Bytes"]) == 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(
                              cleared_counters[entry]["Bytes"]))

    @pytest.mark.nat_static
    def test_nat_clear_translations_static_basic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                                 protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_translated_source = setup_data[interface_type]["public_ip"]
        nat_source = setup_data[interface_type]["src_ip"]
        nat_translated_destination = nat_source
        nat_destination = nat_translated_source
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # make sure static NAT translations have created
        translations = nat_translations(duthost, show=True)
        for entry in translations:
            if entry == nat_source:
                pytest_assert(nat_translated_source == translations[entry]["Translated Source"],
                              "Unexpected source translation rule for {}".format(entry))
                pytest_assert(nat_source == translations[entry]["Source"],
                              "Unexpected source translation rule for {}".format(entry))
            elif entry == nat_destination:
                pytest_assert(nat_translated_destination == translations[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}".format(entry))
                pytest_assert(nat_destination == translations[entry]["Destination"],
                              "Unexpected source translation rule for {}".format(entry))
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # try to clear static NAT translations
        nat_translations(duthost, clear=True)
        # make sure static NAT translations exist
        cleared_translations = nat_translations(duthost, show=True)
        for entry in cleared_translations:
            if entry == nat_source:
                pytest_assert(nat_translated_source == cleared_translations[entry]["Translated Source"],
                              "Unexpected source translation rule for {}".format(entry))
                pytest_assert(nat_source == cleared_translations[entry]["Source"],
                              "Unexpected source translation rule for {}".format(entry))
            elif entry == nat_destination:
                pytest_assert(nat_translated_destination == cleared_translations[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}".format(entry))
                pytest_assert(nat_destination == cleared_translations[entry]["Destination"],
                              "Unexpected destination translation rule for {}".format(entry))
        # wait for counters update
        time.sleep(5)
        # make sure NAT counters exist and have incremented
        nat_counters = nat_statistics(duthost, show=True)
        pytest_assert(nat_counters,
                      "Unexpected empty NAT counters output")
        for entry in nat_counters:
            pytest_assert(int(nat_counters[entry]["Packets"]) > 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(nat_counters[entry]["Packets"]))
            pytest_assert(int(nat_counters[entry]["Bytes"]) > 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(nat_counters[entry]["Bytes"]))
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    def test_nat_clear_translations_static_napt(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                                protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        nat_translated_source = "{}:{}".format(setup_data[interface_type]["public_ip"], dst_port)
        nat_source = "{}:{}".format(setup_data[interface_type]["src_ip"], src_port)
        nat_translated_destination = nat_source
        nat_destination = nat_translated_source
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # make sure static NAT translations have created
        translations = nat_translations(duthost, show=True)
        for entry in translations:
            if entry == nat_source:
                pytest_assert(nat_translated_source == translations[entry]["Translated Source"],
                              "Unexpected source translation rule for {}".format(entry))
                pytest_assert(nat_source == translations[entry]["Source"],
                              "Unexpected source translation rule for {}".format(entry))
            elif entry == nat_destination:
                pytest_assert(nat_translated_destination == translations[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}".format(entry))
                pytest_assert(nat_destination == translations[entry]["Destination"],
                              "Unexpected source translation rule for {}".format(entry))
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # try to clear static NAT translations
        nat_translations(duthost, clear=True)
        # make sure static NAT translations exist
        cleared_translations = nat_translations(duthost, show=True)
        for entry in cleared_translations:
            if entry == nat_source:
                pytest_assert(nat_translated_source == cleared_translations[entry]["Translated Source"],
                              "Unexpected source translation rule for {}".format(entry))
                pytest_assert(nat_source == cleared_translations[entry]["Source"],
                              "Unexpected source translation rule for {}".format(entry))
            elif entry == nat_destination:
                pytest_assert(nat_translated_destination == cleared_translations[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}".format(entry))
                pytest_assert(nat_destination == cleared_translations[entry]["Destination"],
                              "Unexpected source translation rule for {}".format(entry))
        # wait for counters update
        time.sleep(5)
        # make sure NAT counters exist and have incremented
        nat_counters = nat_statistics(duthost, show=True)
        pytest_assert(nat_counters,
                      "Unexpected empty NAT counters output")
        for entry in nat_counters:
            pytest_assert(int(nat_counters[entry]["Packets"]) > 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(nat_counters[entry]["Packets"]))
            pytest_assert(int(nat_counters[entry]["Bytes"]) > 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(nat_counters[entry]["Bytes"]))
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    def test_nat_crud_static_nat(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                 protocol_type):
        entries_table = {}
        expected_error = "KeyError: \'{}\'"
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Create with CLI
        crud_create = {"create": {"action": "add", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_create))
        # Read from running config and check
        nat_rules_config = json.loads(duthost.command("sudo sonic-cfggen -d --var-json {}".format(STATIC_NAT_TABLE_NAME))["stdout"])
        pytest_assert(nat_rules_config[network_data.public_ip] == entries_table[network_data.public_ip],
                      "Unexpected NAT rule configuration for {}."
                      " Actual: {}."
                      " Expected: {}".format(network_data.public_ip,
                                             nat_rules_config[network_data.public_ip],
                                             entries_table[network_data.public_ip]))
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Update with CLI
        crud_remove = {"remove": {"action": "remove", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_remove))
        # Read
        nat_rules_config = exec_command(duthost,
                                        ["sudo sonic-cfggen -d --var-json {}".format(STATIC_NAT_TABLE_NAME)])
        condition = (expected_error.format(STATIC_NAT_TABLE_NAME) in nat_rules_config['stderr_lines'] or nat_rules_config['stdout'] == '')
        pytest_assert(condition,
                      "Unexpected error for deleted static NAT rule: {}".format(nat_rules_config['stderr_lines']))
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type)
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type, second_port=True)
        crud_create = {"create": {"action": "add", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_create))
        # Read from running config and check
        nat_rules_config = json.loads(duthost.command("sudo sonic-cfggen "
                                                      "-d --var-json {}".format(STATIC_NAT_TABLE_NAME))["stdout"])
        pytest_assert(nat_rules_config[network_data.public_ip] == entries_table[network_data.public_ip],
                      "Unexpected NAT rule configuration for {}."
                      " Actual: {}."
                      " Expected: {}".format(network_data.public_ip,
                                             nat_rules_config[network_data.public_ip],
                                             entries_table[network_data.public_ip]))
        # Perform TCP handshake from leaf-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.exp_src_ip, dst_port,
                          network_data.exp_dst_ip, src_port,
                          network_data.public_ip)
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type)
        # Remove with CLI
        crud_remove = {"remove": {"action": "remove", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_remove))
        # Read
        nat_rules_config = exec_command(duthost,
                                        ["sudo sonic-cfggen -d --var-json {}".format(STATIC_NAT_TABLE_NAME)])
        condition = (expected_error.format(STATIC_NAT_TABLE_NAME) in nat_rules_config['stderr_lines'] or nat_rules_config['stdout'] == '')
        pytest_assert(condition, "Unexpected error for deleted static basic NAT rule: {}".format(nat_rules_config['stderr_lines']))
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    def test_nat_crud_static_napt(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        entries_table = {}
        expected_error = "KeyError: \'{}\'"
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Create with CLI
        crud_create = {"create": {"action": "add", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip,
                                  "proto": protocol_type, "global_port": dst_port, "local_port": src_port
                                 }
                      }
        entries_table.update(crud_operations_napt(duthost, crud_create))
        # Read from running config and check
        nat_rules_config = json.loads(duthost.command("sudo sonic-cfggen "
                                                      "-d --var-json {}".format(STATIC_NAPT_TABLE_NAME))["stdout"])
        key_entry = "{}|{}|{}".format(network_data.public_ip, protocol_type.upper(), dst_port)
        pytest_assert(nat_rules_config[key_entry] == entries_table[key_entry],
                      "Unexpected NAPT rule for {}".format(key_entry))
        # Perform TCP handshake from leaf-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.exp_src_ip, dst_port,
                          network_data.exp_dst_ip, src_port,
                          network_data.public_ip)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Update with CLI
        crud_remove = {"remove": {"action": "remove", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip,
                                  "proto": protocol_type, "global_port": dst_port, "local_port": src_port
                                 }
                      }
        entries_table.update(crud_operations_napt(duthost, crud_remove))
        # Read
        nat_rules_config = exec_command(duthost,
                                        ["sudo sonic-cfggen -d --var-json {}".format(STATIC_NAPT_TABLE_NAME)])
        condition = (expected_error.format(STATIC_NAPT_TABLE_NAME) in nat_rules_config['stderr_lines'] or nat_rules_config['stdout'] == '')
        pytest_assert(condition,
                      "Unexpected error for deleted static NAPT rule")
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type)
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type, second_port=True)
        crud_create = {"create": {"action": "add", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip,
                                  "proto": protocol_type, "global_port": dst_port, "local_port": src_port
                                 }
                      }
        entries_table.update(crud_operations_napt(duthost, crud_create))
        # Read from running config and check
        nat_rules_config = json.loads(duthost.command("sudo sonic-cfggen "
                                                      "-d --var-json {}".format(STATIC_NAPT_TABLE_NAME))["stdout"])
        key_entry = "{}|{}|{}".format(network_data.public_ip, protocol_type.upper(), dst_port)
        pytest_assert(nat_rules_config[key_entry] == entries_table[key_entry],
                      "Unexpected NAT rule for {}".format(key_entry))
        # Perform TCP handshake from leaf-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.exp_src_ip, dst_port,
                          network_data.exp_dst_ip, src_port,
                          network_data.public_ip)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type, second_port=True)
        # Remove with CLI
        crud_remove = {"remove": {"action": "remove", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip,
                                  "proto": protocol_type, "global_port": dst_port, "local_port": src_port
                                 }
                      }
        entries_table.update(crud_operations_napt(duthost, crud_remove))
        # Read
        nat_rules_config = exec_command(duthost,
                                        ["sudo sonic-cfggen -d --var-json {}".format(STATIC_NAPT_TABLE_NAME)])
        condition = (expected_error.format(STATIC_NAPT_TABLE_NAME) in nat_rules_config['stderr_lines'] or nat_rules_config['stdout'] == '')
        pytest_assert(condition, "Unexpected error for deleted static NAPT rule")
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type, second_port=True)

    @pytest.mark.nat_static
    @pytest.mark.parametrize("reboot_type", ['cold', 'fast'])
    def test_nat_reboot_static_basic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type,
                                     reboot_type, localhost, reload_dut_config):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Save current configuration
        duthost.command('sudo config save -y')
        # Reboot
        common_reboot(duthost, localhost, reboot_type=reboot_type, delay=10,
                      timeout=REBOOT_MAP[reboot_type]["timeout"], wait=120)
        # Perform handshake from host-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    @pytest.mark.parametrize("reboot_type", ['cold', 'fast'])
    def test_nat_reboot_static_napt(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type,
                                    reboot_type, localhost, reload_dut_config):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)
        # Save current configuration
        duthost.command('sudo config save -y')
        # Reboot
        common_reboot(duthost, localhost, reboot_type=reboot_type, delay=10,
                      timeout=REBOOT_MAP[reboot_type]["timeout"], wait=120)
        # set_arp entries
        check_peers_by_ping(duthost)
        # Perform TCP handshake from leaf-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.exp_src_ip, dst_port,
                          network_data.exp_dst_ip, src_port,
                          network_data.public_ip)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    def test_nat_static_zones_basic_snat(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                         protocol_type):
        # Prepare configuration for NAT zones modify test
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Prepare configuration for NAT zones negative test
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = 1
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_info_negative_zones, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info_negative_zones, interface_type, 'host-tor', protocol_type, nat_type=nat_type)
        # Check static NAT when all NAT interfaces zones are corect
        nat_zones_config(duthost, setup_data, interface_type)
        # Perform TCP handshake from host-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    def test_nat_static_zones_basic_icmp_snat(self, tbinfo, ptfhost, duthost, ptfadapter, setup_test_env):
        # Prepare configuration for NAT zones modify test
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Prepare configuration for NAT zones negative test
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = 1
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_info_negative_zones, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type="ICMP", nat_entry=nat_type)
        # Traffic send and check that NAT translation will not perform for SNAT(host-tor)
        generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_data, interface_type, direction, nat_type)
        # Check static NAT when all NAT interfaces zones are corect
        nat_zones_config(duthost, setup_data, interface_type)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_icmp_traffic(ptfadapter, setup_data, interface_type, path, nat_type)

    @pytest.mark.nat_static
    def test_nat_static_zones_napt_dnat_and_snat(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                                 protocol_type):
        # Prepare configuration for NAT zones modify test
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Prepare configuration for NAT zones negative test
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = 1
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_info_negative_zones, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Traffic send and check that NAT translation will not be performed for DNAT(leaf-tor) and SNAT(host-tor)
        generate_and_verify_traffic_dropped(ptfadapter, setup_info, interface_type, 'leaf-tor', protocol_type, nat_type, src_port=dst_port,
                                            dst_port=dst_port, exp_src_port=dst_port, exp_dst_port=src_port)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info_negative_zones, interface_type, "host-tor", protocol_type, nat_type=nat_type)
        # Check static NAPT when all NAT interfaces zones are corect
        nat_zones_config(duthost, setup_data, interface_type)
        # Perform TCP handshake from leaf-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.exp_src_ip, dst_port,
                          network_data.exp_dst_ip, src_port,
                          network_data.public_ip)
        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

    @pytest.mark.nat_static
    def test_nat_static_iptables_add_remove(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                            protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        entries_table = {}
        # Check that NAT entries are NOT present in iptables before adding
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Set NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Create with CLI
        crud_create = {"create": {"action": "add", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_create))
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Check that NAT entries are present in iptables after adding
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {
            "prerouting": [
                "DNAT all -- 0.0.0.0/0 {} mark match 0x2 to:{}".format(network_data.public_ip, network_data.private_ip),
                "DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone"],
            "postrouting": [
                "SNAT all -- {} 0.0.0.0/0 mark match 0x2 to:{}".format(network_data.private_ip, network_data.public_ip)]
            }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Remove with CLI
        crud_remove = {"remove": {"action": "remove", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_remove))
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_data, interface_type, 'host-tor', protocol_type, nat_type=nat_type)
        # Check that NAT entries are not present in iptables after removal
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))

    @pytest.mark.nat_static
    def test_nat_static_global_double_add(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                          protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        entries_table = {}
        # Check that NAT entries are NOT present in iptables before adding
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        # Set NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Create with CLI
        crud_create = {"create": {"action": "add", "global_ip": network_data.public_ip, "local_ip": network_data.private_ip}}
        entries_table.update(crud_operations_basic(duthost, crud_create))
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Add static rule with overlapping global IP
        output = exec_command(duthost, ["sudo config nat add static tcp {} 100 12.12.12.12 200 -nat_type dnat".format(network_data.public_ip)])
        # Confirm that expected error occured
        pattern = r"Error: Given entry is overlapping with existing NAT entry"
        entries = re.findall(pattern.format(get_public_ip(setup_data, interface_type), "{0}-{1}".
                                            format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT)), output)
        pytest_assert(len(entries) == 2, "Expected error wasn't found: found {} occurences; \nLog:\n{}\n".format(len(entries), output))

    @pytest.mark.nat_static
    def test_nat_static_interface_add_remove_interface_ip(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                                          protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Check that NAT entries are NOT present in iptables before adding
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        tested_zones = {
            0 : {
                "path" : "host-tor",
                "exp_zone" : "0x2"
            },
            1 : {
                "path" : "leaf-tor",
                "exp_zone" : "0x1"
            }
        }
        # Set NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        for zone in tested_zones:
            # Create rule with CLI and set zones for interfaces: zone value from tested_zones for all interfaces, opposite zone value for tested interface
            for key in setup_data['interfaces_nat_zone']:
                setup_data['interfaces_nat_zone'][key]['zone_id'] = zone
            apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                    network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
            exec_command(duthost, ["sudo config nat add interface {} -nat_zone {}".format(setup_data[interface_type]["vrf_conf"]["red"]["dut_iface"], int(not zone))])
            # Send TCP/UDP traffic and check
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, tested_zones[zone]["path"], protocol_type, nat_type=nat_type)
            # Check that NAT entries are present in iptables after adding
            iptables_output = dut_nat_iptables_status(duthost)
            iptables_rules = {
                "prerouting": [
                    "DNAT all -- 0.0.0.0/0 {} mark match {} to:{}".format(network_data.public_ip, tested_zones[zone]["exp_zone"], network_data.private_ip),
                    "DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone"],
                "postrouting": [
                    "SNAT all -- {} 0.0.0.0/0 mark match {} to:{}".format(network_data.private_ip, tested_zones[zone]["exp_zone"], network_data.public_ip)]
                }
            pytest_assert(iptables_rules == iptables_output,
                          "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
            # Remove interface IP
            interface_ip = "{} {}/{}".format(setup_data[interface_type]["vrf_conf"]["red"]["dut_iface"],
                                             setup_data[interface_type]["vrf_conf"]["red"]["gw"],
                                             setup_data[interface_type]["vrf_conf"]["red"]["mask"])
            ifname_to_disable = setup_data[interface_type]["outer_zone_interfaces"][0]
            dut_interface_control(duthost, "ip remove", setup_data["config_portchannels"][ifname_to_disable]['members'][0], interface_ip)
            # Check that NAT entries are not present in iptables after removing interface IP
            iptables_output = dut_nat_iptables_status(duthost)
            iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                              "postrouting": []
                             }
            pytest_assert(iptables_rules == iptables_output,
                          "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
            # Readd interface IP
            dut_interface_control(duthost, "ip add", setup_data["config_portchannels"][ifname_to_disable]['members'][0], interface_ip)
            # Check that NAT entries are present in iptables after readding interface IP
            time.sleep(90)
            iptables_output = dut_nat_iptables_status(duthost)
            iptables_rules = {
                "prerouting": [
                    "DNAT all -- 0.0.0.0/0 {} mark match {} to:{}".format(network_data.public_ip, tested_zones[zone]["exp_zone"], network_data.private_ip),
                    "DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone"],
                "postrouting": [
                    "SNAT all -- {} 0.0.0.0/0 mark match {} to:{}".format(network_data.private_ip, tested_zones[zone]["exp_zone"], network_data.public_ip)]
                }
            pytest_assert(iptables_rules == iptables_output,
                          "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
            # Send TCP/UDP traffic and confirm that restoring previous configuration went well
            perform_handshake(ptfhost, setup_info, protocol_type, tested_zones[zone]["path"],
                              network_data.ip_dst, dst_port,
                              network_data.ip_src, src_port,
                              network_data.public_ip)
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, tested_zones[zone]["path"], protocol_type, nat_type=nat_type)
            exec_command(duthost, ["sudo config nat remove static all"])

    @pytest.mark.nat_static
    def test_nat_static_interface_add_remove_interface(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Check that NAT entries are NOT present in iptables before adding
        iptables_output = dut_nat_iptables_status(duthost)
        iptables_rules = {"prerouting": ['DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone'],
                          "postrouting": []
                         }
        pytest_assert(iptables_rules == iptables_output,
                      "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
        tested_zones = {
            0 : {
                "path" : "host-tor",
                "exp_zone" : "0x2"
            },
            1 : {
                "path" : "leaf-tor",
                "exp_zone" : "0x1"
            }
        }
        # Set NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        for zone in tested_zones:
            # Create rule with CLI and set zones for interfaces: zone value from tested_zones for all interfaces, opposite zone value for tested interface
            for key in setup_data['interfaces_nat_zone']:
                setup_data['interfaces_nat_zone'][key]['zone_id'] = zone
            apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                    network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
            exec_command(duthost, ["sudo config nat add interface {} -nat_zone {}".format(setup_data[interface_type]["vrf_conf"]["red"]["dut_iface"], int(not zone))])
            # Send TCP/UDP traffic and check
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, tested_zones[zone]["path"], protocol_type, nat_type=nat_type)
            # Check that NAT entries are present in iptables after adding
            iptables_output = dut_nat_iptables_status(duthost)
            iptables_rules = {
                "prerouting": [
                    "DNAT all -- 0.0.0.0/0 {} mark match {} to:{}".format(network_data.public_ip, tested_zones[zone]["exp_zone"], network_data.private_ip),
                    "DNAT all -- 0.0.0.0/0 0.0.0.0/0 to:1.1.1.1 fullcone"],
                "postrouting": [
                    "SNAT all -- {} 0.0.0.0/0 mark match {} to:{}".format(network_data.private_ip, tested_zones[zone]["exp_zone"], network_data.public_ip)]
                }
            pytest_assert(iptables_rules == iptables_output,
                          "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
            # Remove interface
            ifname_to_disable = setup_data[interface_type]["outer_zone_interfaces"][0]
            dut_interface_control(duthost, "disable", setup_data["config_portchannels"][ifname_to_disable]['members'][0])
            # Check that NAT entries are still present in iptables after disabling interface
            iptables_output = dut_nat_iptables_status(duthost)
            pytest_assert(iptables_rules == iptables_output,
                          "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
            # Readd interface
            dut_interface_control(duthost, "enable", setup_data["config_portchannels"][ifname_to_disable]['members'][0])
            # Check that NAT entries are present in iptables after enabling interface
            time.sleep(90)
            iptables_output = dut_nat_iptables_status(duthost)
            pytest_assert(iptables_rules == iptables_output,
                          "Unexpected iptables output for nat table \n Got:\n{}\n Expected:\n{}".format(iptables_output, iptables_rules))
            # Send TCP/UDP traffic and confirm that restoring previous configuration went well
            perform_handshake(ptfhost, setup_info, protocol_type, tested_zones[zone]["path"],
                              network_data.ip_dst, dst_port,
                              network_data.ip_src, src_port,
                              network_data.public_ip)
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, tested_zones[zone]["path"], protocol_type, nat_type=nat_type)
            exec_command(duthost, ["sudo config nat remove static all"])

    @pytest.mark.nat_static
    def test_nat_static_redis_global_pool_binding(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        test_pool_range_start_port = 1000
        test_pool_range_end_port = 2000
        test_public_ip = exec_command(duthost, ["/sbin/ifconfig PortChannel0002 | grep 'inet ' | awk -F'[: ]+' '{ print $3 }'"])['stdout']
        nat_type = 'static_napt'
        direction = 'host-tor'
        # Set static NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Verify config change in CONFIG_DB for NAT_GLOBAL is in sync with APP_DB
        # Confirm that APP_DB is set properly before any changes
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'APP_DB timeout')
        output = get_redis_val(duthost, 0, "GLOBAL")
        pytest_assert(db_rules == output['NAT_GLOBAL_TABLE:Values']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_GLOBAL_TABLE:Values']['value'], db_rules))
        # Modify and confirm that APP_DB is updated properly
        nat_global_config(duthost, timeout_in=GLOBAL_NAT_TIMEOUT+200, tcp_timeout_in=GLOBAL_TCP_NAPT_TIMEOUT+5000, udp_timeout_in=GLOBAL_UDP_NAPT_TIMEOUT+200)
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'APP_DB timeout', post_flag=True)
        output = get_redis_val(duthost, 0, "GLOBAL")
        pytest_assert(db_rules == output['NAT_GLOBAL_TABLE:Values']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_GLOBAL_TABLE:Values']['value'], db_rules))
        # Restore default values and confirm that APP_DB is updated properly
        nat_global_config(duthost, timeout_in=GLOBAL_NAT_TIMEOUT, tcp_timeout_in=GLOBAL_TCP_NAPT_TIMEOUT, udp_timeout_in=GLOBAL_UDP_NAPT_TIMEOUT)
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'APP_DB timeout')
        output = get_redis_val(duthost, 0, "GLOBAL")
        pytest_assert(db_rules == output['NAT_GLOBAL_TABLE:Values']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_GLOBAL_TABLE:Values']['value'], db_rules))
        # Verify config change in CONFIG_DB for NAT_POOL and NAT_BINDINGS are in sync with APP_DB
        # Configure default rules for Dynamic NAT
        nat_type = 'dynamic'
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_info, interface_type, protocol_type, default=True, handshake=True)
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Confirm that CONFIG_DB and APP_DB is set properly before any changes
        # Pool CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Pool CONFIG_DB', public_ip=network_data.public_ip)
        output = get_redis_val(duthost, 4, "POOL")
        pytest_assert(db_rules == output['NAT_POOL|test_pool']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_POOL|test_pool']['value'], db_rules))
        # Binding CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Binding CONFIG_DB')
        output = get_redis_val(duthost, 4, "BINDING")
        pytest_assert(db_rules == output['NAT_BINDINGS|test_binding']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_BINDINGS|test_binding']['value'], db_rules))
        # Binding APP_DB
        db_rules = {}
        output = get_redis_val(duthost, 0, "BINDING")
        pytest_assert(db_rules == output,
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))
        # Modify switch configuration and confirm that pool and bindings APP_DB and CONFIG_DB are updated properly
        duthost.command("sudo config nat add pool test_pool {} {}-{}".format(network_data.public_ip, test_pool_range_start_port, test_pool_range_end_port))
        duthost.command("sudo config nat add pool test_pool_2 {} {}-{}".format(test_public_ip, test_pool_range_start_port + 1, test_pool_range_end_port + 1))
        duthost.command("sudo config acl add table test_acl_2 L3")
        duthost.command("sudo config nat add binding test_binding test_pool_2 test_acl_2")
        # Pool CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Pool CONFIG_DB', public_ip=network_data.public_ip, start_port=test_pool_range_start_port, end_port=test_pool_range_end_port)
        output = get_redis_val(duthost, 4, "POOL")
        pytest_assert(db_rules == output['NAT_POOL|test_pool']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_POOL|test_pool']['value'], db_rules))
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Pool CONFIG_DB', public_ip=test_public_ip, start_port=test_pool_range_start_port + 1, end_port=test_pool_range_end_port + 1)
        output = get_redis_val(duthost, 4, "POOL")
        pytest_assert(db_rules == output['NAT_POOL|test_pool_2']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_POOL|test_pool_2']['value'], db_rules))
        # Pool APP_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Pool APP_DB', start_port=test_pool_range_start_port + 1, end_port=test_pool_range_end_port + 1)
        output = get_redis_val(duthost, 0, "POOL")
        pytest_assert(db_rules == output['NAPT_POOL_IP_TABLE:{}'.format(test_public_ip)]['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAPT_POOL_IP_TABLE:{}'.format(test_public_ip)]['value'], db_rules))
        # Binding CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Binding CONFIG_DB', access_list="test_acl_2", nat_pool="test_pool_2")
        output = get_redis_val(duthost, 4, "BINDING")
        pytest_assert(db_rules == output['NAT_BINDINGS|test_binding']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_BINDINGS|test_binding']['value'], db_rules))
        # Binding APP_DB
        db_rules = {}
        output = get_redis_val(duthost, 0, "BINDING")
        pytest_assert(db_rules == output, "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))
        # Restore switch configuration back to original values and confirm that pool and bindings APP_DB and CONFIG_DB are restored properly
        duthost.command("sudo config nat remove pool test_pool_2")
        duthost.command("sudo config nat add pool test_pool {} {}-{}".format(network_data.public_ip, POOL_RANGE_START_PORT, POOL_RANGE_END_PORT))
        duthost.command("sudo config nat add binding test_binding test_pool test_acl_table")
        duthost.command("sudo config acl remove table test_acl_2")
        # Pool CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Pool CONFIG_DB', public_ip=network_data.public_ip)
        output = get_redis_val(duthost, 4, "POOL")
        pytest_assert(db_rules == output['NAT_POOL|test_pool']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_POOL|test_pool']['value'], db_rules))
        # Binding CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'Binding CONFIG_DB')
        output = get_redis_val(duthost, 4, "BINDING")
        pytest_assert(db_rules == output['NAT_BINDINGS|test_binding']['value'],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output['NAT_BINDINGS|test_binding']['value'], db_rules))
        # Binding APP_DB
        db_rules = {}
        output = get_redis_val(duthost, 0, "BINDING")
        pytest_assert(db_rules == output,
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))

    @pytest.mark.nat_static
    def test_nat_static_redis_napt(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        test_private_ip = exec_command(duthost, ["/sbin/ifconfig PortChannel0003 | grep 'inet ' | awk -F'[: ]+' '{ print $3 }'"])['stdout']
        test_public_ip = exec_command(duthost, ["/sbin/ifconfig PortChannel0002 | grep 'inet ' | awk -F'[: ]+' '{ print $3 }'"])['stdout']
        test_private_port = 8000
        test_public_port = 6000
        nat_type = 'static_napt'
        direction = 'host-tor'
        # Set static NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Verify config change in CONFIG_DB for Static NAT/NAPT are in sync with APP_DB
        # NAPT APP_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'NAPT APP_DB')
        output = get_redis_val(duthost, 0, "NAPT")
        pytest_assert(db_rules == output, "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))
        # NAPT CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'NAPT CONFIG_DB')
        output = get_redis_val(duthost, 4, "NAPT")
        pytest_assert(db_rules == output, "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))
        # Modify entries and add new one
        configure_nat_over_cli(duthost, 'add', 'static_napt', test_public_ip, test_private_ip, 'tcp', test_public_port, test_private_port)
        configure_nat_over_cli(duthost, 'add', 'static_napt', test_public_ip, test_private_ip, 'udp', test_public_port, test_private_port)
        # NAPT APP_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'NAPT APP_DB POST',
                                public_ip=test_public_ip, private_ip=test_private_ip, public_port=test_public_port, private_port=test_private_port)
        output = get_redis_val(duthost, 0, "NAPT")
        pytest_assert(db_rules == output, "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))
        # NAPT CONFIG_DB
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'NAPT CONFIG_DB POST',
                                public_ip=test_public_ip, private_ip=test_private_ip, public_port=test_public_port, private_port=test_private_port)
        output = get_redis_val(duthost, 4, "NAPT")
        pytest_assert(db_rules == output, "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))

    @pytest.mark.nat_static
    def test_nat_static_redis_asic(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'static_napt'
        direction = 'host-tor'
        # Set static NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Send TCP/UDP traffic and check
        generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, direction, protocol_type, nat_type=nat_type)
        # Verify the NAT/NAPT entries in the system are in sync b/w APP_DB and ASIC_DB
        # Verify APP_DB status
        db_rules = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'NAPT APP_DB')
        output = get_redis_val(duthost, 0, "NAPT")
        pytest_assert(db_rules == output, "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output, db_rules))
        # Verify ASIC_DB status
        db_rules_src = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'ASIC_DB SRC')
        db_rules_dst = get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, 'ASIC_DB DST')
        output = get_redis_val(duthost, 1, "NAT_ENTRY")
        for count, entry in enumerate(output):
            if 'SAI_NAT_TYPE_SOURCE_NAT' in str(entry):
                output_src = output[(list(output.keys())[count])]['value']
            if 'SAI_NAT_TYPE_DESTINATION_NAT"' in str(entry):
                output_dst = output[(list(output.keys())[count])]['value']
        pytest_assert(db_rules_src["SAI_NAT_ENTRY_ATTR_SRC_IP"] == output_src["SAI_NAT_ENTRY_ATTR_SRC_IP"],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output_src["SAI_NAT_ENTRY_ATTR_SRC_IP"], db_rules_src["SAI_NAT_ENTRY_ATTR_SRC_IP"]))
        pytest_assert(db_rules_src["SAI_NAT_ENTRY_ATTR_L4_SRC_PORT"] == output_src["SAI_NAT_ENTRY_ATTR_L4_SRC_PORT"],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output_src["SAI_NAT_ENTRY_ATTR_L4_SRC_PORT"], db_rules_src["SAI_NAT_ENTRY_ATTR_L4_SRC_PORT"]))
        pytest_assert(db_rules_dst["SAI_NAT_ENTRY_ATTR_DST_IP"] == output_dst["SAI_NAT_ENTRY_ATTR_DST_IP"],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output_dst["SAI_NAT_ENTRY_ATTR_DST_IP"], db_rules_dst["SAI_NAT_ENTRY_ATTR_DST_IP"]))
        pytest_assert(db_rules_dst["SAI_NAT_ENTRY_ATTR_L4_DST_PORT"] == output_dst["SAI_NAT_ENTRY_ATTR_L4_DST_PORT"],
                      "Unexpected output \n Got:\n{}\n Expected:\n{}".format(output_dst["SAI_NAT_ENTRY_ATTR_L4_DST_PORT"], db_rules_dst["SAI_NAT_ENTRY_ATTR_L4_DST_PORT"]))

    @pytest.mark.nat_static
    def test_nat_same_static_and_dynamic_rule(self, ptfhost, tbinfo, duthost, ptfadapter, setup_test_env,
                                              protocol_type):

        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_translated_source = setup_data[interface_type]["public_ip"]
        nat_source = setup_data[interface_type]["src_ip"]
        nat_translated_destination = nat_source
        nat_destination = nat_translated_source
        direction = 'host-tor'
        nat_type = 'static_napt'

        # Set NAT configuration for test
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)

        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data, network_data, direction, interface_type, nat_type,
                                network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)

        # make sure static NAT translations have created
        translations_static = nat_translations(duthost, show=True)
        for entry in translations_static:
            if entry == nat_source:
                pytest_assert(nat_translated_source == translations_static[entry]["Translated Source"],
                              "Unexpected source translation rule for {}".format(entry))
                pytest_assert(nat_source == translations_static[entry]["Source"],
                              "Unexpected source translation rule for {}".format(entry))
            elif entry == nat_destination:
                pytest_assert(nat_translated_destination == translations_static[entry]["Translated Destination"],
                              "Unexpected destination translation rule for {}".format(entry))
                pytest_assert(nat_destination == translations_static[entry]["Destination"],
                              "Unexpected source translation rule for {}".format(entry))

        # Send bidirectional traffic
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_data, interface_type, protocol_type, default=True, handshake=True)

        # make sure static NAT translations are only one present
        translations_after_dynamic_cfg = nat_translations(duthost, show=True)
        pytest_assert(translations_static == translations_after_dynamic_cfg,
                      "Unexpected NAT translation found:\n{}\nexpected:\n{}".format(translations_after_dynamic_cfg, translations_static))

        # Send TCP/UDP bidirectional traffic(host-tor -> leaf-tor and vice versa) and check
        # static config takes precedence so verify as static
        nat_type = 'static_napt'
        for path in DIRECTION_PARAMS:
            generate_and_verify_traffic(duthost, ptfadapter, setup_data, interface_type, path, protocol_type, nat_type=nat_type)

        # make sure static NAT translations are only one present even after traffic
        translations_after_traffic = nat_translations(duthost, show=True)
        pytest_assert(translations_static == translations_after_traffic,
                      "Unexpected NAT translation found:\n{}\nexpected:\n{}".format(translations_after_traffic, translations_static))

        # make sure NAT counters have incremented
        nat_counters = nat_statistics(duthost, show=True)
        pytest_assert(nat_counters,
                      "Unexpected empty NAT counters output")
        for entry in nat_counters:
            pytest_assert(int(nat_counters[entry]["Packets"]) > 0,
                          "Unexpected value {} for NAT counter 'Packets'".format(nat_counters[entry]["Packets"]))
            pytest_assert(int(nat_counters[entry]["Bytes"]) > 0,
                          "Unexpected value {} for NAT counter 'Bytes'".format(nat_counters[entry]["Bytes"]))
