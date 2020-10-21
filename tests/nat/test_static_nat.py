import copy
import time
import json

import pytest

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import STATIC_NAT_TABLE_NAME
from nat_helpers import STATIC_NAPT_TABLE_NAME
from nat_helpers import REBOOT_MAP
from nat_helpers import apply_static_nat_config
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
from nat_helpers import generate_and_verify_icmp_traffic
from nat_helpers import generate_and_verify_not_translated_traffic
from nat_helpers import generate_and_verify_not_translated_icmp_traffic
import tests.common.reboot as common_reboot
from tests.common.helpers.assertions import pytest_assert


class TestStaticNat(object):
    """ TestStaticNat class for testing static nat """

    @pytest.mark.nat_static
    def test_nat_static_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
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

    @pytest.mark.nat_static
    def test_nat_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
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

    @pytest.mark.nat_static
    def test_nat_clear_statistics_static_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
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
    def test_nat_clear_statistics_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set NAT configuration for test
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
    def test_nat_clear_translations_static_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
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
    def test_nat_clear_translations_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
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
    def test_nat_crud_static_nat(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
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
    def test_nat_static_zones_basic_snat(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
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
    def test_nat_static_zones_basic_dnat(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
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
        # Set NAT configuration for test
        apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_info_negative_zones, network_data, direction, interface_type, nat_type,
                                 network_data.public_ip, network_data.private_ip, protocol_type=protocol_type, nat_entry=nat_type, handshake=True)
        # Traffic send and check that NAT translation will be performed for DNAT(leaf-tor)
        generate_and_verify_traffic(duthost, ptfadapter, setup_info_negative_zones, interface_type, 'leaf-tor', protocol_type, nat_type=nat_type)
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
    def test_nat_static_zones_napt_dnat_and_snat(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
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
       # Check that NAT translation will be performed for DNAT(leaf-tor)
        generate_and_verify_traffic(duthost, ptfadapter, setup_info_negative_zones, interface_type, direction, protocol_type, nat_type=nat_type)
        # Traffic send and check that NAT translation will not be performed for SNAT(host-tor)
        generate_and_verify_not_translated_traffic(ptfadapter, setup_info_negative_zones, interface_type, 'host-tor', protocol_type, nat_type=nat_type)
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
