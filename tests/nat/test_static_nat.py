import copy
import time
import json

import pytest

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import apply_static_nat_config
from nat_helpers import nat_zones_config
from nat_helpers import nat_statistics
from nat_helpers import nat_translations
from nat_helpers import perform_handshake
from nat_helpers import get_network_data
from nat_helpers import generate_and_verify_traffic
from nat_helpers import get_l4_default_ports
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
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, network_data.public_ip, network_data.private_ip, nat_entry=nat_type)
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
    def test_nat_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'leaf-tor'
        nat_type = 'static_napt'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, network_data.public_ip, network_data.private_ip, nat_entry=nat_type,
                                protocol_type=protocol_type, global_port=dst_port, local_port=src_port)
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
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, network_data.public_ip, network_data.private_ip, nat_entry='static_nat')
        nat_zones_config(duthost, setup_data, interface_type)
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
        # Perform TCP handshake from host-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
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
        apply_static_nat_config(duthost, network_data.public_ip, network_data.private_ip, nat_entry='static_napt',
                                protocol_type=protocol_type, global_port=dst_port, local_port=src_port)
        nat_zones_config(duthost, setup_data, interface_type)
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
        # Perform TCP handshake from leaf-tor
        perform_handshake(ptfhost, setup_data, protocol_type, direction,
                          network_data.exp_src_ip, dst_port,
                          network_data.exp_dst_ip, src_port,
                          network_data.public_ip)
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
    @pytest.mark.parametrize("zone_type", [0, 1])
    def test_nat_static_zones_basic_dnat(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                         protocol_type, zone_type):
        # Prepare configuration for NAT zones modify test
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Prepare configuration for NAT zones negative test
        setup_info_negative_zones = copy.deepcopy(setup_info)
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = zone_type
        direction = 'host-tor'
        nat_type = 'static_nat'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, network_data.public_ip, network_data.private_ip, nat_entry=nat_type)
        # Check static NAT when all NAT interfaces zones are 0 or 1
        nat_zones_config(duthost, setup_info_negative_zones, interface_type)
        # Perform TCP handshake from host-tor
        perform_handshake(ptfhost, setup_info_negative_zones, protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)
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
