import copy
import time

import pytest

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import check_rule_by_traffic
from nat_helpers import get_public_ip
from nat_helpers import get_src_ip
from nat_helpers import apply_static_nat_config
from nat_helpers import nat_zones_config
from nat_helpers import get_static_l4_ports
from nat_helpers import nat_statistics
from nat_helpers import nat_translations
from common.helpers.assertions import pytest_assert


class TestStaticNat(object):
    """ TestStaticNat class for testing static nat """

    @pytest.mark.nat_static
    def test_nat_static_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        # Set public and private IPs for NAT configuration
        public_ip = get_public_ip(setup_data, interface_type)
        private_ip = get_src_ip(setup_data, direction, interface_type)
        # Set NAT configuration for test
        apply_static_nat_config(duthost, public_ip, private_ip, direction, nat_entry='static_nat')
        nat_zones_config(duthost, setup_data, interface_type)
        # Traffic send and check
        for path in DIRECTION_PARAMS:
            src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = \
                get_static_l4_ports(protocol_type, direction=path, nat_type='static_nat')
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, path, interface_type,
                                  protocol_type, source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                  exp_source_port=exp_src_port, exp_dst_port=exp_dst_port, negative=False,
                                  handshake=True)

    @pytest.mark.nat_static
    def test_nat_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env, protocol_type):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        reversed_path = DIRECTION_PARAMS[::-1]
        for direction in DIRECTION_PARAMS:
            if direction == 'host-tor' and protocol_type != "ICMP":
                continue
            elif direction == 'leaf-tor' and protocol_type == "ICMP":
                continue
            # set TCP/UDP SRC and DST ports
            src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type, direction,
                                                                                       nat_type='static_napt')
            # Set public and private IPs for NAT configuration
            public_ip = get_public_ip(setup_data, interface_type)
            private_ip = get_src_ip(setup_data, direction, interface_type, nat_type="static_napt")
            # Set NAT configuration for test
            apply_static_nat_config(duthost, public_ip, private_ip, direction, nat_entry='static_napt',
                                    protocol_type=protocol_type, global_port=dst_l4_port, local_port=src_l4_port)
            nat_zones_config(duthost, setup_data, interface_type)
            # Traffic send and check
            for path in reversed_path:
                src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type, direction=path,
                                                                                           nat_type='static_napt')
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, path, interface_type,
                                      protocol_type, source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                      exp_source_port=exp_src_port, exp_dst_port=exp_dst_port,
                                      nat_type='static_napt', negative=False, handshake=True)

    @pytest.mark.nat_static
    def test_nat_clear_statistics_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                              protocol_type_no_icmp):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        reversed_path = DIRECTION_PARAMS[::-1]
        direction = 'leaf-tor'
        # set TCP/UDP SRC and DST ports
        src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type_no_icmp, direction,
                                                                                   nat_type='static_napt')
        # Set public and private IPs for NAT configuration
        public_ip = get_public_ip(setup_data, interface_type)
        private_ip = get_src_ip(setup_data, direction, interface_type, nat_type="static_napt")
        # Set NAT configuration for test
        apply_static_nat_config(duthost, public_ip, private_ip, direction, nat_entry='static_napt',
                                protocol_type=protocol_type_no_icmp, global_port=dst_l4_port, local_port=src_l4_port)
        nat_zones_config(duthost, setup_data, interface_type)
        # Traffic send and check
        for path in reversed_path:
            src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type_no_icmp,
                                                                                       direction=path,
                                                                                       nat_type='static_napt')
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, path, interface_type,
                                  protocol_type_no_icmp, source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                  exp_source_port=exp_src_port, exp_dst_port=exp_dst_port,
                                  nat_type='static_napt', handshake=True)
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
    def test_nat_clear_translations_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                                                protocol_type_no_icmp):
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        reversed_path = DIRECTION_PARAMS[::-1]
        direction = 'leaf-tor'
        # set TCP/UDP SRC and DST ports
        src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type_no_icmp, direction,
                                                                                   nat_type='static_napt')
        nat_translated_source = "{}:{}".format(setup_data[interface_type]["public_ip"], dst_l4_port)
        nat_source = "{}:{}".format(setup_data[interface_type]["src_ip"], src_l4_port)
        nat_translated_destination = nat_source
        nat_destination = nat_translated_source
        # Set public and private IPs for NAT configuration
        public_ip = get_public_ip(setup_data, interface_type)
        private_ip = get_src_ip(setup_data, direction, interface_type, nat_type="static_napt")
        # Set NAT configuration for test
        apply_static_nat_config(duthost, public_ip, private_ip, direction, nat_entry='static_napt',
                                protocol_type=protocol_type_no_icmp, global_port=dst_l4_port, local_port=src_l4_port)
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
        # Traffic send and check
        for path in reversed_path:
            src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type_no_icmp,
                                                                                       direction=path,
                                                                                       nat_type='static_napt')
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, path, interface_type,
                                  protocol_type_no_icmp, source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                  exp_source_port=exp_src_port, exp_dst_port=exp_dst_port,
                                  nat_type='static_napt', handshake=True)
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
        # Traffic send and check
        for path in reversed_path:
            src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type_no_icmp,
                                                                                       direction=path,
                                                                                       nat_type='static_napt')
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_data, path, interface_type,
                                  protocol_type_no_icmp, source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                  exp_source_port=exp_src_port, exp_dst_port=exp_dst_port,
                                  nat_type='static_napt')
