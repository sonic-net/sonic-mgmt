import re
import copy
import time
import random
import multiprocessing

import pytest
import logging

from nat_helpers import DIRECTION_PARAMS
from nat_helpers import POOL_RANGE_START_PORT
from nat_helpers import GLOBAL_UDP_NAPT_TIMEOUT
from nat_helpers import POOL_RANGE_END_PORT
from nat_helpers import TCP_GLOBAL_PORT
from nat_helpers import configure_dynamic_nat_rule
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
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert

logging.basicConfig(level=logging.DEBUG)
mylogger = logging.getLogger()


class TestNatScale(object):
    """ TestNatScale class for testing nat scaling """

    @pytest.mark.nat_scale
    def test_nat_scale_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                             protocol_type):
        mylogger.info('--- TEST STARTED ---')

        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        scale_range = [5000, 5100]
        p_range_conf = "{}-{}".format(scale_range[0], scale_range[1])
        exp_entries = scale_range[1] - scale_range[0]
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, port_range=p_range_conf, default=True, remove_bindings=False)
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set TCP timeout to max
        duthost.command('sudo config nat set tcp-timeout 432000')
        duthost.command('sudo config nat set udp-timeout 600')
        mylogger.info('Timeouts set to maximum value')
        # Perform TCP handshake (host-tor -> leaf-tor)
        for dst_port in range(scale_range[0], scale_range[1]):
            mylogger.info('port: {}'.format(dst_port))
            perform_handshake(ptfhost, setup_data, protocol_type, direction,
                            network_data.ip_dst, dst_port,
                            network_data.ip_src, dst_port - 4020,
                            network_data.public_ip)
        # Checking numbers
        mylogger.info('Checking translation numbers')
        output = exec_command(duthost, ['show nat translations | grep DNAPT'])['stdout']
        mylogger.info(output)
        entries_no = [int(s) for s in output.split() if s.isdigit()]
        fail_msg = "Unexpected number of translations. Got {} while {} expected".format(entries_no[0], exp_entries)
        pytest_assert(exp_entries == entries_no[0], fail_msg)

        mylogger.info('--- TEST FINISHED ---')

    @pytest.mark.nat_scale
    def test_nat_scale_perf(self, ptfhost, testbed, duthost, ptfadapter, setup_test_env,
                             protocol_type):
        mylogger.info('--- TEST STARTED ---')

        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        direction = 'host-tor'
        nat_type = 'dynamic'
        dst_port = 5000
        n_c = 1000
        p_range_conf = "{}-{}".format(dst_port, dst_port + n_c)
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_data, interface_type, port_range=p_range_conf, default=True, remove_bindings=False)
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        # Set TCP timeout to max
        duthost.command('sudo config nat set tcp-timeout 432000')
        duthost.command('sudo config nat set udp-timeout 600')
        mylogger.info('Timeouts set to maximum value')
        # Starting server and clients
        ex_time = perform_handshake(ptfhost, setup_data, protocol_type, direction,
                                    network_data.ip_dst, dst_port,
                                    network_data.ip_src, dst_port - 4020,
                                    network_data.public_ip, False, n_c)

        # Checking numbers
        output = exec_command(duthost, ['show nat translations | grep DNAPT'])['stdout']
        entries_no = [int(s) for s in output.split() if s.isdigit()]
        fail_msg = "Unexpected number of translations. Got {} while {} expected".format(entries_no[0], n_c)
        #pytest_assert(n_c == entries_no[0], fail_msg)

        rate = entries_no[0] / ex_time
        mylogger.info("Number of connections: {}".format(n_c))
        mylogger.info("Entries added: {}".format(entries_no[0]))
        mylogger.info("Execution time: {}".format(ex_time))
        mylogger.info("Rate: {}".format(rate))

        mylogger.info('--- TEST FINISHED ---')
