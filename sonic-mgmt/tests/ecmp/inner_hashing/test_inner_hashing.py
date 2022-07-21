# Summary: Inner packet hashing test
# How to run this test: sudo ./run_tests.sh -n <tb name> -i <inventory files> -u -m group -e --skip_sanity -l info -c ecmp/test_inner_hashing.py --static_config
# parameter "--static_config" used when already exists hashing configurations and will be executed suitable test

import logging
import pytest
import allure
import random

from datetime import datetime
from retry.api import retry_call
from tests.ptf_runner import ptf_runner
from tests.ecmp.inner_hashing.conftest import get_src_dst_ip_range, FIB_INFO_FILE_DST,\
    VXLAN_PORT, PTF_QLEN, check_pbh_counters, OUTER_ENCAP_FORMATS, NVGRE_TNI, IP_VERSIONS_LIST, config_pbh

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]

update_outer_ipver = random.choice(IP_VERSIONS_LIST)
update_inner_ipver = random.choice(IP_VERSIONS_LIST)


@pytest.mark.dynamic_config
class TestDynamicInnerHashing():

    @pytest.fixture(scope="module", autouse=True)
    def setup_dynamic_pbh(self, duthost, vlan_ptf_ports, tbinfo):
        with allure.step('Config Dynamic PBH'):
            config_pbh(duthost, vlan_ptf_ports, tbinfo)

    def test_inner_hashing(self, request, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                           vlan_ptf_ports, symmetric_hashing, duthost, lag_mem_ptf_ports_groups):
        logging.info("Executing dynamic inner hash test for outer {} and inner {} with symmetric_hashing set to {}"
                     .format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        with allure.step('Run ptf test InnerHashTest'):
            timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
            log_file = "/tmp/inner_hash_test.DynamicInnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
            logging.info("PTF log file: %s" % log_file)

            outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
            inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

            balancing_test_times = 120
            balancing_range = 0.3

            ptf_params = {"fib_info": FIB_INFO_FILE_DST,
                          "router_mac": router_mac,
                          "src_ports": vlan_ptf_ports,
                          "exp_port_groups": lag_mem_ptf_ports_groups,
                          "hash_keys": hash_keys,
                          "vxlan_port": VXLAN_PORT,
                          "inner_src_ip_range": ",".join(inner_src_ip_range),
                          "inner_dst_ip_range": ",".join(inner_dst_ip_range),
                          "outer_src_ip_range": ",".join(outer_src_ip_range),
                          "outer_dst_ip_range": ",".join(outer_dst_ip_range),
                          "balancing_test_times": balancing_test_times,
                          "balancing_range": balancing_range,
                          "outer_encap_formats": OUTER_ENCAP_FORMATS,
                          "nvgre_tni": NVGRE_TNI,
                          "symmetric_hashing": symmetric_hashing}

            duthost.shell("sonic-clear pbh statistics")
            ptf_runner(ptfhost,
                       "ptftests",
                       "inner_hash_test.InnerHashTest",
                       platform_dir="ptftests",
                       params=ptf_params,
                       log_file=log_file,
                       qlen=PTF_QLEN,
                       socket_recv_size=16384,
                       is_python3=True)

            retry_call(check_pbh_counters,
                       fargs=[duthost, outer_ipver, inner_ipver, balancing_test_times,
                              symmetric_hashing, hash_keys, lag_mem_ptf_ports_groups],
                       tries=5,
                       delay=5)

        if update_outer_ipver == outer_ipver and update_inner_ipver == inner_ipver:
            logging.info("Validate dynamic inner hash Edit Flow for outer {} and inner {} ip versions with"
                         " symmetric_hashing set to {}".format(outer_ipver, inner_ipver, str(symmetric_hashing)))

            swapped_outer_ipver = "ipv6" if outer_ipver == "ipv4" else "ipv4"
            swapped_inner_ipver = "ipv6" if inner_ipver == "ipv4" else "ipv4"
            with allure.step('Swap configuration of rules {}_{} with {}_{}'.format(outer_ipver,
                                                                                   inner_ipver,
                                                                                   swapped_outer_ipver,
                                                                                   swapped_inner_ipver)):
                request.getfixturevalue("update_rule")

            with allure.step('Run again the ptf test InnerHashTest after updating the rules'):
                logging.info('Run again the ptf test InnerHashTest after updating the rules')
                duthost.shell("sonic-clear pbh statistics")
                ptf_runner(ptfhost,
                           "ptftests",
                           "inner_hash_test.InnerHashTest",
                           platform_dir="ptftests",
                           params=ptf_params,
                           log_file=log_file,
                           qlen=PTF_QLEN,
                           socket_recv_size=16384,
                           is_python3=True)

            retry_call(check_pbh_counters,
                       fargs=[duthost, swapped_outer_ipver, swapped_inner_ipver, balancing_test_times,
                              symmetric_hashing, hash_keys, lag_mem_ptf_ports_groups],
                       tries=5,
                       delay=5)


@pytest.mark.static_config
class TestStaticInnerHashing():

    def test_inner_hashing(self, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                           vlan_ptf_ports, symmetric_hashing, lag_mem_ptf_ports_groups):
        logging.info("Executing static inner hash test for outer {} and inner {} with symmetric_hashing set to {}"
                     .format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
        log_file = "/tmp/inner_hash_test.StaticInnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
        logging.info("PTF log file: %s" % log_file)

        outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
        inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

        ptf_runner(ptfhost,
                   "ptftests",
                   "inner_hash_test.InnerHashTest",
                   platform_dir="ptftests",
                   params={"fib_info": FIB_INFO_FILE_DST,
                           "router_mac": router_mac,
                           "src_ports": vlan_ptf_ports,
                           "exp_port_groups": lag_mem_ptf_ports_groups,
                           "hash_keys": hash_keys,
                           "vxlan_port": VXLAN_PORT,
                           "inner_src_ip_range": ",".join(inner_src_ip_range),
                           "inner_dst_ip_range": ",".join(inner_dst_ip_range),
                           "outer_src_ip_range": ",".join(outer_src_ip_range),
                           "outer_dst_ip_range": ",".join(outer_dst_ip_range),
                           "outer_encap_formats": OUTER_ENCAP_FORMATS,
                           "symmetric_hashing": symmetric_hashing},
                   log_file=log_file,
                   qlen=PTF_QLEN,
                   socket_recv_size=16384,
                   is_python3=True)
