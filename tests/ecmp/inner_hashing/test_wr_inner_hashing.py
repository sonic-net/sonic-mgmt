import logging
import threading
import pytest
import random
import allure

from datetime import datetime
from tests.common import reboot
from tests.ecmp.inner_hashing.conftest import get_src_dst_ip_range, FIB_INFO_FILE_DST, VXLAN_PORT,\
    PTF_QLEN, OUTER_ENCAP_FORMATS, NVGRE_TNI
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]

@pytest.mark.dynamic_config
class TestWRDynamicInnerHashing():

    @pytest.fixture(scope="class", autouse=True)
    def setup_dynamic_pbh(self, request):
        with allure.step('Config Dynamic PBH'):
            request.getfixturevalue("config_pbh_table")
            request.getfixturevalue("config_hash_fields")
            request.getfixturevalue("config_hash")
            request.getfixturevalue("config_rules")

    def test_inner_hashing(self, duthost, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                           vlan_ptf_ports, symmetric_hashing, localhost):
        logging.info("Executing warm boot dynamic inner hash test for outer {} and inner {} with symmetric_hashing"
                     " set to {}".format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        with allure.step('Run ptf test InnerHashTest and warm-reboot in parallel'):
            timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
            log_file = "/tmp/wr_inner_hash_test.DynamicInnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
            logging.info("PTF log file: %s" % log_file)

            # to reduce test run time, check one of encapsulation formats
            outer_encap_format = random.choice(OUTER_ENCAP_FORMATS).split()
            logging.info("Tested encapsulation format: {}".format(outer_encap_format[0]))

            outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
            inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

            balancing_test_times = 200
            balancing_range = 0.3

            reboot_thr = threading.Thread(target=reboot, args=(duthost, localhost, 'warm',))
            reboot_thr.start()

            ptf_runner(ptfhost,
                       "ptftests",
                       "inner_hash_test.InnerHashTest",
                       platform_dir="ptftests",
                       params={"fib_info": FIB_INFO_FILE_DST,
                               "router_mac": router_mac,
                               "src_ports": vlan_ptf_ports,
                               "hash_keys": hash_keys,
                               "vxlan_port": VXLAN_PORT,
                               "inner_src_ip_range": ",".join(inner_src_ip_range),
                               "inner_dst_ip_range": ",".join(inner_dst_ip_range),
                               "outer_src_ip_range": ",".join(outer_src_ip_range),
                               "outer_dst_ip_range": ",".join(outer_dst_ip_range),
                               "balancing_test_times": balancing_test_times,
                               "balancing_range": balancing_range,
                               "outer_encap_formats": outer_encap_format,
                               "nvgre_tni": NVGRE_TNI,
                               "symmetric_hashing": symmetric_hashing},
                       log_file=log_file,
                       qlen=PTF_QLEN,
                       socket_recv_size=16384)
            reboot_thr.join()


@pytest.mark.static_config
class TestWRStaticInnerHashing():

    def test_inner_hashing(self, duthost, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                           vlan_ptf_ports, symmetric_hashing, localhost):
        logging.info("Executing static inner hash test for outer {} and inner {} with symmetric_hashing set to {}"
                     .format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
        log_file = "/tmp/wr_inner_hash_test.StaticInnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
        logging.info("PTF log file: %s" % log_file)

        outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
        inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

        reboot_thr = threading.Thread(target=reboot, args=(duthost, localhost, 'warm',))
        reboot_thr.start()

        ptf_runner(ptfhost,
                   "ptftests",
                   "inner_hash_test.InnerHashTest",
                   platform_dir="ptftests",
                   params={"fib_info": FIB_INFO_FILE_DST,
                           "router_mac": router_mac,
                           "src_ports": vlan_ptf_ports,
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
                   socket_recv_size=16384)
        reboot_thr.join()
