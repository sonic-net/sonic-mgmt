import logging
import threading
import pytest
import random
import allure

from datetime import datetime
from tests.common import reboot
from tests.ecmp.inner_hashing.conftest import get_src_dst_ip_range, FIB_INFO_FILE_DST, VXLAN_PORT,\
    PTF_QLEN, OUTER_ENCAP_FORMATS, NVGRE_TNI, config_pbh
from tests.ptf_runner import ptf_runner
from tests.common.fixtures.ptfhost_utils import skip_traffic_test   # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0')
]


@pytest.mark.dynamic_config
class TestWRDynamicInnerHashing():

    @pytest.fixture(scope="module", autouse=True)
    def setup_dynamic_pbh(self, duthost, vlan_ptf_ports, tbinfo):
        with allure.step('Config Dynamic PBH'):
            config_pbh(duthost, vlan_ptf_ports, tbinfo)

    def test_inner_hashing(self, duthost, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                           vlan_ptf_ports, symmetric_hashing, localhost, lag_mem_ptf_ports_groups,
                           get_function_completeness_level, skip_traffic_test):     # noqa F811
        logging.info("Executing warm boot dynamic inner hash test for outer {} and inner {} with symmetric_hashing"
                     " set to {}".format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        with allure.step('Run ptf test InnerHashTest and warm-reboot in parallel'):
            timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
            log_file = "/tmp/wr_inner_hash_test.DynamicInnerHashTest.{}.{}.{}.log"\
                       .format(outer_ipver, inner_ipver, timestamp)
            logging.info("PTF log file: %s" % log_file)

            # to reduce test run time, check one of encapsulation formats
            outer_encap_format = random.choice(OUTER_ENCAP_FORMATS).split()
            logging.info("Tested encapsulation format: {}".format(outer_encap_format[0]))

            outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
            inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

            normalize_level = get_function_completeness_level if get_function_completeness_level else 'thorough'

            if normalize_level == 'thorough':
                balancing_test_times = 200
                balancing_range = 0.3
            else:
                balancing_test_times = 100
                balancing_range = 0.3

            reboot_thr = threading.Thread(target=reboot, args=(duthost, localhost, 'warm', 10, 0, 0, True, True,))
            reboot_thr.start()

            if not skip_traffic_test:
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
                                   "balancing_test_times": balancing_test_times,
                                   "balancing_range": balancing_range,
                                   "outer_encap_formats": outer_encap_format,
                                   "nvgre_tni": NVGRE_TNI,
                                   "symmetric_hashing": symmetric_hashing},
                           log_file=log_file,
                           qlen=PTF_QLEN,
                           socket_recv_size=16384,
                           is_python3=True)
            reboot_thr.join()


@pytest.mark.static_config
class TestWRStaticInnerHashing():

    def test_inner_hashing(self, duthost, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                           vlan_ptf_ports, symmetric_hashing, localhost, lag_mem_ptf_ports_groups, skip_traffic_test):   # noqa F811
        logging.info("Executing static inner hash test for outer {} and inner {} with symmetric_hashing set to {}"
                     .format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
        log_file = "/tmp/wr_inner_hash_test.StaticInnerHashTest.{}.{}.{}.log"\
                   .format(outer_ipver, inner_ipver, timestamp)
        logging.info("PTF log file: %s" % log_file)

        outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
        inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

        reboot_thr = threading.Thread(target=reboot, args=(duthost, localhost, 'warm', 10, 0, 0, True, True,))
        reboot_thr.start()

        if not skip_traffic_test:
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
        reboot_thr.join()
