# Summary: Inner packet hashing test
# How to run this test: sudo ./run_tests.sh -n <tb name> -i <inventory files> -u -m group -e --skip_sanity -l info -c ecmp/test_inner_hashing.py --static_config
# parameter "--static_config" used when already exists hashing configurations and will be executed suitable test

import logging
import pytest

from datetime import datetime
from retry.api import retry_call
from tests.ptf_runner import ptf_runner
from tests.ecmp.inner_hashing.conftest import get_src_dst_ip_range, FIB_INFO_FILE_DST,\
    VXLAN_PORT, PTF_QLEN, check_pbh_counters, OUTER_ENCAP_FORMATS

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]


@pytest.mark.dynamic_config
class TestDynamicInnerHashing():

    @pytest.fixture(scope="class", autouse=True)
    def setup_dynamic_pbh(self, request):
        request.getfixturevalue("config_pbh_table")
        request.getfixturevalue("config_hash_fields")
        request.getfixturevalue("config_hash")
        request.getfixturevalue("config_rules")

    def test_inner_hashing(self, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac, vlan_ptf_ports, symmetric_hashing, duthost):
        logging.info("Executing dynamic inner hash test for outer {} and inner {} with symmetric_hashing set to {}"
                     .format(outer_ipver, inner_ipver, str(symmetric_hashing)))
        timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
        log_file = "/tmp/inner_hash_test.DynamicInnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
        logging.info("PTF log file: %s" % log_file)

        outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
        inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

        balancing_test_times = 150
        balancing_range = 0.3

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
                           "outer_encap_formats": OUTER_ENCAP_FORMATS,
                           "symmetric_hashing": symmetric_hashing},
                   log_file=log_file,
                   qlen=PTF_QLEN,
                   socket_recv_size=16384)

        retry_call(check_pbh_counters,
                   fargs=[duthost, outer_ipver, inner_ipver, balancing_test_times, symmetric_hashing, hash_keys],
                   tries=5,
                   delay=5)


@pytest.mark.static_config
class TestStaticInnerHashing():

    def test_inner_hashing(self, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac, vlan_ptf_ports, symmetric_hashing):
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
