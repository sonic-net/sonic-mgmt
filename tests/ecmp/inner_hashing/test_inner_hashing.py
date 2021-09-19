# Summary: Inner packet hashing test
# How to run this test: sudo ./run_tests.sh -n <tb name> -i <inventory files> -u -m group -e --skip_sanity -l info -c ecmp/test_inner_hashing.py

import logging
import pytest

from datetime import datetime
from tests.ptf_runner import ptf_runner
from tests.ecmp.inner_hashing.conftest import get_src_dst_ip_range, FIB_INFO_FILE_DST, VXLAN_PORT, PTF_QLEN

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]


def test_inner_hashing(hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac, vlan_ptf_ports, symmetric_hashing):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/inner_hash_test.InnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)

    outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
    inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

    balancing_test_times = 150

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
                       "symmetric_hashing": symmetric_hashing},
              log_file=log_file,
              qlen=PTF_QLEN,
              socket_recv_size=16384)
