import logging
import threading
import pytest
import random

from datetime import datetime
from tests.common import reboot
from tests.ecmp.inner_hashing.conftest import get_src_dst_ip_range, FIB_INFO_FILE_DST, VXLAN_PORT, PTF_QLEN
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.asic('mellanox')
]


def test_inner_hashing(duthost, hash_keys, ptfhost, outer_ipver, inner_ipver, router_mac,
                       vlan_ptf_ports, symmetric_hashing, localhost):
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
    log_file = "/tmp/wr_inner_hash_test.InnerHashTest.{}.{}.{}.log".format(outer_ipver, inner_ipver, timestamp)
    logging.info("PTF log file: %s" % log_file)

    # to reduce test run time, check one of encapsulation formats
    outer_encap_format = random.choice([["vxlan"], ["nvgre"]])
    logging.info("Tested encapsulation format: {}".format(outer_encap_format[0]))

    outer_src_ip_range, outer_dst_ip_range = get_src_dst_ip_range(outer_ipver)
    inner_src_ip_range, inner_dst_ip_range = get_src_dst_ip_range(inner_ipver)

    balancing_test_times = 200

    duthost.command('sudo config save -y')
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
                       "outer_encap_formats": outer_encap_format,
                       "symmetric_hashing": symmetric_hashing},
               log_file=log_file,
               qlen=PTF_QLEN,
               socket_recv_size=16384)
    reboot_thr.join()
