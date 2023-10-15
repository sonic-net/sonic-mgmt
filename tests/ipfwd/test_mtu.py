import pytest
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa F401
from tests.ptf_runner import ptf_runner
from datetime import datetime

pytestmark = [
    pytest.mark.topology('t1', 't2'),
    pytest.mark.device_type('vs')
]


@pytest.mark.parametrize("mtu", [1514, 9114])
def test_mtu(tbinfo, ptfhost, mtu, gather_facts):

    testbed_type = tbinfo['topo']['name']

    log_file = "/tmp/mtu_test.{}-{}.log".format(mtu, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": gather_facts['src_router_mac'],
                       "testbed_mtu": mtu,
                       "src_host_ip": gather_facts['src_host_ipv4'],
                       "src_router_ip": gather_facts['src_router_ipv4'],
                       "dst_host_ip": gather_facts['dst_host_ipv4'],
                       "src_host_ipv6": gather_facts['src_host_ipv6'],
                       "src_router_ipv6": gather_facts['src_router_ipv6'],
                       "dst_host_ipv6": gather_facts['dst_host_ipv6'],
                       "src_ptf_port_list": gather_facts['src_port_ids'],
                       "dst_ptf_port_list": gather_facts['dst_port_ids']
                       },
               log_file=log_file,
               socket_recv_size=16384,
               is_python3=True)
