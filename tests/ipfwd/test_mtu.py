import pytest
import time
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from datetime import datetime

pytestmark = [
    pytest.mark.topology('t1')
]

@pytest.mark.parametrize("mtu", [1514,9114])
def test_mtu(tbinfo, duthost, ptfhost, mtu):

    testbed_type = tbinfo['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_test.{}-{}.log".format(mtu,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu },
               log_file=log_file,
               socket_recv_size=16384)
