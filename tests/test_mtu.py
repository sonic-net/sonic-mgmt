import pytest
import time
import logging
from ptf_runner import ptf_runner

from datetime import datetime


@pytest.mark.parametrize("mtu", [1514,9114])
def test_mtu(testbed, duthost, ptfhost, mtu):

    testbed_type = testbed['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_test.{}-{}.log".format(mtu,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)
    ptfhost.copy(src="ptftests", dest="/root")

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu },
               log_file=log_file,
               socket_recv_size=16384)
