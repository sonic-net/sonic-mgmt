import pytest
import time
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode
from tests.ptf_runner import ptf_runner
from datetime import datetime

pytestmark = [
    pytest.mark.topology('t1', 't2'),
    pytest.mark.device_type('vs')
]

DUT_PORT_NAME_LIST = []
dut_def_mtu = 9100

@pytest.fixture(scope="module", autouse=True)
def get_dut_port_name_list(duthost):
    global DUT_PORT_NAME_LIST
    res = duthost.shell("show interfaces description")
    stdout_lines = res['stdout_lines']
    for line in stdout_lines:
        port_name = line.split()[0]
        if port_name.startswith("Ethernet"):
            DUT_PORT_NAME_LIST.append(port_name)

@pytest.fixture(scope="function", autouse=True)
def setup_port_mtu(duthost, get_dut_port_name_list, gather_facts):

    yield
    for port in gather_facts['dst_port_ids']:
        duthost.shell('config interface mtu {} {}'.format(DUT_PORT_NAME_LIST[port],dut_def_mtu))
    for port in gather_facts['src_port_ids']:
        duthost.shell('config interface mtu {} {}'.format(DUT_PORT_NAME_LIST[port],dut_def_mtu))

@pytest.mark.parametrize("mtu", [1514,9114])
def test_mtu(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, mtu, gather_facts):
    """
    Before the test starts, it is given that the mtu of the ports used in the test is set as
    default value.(L3 MTU=9100, L2 MTU=9014)
    Invoke ptf test 'mtu_test.MtuTest' to inject packets with size 'mtu'(i.e. l2 mtu) which is set as
    parametrized arg
    All of the values listed in parametrized arg 'mtu' must be smaller or equal to the default mtu
    size.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    topo_type = tbinfo['topo']['type']
    if topo_type not in ('t1', 't2'):
        pytest.skip("Unsupported topology")

    testbed_type = tbinfo['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_test.{}-{}.log".format(mtu,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)

    expect_drop_pkt = False

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu,
                       "src_host_ip": gather_facts['src_host_ipv4'],
                       "src_router_ip": gather_facts['src_router_ipv4'],
                       "dst_host_ip": gather_facts['dst_host_ipv4'],
                       "src_host_ipv6": gather_facts['src_host_ipv6'],
                       "src_router_ipv6": gather_facts['src_router_ipv6'],
                       "dst_host_ipv6": gather_facts['dst_host_ipv6'],
                       "src_ptf_port_list": gather_facts['src_port_ids'],
                       "dst_ptf_port_list": gather_facts['dst_port_ids'],
                       "expect_drop_pkt": expect_drop_pkt
                       },
               log_file=log_file,
               socket_recv_size=16384)

@pytest.mark.parametrize("mtu", [1514,1515,9114])
def test_mtu_change(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, mtu, gather_facts):
    """
    The test set the l2 mtu of the ports used in the test is set as 1514.
    Invoke ptf test 'mtu_test.MtuTest' to inject packets with size 'mtu'(l2 mtu) which is set as
    parametrized arg
    For the values listed in parametrized arg 'mtu' that are larger than the 1514, it is expected
    that the ptf test resut is falied. For the values listed in parametrized arg 'mtu' that are less
    than or equal to 1514, it is expected the ptf test is passed.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    topo_type = tbinfo['topo']['type']
    if topo_type not in ('t1', 't2'):
        pytest.skip("Unsupported topology")

    testbed_type = tbinfo['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_change_test.{}-{}.log".format(mtu,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)

    dut_intf_mtu_size = 1500

    for port in gather_facts['dst_port_ids']:
        duthost.shell('config interface mtu {} {}'.format(DUT_PORT_NAME_LIST[port],dut_intf_mtu_size))
    for port in gather_facts['src_port_ids']:
        duthost.shell('config interface mtu {} {}'.format(DUT_PORT_NAME_LIST[port],dut_intf_mtu_size))

    expect_drop_pkt = False
    if (dut_intf_mtu_size+14) < mtu:
        expect_drop_pkt = True

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu,
                       "src_host_ip": gather_facts['src_host_ipv4'],
                       "src_router_ip": gather_facts['src_router_ipv4'],
                       "dst_host_ip": gather_facts['dst_host_ipv4'],
                       "src_host_ipv6": gather_facts['src_host_ipv6'],
                       "src_router_ipv6": gather_facts['src_router_ipv6'],
                       "dst_host_ipv6": gather_facts['dst_host_ipv6'],
                       "src_ptf_port_list": gather_facts['src_port_ids'],
                       "dst_ptf_port_list": gather_facts['dst_port_ids'],
                       "expect_drop_pkt": expect_drop_pkt
                       },
               log_file=log_file,
               socket_recv_size=16384)


@pytest.mark.parametrize("mtu_boundary, boundary_type", [(1500, "lower"), (9216,"upper")])
def test_mtu_boundary(tbinfo, duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, gather_facts, mtu_boundary, boundary_type):
    """
        Set the value mtu_boundary as mtu on the ports used in this test.
        Invoke ptf test 'mtu_test.MtuTest' to inject packets with size
        mtu_boundary(i.e. l2 mtu) which is set as parametrized arg. The ptf test is expected to pass.

        When 'boundary_type' is upper:
            Set the value mtu_boundary+1 as mtu on the ports used in this test.
            It is expected that all of the executed commands to set mtu are failed on all of the ports
            used in this test.
        When 'boundary_type' is lower:
            Set the value mtu_boundary-1 as mtu on the ports used in this test.
            It is expected that all of the executed commands to set mtu are failed on all of the ports
            used in this test.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    topo_type = tbinfo['topo']['type']
    if topo_type not in ('t1', 't2'):
        pytest.skip("Unsupported topology")

    testbed_type = tbinfo['topo']['name']
    router_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0].decode("utf-8")

    log_file = "/tmp/mtu_change_test.{}-{}.log".format(mtu_boundary,datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    logging.info("Starting MTU test. PTF log file: %s" % log_file)

    if boundary_type == "lower" :
        mtu_expect_fail=mtu_boundary-1
    elif boundary_type == "upper":
        mtu_expect_fail =mtu_boundary+1
    else:
        logging.info("no boundary_type!!")
        assert(0)
    # test set boundary
    result=duthost.shell(cmd='config interface mtu Ethernet0 {}'.format(mtu_expect_fail),module_ignore_errors=True)
    assert("Error: Interface MTU is invalid. Please enter a valid MTU" in result["stderr"] )

    for port in gather_facts['dst_port_ids']:
        duthost.shell('config interface mtu {} {}'.format(DUT_PORT_NAME_LIST[port],mtu_boundary))
    for port in gather_facts['src_port_ids']:
        duthost.shell('config interface mtu {} {}'.format(DUT_PORT_NAME_LIST[port],mtu_boundary))

    ptf_runner(ptfhost,
               "ptftests",
               "mtu_test.MtuTest",
               platform_dir="ptftests",
               params={"testbed_type": testbed_type,
                       "router_mac": router_mac,
                       "testbed_mtu": mtu_boundary,
                       "src_host_ip": gather_facts['src_host_ipv4'],
                       "src_router_ip": gather_facts['src_router_ipv4'],
                       "dst_host_ip": gather_facts['dst_host_ipv4'],
                       "src_host_ipv6": gather_facts['src_host_ipv6'],
                       "src_router_ipv6": gather_facts['src_router_ipv6'],
                       "dst_host_ipv6": gather_facts['dst_host_ipv6'],
                       "src_ptf_port_list": gather_facts['src_port_ids'],
                       "dst_ptf_port_list": gather_facts['dst_port_ids'],
                       "expect_drop_pkt": False
                       },
               log_file=log_file,
               socket_recv_size=16384)
