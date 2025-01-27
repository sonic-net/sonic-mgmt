import os
import yaml
import pytest

import apis.system.reboot as reboot_obj
from spytest import st
from spytest.infra import poll_wait2 as wait_until
from spytest.infra import download_file_from_dut
from infra_utils import is_simulation

'''
                ----------------------------------
                |             Spine0              |
                |---------------------------------|
                | Ethernet1_1       Ethernet1_2   |
                |10.10.10.2/24     10.10.20.2/24  |
                |2001::10:2/64     2002::10:2/64  |
                ----------------------------------
                    /                     \
                   /                       \
            ----------------         ------------------
            |  Ethernet1_1  |        |   Ethrnet1_1   |
            | 10.10.10.1/24 |        |  10.10.20.1/24 |
            | 2001::10:1/64 |        |  2002::10:1/64 |
            |---------------|        |----------------|
            |    Leaf0      |        |     Leaf1      |
            ----------------         ------------------
SpyTestDict([('SD1', 'D1'), ('SD2', 'D2'), ('SD3', 'D3')])),
('D1', 'SD1'),
('D2', 'SD2'),
('D3', 'SD3'),
('D1D2P1', 'Ethernet0'),
('D2D1P1', 'Ethernet0'),
('D1D3P1', 'Ethernet8'),
('D3D1P1', 'Ethernet0'),


'''
nodes = {}
tests = []
negative_tests = []
combo_tests    = []

# Leaf0 Ethernet1_1
leaf0_iface      = ''
leaf0_ip         = '10.10.10.1/24'
leaf0_prefix     = '10.10.10.0/24'
leaf0_ip_v6      = '2001::10:1/64'
leaf0_prefix_v6  = '2001::/64'

# Leaf1 Ethernet1_1
leaf1_iface      = ''
leaf1_ip         = '10.10.20.1/24'
leaf1_prefix     = '10.10.20.0/24'
leaf1_ip_v6      = '2002::10:1/64'
leaf1_prefix_v6  = '2002::/64'

# spine Ethernet1_1
spine0_l0_iface  = ''
spine0_l0_ip     = '10.10.10.2/24'
leaf0_nexthop    = '10.10.10.2'
spine0_l0_ip_v6  = '2001::10:2/64'
leaf0_nexthop_v6 = '2001::10:2'

# spine Ethernet1_2
spine0_l1_iface  = ''
spine0_l1_ip     = '10.10.20.2/24'
leaf1_nexthop    = '10.10.20.2'
spine0_l1_ip_v6  = '2002::10:2/64'
leaf1_nexthop_v6 = '2002::10:2'

ipv4_netmask     = '/24'
ipv6_netmask     = '/64'
packet_count     = 1000

dport            = '1024'
sport            = '1025'

@pytest.fixture(scope="module", autouse=True)
def setup():
    global DUT
    global PKT_SRC
    global PKT_DST

    vars = st.get_testbed_vars()

    nodes['leaf0']   = vars.D2
    nodes['leaf1']   = vars.D3
    nodes['spine0']  = vars.D1

    DUT              = nodes['spine0']
    PKT_SRC          = nodes['leaf0']
    PKT_DST          = nodes['leaf1']

    if is_simulation(DUT):
        pytest.skip("This test is only supported on HW", allow_module_level=True)
        return

    leaf0_iface      = vars.D2D1P1
    leaf1_iface      = vars.D3D1P1
    spine0_l0_iface  = vars.D1D2P1
    spine0_l1_iface  = vars.D1D3P1

    # v4 test cases
    tests.append('v4 enable -dip {} -p {}'.format(leaf1_ip.strip(ipv4_netmask), spine0_l0_iface))
    tests.append('v4 enable -sip {} -p {}'.format(leaf0_ip.strip(ipv4_netmask), spine0_l0_iface))
    tests.append('v4 enable -dip {} -p {}'.format(leaf1_prefix, spine0_l0_iface))
    tests.append('v4 enable -sip {} -p {}'.format(leaf0_prefix, spine0_l0_iface))
    tests.append('v4 enable -dip {} -sip {} -p {}'.format(leaf1_ip.strip(ipv4_netmask), leaf0_ip.strip(ipv4_netmask), spine0_l0_iface))
    tests.append('v4 enable -dip {} -sip {} -p {}'.format(leaf1_prefix, leaf0_prefix, spine0_l0_iface))
    tests.append('v4 enable -ip 6 -dp {} -p {}'.format(dport, spine0_l0_iface))
    tests.append('v4 enable -ip 6 -sp {} -p {}'.format(sport, spine0_l0_iface))
    tests.append('v4 enable -dip {} -sip {} -ip 6 -dp {} -sp {} -p {}'.format(leaf1_ip.strip(ipv4_netmask), leaf0_ip.strip(ipv4_netmask), dport, sport, spine0_l0_iface))
    # v6 test cases
    tests.append('v6 enable -dip {} -p {}'.format(leaf1_ip_v6.strip(ipv6_netmask), spine0_l0_iface))
    tests.append('v6 enable -sip {} -p {}'.format(leaf0_ip_v6.strip(ipv6_netmask), spine0_l0_iface))
    tests.append('v6 enable -dip {} -p {}'.format(leaf1_prefix_v6, spine0_l0_iface))
    tests.append('v6 enable -sip {} -p {}'.format(leaf0_prefix_v6, spine0_l0_iface))
    tests.append('v6 enable -dip {} -sip {} -p {}'.format(leaf1_ip_v6.strip(ipv6_netmask), leaf0_ip_v6.strip(ipv6_netmask), spine0_l0_iface))
    tests.append('v6 enable -dip {} -sip {} -p {}'.format(leaf1_prefix_v6, leaf0_prefix_v6, spine0_l0_iface))
    tests.append('v6 enable -nh 6 -dp {} -p {}'.format(dport, spine0_l0_iface))
    tests.append('v6 enable -nh 6 -sp {} -p {}'.format(sport, spine0_l0_iface))
    tests.append('v6 enable -dip {} -sip {} -nh 6 -dp {} -sp {} -p {}'.format(leaf1_ip_v6.strip(ipv6_netmask), leaf0_ip_v6.strip(ipv6_netmask), dport, sport, spine0_l0_iface))
    # negative tests
    negative_tests.append('v4 enable -dip 1.2.3.4 -p {}'.format(spine0_l0_iface))
    # combo tests
    combo_tests.append('v4 enable -dip {} -sip {} -ip 6 -dp {} -sp {} -p {}'.format(leaf1_ip.strip(ipv4_netmask),leaf0_ip.strip(ipv4_netmask), dport, sport , spine0_l0_iface))
    combo_tests.append('v6 enable -dip {} -sip {} -nh 6 -dp {} -sp {} -p {}'.format(leaf1_ip_v6.strip(ipv6_netmask), leaf0_ip_v6.strip(ipv6_netmask), dport, sport, spine0_l0_iface))

    # program interfaces with IP
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format(leaf0_iface, leaf0_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format(leaf1_iface, leaf1_ip))
    st.config(nodes['spine0'], 'sudo config interface ip add {} {}'.format(spine0_l0_iface, spine0_l0_ip))
    st.config(nodes['spine0'], 'sudo config interface ip add {} {}'.format(spine0_l1_iface, spine0_l1_ip))

    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format(leaf0_iface, leaf0_ip_v6))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format(leaf1_iface, leaf1_ip_v6))
    st.config(nodes['spine0'], 'sudo config interface ip add {} {}'.format(spine0_l0_iface, spine0_l0_ip_v6))
    st.config(nodes['spine0'], 'sudo config interface ip add {} {}'.format(spine0_l1_iface, spine0_l1_ip_v6))

    # Add route
    st.config(nodes['leaf0'], 'sudo config route add prefix {} nexthop {}'.format(leaf1_prefix, leaf0_nexthop))
    st.config(nodes['leaf1'], 'sudo config route add prefix {} nexthop {}'.format(leaf0_prefix, leaf1_nexthop))

    st.config(nodes['leaf0'], 'sudo config route add prefix {} nexthop {}'.format(leaf1_prefix_v6, leaf0_nexthop_v6))
    st.config(nodes['leaf1'], 'sudo config route add prefix {} nexthop {}'.format(leaf0_prefix_v6, leaf1_nexthop_v6))

    # Download decode files for scapy
    download_file_from_dut(DUT, "/usr/lib/python3/dist-packages/sonic_platform/cli/packet_decoder.py" , "/tmp/packet_decoder.py")
    download_file_from_dut(DUT, "/usr/lib/python3/dist-packages/sonic_platform/cli/packet_decode_enums.py" , "/tmp/packet_decode_enums.py")

    yield
    """ If no static route return True
    """
    def check_and_remove_static_route(node, ip_type, cmd):
        st.config(node, cmd)
        output = st.show(node, 'show {} route vrf all static'.format(ip_type))
        if not output:
            return True
        return False

    # Remove route
    # Sonic not able to remove static route with one attempt, adding a retry loop to remove them.
    # Otherwise IP remove command bails out and we see xfail.
    cmd = 'sudo config route del prefix {} nexthop {}'.format(leaf1_prefix, leaf0_nexthop)
    if not wait_until(2, 10, check_and_remove_static_route, nodes['leaf0'], 'ip', cmd):
        st.log('{}: could not delete route with: {}',nodes['leaf0'], cmd)

    cmd = 'sudo config route del prefix {} nexthop {}'.format(leaf0_prefix, leaf1_nexthop)
    if not wait_until(2, 10, check_and_remove_static_route, nodes['leaf1'], 'ip', cmd):
        st.log('{}: could not delete route with: {}',nodes['leaf1'], cmd)

    cmd = 'sudo config route del prefix {} nexthop {}'.format(leaf1_prefix_v6, leaf0_nexthop_v6)
    if not wait_until(2, 10, check_and_remove_static_route, nodes['leaf0'], 'ipv6', cmd):
        st.log('{}: could not delete route with: {}',nodes['leaf0'], cmd)

    cmd = 'sudo config route del prefix {} nexthop {}'.format(leaf0_prefix_v6, leaf1_nexthop_v6)
    if not wait_until(2, 10, check_and_remove_static_route, nodes['leaf1'], 'ipv6', cmd):
        st.log('{}: could not delete route with: {}',nodes['leaf1'], cmd)

    # Remove IP addresses from interfaces
    st.config(nodes['leaf0'], 'sudo config interface ip remove {} {}'.format(leaf0_iface, leaf0_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip remove {} {}'.format(leaf1_iface, leaf1_ip))
    st.config(nodes['spine0'], 'sudo config interface ip remove {} {}'.format(spine0_l0_iface, spine0_l0_ip))
    st.config(nodes['spine0'], 'sudo config interface ip remove {} {}'.format(spine0_l1_iface, spine0_l1_ip))

    st.config(nodes['leaf0'], 'sudo config interface ip remove {} {}'.format(leaf0_iface, leaf0_ip_v6))
    st.config(nodes['leaf1'], 'sudo config interface ip remove {} {}'.format(leaf1_iface, leaf1_ip_v6))
    st.config(nodes['spine0'], 'sudo config interface ip remove {} {}'.format(spine0_l0_iface, spine0_l0_ip_v6))
    st.config(nodes['spine0'], 'sudo config interface ip remove {} {}'.format(spine0_l1_iface, spine0_l1_ip_v6))

    os.remove("/tmp/packet_decoder.py")
    os.remove("/tmp/packet_decode_enums.py")


@pytest.fixture(scope="function", autouse=True)
def setup_and_cleanup():
    # wait for packet capture infra to be up
    if not wait_until(10, 300, check_dut_health):
        st.error('DUT is not ready', DUT)
        st.report_fail('test_case_failed', DUT)
        return
    yield
    # remove configs if not removed
    st.config(DUT, 'sudo config platform cisco packet-debug v4 disable')
    st.config(DUT, 'sudo config platform cisco packet-debug v6 disable')

def check_dut_health():
    output = st.show(DUT, 'sudo show platform npu packet-debug status', skip_tmpl=True, skip_error_check=True)
    if 'Packet capture' in output:
        return True
    else:
        return False

def check_capture(node, negative_test = False, count = packet_count):
    output = st.show(node, 'sudo show platform npu packet-debug capture -c', skip_tmpl=True, skip_error_check=True)
    # 4. Verify output captured all 1000 packets
    # Wrote 1000 packets to pcap file.  dump captured in /var/dump/capture_0.pcap
    # Capture buffer is cleared.
    words = output.split()
    if not negative_test:
        assert(words[0] == "Wrote")
        if words[0] == "Wrote":
            assert int(words[1]) >= count
            for word in words:
                if word.startswith('/var/dump'):
                    remote_pcap_file = word
                    return remote_pcap_file
    else:
        if words[0] == "Wrote":
            assert int(words[1]) == 0
        else:
            assert('disabled' in output or 'not enabled' in output)
    return None


def validate_capture(traffic_type, remote_file_name):
    local_file = '/tmp/capture.pcap'
    # Download scapy decode files from DUT
    download_file_from_dut(DUT, remote_file_name , local_file)
    import sys
    sys.path.append('/tmp')
    import packet_decode_enums as enums
    from scapy.utils import PcapReader
    import packet_decoder

    decodedPkts = PcapReader(local_file).read_all()
    # Validate 1st decoded packet
    if traffic_type == 'v4':
        assert decodedPkts[0][packet_decoder.IP].src == leaf0_ip.strip(ipv4_netmask)
        assert decodedPkts[0][packet_decoder.IP].dst == leaf1_ip.strip(ipv4_netmask)
        assert decodedPkts[0][packet_decoder.IP].sport == eval(sport)
        assert decodedPkts[0][packet_decoder.IP].dport == eval(dport)
    elif traffic_type == 'v6':
        assert decodedPkts[0][packet_decoder.IPv6].src == leaf0_ip_v6.strip(ipv6_netmask)
        assert decodedPkts[0][packet_decoder.IPv6].dst == leaf1_ip_v6.strip(ipv6_netmask)
        assert decodedPkts[0][packet_decoder.IPv6].sport == eval(sport)
        assert decodedPkts[0][packet_decoder.IPv6].dport == eval(dport)
    os.remove(local_file)


def send_packet(traffic_type, count = packet_count):
    if traffic_type == 'v4':
        st.show(PKT_SRC, 'sudo /usr/bin/python -c "from scapy.all import *; send(IP(dst=\'{}\')/TCP(dport={}, sport={}, flags=\'S\'), count={})"'.format(leaf1_ip.strip(ipv4_netmask), dport, sport, count), skip_tmpl=True, skip_error_check=True)
    elif traffic_type == 'v6':
        st.show(PKT_SRC, 'sudo /usr/bin/python -c "from scapy.all import *; send(IPv6(dst=\'{}\')/TCP(dport={}, sport={}, flags=\'S\'), count={})"'.format(leaf1_ip_v6.strip(ipv6_netmask), dport, sport, count), skip_tmpl=True, skip_error_check=True)


""" Test feature enable/disable
"""
def test_enable():
    # start with a clean slate
    st.config(DUT, 'sudo config platform cisco packet-debug v4 disable')
    st.config(DUT, 'sudo config platform cisco packet-debug v6 disable')
    # enable feature
    output = st.config(DUT, 'sudo config platform cisco packet-debug v4 enable -dip 1.2.3.4 -p {},{}'.format(spine0_l0_iface, spine0_l1_iface))
    assert "Packet capture enabled" in output
    # enable it again, it shall throw error.
    output = st.config(DUT, 'sudo config platform cisco packet-debug v4 enable -dip 5.6.7.8 -p {},{}'.format(spine0_l0_iface, spine0_l1_iface))
    assert "session is already enabled" in output
    # disable and repeat for v6
    output = st.config(DUT, 'sudo config platform cisco packet-debug v4 disable')
    assert "Packet capture disabled" in output
    output = st.config(DUT, 'sudo config platform cisco packet-debug v6 enable -dip 1234::56 -p {},{}'.format(spine0_l0_iface, spine0_l1_iface))
    assert "Packet capture enabled" in output
    output = st.config(DUT, 'sudo config platform cisco packet-debug v6 enable -dip 5678::9 -p {},{}'.format(spine0_l0_iface, spine0_l1_iface))
    assert "session is already enabled" in output
    output = st.config(DUT, 'sudo config platform cisco packet-debug v6 disable')
    assert "Packet capture disabled" in output
    st.report_pass('test_case_passed', DUT)


""" Test various combination of ipv4 or ipv6 packets
"""
def test_capture():
    for test in tests:
        st.log('Running tests with criteria {}'.format(test), DUT)
        # 1. configure spine0 to intercept packets
        st.config(DUT, 'sudo config platform cisco packet-debug {}'.format(test))
        # 2 clear capture buffer
        output = st.show(DUT, 'sudo show platform npu packet-debug capture -c', skip_tmpl=True, skip_error_check=True)
        # 3. Send packets from leaf0 towards leaf1. It shall go via spine0
        send_packet(test.split()[0])
        # 4. Validate capture
        remote_file_name = check_capture(DUT)
        validate_capture(test.split()[0], remote_file_name)
        # 5. Disable config
        st.config(DUT, 'sudo config platform cisco packet-debug {} disable'.format(test.split()[0]))
        # 6. Send packets and verify no capture
        send_packet(test.split()[0])
        check_capture(DUT, negative_test = True)
    st.report_pass('test_case_passed', DUT)


""" Test few negative tests of ipv4 or ipv6 packets
"""
def test_capture_negative():
    for test in negative_tests:
        st.log('Running tests with criteria {}'.format(test), DUT)
        # 1. configure spine0 to intercept packets
        st.config(DUT, 'sudo config platform cisco packet-debug {}'.format(test))
        # 2 clear capture buffer
        output = st.show(DUT, 'sudo show platform npu packet-debug capture -c', skip_tmpl=True, skip_error_check=True)
        # 3. Send packets from leaf0 towards leaf1. It shall go via spine0
        send_packet(test.split()[0])
        # 4. Validate capture
        check_capture(DUT, negative_test = True)
        # 5. disable config
        st.config(DUT, 'sudo config platform cisco packet-debug {} disable'.format(test.split()[0]))
    st.report_pass('test_case_passed', DUT)


""" Test a combination of ipv4 and ipv6 packets
"""
def test_capture_combo():
    # 1. setup all combo criteria
    total_count = 0
    for test in combo_tests:
        st.log('Running combo tests with criteria {}'.format(test), DUT)
        st.config(DUT, 'sudo config platform cisco packet-debug {}'.format(test))
        send_packet(test.split()[0], count=100)
        total_count+=100

    # 2. Check we captured all the packets
    check_capture(DUT, count = total_count)
    st.report_pass('test_case_passed', DUT)


""" Do config reload and verify feature works post reload
"""
def test_config_reload():
    status = reboot_obj.config_reload(DUT)
    if status:
        st.banner("config reload cmd success!")
    else:
        st.banner("config reload cmd failed!")
        st.report_fail("test_case_failed")
    if not wait_until(10, 600, check_dut_health):
        st.error('DUT is not ready', DUT)
        st.report_fail('test_case_failed', DUT)
    # Configure and test one flow.
    st.log('Running tests with criteria {}'.format(tests[0]), DUT)
    # 1. configure spine0 to intercept packets
    st.config(DUT, 'sudo config platform cisco packet-debug {}'.format(tests[0]))
    # 2 clear capture buffer
    output = st.show(DUT, 'sudo show platform npu packet-debug capture -c', skip_tmpl=True, skip_error_check=True)
    # 3. Send packets from leaf0 towards leaf1. It shall go via spine0
    send_packet(tests[0].split()[0])
    # 4. Validate capture
    check_capture(DUT)
    # 5. Disable config
    st.config(DUT, 'sudo config platform cisco packet-debug {} disable'.format(tests[0].split()[0]))
    # 6. Send packets and verify no capture
    send_packet(tests[0].split()[0])
    check_capture(DUT, negative_test = True)
    st.report_pass('test_case_passed', DUT)

