'''
Helper functions for span tests
'''

import ptf.testutils as testutils


def send_and_verify_mirrored_packet(ptfadapter, src_port, monitor):
    '''
    Send packet from ptf and verify it on monitor port

    Args:
        ptfadapter: ptfadapter fixture
        src_port: ptf port index, from which packet will be sent
        monitor: ptf port index, where packet will be verified on
    '''
    src_mac = ptfadapter.dataplane.get_mac(0, src_port)

    pkt = testutils.simple_icmp_packet(eth_src=src_mac, eth_dst='ff:ff:ff:ff:ff:ff')

    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, src_port, pkt)
    # The monitor port is dedicated to the SPAN session, so it will not receive or forward other traffic.
    # Therefore, we only expect 1 copy of pkt to be received on the monitor port (even though pkt's eth_dst is set to
    # the broadcast address). All other ports (except the src_port) should also receive a copy of pkt because of the
    # broadcast destination MAC.
    testutils.verify_packet(ptfadapter, pkt, monitor)
