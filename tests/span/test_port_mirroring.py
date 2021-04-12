'''
Test local port mirroring on SONiC
'''

import pytest

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # lgtm[py/unused-import]
from span_helpers import send_and_verify_mirrored_packet

pytestmark = [
    pytest.mark.topology('t0')
]

def test_mirroring_rx(ptfadapter, setup_session):
    '''
    Test case #1
    Verify ingress direction session

    Steps:
        1. Create ICMP packet
        2. Send packet from PTF to DUT
        3. Verify that packet is mirrored to monitor port

    Pass Criteria: PTF gets ICMP packet on monitor port.
    '''
    send_and_verify_mirrored_packet(ptfadapter,
                                    setup_session['source1_index'],
                                    setup_session['destination_index'])

def test_mirroring_tx(ptfadapter, setup_session):
    '''
    Test case #2
    Verify egress direction session

    Steps:
        1. Create ICMP packet
        2. Send packet from DUT to PTF
        3. Verify that packet is mirrored to monitor port

    Pass Criteria: PTF gets ICMP packet on monitor port.
    '''
    send_and_verify_mirrored_packet(ptfadapter,
                                    setup_session['source2_index'],
                                    setup_session['destination_index'])

def test_mirroring_both(ptfadapter, setup_session):
    '''
    Test case #3
    Verify bidirectional session

    Steps:
        1. Create ICMP packet
        2. Send packet from PTF to DUT
        3. Verify that packet is mirrored to monitor port
        4. Create ICMP packet
        5. Send packet from DUT to PTF
        6. Verify that packet is mirrored to monitor port

    Pass Criteria: PTF gets both ICMP packets on monitor port.
    '''
    send_and_verify_mirrored_packet(ptfadapter,
                                    setup_session['source1_index'],
                                    setup_session['destination_index'])

    send_and_verify_mirrored_packet(ptfadapter,
                                    setup_session['source2_index'],
                                    setup_session['destination_index'])

def test_mirroring_multiple_source(ptfadapter, setup_session):
    '''
    Test case #4
    Verify ingress direction session with multiple source ports

    Steps:
        1. Create ICMP packet
        2. Send packet from PTF to first source port on DUT
        3. Verify that packet is mirrored to monitor port
        4. Create ICMP packet
        5. Send packet from PTF to second source port on DUT
        6. Verify that packet is mirrored to monitor port

    Pass Criteria: PTF gets both ICMP packets on monitor port.
    '''
    send_and_verify_mirrored_packet(ptfadapter,
                                    setup_session['source1_index'],
                                    setup_session['destination_index'])

    send_and_verify_mirrored_packet(ptfadapter,
                                    setup_session['source2_index'],
                                    setup_session['destination_index'])
