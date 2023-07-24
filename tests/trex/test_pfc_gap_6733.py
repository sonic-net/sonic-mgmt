'''This script is to test PFC gap from community.
The site is : https://github.com/sonic-net/sonic-mgmt/issues/6733
'''
import logging

import pytest

pytestmark = [
    pytest.mark.topology('t0')
]

def test_pfc_gap_6733(trexhost, duthost):
    trexhost.set_dut_buffer()
    trexhost.set_dut_pfc("55", [0])
    trexhost.set_dut_pfc_counter()
    trexhost.set_dut_ip_route(duthost)
    trexhost.start_trex_server()
    trexhost.learn_arp()
    trexhost.portattr()
    trexhost.start_flow()
    logging.info("pfc_counters before sending pfc packets")
    trexhost.pfc_statistics()
    trexhost.start_pfc_flow(ls_octet='00')
    logging.info("pfc_counters after sending pfc packets, with class enable vector set 00")
    trexhost.pfc_statistics()
    trexhost.start_pfc_flow(ls_octet='01')
    logging.info("pfc_counters after sending pfc packets, with class enable vector set 01")
    trexhost.pfc_statistics()
    trexhost.del_dut_pfc('55', [0])
    trexhost.del_dut_buffer(profile='pg-lossless')
