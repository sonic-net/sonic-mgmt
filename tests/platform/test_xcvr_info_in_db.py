"""
Check xcvrd information in DB

This script is to cover the test case 'Check xcvrd information in DB' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os

from check_transceiver_status import check_transceiver_status
from common.fixtures.conn_graph_facts import conn_graph_facts


def test_xcvr_info_in_db(testbed_devices, conn_graph_facts):
    """
    @summary: This test case is to verify that xcvrd works as expected by checking transceiver information in DB
    """
    dut = testbed_devices["dut"]

    logging.info("Check transceiver status")
    check_transceiver_status(dut, conn_graph_facts["device_conn"])
