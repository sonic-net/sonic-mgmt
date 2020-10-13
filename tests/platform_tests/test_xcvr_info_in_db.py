"""
Check xcvrd information in DB

This script is to cover the test case 'Check xcvrd information in DB' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os
import pytest
from tests.common.platform.transceiver_utils import check_transceiver_status
from tests.common.fixtures.conn_graph_facts import conn_graph_facts

pytestmark = [
    pytest.mark.topology('any')
]

def test_xcvr_info_in_db(duthost, conn_graph_facts):
    """
    @summary: This test case is to verify that xcvrd works as expected by checking transceiver information in DB
    """
    logging.info("Check transceiver status")
    check_transceiver_status(duthost, conn_graph_facts["device_conn"])
