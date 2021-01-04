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
from tests.common.platform.interface_utils import get_port_map
from tests.common.fixtures.conn_graph_facts import conn_graph_facts

pytestmark = [
    pytest.mark.topology('any')
]

def test_xcvr_info_in_db(duthosts, dut_index, frontend_asic_index, conn_graph_facts):
    """
    @summary: This test case is to verify that xcvrd works as expected by checking transceiver information in DB
    """
    logging.info("Check transceiver status")
    duthost = duthosts[dut_index]
    all_interfaces = conn_graph_facts["device_conn"]

    if frontend_asic_index is not None:
        # Get the interface pertaining to that asic
        interface_list = get_port_map(duthost, frontend_asic_index)

        new_intf_dict = {k:v for k, v in interface_list.items() if k in all_interfaces}
        all_interfaces = new_intf_dict
        logging.info("ASIC {} interface_list {}".format(frontend_asic_index, all_interfaces))

    check_transceiver_status(duthost, frontend_asic_index, all_interfaces);
