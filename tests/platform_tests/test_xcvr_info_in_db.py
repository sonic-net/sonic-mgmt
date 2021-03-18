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

def test_xcvr_info_in_db(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to verify that xcvrd works as expected by checking transceiver information in DB
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logging.info("Check transceiver status")
    all_interfaces = conn_graph_facts["device_conn"][duthost.hostname]

    if enum_frontend_asic_index is not None:
        # Get the interface pertaining to that asic
        interface_list = get_port_map(duthost, enum_frontend_asic_index)

        # Check if the interfaces of this AISC is present in conn_graph_facts
        all_interfaces = {k:v for k, v in interface_list.items() if k in conn_graph_facts["device_conn"][duthost.hostname]}
        logging.info("ASIC {} interface_list {}".format(enum_frontend_asic_index, all_interfaces))

    check_transceiver_status(duthost, enum_frontend_asic_index, all_interfaces, xcvr_skip_list);
