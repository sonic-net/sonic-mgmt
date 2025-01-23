import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from bmp.helper import enable_bmp_neighbor_table, enable_bmp_rib_in_table, enable_bmp_rib_out_table
from bmp.helper import disable_bmp_neighbor_table, disable_bmp_rib_in_table, disable_bmp_rib_out_table
from bmp.helper import show_bmp_tables



logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

def check_table_status(table_name):
    output = """
    BMP tables:
    Table_Name          Enabled
    ------------------  ---------
    bgp_neighbor_table  true
    bgp_rib_in_table    true
    bgp_rib_out_table   true
    """

    lines = [line.strip() for line in output.split('\n')]

    table_line = [line for line in lines if line.startswith(table_name)][0]
    _, table_value = table_line.split()

    return table_value

def test_bmp_configdb(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]

    logger.info('enable bmp neighbor table on dut hosts')
    enable_bmp_neighbor_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(table_name)
    assert(status == 'true')

    logger.info('disable bmp neighbor table on dut hosts')
    disable_bmp_neighbor_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(table_name)
    assert(status == 'false')

    logger.info('enable bmp rib-in table on dut hosts')
    enable_bmp_rib_in_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_in_table'
    status = check_table_status(table_name)
    assert(status == 'true')

    logger.info('disable bmp rib-in table on dut hosts')
    disable_bmp_rib_in_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_in_table'
    status = check_table_status(table_name)
    assert(status == 'false')

    logger.info('enable bmp rib-out table on dut hosts')
    enable_bmp_rib_out_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_out_table'
    status = check_table_status(table_name)
    assert(status == 'true')

    logger.info('disable bmp rib-out table on dut hosts')
    disable_bmp_rib_out_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_out_table'
    status = check_table_status(table_name)
    assert(status == 'false')

