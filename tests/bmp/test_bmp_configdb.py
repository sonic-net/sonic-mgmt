import logging
import pytest

from bmp.helper import enable_bmp_neighbor_table, enable_bmp_rib_in_table, enable_bmp_rib_out_table
from bmp.helper import disable_bmp_neighbor_table, disable_bmp_rib_in_table, disable_bmp_rib_out_table
from bmp.helper import show_bmp_tables


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def check_table_status(output, table_name):
    # output for show tables looks like below:
    # BMP tables:
    # Table_Name          Enabled
    # ------------------  ---------
    # bgp_neighbor_table  true
    # bgp_rib_in_table    true
    # bgp_rib_out_table   true
    table_lines = output['stdout_lines'][3:]  # Exclude the header lines
    for line in table_lines:
        current_table_name, enabled = line.split()
        if current_table_name == table_name:
            return enabled.lower()


def test_bmp_configdb(duthosts, rand_one_dut_hostname, localhost):

    duthost = duthosts[rand_one_dut_hostname]

    # enable all table by default
    enable_bmp_neighbor_table(duthost)
    enable_bmp_rib_in_table(duthost)
    enable_bmp_rib_out_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(output, table_name)
    assert (status == 'true'), (
        "Enabling all BMP tables by default failed for bgp_neighbor_table. Actual status: {}."
    ).format(status)

    # disable bgp_neighbor_table
    logger.info('disable bmp neighbor table on dut hosts')
    disable_bmp_neighbor_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(output, table_name)
    assert (status == 'false'), (
        "Disabling bgp_neighbor_table failed. Actual status: {}."
    ).format(status)

    # enable bgp_neighbor_table
    logger.info('enable bmp neighbor table on dut hosts')
    enable_bmp_neighbor_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(output, table_name)
    assert (status == 'true'), (
        "Enabling bgp_neighbor_table failed. Actual status: {}."
    ).format(status)

    # disable bgp_rib_in_table
    logger.info('disable bmp rib-in table on dut hosts')
    disable_bmp_rib_in_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_in_table'
    status = check_table_status(output, table_name)
    assert (status == 'false'), (
        "Disabling bgp_rib_in_table failed. Actual status: {}."
    ).format(status)

    # enable bgp_rib_in_table
    logger.info('enable bmp rib-in table on dut hosts')
    enable_bmp_rib_in_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_in_table'
    status = check_table_status(output, table_name)
    assert (status == 'true'), (
        "Enabling bgp_rib_in_table failed. Actual status: {}."
    ).format(status)

    # disable bgp_rib_out_table
    logger.info('disable bmp rib-out table on dut hosts')
    disable_bmp_rib_out_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_out_table'
    status = check_table_status(output, table_name)
    assert (status == 'false'), (
        "Disabling bgp_rib_out_table failed. Actual status: {}."
    ).format(status)

    # enable bgp_rib_out_table
    logger.info('enable bmp rib-out table on dut hosts')
    enable_bmp_rib_out_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_rib_out_table'
    status = check_table_status(output, table_name)
    assert (status == 'true'), (
        "Enabling bgp_rib_out_table failed. Actual status: {}."
    ).format(status)
