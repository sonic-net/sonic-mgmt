import logging
import pytest
import re

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
    lines = [line.strip() for line in output.split('\n')]

    table_line = [line for line in lines if line.startswith(table_name)][0]
    _, table_value = table_line.split()

    return table_value


def check_syslog__change(duthost, times):
    last_logs = duthost.shell("tail -n 1000 /var/log/syslog",
                              module_ignore_errors=True)["stdout"]
    matches = re.findall('bmpcfgd: config update', last_logs)
    return len(matches) == times


def test_bmp_configdb(duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    # enable all table by default
    enable_bmp_neighbor_table(duthost)
    enable_bmp_rib_in_table(duthost)
    enable_bmp_rib_out_table(duthost)
    assert (check_syslog__change(duthost, 3))
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(output, table_name)
    assert (status == 'true')

    logger.info('disable bmp neighbor table on dut hosts')
    disable_bmp_neighbor_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(output, table_name)
    assert (status == 'false')
    assert (check_syslog__change(duthost, 4))

    logger.info('enable bmp neighbor table on dut hosts')
    enable_bmp_neighbor_table(duthost)
    output = show_bmp_tables(duthost)
    table_name = 'bgp_neighbor_table'
    status = check_table_status(output, table_name)
    assert (status == 'true')
    assert (check_syslog__change(duthost, 5))

    logger.info('disable bmp rib-in table on dut hosts')
    disable_bmp_rib_in_table(duthost)
    show_bmp_tables(duthost)
    table_name = 'bgp_rib_in_table'
    status = check_table_status(table_name)
    assert (status == 'false')
    assert (check_syslog__change(duthost, 6))

    logger.info('enable bmp rib-in table on dut hosts')
    enable_bmp_rib_in_table(duthost)
    show_bmp_tables(duthost)
    table_name = 'bgp_rib_in_table'
    status = check_table_status(table_name)
    assert (status == 'true')
    assert (check_syslog__change(duthost, 7))

    logger.info('disable bmp rib-out table on dut hosts')
    disable_bmp_rib_out_table(duthost)
    show_bmp_tables(duthost)
    table_name = 'bgp_rib_out_table'
    status = check_table_status(table_name)
    assert (status == 'false')
    assert (check_syslog__change(duthost, 8))

    logger.info('enable bmp rib-out table on dut hosts')
    enable_bmp_rib_out_table(duthost)
    show_bmp_tables(duthost)
    table_name = 'bgp_rib_out_table'
    status = check_table_status(table_name)
    assert (status == 'true')
    assert (check_syslog__change(duthost, 9))
