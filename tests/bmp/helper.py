
import logging
from tests.common.helpers.bmp_utils import BMPEnvironment


logger = logging.getLogger(__name__)


def bmp_container(duthost):
    env = BMPEnvironment(duthost)
    return env.bmp_container


def dump_bmp_log(duthost):
    env = BMPEnvironment(duthost)
    dut_command = "docker exec %s cat /var/log/openbmpd.log" % (env.bmp_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("BMP log: " + res['stdout'])


def dump_system_status(duthost):
    env = BMPEnvironment(duthost)
    dut_command = "docker exec %s ps -efwww" % (env.bmp_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("BMP process: " + res['stdout'])
    dut_command = "docker exec %s date" % (env.bmp_container)
    res = duthost.shell(dut_command, module_ignore_errors=True)
    logger.info("System time: " + res['stdout'] + res['stderr'])


def check_bmp_status(duthost):
    env = BMPEnvironment(duthost)
    dut_command = "docker exec %s supervisorctl status %s" % (env.bmp_container, env.bmp_program)
    output = duthost.shell(dut_command, module_ignore_errors=True)
    logging.info("check_bmp_status output is: {}".format(output))

    return "RUNNING" in output['stdout']


"""
    Usage: config bmp [OPTIONS] COMMAND [ARGS]...

    BMP-related configuration

    Options:
    -h, -?, --help  Show this message and exit.

    Commands:
    disable  Disable BMP table dump
    enable   Enable BMP table dump
"""


def enable_bmp_neighbor_table(duthost):

    cmd_enable_neighbore_table = 'sudo config bmp enable bgp-neighbor-table'
    logging.debug("enable_bmp_neighbor_table command is: {}".format(cmd_enable_neighbore_table))
    ret = duthost.command(cmd_enable_neighbore_table, module_ignore_errors=True)
    logging.debug("enable_bmp_neighbor_table output is: {}".format(ret))
    return ret


def enable_bmp_rib_in_table(duthost):

    cmd_enable_rib_in_table = 'sudo config bmp enable bgp-rib-in-table'
    logging.debug("enable_bmp_rib_in_table command is: {}".format(cmd_enable_rib_in_table))
    ret = duthost.command(cmd_enable_rib_in_table, module_ignore_errors=True)
    logging.debug("enable_bmp_rib_in_table output is: {}".format(ret))
    return ret


def enable_bmp_rib_out_table(duthost):

    cmd_enable_rib_out_table = 'sudo config bmp enable bgp-rib-out-table'
    logging.debug("enable_bmp_rib_out_table command is: {}".format(cmd_enable_rib_out_table))
    ret = duthost.command(cmd_enable_rib_out_table, module_ignore_errors=True)
    logging.debug("enable_bmp_rib_out_table output is: {}".format(ret))
    return ret


def disable_bmp_neighbor_table(duthost):

    cmd_disable_neighbore_table = 'sudo config bmp disable bgp-neighbor-table'
    logging.debug("cmd_disable_neighbore_table command is: {}".format(cmd_disable_neighbore_table))
    ret = duthost.command(cmd_disable_neighbore_table, module_ignore_errors=True)
    logging.debug("cmd_disable_neighbore_table output is: {}".format(ret))
    return ret


def disable_bmp_rib_in_table(duthost):

    cmd_disable_rib_in_table = 'sudo config bmp disable bgp-rib-in-table'
    logging.debug("disable_bmp_rib_in_table command is: {}".format(cmd_disable_rib_in_table))
    ret = duthost.command(cmd_disable_rib_in_table, module_ignore_errors=True)
    logging.debug("disable_bmp_rib_in_table output is: {}".format(ret))
    return ret


def disable_bmp_rib_out_table(duthost):

    cmd_disable_rib_out_table = 'sudo config bmp disable bgp-rib-out-table'
    logging.debug("disable_bmp_rib_out_table command is: {}".format(cmd_disable_rib_out_table))
    ret = duthost.command(cmd_disable_rib_out_table, module_ignore_errors=True)
    logging.debug("disable_bmp_rib_out_table output is: {}".format(ret))
    return ret


def disable_bmp_feature(duthost):

    cmd_disable_feature = 'sudo config feature state bmp disabled'
    logging.debug("cmd_disable_feature command is: {}".format(cmd_disable_feature))
    ret = duthost.command(cmd_disable_feature, module_ignore_errors=True)
    logging.debug("cmd_disable_feature output is: {}".format(ret))
    return ret


def enable_bmp_feature(duthost):

    cmd_enable_feature = 'sudo config feature state bmp enabled'
    logging.debug("cmd_enable_feature command is: {}".format(cmd_enable_feature))
    ret = duthost.command(cmd_enable_feature, module_ignore_errors=True)
    logging.debug("cmd_enable_feature output is: {}".format(ret))
    return ret


"""
    Usage: show bmp [OPTIONS] COMMAND [ARGS]...

    Show details of the bmp dataset

    Options:
    -h, -?, --help  Show this message and exit.

    Commands:
    bgp-neighbor-table  Show bmp bgp-neighbor-table information
    bgp-rib-in-table    Show bmp bgp-rib-in-table information
    bgp-rib-out-table   Show bmp bgp-rib-out-table information
    tables              Show bmp table status information
"""


def show_bmp_tables(duthost):

    cmd_show_tables = 'sudo show bmp tables'
    logging.debug("show_bmp_tables command is: {}".format(cmd_show_tables))
    ret = duthost.command(cmd_show_tables, module_ignore_errors=True)
    logging.debug("show_bmp_tables output is: {}".format(ret))
    return ret
