"""
Tool used for shutdown/startup port on the DUT.
"""

import datetime
import time
import logging
import pprint

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


def port_toggle(duthost, tbinfo, ports=None, wait_time_getter=None, wait_after_ports_up=60, watch=False):
    """
    Toggle ports on DUT.

    Args:
        duthost: DUT host object
        ports: Specify list of ports, None if toggle all ports
        wait_time_getter: A call back function to get port toggle wait time.
        wait_after_ports_up: Time to wait after interfaces become up
        watch: Logging system state
    """

    def __get_down_ports(expect_up=True):
        """Check interface status and return the down ports in a set
        """
        ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
        db_ports_down = duthost.show_interface(command='status', up_ports=ports)['ansible_facts']\
            ['ansible_interface_link_down_ports']
        if expect_up:
            return set(ports_down) | set(db_ports_down)
        else:
            return set(ports_down) & set(db_ports_down)

    if ports is None:
        logger.debug('ports is None, toggling all minigraph ports')
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = mg_facts['minigraph_ports'].keys()
    if not wait_time_getter:
        wait_time_getter = get_port_toggle_wait_time
    port_down_wait_time, port_up_wait_time = wait_time_getter(duthost, len(ports))
    logger.info('toggling ports:\n%s', pprint.pformat(ports))

    cmds_down = []
    cmds_up = []
    for port in ports:
        cmds_down.append('config interface shutdown {}'.format(port))
        cmds_up.append('config interface startup {}'.format(port))

    shutdown_ok = False
    shutdown_err_msg = ''
    try:
        duthost.shell_cmds(cmds=cmds_down)
        if watch:
            time.sleep(1)

            # Watch memory status
            memory_output = duthost.shell("show system-memory")["stdout"]
            logger.info("Memory Status: %s", memory_output)

            # Watch orchagent CPU utilization
            orch_cpu = duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"]
            logger.info("Orchagent CPU Util: %s", orch_cpu)

            # Watch Redis Memory
            redis_memory = duthost.shell("redis-cli info memory | grep used_memory_human")["stdout"]
            logger.info("Redis Memory: %s", redis_memory)

        logger.info('Wait for ports to become down.')
        start_time = datetime.datetime.now()
        while True:
            down_ports = __get_down_ports(expect_up=False)
            if len(down_ports) == len(ports):
                shutdown_ok = True
                break
            time.sleep(5)
            if (datetime.datetime.now() - start_time).seconds > port_down_wait_time:
                break

        if not shutdown_ok:
            shutdown_err_msg = 'Some ports did not go down as expected: {}'.format(str(set(ports) - set(down_ports)))
    except Exception as e:
        shutdown_err_msg = 'Shutdown ports failed with exception: {}'.format(repr(e))

    startup_ok = False
    startup_err_msg = ''
    try:
        duthost.shell_cmds(cmds=cmds_up)

        logger.info('Wait for ports to become up.')
        start_time = datetime.datetime.now()
        while True:
            down_ports = __get_down_ports()
            if len(down_ports) == 0:
                startup_ok = True
                break
            time.sleep(5)
            if (datetime.datetime.now() - start_time).seconds > port_up_wait_time:
                break

        if not startup_ok:
            startup_err_msg = 'Some ports did not go up as expected: {}'.format(str(down_ports))

    except Exception as e:
        startup_err_msg = 'Startup interfaces failed with exception: {}'.format(repr(e))

    pytest_assert(shutdown_ok, shutdown_err_msg)
    pytest_assert(startup_ok, startup_err_msg)

    logger.info('wait %d seconds for system to startup', wait_after_ports_up)
    time.sleep(wait_after_ports_up)


def get_port_toggle_wait_time(duthost, port_count):
    """
    Port toggle wait time depends on many factors: port count, cpu type. This function allow user to customize port
    toggle wait time according to DUT host information and port count.
    :param duthost: DUT host object
    :param port_count: total port count to be toggled
    :return: port down wait time and port up wait time
    """
    port_down_wait_time, port_up_wait_time = 20, 60
    asic_type = duthost.facts["asic_type"]
    if asic_type == 'mellanox':
        # default t0 topology has 28 ports to toggle
        base_port_count = 28.0
        if port_count <= base_port_count:
            port_count_factor = 1
        else:
            port_count_factor = port_count / base_port_count
        from .mellanox_data import get_chip_type
        chip_type = get_chip_type(duthost)
        if chip_type == 'spectrum1':
            # spectrum based switch usually has less powerful cpu
            port_down_wait_time = 40
            port_up_wait_time = 70
        else:
            port_down_wait_time = 30

        port_down_wait_time = int(port_down_wait_time * port_count_factor)
        port_up_wait_time = int(port_up_wait_time * port_count_factor)

    return port_down_wait_time, port_up_wait_time
