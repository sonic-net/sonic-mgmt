"""
Tool used for shutdown/startup port on the DUT.
"""

import time
import logging
import pprint

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


def port_toggle(duthost, tbinfo, ports=None, wait=60, wait_after_ports_up=60, watch=False):
    """
    Toggle ports on DUT.

    Args:
        duthost: DUT host object
        ports: Specify list of ports, None if toggle all ports
        wait: Time to wait for interface to become up
        wait_after_ports_up: Time to wait after interfaces become up
        watch: Logging system state
    """

    def __get_down_ports():
        """Check interface status and return the down ports in a set
        """
        total_down_ports = set()
        ports_down = duthost.interface_facts(up_ports=ports)['ansible_facts']['ansible_interface_link_down_ports']
        db_ports_down = duthost.show_interface(command='status', up_ports=ports)['ansible_facts']\
            ['ansible_interface_link_down_ports']
        total_down_ports.update(ports_down)
        total_down_ports.update(db_ports_down)
        return total_down_ports

    def __check_interface_state(state='up'):
        """
        Check interfaces status

        Args:
            state: state of DUT's interface
        """
        total_down_ports = __get_down_ports()
        if 'down' in state:
            return len(total_down_ports) == len(ports)
        else:
            return len(total_down_ports) == 0

    if ports is None:
        logger.debug('ports is None, toggling all minigraph ports')
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = mg_facts['minigraph_ports'].keys()

    logger.info('toggling ports:\n%s', pprint.pformat(ports))

    cmds_down = []
    cmds_up = []
    for port in ports:
        cmds_down.append('config interface shutdown {}'.format(port))
        cmds_up.append('config interface startup {}'.format(port))

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

    # verify all interfaces are down
    pytest_assert(wait_until(20, 5, __check_interface_state, 'down'),
                  "dut ports {} didn't go down as expected"
                  .format(list(set(ports).difference(__get_down_ports()))))

    duthost.shell_cmds(cmds=cmds_up)

    logger.info('waiting for ports to become up')

    pytest_assert(wait_until(wait, 5, __check_interface_state),
                  "dut ports {} didn't go up as expected".format(__get_down_ports()))

    logger.info('wait %d seconds for system to startup', wait_after_ports_up)
    time.sleep(wait_after_ports_up)
