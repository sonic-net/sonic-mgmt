"""This module provides ptfadapter fixture to be used by tests to send/receive traffic via PTF ports"""

import pytest

from ptfadapter import PtfTestAdapter
from ansible_host import AnsibleHost

DEFAULT_PTF_NN_PORT = 10900
DEFAULT_DEVICE_NUM = 0
ETH_PFX = 'eth'


def get_ifaces(netdev_output):
    """ parse /proc/net/dev content
    :param netdev_output: content of /proc/net/dev
    :return: interface names list
    """

    ifaces = []
    for line in netdev_output.split('\n'):
        # Skip a header
        if ':' not in line:
            continue

        iface = line.split(':')[0].strip()

        # Skip not FP interfaces
        if ETH_PFX not in iface:
            continue

        ifaces.append(iface)

    return ifaces


@pytest.fixture(scope='module')
def ptfadapter(ptfhost, testbed):
    """return ptf test adapter object.
    The fixture is module scope, because usually there is not need to
    restart PTF nn agent and reinitialize data plane thread on every
    test class or test function/method. Session scope should also be Ok,
    however if something goes really wrong in one test module it is safer
    to restart PTF before proceeding running other test modules
    """

    # get the eth interfaces from PTF and initialize ifaces_map
    res = ptfhost.command('cat /proc/net/dev')
    ifaces = get_ifaces(res['stdout'])
    ifaces_map = {int(ifname.replace(ETH_PFX, '')): ifname for ifname in ifaces}

    # generate supervisor configuration for ptf_nn_agent
    ptfhost.host.options['variable_manager'].extra_vars = {
        'device_num': DEFAULT_DEVICE_NUM,
        'ptf_nn_port': DEFAULT_PTF_NN_PORT,
        'ifaces_map': ifaces_map,
    }
    ptfhost.template(src='ptfadapter/templates/ptf_nn_agent.conf.ptf.j2',
                     dest='/etc/supervisor/conf.d/ptf_nn_agent.conf')

    # reread configuration and update supervisor
    ptfhost.command('supervisorctl reread')
    ptfhost.command('supervisorctl update')

    with PtfTestAdapter(testbed['ptf_ip'], DEFAULT_PTF_NN_PORT, 0, len(ifaces_map)) as adapter:
        yield adapter

