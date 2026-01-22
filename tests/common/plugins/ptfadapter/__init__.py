"""This module provides ptfadapter fixture to be used by tests to send/receive traffic via PTF ports"""
import os
import pytest
import time
import logging

from .ptfadapter import PtfTestAdapter, PtfAgent
import ptf.testutils

from tests.common import constants
from tests.common.utilities import wait_until
import random

logger = logging.getLogger(__name__)

DEFAULT_PTF_NN_PORT_RANGE = [10900, 10999]
DEFAULT_DEVICE_NUM = 0
ETH_PFX = 'eth'
ETHERNET_PFX = "Ethernet"
BACKPLANE = 'backplane'
MAX_RETRY_TIME = 3
PORTS_DATA_READY_AFTER_NN_AGENT_START_TIMEOUT = 120
CHECK_PORTS_DATA_READY_AFTER_NN_AGENT_START_INTERVAL = 20
CHECK_PORTS_DATA_READY_AFTER_NN_AGENT_START_INITIAL_DELAY = 0


def pytest_addoption(parser):
    parser.addoption("--keep_payload", action="store_true", default=False,
                     help="Keep the original packet payload, do not update payload to default pattern")


def override_ptf_functions():
    # Below code is to override the 'send' function in the ptf.testutils module. Purpose of this change is to insert
    # code for updating the packet pattern before send it out. Generally we want to make the payload part of injected
    # packet to have string of current test module and case name. While inspecting the captured packets, it is easier
    # to fiture out which packets are injected by which test case.
    origin_send_packet = ptf.testutils.send_packet

    def _send(test, port_id, pkt, count=1):
        update_payload = getattr(test, "update_payload", None)
        if update_payload and callable(update_payload):
            pkt = test.update_payload(pkt)

        return origin_send_packet(test, port_id, pkt, count=count)
    setattr(ptf.testutils, "send", _send)

    # Below code is to override the 'dp_poll' function in the ptf.testutils module. This function is called by all
    # the other functions for receiving packets in the ptf.testutils module. Purpose of this overriding is to update
    # the payload of received packet using the same method to match the updated injected packets.
    origin_dp_poll = ptf.testutils.dp_poll

    def _dp_poll(test, device_number=0, port_number=None, timeout=-1, exp_pkt=None):
        update_payload = getattr(test, "update_payload", None)
        if update_payload and callable(update_payload):
            exp_pkt = test.update_payload(exp_pkt)

        return origin_dp_poll(test, device_number=device_number, port_number=port_number,
                              timeout=timeout, exp_pkt=exp_pkt)
    setattr(ptf.testutils, "dp_poll", _dp_poll)


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
        if ETH_PFX not in iface and ETHERNET_PFX not in iface and BACKPLANE != iface:
            continue

        ifaces.append(iface)

    return ifaces


def get_ifaces_map(ifaces, ptf_port_mapping_mode, need_backplane=False):
    """Get interface map."""
    sub_ifaces = []
    iface_map = {}
    used_index = set()
    backplane_exist = False
    for iface in ifaces:
        iface_suffix = iface.lstrip(ETH_PFX)
        if "." in iface_suffix:
            iface_index = int(iface_suffix.split(".")[0])
            sub_ifaces.append((iface_index, iface))
        elif iface == BACKPLANE:
            backplane_exist = True
        else:
            iface_index = int(iface_suffix)
            iface_map[iface_index] = iface
            used_index.add(iface_index)

    count = 1
    while count in used_index:
        count = count + 1
    if backplane_exist and need_backplane:
        iface_map[count] = "backplane"

    if ptf_port_mapping_mode == "use_sub_interface":
        # override those interfaces that has sub interface
        for i, si in sub_ifaces:
            iface_map[i] = si
        return iface_map
    elif ptf_port_mapping_mode == "use_orig_interface":
        return iface_map
    else:
        raise ValueError("Unsupported ptf port mapping mode: %s" % ptf_port_mapping_mode)


def check_nn_agent_ready(adapter, sample_size=None):
    """Wait for ptf_nn_agent to cache all interface MACs
    """

    def all_ports_ready(ports_to_check):
        """Check if sampled ports have MACs cached"""
        try:
            for device_id, port in list(ports_to_check):
                mac = adapter.dataplane.get_mac(device_id, port)
                if mac:
                    ports_to_check.discard((device_id, port))
            return len(ports_to_check) == 0
        except Exception:
            return False

    all_ports = list(adapter.dataplane.ports.keys())
    num_ports = len(all_ports)
    if sample_size:
        random_indices = random.sample(range(num_ports), sample_size)
        ports_to_check = set([all_ports[i] for i in random_indices])
    else:
        ports_to_check = set(all_ports)
    are_all_ports_ready = wait_until(
        PORTS_DATA_READY_AFTER_NN_AGENT_START_TIMEOUT,
        CHECK_PORTS_DATA_READY_AFTER_NN_AGENT_START_INTERVAL,
        CHECK_PORTS_DATA_READY_AFTER_NN_AGENT_START_INITIAL_DELAY,
        all_ports_ready,
        ports_to_check
        )
    if not are_all_ports_ready:
        logger.warning(
            f"ptf_nn_agent not fully ready - {len(ports_to_check)} ports "
            f"(out of {num_ports} ports) still not ready"
        )


@pytest.fixture(scope='module')
def ptfadapter(ptfhosts, tbinfo, request, duthost):
    """return ptf test adapter object.
    The fixture is module scope, because usually there is not need to
    restart PTF nn agent and reinitialize data plane thread on every
    test class or test function/method. Session scope should also be Ok,
    however if something goes really wrong in one test module it is safer
    to restart PTF before proceeding running other test modules
    """
    # get ptf port mapping mode
    if 'backend' in tbinfo['topo']['name']:
        ptf_port_mapping_mode = getattr(request.module, "PTF_PORT_MAPPING_MODE",
                                        constants.PTF_PORT_MAPPING_MODE_DEFAULT)
    else:
        ptf_port_mapping_mode = 'use_orig_interface'

    def start_ptf_nn_agent(device_num):
        for i in range(MAX_RETRY_TIME):
            ptf_nn_port = random.randint(*DEFAULT_PTF_NN_PORT_RANGE)

            # generate supervisor configuration for ptf_nn_agent
            ptfhost.host.options['variable_manager'].extra_vars.update({
                'device_num': device_num,
                'ptf_nn_port': ptf_nn_port,
                'ifaces_map': ifaces_map,
            })
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            ptfhost.template(src=os.path.join(current_file_dir, 'templates/ptf_nn_agent.conf.ptf.j2'),
                             dest='/etc/supervisor/conf.d/ptf_nn_agent.conf')

            # reread configuration and update supervisor
            ptfhost.command('supervisorctl reread')
            ptfhost.command('supervisorctl update')

            # Force a restart of ptf_nn_agent to ensure that it is in good status.
            ptfhost.command('supervisorctl restart ptf_nn_agent')

            # check whether ptf_nn_agent starts successfully
            if "RUNNING" in ptfhost.command('supervisorctl status ptf_nn_agent',
                                            module_ignore_errors=True)["stdout_lines"][0]:
                return ptf_nn_port
        return None

    need_backplane = False
    if 'ciscovs-7nodes' in tbinfo['topo']['name']:
        need_backplane = True
    ptfagents = []
    for seq, ptfhost in enumerate(ptfhosts):
        res = ptfhost.command('cat /proc/net/dev')
        ifaces = get_ifaces(res['stdout'])
        ifaces_map = get_ifaces_map(ifaces, ptf_port_mapping_mode, need_backplane)
        ptf_nn_agent_port = start_ptf_nn_agent(seq)
        ptfagents.append(PtfAgent(ptfhost.mgmt_ip, ptfhost.mgmt_ipv6, ptf_nn_agent_port, seq, ifaces_map))
        assert ptf_nn_agent_port is not None

    def check_if_use_minigraph_from_tbinfo(tbinfo):
        if 'properties' in tbinfo['topo'] and "init_cfg_profile" in tbinfo['topo']['properties']:
            #
            # Since init_cfg_profile is used, this topology would not use minigraph
            #
            return False
        return True

    with PtfTestAdapter(ptfagents, ptfhosts) as adapter:
        if not request.config.option.keep_payload:
            override_ptf_functions()
            node_id = request.module.__name__
            adapter.payload_pattern = node_id + " "

        adapter.duthost = duthost
        if check_if_use_minigraph_from_tbinfo(tbinfo):
            adapter.mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        check_nn_agent_ready(adapter)
        yield adapter


@pytest.fixture(scope='module')
def nbr_device_numbers(nbrhosts, ptfhosts):
    """return the mapping of neighbor devices name to ptf device number.
    """
    numbers = sorted(nbrhosts.keys())
    device_numbers = {
        nbr_name: numbers.index(nbr_name) + len(ptfhosts)
        for nbr_name in list(nbrhosts.keys())}
    return device_numbers


@pytest.fixture(scope='module')
def nbr_ptfadapter(request, nbrhosts, nbr_device_numbers, ptfadapter):
    """return ptf test adapter object.
    Start the ptf nn services in neighbor devices and register them in ptfadapter.
    """
    if request.config.getoption("--neighbor_type") != "sonic":
        pytest.skip("Neighbor devices aren't SONiC so that the ptf nn service cannot be started")
    device_sockets = ptf.config['device_sockets']
    current_file_dir = os.path.dirname(os.path.realpath(__file__))
    for name, attr in list(nbrhosts.items()):
        host = attr["host"]
        res = host.command('cat /proc/net/dev')
        ifaces = get_ifaces(res['stdout'])
        ifaces_map = {int(ifname.replace(ETHERNET_PFX, '')):
                      ifname for ifname in ifaces if ifname.startswith(ETHERNET_PFX)}

        def start_ptf_nn_agent():
            for i in range(MAX_RETRY_TIME):
                ptf_nn_port = random.randint(*DEFAULT_PTF_NN_PORT_RANGE)

                host.host.options['variable_manager'].extra_vars.update({
                        'device_num': nbr_device_numbers[name],
                        'ptf_nn_port': ptf_nn_port,
                        'ifaces_map': ifaces_map,
                    })
                host.template(src=os.path.join(current_file_dir, 'templates/ptf_nn_agent.conf.ptf.j2'),
                              dest='/tmp/ptf_nn_agent.conf')
                host.shell('docker rm -f ptf || true')
                host.shell('docker run -dt --network=host --rm --name ptf -v '
                           '/tmp/ptf_nn_agent.conf:/etc/supervisor/conf.d/ptf_nn_agent.conf docker-ptf')

                # Maybe the threads in this docker are not ready and may return None
                for j in range(MAX_RETRY_TIME):
                    time.sleep(1)
                    if "RUNNING" in host.shell('docker exec ptf supervisorctl status ptf_nn_agent',
                                               module_ignore_errors=True)["stdout_lines"][0]:
                        return ptf_nn_port
            return None

        ptf_nn_agent_port = start_ptf_nn_agent()
        assert ptf_nn_agent_port is not None

        ptf_nn_sock_addr = 'tcp://{}:{}'.format(host.facts["mgmt_interface"][0], ptf_nn_agent_port)
        device_sockets.append((nbr_device_numbers[name], ifaces_map, ptf_nn_sock_addr))

    ptfadapter.reinit({"device_sockets": device_sockets})
    return ptfadapter
