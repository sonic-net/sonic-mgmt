import logging
import pytest
import pprint
import random
import os

logger = logging.getLogger(__name__)

DUT_TMP_DIR = '/tmp'

LABEL_POP_ROUTES = 'label_pop_routes'
LABEL_PUSH_ROUTES = 'label_push_routes'
LABEL_SWAP_ROUTES = 'label_swap_routes'
LABEL_DEL_ROUTES = 'label_del_routes'


def _resolve_ptf_port_ids(dut_port, mg_facts):
    """Resolve a DUT L3 interface to its PTF port indices.

    On t1-lag the spine/tor facing interfaces can be PortChannels, which are not
    present in minigraph_port_indices. Resolve such a PortChannel to the PTF port
    indices of its physical member ports. A physical interface resolves to a
    single-element list.
    """
    portchannels = mg_facts.get('minigraph_portchannels', {})
    if dut_port in portchannels:
        members = portchannels[dut_port]['members']
    else:
        members = [dut_port]
    return [mg_facts['minigraph_port_indices'][member] for member in members]


@pytest.fixture(scope='module')
def setup(duthost, tbinfo, ptfadapter):
    """
    setup fixture gathers all test required information from DUT facts and tbinfo
    :param duthost: DUT host object
    :param tbinfo: fixture provides information about testbed
    :return: dictionary with all test required information
    """
    if tbinfo['topo']['type'] != 't1':
        pytest.skip('Unsupported topology')

    # Enabling MPLS on an interface makes intfmgrd run
    # "sysctl -w net.mpls.conf.<intf>.input=1", which needs the mpls_router kernel
    # module. The module ships in the image but nothing loads it, so without this
    # the sysctl fails and is logged as an ERR. sonic-swss's own MPLS test loads it
    # the same way. Left loaded on teardown: modprobe is idempotent and unloading
    # could disrupt anything else using MPLS.
    if duthost.facts['asic_type'] == 'vpp':
        result = duthost.shell('modprobe mpls_router', module_ignore_errors=True)
        if result['rc'] != 0:
            # Not fatal here: let the test itself fail on the resulting syslog
            # error rather than hiding a genuine loss of kernel MPLS support
            # behind a setup failure.
            logger.warning('Failed to load mpls_router: %s. Enabling MPLS on an '
                           'interface will log a setIntfMpls error.', result['stderr'])

    # gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    host_facts = duthost.setup()['ansible_facts']

    tor_ports_ids = {}
    tor_ports = []
    spine_ports_ids = {}
    spine_ports = []
    tor_addr = {}
    tor_peer_addr = {}
    spine_addr = {}
    spine_peer_addr = {}
    tor_mac = {}
    spine_mac = {}

    all_ifs = []

    ip_ifaces = duthost.get_active_ip_interfaces(tbinfo, asic_index="all")

    for k, v in list(ip_ifaces[0].items()):
        all_ifs.append(k)
        logger.info(ip_ifaces[0][k])
        if 'T0' in v['bgp_neighbor']:
            tor_ports.append(k)
            tor_addr[k] = v['ipv4']
            tor_peer_addr[k] = v['peer_ipv4']
        elif 'T2' in v['bgp_neighbor']:
            spine_ports.append(k)
            spine_addr[k] = v['ipv4']
            spine_peer_addr[k] = v['peer_ipv4']

    logger.info('tor_ports: {}'.format(tor_ports))
    logger.info('spine_ports: {}'.format(spine_ports))
    logger.info('tor_addr: {}'.format(tor_addr))

    # The test needs both a T2-facing ingress and a T0-facing egress interface.
    # Some t1 variants (e.g. t1-backend, whose neighbors are all BT0) have no T2
    # peer at all, so bail out cleanly instead of failing later in random.choice().
    if not spine_ports or not tor_ports:
        pytest.skip('Topology has no T2-facing ({}) or T0-facing ({}) interface'
                    .format(len(spine_ports), len(tor_ports)))

    for dut_port in tor_ports:
        tor_ports_ids[dut_port] = _resolve_ptf_port_ids(dut_port, mg_facts)
        ansible_port = 'ansible_'+dut_port
        tor_mac[dut_port] = host_facts[ansible_port]['macaddress']

    for dut_port in spine_ports:
        spine_ports_ids[dut_port] = _resolve_ptf_port_ids(dut_port, mg_facts)
        ansible_port = 'ansible_'+dut_port
        spine_mac[dut_port] = host_facts[ansible_port]['macaddress']

    logger.info('spine_mac: {}'.format(spine_mac))
    logger.info('spine_ports_ids: {}'.format(spine_ports_ids))

    src_port = random.choice(spine_ports)
    dst_port = random.choice(tor_ports)

    # dst_pid is the list of egress PortChannel member PTF ports (verify on any member).
    # src_pid is a single ingress member PTF port used to inject the test packet.
    dst_pid = tor_ports_ids[dst_port]
    src_pid = spine_ports_ids[src_port][0]

    dst_mac = tor_mac[dst_port]
    src_mac = spine_mac[src_port]

    dst_addr = tor_addr[dst_port]
    src_addr = spine_addr[src_port]

    dst_peer_addr = tor_peer_addr[dst_port]
    src_peer_addr = spine_peer_addr[src_port]

    setup_information = {
        'duthost': duthost,
        'dut_tmp_dir': DUT_TMP_DIR,
        'dst_ip_spine_blocked': '192.168.144.1',
        'src_port': src_port,
        'dst_port': dst_port,
        'src_addr': src_addr,
        'src_peer_addr': src_peer_addr,
        'dst_addr': dst_addr,
        'dst_peer_addr': dst_peer_addr,
        'src_pid': src_pid,
        'dst_pid': dst_pid,
        'src_mac': src_mac,
        'dst_mac': dst_mac,
    }

    logger.info('setup variables {}'.format(pprint.pformat(setup)))

    # FIXME: There seems to be some issue with the initial setup of the ptfadapter, causing some of the
    # TestBasicMPLS tests to fail because the forwarded packets are not being collected. This is an
    # attempt to mitigate that issue while we continue to investigate the root cause.
    #
    # Ref: GitHub Issue #2032
    logger.info("setting up the ptfadapter")
    ptfadapter.reinit()

    yield setup_information

    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_POP_ROUTES, '.json')))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_SWAP_ROUTES, '.json')))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_PUSH_ROUTES, '.json')))
    duthost.command('rm -rf {}'.format(os.path.join(DUT_TMP_DIR, LABEL_DEL_ROUTES, '.json')))
