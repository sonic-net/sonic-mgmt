import logging
import pytest
import pprint

logger = logging.getLogger(__name__)

DUT_TMP_DIR='/tmp'

LABEL_POP_ROUTES='label_pop_routes'
LABEL_PUSH_ROUTES='label_push_routes'
LABEL_SWAP_ROUTES='label_swap_routes'
LABEL_DEL_ROUTES='label_del_routes'

@pytest.fixture(scope='module')
def setup(duthost, tbinfo, ptfadapter):
    """
    setup fixture gathers all test required information from DUT facts and tbinfo
    :param duthost: DUT host object
    :param tbinfo: fixture provides information about testbed
    :return: dictionary with all test required information
    """
    if tbinfo['topo']['name'] not in ('t1'):
        pytest.skip('Unsupported topology')

    # gather ansible facts
    mg_facts=duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    host_facts=duthost.setup()['ansible_facts']

    tor_ports_ids={}
    tor_ports=[]
    spine_ports_ids={}
    spine_ports=[]
    tor_addr={}
    tor_peer_addr={}
    spine_addr={}
    spine_peer_addr={}
    tor_mac={}
    spine_mac={}

    all_ifs=[]

    ip_ifaces=duthost.get_active_ip_interfaces(tbinfo, asic_index="all")

    for k,v in ip_ifaces[0].items():
        all_ifs.append(k)
        logger.info(ip_ifaces[0][k])
        if 'T0' in v['bgp_neighbor']:
            tor_ports.append(k)
            tor_addr[k]=v['ipv4']
            tor_peer_addr[k]=v['peer_ipv4']
        elif 'T2' in v['bgp_neighbor']:
            spine_ports.append(k) 
            spine_addr[k]=v['ipv4']    
            spine_peer_addr[k]=v['peer_ipv4']           
    
    logger.info('tor_ports: {}'.format(tor_ports))
    logger.info('spine_ports: {}'.format(spine_ports))    
    logger.info('tor_addr: {}'.format(tor_addr)) 
  
    for dut_port in tor_ports:
        port_id=mg_facts['minigraph_port_indices'][dut_port]
        tor_ports_ids[dut_port]=port_id
        ansible_port='ansible_'+dut_port
        tor_mac[dut_port]=host_facts[ansible_port]['macaddress']
    
    for dut_port in spine_ports:
        port_id=mg_facts['minigraph_port_indices'][dut_port]
        spine_ports_ids[dut_port]=port_id
        ansible_port='ansible_'+dut_port
        spine_mac[dut_port]=host_facts[ansible_port]['macaddress']

    logger.info('spine_mac: {}'.format(spine_mac))
    logger.info('spine_ports_ids: {}'.format(spine_ports_ids))

    src_port=random.choice(spine_ports)
    dst_port=random.choice(tor_ports)

    dst_pid=tor_ports_ids[dst_port]
    src_pid=spine_ports_ids[src_port]

    dst_mac=tor_mac[dst_port]
    src_mac=spine_mac[src_port]

    dst_addr=tor_addr[dst_port]
    src_addr=spine_addr[src_port]

    dst_peer_addr=tor_peer_addr[dst_port]
    src_peer_addr=spine_peer_addr[src_port]

    setup_information={
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
