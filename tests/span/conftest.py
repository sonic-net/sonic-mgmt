'''
Conftest file for span tests
'''

import pytest

@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    '''
    Used to get config facts for selected DUT

    Args:
        duthosts: All DUTs belonging to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

@pytest.fixture(scope="module")
def ports_for_test(cfg_facts):
    '''
    Used to select 3 ports for test and generate info on them

    Args:
        duthosts: All DUTs belonging to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        cfg_facts: pytest fixture

    Return:
        dict: port info for 3 selected ports
    '''
    # Select vlan for test
    vlans = cfg_facts['VLAN']
    vlan = [vlans[vlan]['vlanid'] for vlan in vlans.keys()][0]

    # Select 3 ports for test
    ports = cfg_facts['VLAN_MEMBER']['Vlan{}'.format(vlan)]
    port_names = ports.keys()
    selected_ports = [port_names[0], port_names[1], port_names[-1]]

    # Generate port info for selected ports
    port_info = []
    for port in selected_ports:
        port_info.append({'name': port,
                          'tagging_mode': ports[port]['tagging_mode'],
                          'index': cfg_facts['port_index_map'][port]}
                        )

    return {
        'source1': port_info[0],
        'source2': port_info[1],
        'monitor': port_info[2],
        'vlan': vlan
    }

@pytest.fixture(scope='module', autouse=True)
def skip_unsupported_asic_type(duthost):
    SPAN_UNSUPPORTED_ASIC_TYPE = ["broadcom", "cisco-8000"]
    if duthost.facts["asic_type"] in SPAN_UNSUPPORTED_ASIC_TYPE:
        pytest.skip(
            "Skipping span test on {} platform".format(duthost.facts["asic_type"]))

@pytest.fixture(scope='module', autouse=True)
def setup_monitor_port(duthosts, rand_one_dut_hostname, ports_for_test):
    '''
    Used to prepare monitor port for test

    Args:
        duthosts: All DUTs belonging to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        ports_for_test: pytest fixture containing info on selected ports
    '''
    duthost = duthosts[rand_one_dut_hostname]

    port = ports_for_test['monitor']['name']
    tagging_mode = ports_for_test['monitor']['tagging_mode']
    vlan = ports_for_test['vlan']

    # Remove monitor port from vlan members
    duthost.command('config vlan member del {} {}'.format(vlan, port))

    yield

    # Add monitor port to vlan members
    duthost.command('config vlan member add {} {} --{}'.format(vlan, port, tagging_mode))

@pytest.fixture
def session_info(request, ports_for_test):
    '''
    Used to generate mirroring session info based on selected ports

    Args:
        request: pytest request object.
        ports_for_test: pytest fixture containing info on selected ports

    Return:
        dict: mirroring session configuration params and port indices
    '''
    src1 = ports_for_test['source1']
    src2 = ports_for_test['source2']
    dst = ports_for_test['monitor']
    src = src1['name']

    if 'rx' in request.node.name:
        direction = 'rx'
    elif 'tx' in request.node.name:
        direction = 'tx'
    elif 'both' in request.node.name:
        direction = 'both'
    elif 'multiple' in request.node.name:
        direction = 'rx'
        src = '{},{}'.format(src1['name'], src2['name'])

    return {
        'session_name':'session_1',
        'session_destination_port': dst['name'],
        'destination_index': dst['index'],
        'session_source_ports': src,
        'source1_index': src1['index'],
        'source2_index': src2['index'],
        'session_direction': direction,
    }

@pytest.fixture
def setup_session(duthosts, rand_one_dut_hostname, session_info):
    '''
    Used to add/remove mirroring session on DUT

    Args:
        duthosts: All DUTs belonging to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        session_info: pytest fixture containing mirroring session info

    Return:
        dict: ptf port indices for session source ports and monitor port
    '''
    duthost = duthosts[rand_one_dut_hostname]
    # Add mirroring session
    duthost.command('config mirror_session span add {} {} {} {}'.format(
        session_info["session_name"],
        session_info["session_destination_port"],
        session_info["session_source_ports"],
        session_info["session_direction"]
        )
                   )
    yield {
        'source1_index': session_info['source1_index'],
        'source2_index': session_info['source2_index'],
        'destination_index': session_info['destination_index']
    }
    # Remove mirroring session
    duthost.command('config mirror_session remove {}'.format(session_info["session_name"]))
