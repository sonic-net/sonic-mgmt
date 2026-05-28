'''
Conftest file for span tests
'''

import pytest
import logging

from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
from tests.common.utilities import skip_release

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname, skip_test_module_over_backend_topologies):   # noqa F811
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
    vlan_ids = [vlans[vlan]['vlanid'] for vlan in list(vlans.keys())]

    # Select 3 ports for test
    for vlan in vlan_ids:
        ports = cfg_facts['VLAN_MEMBER']['Vlan{}'.format(vlan)]
        port_names = [port_name for port_name in list(ports.keys()) if 'PortChannel' not in port_name]
        if len(port_names) >= 3:
            break
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


@pytest.fixture(scope='session', autouse=True)
def skip_unsupported_release(duthost):
    """ Span mirror is not supported on release < 202012
    """
    skip_release(duthost, ["201811", "201911"])


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
        'session_name': 'session_1',
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
        ))
    mirror_session_output = duthost.shell("show mirror_session")
    assert session_info["session_name"] in mirror_session_output['stdout']

    yield {
        'source1_index': session_info['source1_index'],
        'source2_index': session_info['source2_index'],
        'destination_index': session_info['destination_index']
    }
    # Remove mirroring session
    duthost.command('config mirror_session remove {}'.format(session_info["session_name"]))


# ---------------------------------------------------------------------------
# ERSPAN sampling/truncation fixtures
# ---------------------------------------------------------------------------

ERSPAN_SESSION_NAME = "erspan_sample_trunc"
ERSPAN_SRC_IP = "10.1.0.32"
ERSPAN_DST_IP = "10.20.0.33"
ERSPAN_DST_PREFIX = "10.20.0.33/32"
ERSPAN_DSCP = "8"
ERSPAN_TTL = "64"
ERSPAN_GRE_TYPE = "0x8949"
ERSPAN_QUEUE = "0"
ERSPAN_DEFAULT_DIRECTION = "rx"


@pytest.fixture(scope="module")
def erspan_capabilities(duthosts, rand_one_dut_hostname):
    '''
    Collect switch capability facts for sampling/truncation support.
    Follows the everflow conftest.py pattern using switch_capabilities_facts().
    '''
    duthost = duthosts[rand_one_dut_hostname]
    facts = duthost.switch_capabilities_facts()
    caps = (facts
            .get("ansible_facts", {})
            .get("switch_capabilities", {})
            .get("switch", {}))
    return caps


@pytest.fixture(scope="module")
def skip_if_sampling_unsupported(erspan_capabilities):
    '''Skip test if the platform does not support sampled port mirroring.'''
    ingress = erspan_capabilities.get("PORT_INGRESS_SAMPLE_MIRROR_CAPABLE", "false")
    egress = erspan_capabilities.get("PORT_EGRESS_SAMPLE_MIRROR_CAPABLE", "false")
    if ingress.lower() != 'true' and egress.lower() != 'true':
        pytest.skip("Platform does not support sampled port mirroring")


@pytest.fixture(scope="module")
def skip_if_truncation_unsupported(erspan_capabilities):
    '''Skip test if the platform does not support sample packet truncation.'''
    capable = erspan_capabilities.get("SAMPLEPACKET_TRUNCATION_CAPABLE", "false")
    if capable.lower() != 'true':
        pytest.skip("Platform does not support sample packet truncation")


@pytest.fixture(scope="module")
def erspan_ports(duthosts, rand_one_dut_hostname, cfg_facts):
    '''
    Select ports for ERSPAN tests:
      - source: VLAN member port where test traffic is injected
      - gre_egress: different VLAN member port used as next-hop for ERSPAN dst IP
    '''
    duthost = duthosts[rand_one_dut_hostname]
    vlans = cfg_facts['VLAN']
    vlan_ids = [vlans[vlan]['vlanid'] for vlan in list(vlans.keys())]

    for vlan in vlan_ids:
        ports = cfg_facts['VLAN_MEMBER']['Vlan{}'.format(vlan)]
        port_names = [p for p in list(ports.keys()) if 'PortChannel' not in p]
        if len(port_names) >= 3:
            break

    assert len(port_names) >= 3, "Need at least 3 non-PortChannel VLAN member ports"

    router_mac = duthost.facts['router_mac']
    return {
        'source': {
            'name': port_names[0],
            'index': cfg_facts['port_index_map'][port_names[0]],
        },
        'gre_egress': {
            'name': port_names[1],
            'index': cfg_facts['port_index_map'][port_names[1]],
            'tagging_mode': ports[port_names[1]]['tagging_mode'],
        },
        'vlan': vlan,
        'router_mac': router_mac,
    }


@pytest.fixture(scope="module")
def setup_erspan_route(duthosts, rand_one_dut_hostname, ptfhost, erspan_ports):
    '''
    Set up routing so ERSPAN GRE packets reach the PTF port.
    Follows the everflow pattern: static route + neighbor resolution.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    egress = erspan_ports['gre_egress']
    egress_port = egress['name']
    egress_ptf_index = egress['index']
    vlan = erspan_ports['vlan']
    tagging_mode = egress['tagging_mode']

    dut_intf_ip = "192.168.200.1/30"
    nexthop_ip = "192.168.200.2"

    duthost.command('config vlan member del {} {}'.format(vlan, egress_port))
    duthost.command('config interface ip add {} {}'.format(egress_port, dut_intf_ip))
    duthost.command('vtysh -c "configure terminal" -c "ip route {} {}"'.format(
        ERSPAN_DST_PREFIX, nexthop_ip
    ))

    ptf_mac = ptfhost.shell(
        "cat /sys/class/net/eth{}/address".format(egress_ptf_index)
    )['stdout'].strip()
    duthost.command('ip neigh replace {} lladdr {} dev {}'.format(
        nexthop_ip, ptf_mac, egress_port
    ))

    logger.info("ERSPAN route setup: %s -> %s (nexthop %s, PTF port %d, mac %s)",
                ERSPAN_DST_PREFIX, egress_port, nexthop_ip, egress_ptf_index, ptf_mac)

    yield {
        'nexthop_ip': nexthop_ip,
        'ptf_mac': ptf_mac,
    }

    duthost.command('vtysh -c "configure terminal" -c "no ip route {} {}"'.format(
        ERSPAN_DST_PREFIX, nexthop_ip
    ), module_ignore_errors=True)
    duthost.command('ip neigh del {} dev {}'.format(nexthop_ip, egress_port),
                    module_ignore_errors=True)
    duthost.command('config interface ip remove {} {}'.format(egress_port, dut_intf_ip),
                    module_ignore_errors=True)
    duthost.command('config vlan member add {} {} --{}'.format(vlan, egress_port, tagging_mode),
                    module_ignore_errors=True)


@pytest.fixture
def erspan_session(request, duthosts, rand_one_dut_hostname, erspan_ports, setup_erspan_route):
    '''
    Create and teardown an ERSPAN mirror session with optional sample_rate/truncate_size.

    Usage:
        @pytest.mark.parametrize('erspan_session', [{'sample_rate': 256}], indirect=True)
        def test_something(erspan_session): ...
    '''
    duthost = duthosts[rand_one_dut_hostname]
    params = getattr(request, 'param', {}) or {}
    sample_rate = params.get('sample_rate')
    truncate_size = params.get('truncate_size')
    src_port = erspan_ports['source']['name']
    direction = params.get('direction', ERSPAN_DEFAULT_DIRECTION)

    cmd = 'config mirror_session erspan add {} {} {} {} {} {} {} {} {}'.format(
        ERSPAN_SESSION_NAME, ERSPAN_SRC_IP, ERSPAN_DST_IP,
        ERSPAN_DSCP, ERSPAN_TTL, ERSPAN_GRE_TYPE, ERSPAN_QUEUE,
        src_port, direction
    )
    if sample_rate is not None:
        cmd += ' --sample_rate {}'.format(sample_rate)
    if truncate_size is not None:
        cmd += ' --truncate_size {}'.format(truncate_size)

    logger.info("Creating ERSPAN session: %s", cmd)
    duthost.command(cmd)

    output = duthost.shell("show mirror_session")
    assert ERSPAN_SESSION_NAME in output['stdout'], \
        "Mirror session {} not found after creation".format(ERSPAN_SESSION_NAME)

    yield {
        'session_name': ERSPAN_SESSION_NAME,
        'source_index': erspan_ports['source']['index'],
        'gre_egress_index': erspan_ports['gre_egress']['index'],
        'source_port': src_port,
        'gre_egress_port': erspan_ports['gre_egress']['name'],
        'router_mac': erspan_ports['router_mac'],
        'sample_rate': sample_rate,
        'truncate_size': truncate_size,
        'direction': direction,
        'mirror_session_info': {
            'src_ip': ERSPAN_SRC_IP,
            'dst_ip': ERSPAN_DST_IP,
            'dscp': ERSPAN_DSCP,
            'ttl': ERSPAN_TTL,
            'gre_type': ERSPAN_GRE_TYPE,
        },
    }

    duthost.command('config mirror_session remove {}'.format(ERSPAN_SESSION_NAME),
                    module_ignore_errors=True)
