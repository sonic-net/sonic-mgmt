'''
Conftest file for span tests
'''

import pytest
import logging
import ipaddress
import json
from contextlib import ExitStack

from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
from tests.common.utilities import skip_release, wait_until
from tests.common.helpers.assertions import pytest_assert as _pytest_assert
from erspan_helpers import (   # noqa F401
    ERSPAN_SESSION_NAME,
    ERSPAN_SRC_IP,
    ERSPAN_DST_IP,
    ERSPAN_DST_PREFIX,
    ERSPAN_DSCP,
    ERSPAN_TTL,
    ERSPAN_GRE_TYPE,
    ERSPAN_DEFAULT_DIRECTION,
    PROBE_UNICAST_DST_MAC,
    remove_mirror_session,
    create_erspan_session_config,
    apply_static_fdb,
)

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
def setup_monitor_port(duthosts, rand_one_dut_hostname, request, tbinfo):
    '''
    Used to prepare monitor port for test

    Args:
        duthosts: All DUTs belonging to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        ports_for_test: pytest fixture containing info on selected ports
    '''
    # T1 ERSPAN does not need VLAN monitor setup.
    if tbinfo['topo']['type'] == 't1' and request.module.__name__.endswith('test_erspan_sampling_truncation'):
        yield
        return
    ports_for_test = request.getfixturevalue('ports_for_test')
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

# ERSPAN_* endpoint constants are imported from erspan_helpers (see imports above).

RX_PROBE_IP = '198.18.254.1'
TX_PROBE_IP = '198.18.254.2'


def select_t1_ports(duthost, tbinfo):
    '''Select three up, PTF-mapped IPv4 interfaces.

    Exclude multi-member LAGs to keep physical TX egress deterministic.
    '''
    if duthost.is_multi_asic:
        pytest.skip('T1 ERSPAN routing setup currently requires a single-ASIC DUT')
    config = duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']
    minigraph = duthost.get_extended_minigraph_facts(tbinfo)
    status = duthost.show_interface(command='status')['ansible_facts']['int_status']
    ptf_map = minigraph['minigraph_ptf_indices']

    def usable(name):
        return (name in ptf_map and name.startswith('Ethernet')
                and config.get('PORT', {}).get(name, {}).get('admin_status') == 'up'
                and status.get(name, {}).get('oper_state') == 'up')

    def port(name, **kwargs):
        return dict(name=name, index=int(ptf_map[name]), **kwargs)

    candidates = []
    seen = set()
    portchannels = minigraph.get('minigraph_portchannels', {})
    interfaces = (minigraph.get('minigraph_interfaces', [])
                  + minigraph.get('minigraph_portchannel_interfaces', []))
    lag_members = {member for pc in config.get('PORTCHANNEL_MEMBER', {}).values() for member in pc}
    vlan_members = {member for vlan in config.get('VLAN_MEMBER', {}).values() for member in vlan}
    for intf in interfaces:
        name = intf['attachto']
        if name in seen or ipaddress.ip_address(str(intf['addr'])).version != 4:
            continue
        if name.startswith('PortChannel'):
            members = sorted(config.get('PORTCHANNEL_MEMBER', {}).get(name, {}))
            if len(members) != 1 or members != sorted(portchannels.get(name, {}).get('members', [])):
                continue
            physical = members[0]
            table = 'PORTCHANNEL_INTERFACE'
        else:
            physical = name
            table = 'INTERFACE'
            if physical in lag_members:
                continue
        if (not usable(physical) or physical in vlan_members
                or name not in config.get(table, {})):
            continue
        candidates.append(port(physical, l3_interface=name))
        seen.add(name)

    candidates.sort(key=lambda p: (p['l3_interface'].startswith('PortChannel'), p['index']))
    if len(candidates) < 3:
        pytest.skip('ERSPAN T1 needs three up, PTF-mapped IPv4 interfaces '
                    '(standalone ports or single-member PortChannels)')
    ports = {'topology': 't1', 'source': candidates[0],
             'gre_egress': candidates[1], 'tx_ingress': candidates[2]}
    logger.info('ERSPAN T1 ports: %s', ports)
    return ports


def _add_route(duthost, cleanup, prefix, nexthop, interface):
    '''Reuse matching FRR/kernel routes; clean up only new routes.

    FRR may retain routes absent from the kernel while next hops are unresolved.
    '''
    existing = json.loads(duthost.shell('ip -j -4 route show exact {}'.format(prefix))['stdout'])
    command = 'ip route {} {} {}'.format(prefix, nexthop, interface)
    running = duthost.shell('vtysh -c "show running-config"')['stdout']
    configured = [line.strip() for line in running.splitlines()
                  if line.strip().split()[:3] == ['ip', 'route', prefix]]
    accepted = {command, 'ip route {} {}'.format(prefix, nexthop)}
    _pytest_assert(not configured or (len(configured) == 1 and configured[0] in accepted),
                   'Conflicting FRR static route for {}: {}'.format(prefix, configured))

    def matches(routes):
        # Normalize host prefixes and require a single unicast next hop.
        return (len(routes) == 1
                and ipaddress.ip_network(routes[0].get('dst', '0.0.0.0/0'), strict=False)
                == ipaddress.ip_network(prefix)
                and routes[0].get('dev') == interface
                and routes[0].get('gateway') == nexthop
                and routes[0].get('type', 'unicast') == 'unicast'
                and not routes[0].get('nexthops'))

    if existing:
        _pytest_assert(matches(existing),
                       'Conflicting ERSPAN route for {}: expected via {} dev {}, found {}'.format(
                           prefix, nexthop, interface, existing))
        logger.info('Reusing existing ERSPAN route: %s', existing)
    elif configured:
        logger.info('Reusing configured FRR route, waiting for kernel convergence: %s', configured)
    else:
        cleanup.callback(duthost.command, 'vtysh -c "configure terminal" -c "no {}"'.format(command))
        duthost.command('vtysh -c "configure terminal" -c "{}"'.format(command))

    def installed():
        routes = json.loads(duthost.shell('ip -j -4 route show exact {}'.format(prefix))['stdout'])
        return matches(routes)

    _pytest_assert(wait_until(30, 1, 0, installed),
                   'ERSPAN route {} via {} dev {} did not converge'.format(prefix, nexthop, interface))


def _setup_t1_rx_discard(duthost, cleanup):
    '''Create or reuse an RX probe blackhole; clean up only our additions.'''
    prefix = RX_PROBE_IP + '/32'
    command = 'ip route {} blackhole'.format(prefix)
    running = duthost.shell('vtysh -c "show running-config"')['stdout']
    configured = [line.strip() for line in running.splitlines()
                  if line.strip().split()[:3] == ['ip', 'route', prefix]]
    _pytest_assert(not configured or configured == [command],
                   'Conflicting FRR RX probe route: {}'.format(configured))
    routes = json.loads(duthost.shell('ip -j -4 route show exact {}'.format(prefix))['stdout'])
    if routes:
        route = routes[0]
        blackhole = route.get('type') == 'blackhole'
        _pytest_assert(len(routes) == 1 and not route.get('nexthops')
                       and ipaddress.ip_network(route.get('dst', '0.0.0.0/0'), strict=False)
                       == ipaddress.ip_network(prefix)
                       and blackhole,
                       'Conflicting kernel RX probe route: {}'.format(routes))
        if blackhole and not configured:
            logger.info('Reusing existing RX probe blackhole: %s', routes)
            return

    if configured != [command]:
        cleanup.callback(duthost.command, 'vtysh -c "configure terminal" -c "no {}"'.format(command))
        duthost.command('vtysh -c "configure terminal" -c "{}"'.format(command))

    def installed():
        entries = json.loads(duthost.shell('ip -j -4 route show exact {}'.format(prefix))['stdout'])
        return (len(entries) == 1 and entries[0].get('type') == 'blackhole'
                and not entries[0].get('nexthops'))

    _pytest_assert(wait_until(30, 1, 0, installed), 'RX probe blackhole did not converge: {}'.format(prefix))
    logger.info('T1 RX original probes to %s are discarded; ERSPAN collector route is separate', prefix)


def _check_t1_subnets(duthost, paths):
    '''Allow exact test addresses on their intended interfaces, reject overlaps.'''
    addresses = json.loads(duthost.shell('ip -j -4 addr show')['stdout'])
    expected = {ipaddress.ip_network(subnet): port['l3_interface'] for _, port, subnet in paths}
    for link in addresses:
        for addr in link.get('addr_info', []):
            existing = ipaddress.ip_interface('{}/{}'.format(addr['local'], addr['prefixlen'])).network
            for network, interface in expected.items():
                exact = (link['ifname'] == interface and existing == network
                         and addr['local'] == str(network[1]))
                _pytest_assert(not network.overlaps(existing) or exact,
                               'ERSPAN temporary subnet {} overlaps {}'.format(network, existing))
    routes = json.loads(duthost.shell('ip -j -4 route show')['stdout'])
    for route in routes:
        destination = route.get('dst', 'default')
        if destination == 'default':
            continue
        existing = ipaddress.ip_network(destination, strict=False)
        for network, interface in expected.items():
            connected = (existing == network and route.get('dev') == interface
                         and route.get('protocol') == 'kernel' and not route.get('gateway'))
            _pytest_assert(not network.overlaps(existing) or connected,
                           'ERSPAN temporary subnet {} overlaps route {}'.format(network, existing))


def _setup_t1_path(duthost, ptfhost, cleanup, port, subnet, prefix):
    '''Prepare a T1 path, preserving matching pre-existing configuration.'''
    network = ipaddress.ip_network(subnet)
    dut_ip = '{}/{}'.format(network[1], network.prefixlen)
    nexthop = str(network[2])
    interface = port.get('l3_interface', port['name'])
    existing = json.loads(duthost.shell('ip -j neigh show to {} dev {}'.format(nexthop, interface))['stdout'])
    mac = ptfhost.shell('cat /sys/class/net/eth{}/address'.format(port['index']))['stdout'].strip()
    if existing:
        _pytest_assert(
            len(existing) == 1 and existing[0].get('dst') == nexthop
            and existing[0].get('lladdr', '').lower() == mac.lower()
            and existing[0].get('state') == ['PERMANENT'],
            'Conflicting next-hop {} on {}: expected permanent PTF MAC {}, found {}'.format(
                nexthop, interface, mac, existing))
        logger.info('Reusing existing permanent PTF neighbor %s on %s: %s', nexthop, interface, mac)
        # Restore existing neighbors after address removal (LIFO cleanup).
        cleanup.callback(duthost.command, 'ip neigh replace {} lladdr {} nud permanent dev {}'.format(
            nexthop, mac, interface))
    addresses = json.loads(duthost.shell('ip -j -4 addr show dev {}'.format(interface))['stdout'])
    address_exists = any(addr.get('local') == str(network[1]) and addr.get('prefixlen') == network.prefixlen
                         for link in addresses for addr in link.get('addr_info', []))
    if not address_exists:
        cleanup.callback(duthost.command, 'config interface ip remove {} {}'.format(interface, dut_ip))
        duthost.command('config interface ip add {} {}'.format(interface, dut_ip))
    if not existing:
        cleanup.callback(duthost.command, 'ip neigh del {} dev {}'.format(nexthop, interface),
                         module_ignore_errors=True)
    # Replace handles neighbors created during address setup.
    duthost.command('ip neigh replace {} lladdr {} nud permanent dev {}'.format(nexthop, mac, interface))

    def neighbor_ready():
        entries = json.loads(duthost.shell('ip -j neigh show to {} dev {}'.format(nexthop, interface))['stdout'])
        return any(entry.get('dst') == nexthop and entry.get('lladdr', '').lower() == mac.lower()
                   and entry.get('state') == ['PERMANENT'] for entry in entries)

    _pytest_assert(wait_until(10, 1, 0, neighbor_ready),
                   'PTF neighbor {} on {} did not converge to permanent MAC {}'.format(nexthop, interface, mac))
    _add_route(duthost, cleanup, prefix, nexthop, interface)
    logger.info('ERSPAN route setup: %s via %s dev %s (PTF port %s, MAC %s)',
                prefix, nexthop, interface, port['index'], mac)


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
def skip_if_ingress_sampling_unsupported(erspan_capabilities):
    '''Skip if the platform does not support RX (ingress) sampled port mirroring.

    Use for direction=rx dataplane tests, which require ingress sampling specifically.
    '''
    capable = erspan_capabilities.get("PORT_INGRESS_SAMPLE_MIRROR_CAPABLE", "false")
    if capable.lower() != 'true':
        pytest.skip("Skip: platform does not support ingress (RX) sampled port mirroring "
                    "(PORT_INGRESS_SAMPLE_MIRROR_CAPABLE != true)")


@pytest.fixture(scope="module")
def skip_if_egress_sampling_unsupported(erspan_capabilities):
    '''Skip if the platform does not support TX (egress) sampled port mirroring.

    Use for direction=tx dataplane tests, which require egress sampling specifically.
    '''
    capable = erspan_capabilities.get("PORT_EGRESS_SAMPLE_MIRROR_CAPABLE", "false")
    if capable.lower() != 'true':
        pytest.skip("Skip: platform does not support egress (TX) sampled port mirroring "
                    "(PORT_EGRESS_SAMPLE_MIRROR_CAPABLE != true)")


@pytest.fixture(scope="module")
def skip_if_no_tx_ingress(erspan_ports):
    '''Skip direction=tx/both dataplane tests when no peer VLAN-member injection port
    is available (needs >=4 non-PortChannel VLAN members; see erspan_ports). Depends on
    erspan_ports only (no PTF), so it short-circuits before any PTF setup.
    '''
    if erspan_ports['tx_ingress'] is None:
        pytest.skip("Skip: TX/BOTH dataplane needs >=4 non-PortChannel VLAN member ports "
                    "(a peer injection port distinct from source, gre_egress and monitor)")


@pytest.fixture(scope="module")
def skip_if_truncation_unsupported(erspan_capabilities):
    '''Skip test if the platform does not support sample packet truncation.'''
    capable = erspan_capabilities.get("SAMPLEPACKET_TRUNCATION_CAPABLE", "false")
    if capable.lower() != 'true':
        pytest.skip(
            "Skip: platform does not support sample packet truncation "
            "(SAMPLEPACKET_TRUNCATION_CAPABLE != true)")


@pytest.fixture(scope="module")
def skip_if_vs_platform(duthosts, rand_one_dut_hostname):
    '''Skip dataplane mirroring tests on the vs platform.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts["asic_type"] == "vs":
        pytest.skip("Dataplane sampled mirroring is not testable on the vs platform")


def _sampling_direction_supported(erspan_capabilities, direction):
    '''Return True if the platform advertises the sampled-mirroring capability that
    `direction` (rx/tx/both) requires (ingress for rx, egress for tx, both for both).'''
    ingress = erspan_capabilities.get("PORT_INGRESS_SAMPLE_MIRROR_CAPABLE", "false").lower() == 'true'
    egress = erspan_capabilities.get("PORT_EGRESS_SAMPLE_MIRROR_CAPABLE", "false").lower() == 'true'
    if direction in ('rx', 'both') and not ingress:
        return False
    if direction in ('tx', 'both') and not egress:
        return False
    return True


@pytest.fixture
def sampling_direction(request, erspan_capabilities):
    '''Parametrized sampled-mirroring direction (rx/tx/both) for config tests.

    Sampled mirroring requires an explicit direction (swss), and each direction needs
    the matching per-direction capability. Skip the parametrized direction when the
    platform does not advertise it, so we never configure an unsupported direction (which
    orchagent would reject with an ERR log).

    Usage:
        @pytest.mark.parametrize('sampling_direction', ['rx', 'tx', 'both'], indirect=True)
        def test_something(sampling_direction): ...
    '''
    direction = request.param
    if not _sampling_direction_supported(erspan_capabilities, direction):
        pytest.skip("Skip: platform does not support {} sampled port mirroring".format(direction))
    return direction


@pytest.fixture
def mirror_session_cleanup(duthosts, rand_one_dut_hostname):
    '''Register mirror-session names for guaranteed removal at teardown.

    A lightweight alternative to per-test try/finally remove_mirror_session boilerplate for
    config-only tests. Unlike the erspan_session fixture it does no routing/STATE_DB setup.

    Usage:
        session_name = mirror_session_cleanup("my_session")
    '''
    duthost = duthosts[rand_one_dut_hostname]
    session_names = []

    def register(session_name):
        session_names.append(session_name)
        return session_name

    yield register

    for session_name in session_names:
        remove_mirror_session(duthost, session_name)


@pytest.fixture(scope="module")
def erspan_ports(duthosts, rand_one_dut_hostname, request, tbinfo):
    '''
    Select source, GRE collector and TX injection ports.

    T0 uses VLAN members; T1 uses distinct routed interfaces.
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if tbinfo['topo']['type'] == 't1':
        return select_t1_ports(duthost, tbinfo)
    cfg_facts = request.getfixturevalue('cfg_facts')
    vlans = cfg_facts['VLAN']
    vlan_ids = [vlans[vlan]['vlanid'] for vlan in list(vlans.keys())]

    for vlan in vlan_ids:
        ports = cfg_facts['VLAN_MEMBER']['Vlan{}'.format(vlan)]
        port_names = [p for p in list(ports.keys()) if 'PortChannel' not in p]
        if len(port_names) >= 3:
            break

    assert len(port_names) >= 3, "Need at least 3 non-PortChannel VLAN member ports"

    # Collector and monitor leave the VLAN; TX needs a fourth member as its peer.
    tx_ingress = None
    if len(port_names) >= 4:
        tx_ingress = {
            'name': port_names[2],
            'index': cfg_facts['port_index_map'][port_names[2]],
        }

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
        'tx_ingress': tx_ingress,
        'vlan': vlan,
    }


@pytest.fixture(scope="module")
def setup_erspan_route(duthosts, rand_one_dut_hostname, ptfhost, erspan_ports):
    '''Prepare collector routing and topology-specific probe forwarding.'''
    duthost = duthosts[rand_one_dut_hostname]
    if erspan_ports.get('topology') == 't1':
        paths = [
            (ERSPAN_DST_PREFIX, erspan_ports['gre_egress'], '198.18.250.0/30'),
            (TX_PROBE_IP + '/32', erspan_ports['source'], '198.18.250.8/30'),
        ]
        _check_t1_subnets(duthost, paths)
        with ExitStack() as cleanup:
            for prefix, port, subnet in paths:
                _setup_t1_path(duthost, ptfhost, cleanup, port, subnet, prefix)
            _setup_t1_rx_discard(duthost, cleanup)
            erspan_ports['t1_probes'] = {}
            for role, ip_dst in (('source', RX_PROBE_IP), ('tx_ingress', TX_PROBE_IP)):
                port = erspan_ports[role]
                links = json.loads(duthost.shell('ip -j link show dev {}'.format(
                    port['l3_interface']))['stdout'])
                erspan_ports['t1_probes'][port['index']] = {'eth_dst': links[0]['address'], 'ip_dst': ip_dst}
            yield
        return

    # T0 collector setup.
    egress = erspan_ports['gre_egress']
    egress_port = egress['name']
    egress_ptf_index = egress['index']
    vlan = erspan_ports['vlan']
    tagging_mode = egress['tagging_mode']

    dut_intf_ip = "192.168.200.1/30"
    nexthop_ip = "192.168.200.2"

    # Pre-cleanup: idempotent removal of any leftover state from a previous crashed run.
    duthost.command('vtysh -c "configure terminal" -c "no ip route {} {}"'.format(
        ERSPAN_DST_PREFIX, nexthop_ip), module_ignore_errors=True)
    duthost.command('ip neigh del {} dev {}'.format(nexthop_ip, egress_port),
                    module_ignore_errors=True)
    duthost.command('config interface ip remove {} {}'.format(egress_port, dut_intf_ip),
                    module_ignore_errors=True)
    duthost.command('config vlan member add {} {} --{}'.format(vlan, egress_port, tagging_mode),
                    module_ignore_errors=True)

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

    yield

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
    is_t1 = erspan_ports.get('topology') == 't1'
    if is_t1:
        request.addfinalizer(lambda: remove_mirror_session(duthost, ERSPAN_SESSION_NAME))

    # create_erspan_session_config pre-cleans any leftover same-named session, then
    # creates it with the requested direction / sampling / truncation parameters.
    logger.info(
        "Creating ERSPAN session %s on %s (direction=%s, sample_rate=%s, truncate_size=%s)",
        ERSPAN_SESSION_NAME, src_port, direction, sample_rate, truncate_size)
    create_erspan_session_config(
        duthost, ERSPAN_SESSION_NAME,
        sample_rate=sample_rate, truncate_size=truncate_size,
        source_port=src_port, direction=direction)

    # CONFIG_DB sanity
    output = duthost.shell("show mirror_session")
    logger.info("show mirror_session \n%s", output['stdout'])
    _pytest_assert(
        ERSPAN_SESSION_NAME in output['stdout'],
        "Mirror session {} not found after creation".format(ERSPAN_SESSION_NAME),
    )

    # Wait for STATE_DB to converge: status=active AND monitor_port matches gre_egress
    expected_monitor = erspan_ports['gre_egress']['name']

    def _session_ready():
        status = duthost.shell(
            "sonic-db-cli STATE_DB HGET 'MIRROR_SESSION_TABLE|{}' status".format(ERSPAN_SESSION_NAME),
            module_ignore_errors=True
        )['stdout'].strip()
        monitor = duthost.shell(
            "sonic-db-cli STATE_DB HGET 'MIRROR_SESSION_TABLE|{}' monitor_port".format(ERSPAN_SESSION_NAME),
            module_ignore_errors=True
        )['stdout'].strip()
        return status == 'active' and monitor == expected_monitor

    ready = wait_until(30, 2, 0, _session_ready)
    state_dump = duthost.shell(
        "sonic-db-cli STATE_DB HGETALL 'MIRROR_SESSION_TABLE|{}'".format(ERSPAN_SESSION_NAME),
        module_ignore_errors=True
    )['stdout']
    config_dump = duthost.shell(
        "sonic-db-cli CONFIG_DB HGETALL 'MIRROR_SESSION|{}'".format(ERSPAN_SESSION_NAME),
        module_ignore_errors=True
    )['stdout']
    logger.info("STATE_DB MIRROR_SESSION_TABLE|%s \n%s", ERSPAN_SESSION_NAME, state_dump)
    logger.info("CONFIG_DB MIRROR_SESSION|%s \n%s", ERSPAN_SESSION_NAME, config_dump)
    logger.info("Expected monitor_port: %s", expected_monitor)
    _pytest_assert(
        ready,
        "Mirror session {} not active or monitor_port != {}; STATE_DB: {}".format(
            ERSPAN_SESSION_NAME, expected_monitor, state_dump))

    probe_dst_mac = PROBE_UNICAST_DST_MAC
    # T0 uses FDB forwarding; T1 uses routing.
    if not is_t1:
        apply_static_fdb(duthost, erspan_ports['vlan'], src_port, probe_dst_mac,
                         op="DEL", ignore_errors=True)
        apply_static_fdb(duthost, erspan_ports['vlan'], src_port, probe_dst_mac, op="SET")

    yield {
        'session_name': ERSPAN_SESSION_NAME,
        'source_index': erspan_ports['source']['index'],
        'gre_egress_index': erspan_ports['gre_egress']['index'],
        'tx_ingress_index': (erspan_ports['tx_ingress']['index']
                             if erspan_ports['tx_ingress'] else None),
        'sample_rate': sample_rate,
        'truncate_size': truncate_size,
        'probe_dst_mac': probe_dst_mac,
        't1_probes': erspan_ports.get('t1_probes'),
        'mirror_session_info': {
            'src_ip': ERSPAN_SRC_IP,
            'dst_ip': ERSPAN_DST_IP,
            'dscp': ERSPAN_DSCP,
            'ttl': ERSPAN_TTL,
            'gre_type': ERSPAN_GRE_TYPE,
        },
    }

    if not is_t1:
        apply_static_fdb(duthost, erspan_ports['vlan'], src_port, probe_dst_mac,
                         op="DEL", ignore_errors=True)
        remove_mirror_session(duthost, ERSPAN_SESSION_NAME)
