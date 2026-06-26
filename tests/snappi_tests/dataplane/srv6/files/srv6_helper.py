import collections
import re
import logging
# from rich import print as pr

from snappi_tests.dataplane.files.helper import get_autoneg_fec, get_macs

logger = logging.getLogger(__name__)


class Multi_Tier_Map:
    """
    Reads conn_graph_facts to get understanding on how DUTs
    and TGEN are connected and create a full NUT tree.

    Usage:
        topo = MultiTierMap(conn_graph_facts)

        # shortest tgen -> tgen
        topo.shortest_path('snappi-sonic', 'snappi-sonic2')
        # -> ['snappi-sonic', 'switch-t0-1', 'switch-t0-2', 'snappi-sonic2']        (direct T0<->T0)
        # -> ['snappi-sonic', 'switch-t0-1', 'switch-t1-1', 'switch-t0-2', 'snappi-sonic2']  (via spine)

        # every path (e.g. both spines)
        for p in topo.all_paths('snappi-sonic', 'snappi-sonic2'):
            print("  ->  ".join(p))

        # port-level view of the chosen path
        for a, pa, pb, b in topo.path_with_ports(topo.shortest_path('snappi-sonic', 'snappi-sonic2')):
            print(f"{a}:{pa}  -->  {b}:{pb}")
    """
    TIER_RANK = {'tgen': 0, 't0': 1, 't1': 2, 't2': 3}

    def __init__(self, conn_graph_facts):
        self.graph = self._build_graph(conn_graph_facts)

    def _build_graph(self, conn_graph_facts):
        graph = {}
        for section in ('device_conn', 'device_linked_ports'):
            for dut, ports in conn_graph_facts.get(section, {}).items():
                for local_port, props in ports.items():
                    peer, peer_port = props['peerdevice'], props['peerport']
                    graph.setdefault(dut, {}).setdefault(peer, []).append((local_port, peer_port))
                    graph.setdefault(peer, {}).setdefault(dut, []).append((peer_port, local_port))

        return graph

    @staticmethod
    def tier_of(name):
        m = re.search(r'[-_](t[012])', name)
        if m:
            return m.group(1)

        if re.search(r'snappi|tgen|ixia', name, re.IGNORECASE):
            return 'tgen'

        return None

    def _transitable(self, node, src, dst):
        """tgens are only allowed as the path's own endpoints, never transit."""
        return self.tier_of(node) != 'tgen' or node in (src, dst)

    def shortest_path(self, src, dst):
        """
        Fewest-hop device path from src to dst (both can be tgens or switches).
        Returns [] if unreachable.  BFS => first path found is shortest.
        """
        if src == dst:
            return [src]

        queue = collections.deque([[src]])
        seen = {src}
        while queue:
            path = queue.popleft()
            node = path[-1]
            for neighbor in self.graph.get(node, {}):
                if neighbor in seen or not self._transitable(neighbor, src, dst):
                    continue

                if neighbor == dst:
                    return path + [neighbor]

                seen.add(neighbor)
                queue.append(path + [neighbor])

        return []

    def all_paths(self, src, dst, max_hops=8):
        """
        Every loop-free device path from src to dst, up to max_hops edges.
        Shorter paths come first (BFS-ordered).
        """
        paths = []
        queue = collections.deque([[src]])
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == dst and len(path) > 1:
                paths.append(path)
                continue

            if len(path) - 1 >= max_hops:
                continue

            for neighbor in self.graph.get(node, {}):
                if neighbor in path or not self._transitable(neighbor, src, dst):
                    continue

                queue.append(path + [neighbor])

        return paths

    # ---- port-level detail for a resolved path ------------------------------
    def path_with_ports(self, path):
        """
        Annotate a device path with the ports used on each hop:
            [(dev_a, port_a, port_b, dev_b), ...]
        Picks the first available link per hop.
        """
        hops = []
        for a, b in zip(path, path[1:]):
            local_port, peer_port = self.graph[a][b][0]      # first parallel link
            hops.append((a, local_port, peer_port, b))

        return hops

    # ---- endpoint discovery (no params needed) ------------------------------
    def tgens(self):
        """All traffic-generator devices in the graph, sorted by name."""
        return sorted(d for d in self.graph if self.tier_of(d) == 'tgen')

    def edge_t0s(self):
        """All t0 (leaf) switches, sorted — the ingress/egress edge of the fabric."""
        return sorted(d for d in self.graph if self.tier_of(d) == 't0')

    def full_path(self, src=None, dst=None):
        """
        Return the full tgen -> ... -> tgen path with NO required parameters.

        Auto-picks endpoints when not given:
          - src = first tgen (lowest name)
          - dst = first tgen attached to a DIFFERENT t0 than src
        Falls back to the longest discoverable path if the simple pick fails.
        """
        edge_t0s = self.edge_t0s()
        if len(edge_t0s) == 1:
            return edge_t0s[:]                  # only one t0: that's the whole path

        tgens = self.tgens()
        if len(tgens) < 2:
            return tgens[:]                     # 0 or 1 tgen: nothing to traverse

        if src is None:
            src = tgens[0]

        if dst is None:
            dst = self._other_edge_tgen(src, tgens)

        path = self.shortest_path(src, dst)
        if path:
            return path

        # fallback: the longest path among all tgen pairs (most complete traversal)
        return self._longest_tgen_path()

    def _other_edge_tgen(self, src, tgens):
        """First tgen that hangs off a different t0 than `src` (so the path crosses the fabric)."""
        src_t0 = self._attached_t0(src)
        for t in tgens:
            if t != src and self._attached_t0(t) != src_t0:
                return t

        # no distinct t0: just take the next tgen
        return tgens[1]

    def _attached_t0(self, tgen):
        """The t0 switch a tgen is wired to (first one found)."""
        for neighbor in self.graph.get(tgen, {}):
            if self.tier_of(neighbor) == 't0':
                return neighbor
        return None

    def _longest_tgen_path(self):
        """Longest shortest-path between any two tgens — the most complete traversal."""
        tgens = self.tgens()
        best = []
        for i, a in enumerate(tgens):
            for b in tgens[i + 1:]:
                p = self.shortest_path(a, b)
                if len(p) > len(best):
                    best = p
        return best


class Create_Tier:
    def __init__(self, name, type):
        '''
        name: t0|t1|t2
        type: core|spine|leaf|tgen
        '''
        self.name = name
        self.type = type
        self.connections = []

    def add_connection(self, other_switch):
        self.connections.append(other_switch)
        other_switch.connections.append(self)


def display_topology(data, conn_graph_facts, Common_vars):
    """
    Core: switch-t2-1
            Spine: switch-t1-1:
                Leaf: switch-t0-1
                    - 10.36.84.36/1.1 (tgen)
                    - 10.36.84.36/1.3 (tgen)
                    - 10.36.84.36/1.5 (tgen)
                    - 10.36.84.36/1.7 (tgen)
                    - 10.36.84.36/1.2 (tgen)
                    - 10.36.84.36/1.4 (tgen)
                    - 10.36.84.36/1.6 (tgen)
                    - 10.36.84.36/1.8 (tgen)

            Spine: switch-t1-2:
                Leaf: switch-t0-2
                    - 10.36.84.37/3.1 (tgen)
                    - 10.36.84.37/3.3 (tgen)
                    - 10.36.84.37/3.5 (tgen)
                    - 10.36.84.37/3.7 (tgen)
                    - 10.36.84.37/3.2 (tgen)
                    - 10.36.84.37/3.4 (tgen)
                    - 10.36.84.37/3.6 (tgen)
                    - 10.36.84.37/3.8 (tgen)
    """
    cores = [c for c in data['cores'] if c is not None]
    spines = data["spines"]

    # --- Cores (if exist) ---
    for core in cores:
        logger.info(f'\nCore: {core.name}')
        logger.info(f'\t- My-SIDs: {Common_vars.config_data[core.name]["my_sids"]}')

        # Get links to spine
        logger.info('\t- Links to spines:')
        for link_to_spine, properties in conn_graph_facts['device_linked_ports'][core.name].items():
            # 'Ethernet128': {'peerdevice': 'switch-t0-1', 'peerport': 'Ethernet128',
            # 'speed': '100000', 'fec_disable': False}

            logger.info(f'\t    - {link_to_spine} -> {properties["peerdevice"]} interface:{properties["peerport"]}')

    # --- Spines (if exist) ---
    if spines:
        for spine in spines:
            logger.info('\n')
            logger.info(f"\tSpine: {spine.name}:")
            logger.info(f'\t   - My-SIDs: {Common_vars.config_data[spine.name]["my_sids"]}')

            # Get links to Core
            display_leaves(data, spine.connections)
    else:
        # no spines: show every leaf directly
        display_leaves(data, None)


def display_leaves(data, connections, Common_vars):
    logger.info('\n')
    for leaf in data["leaves"]:
        # connections is None  -> no spine Common_vars.tier, show every leaf
        # connections is a set -> only leaves wired to that spine
        if connections is None or leaf in connections:
            logger.info(f"\t    Leaf: {leaf.name}")
            logger.info(f'\t       - My-SIDs: {Common_vars.config_data[leaf.name]["my_sids"]}')

            display_tgen(data, leaf)


def display_tgen(data, leaf):
    logger.info('\t       - TGEN')
    for tgen in data["tgen"]:
        if tgen in leaf.connections:
            logger.info(f"\t\t     - {tgen.name} ({tgen.type})")


def assign_sid_on_tgen_ports(conn_graph_facts, snappi_ports, Common_vars):
    sid = Common_vars.tgen_endpoint_sid_start

    # Assign TGEN ports to the DUT in config_data
    # Assign SID to each snappi port
    for dut_name in conn_graph_facts['device_conn'].keys():
        look_once_only = False

        if conn_graph_facts['device_conn'][dut_name]:
            # These are the tgen ports connected to this current t0 DUT
            for snappi_port in snappi_ports:
                # 'Ethernet71': {'peerdevice': 'snappi-sonic', 'peerport': 'Port1.8'3256,
                #                'speed': '100000', 'fec_disable': False},
                # 'Ethernet128': {'peerdevice': 'switch-t0-2', 'peerport': 'Ethernet128',
                #                 'speed': '100000', 'fec_disable': False},
                if snappi_port['peer_device'] == dut_name:
                    # Assign a SID to snappi ports
                    # This is for creating static route on the DUT where the tgen snappi host resides using its SID
                    assigned_sid = sid
                    sid += 1
                    snappi_port.update({'tgen_endpoint_sid': assigned_sid})
                    logger.info(f'tgen port: {snappi_port["location"]} SID: {assigned_sid}')

                    if look_once_only is False:
                        Common_vars.config_data[dut_name].update(
                            {'router_mac_address': snappi_port['router_mac_address']})
                        look_once_only = True

                    # All ports will be transmitting bi-directionally. So all ports are Tx and Rx ports.
                    Common_vars.config_data[dut_name]['tgen_ports'].append(snappi_port)


def assign_sid_to_duts(Common_vars):
    """
    Mark every dut with a starting SID number (201, 301, 301 ...)
    For configuring my-sids, locators and static routes

    The total tgen ports on each dut is total SIDs because the test assigns
    each tgen port a SID. This total is also total SIDs on the DUT and
    total links connecting to adjacent DUTs and static routes.
    """
    for dut in Common_vars.t0_duts:
        # T0-1 starts at 201.  T0-2 starts at 301
        sid = Common_vars.t0_dut_sid_start

        for x in range(0, len(Common_vars.config_data[dut]['tgen_ports'])):
            Common_vars.config_data[dut]['my_sids'].append(sid)
            sid += 1

        Common_vars.t0_dut_sid_start = increment_to_next_hundred(sid) + 1

    if Common_vars.t1_dut:
        """
        M = 16      # Total traffic generators (must be even)
        N = 8       # Number of SRv6 paths per TG
        """
        def split_in_half(m):
            half = m // 2

            # hex(16) -> '10'
            base1 = hex(m)[2:]
            # hex(16/2 + 1)  -> hex(9) -> '9'
            base2 = hex(m // 2 + 1)[2:]

            group1 = [f'{base1}{i:02d}' for i in range(1, half + 1)]
            group2 = [f'{base2}{i:02d}' for i in range(1, half + 1)]
            return group1, group2

        group1_sids, group2_sids = split_in_half(Common_vars.total_tgen_ports)
        Common_vars.config_data[dut]['my_sids'] = group1_sids + group2_sids

        for t0_dut, t1_sid_group in zip(Common_vars.t0_duts, [group1_sids, group2_sids]):
            Common_vars.config_data[Common_vars.t1_dut]['t1_sid_paths'][t0_dut] = t1_sid_group


def create_snappi_flows(conn_graph_facts, tx_ports, rx_ports, Common_vars):
    """
    Create tx-ports flows

    tx/rx ports
    {'ip': '10.36.84.36',
      'port_id': '1',
      'peer_port': 'Ethernet64', <---
      'peer_device': 'switch-t0-1', <---
      'speed': '100000',
      'location': '10.36.84.36/1.1',
      'intf_config_changed': False,
      'api_server_ip': '10.36.84.36',
      'asic_type': 'broadcom',
      'duthost': None,
      'snappi_speed_type': 'speed_100_gbps',
      'asic_value': None,
      'autoneg': False,
      'fec': True,
      'ipAddress': 'fc0a::2',
      'ipGateway': 'fc0a::1',
      'prefix': '126',
      'router_mac_address': '8c:01:9d:fa:40:cc',
      'src_mac_address': '10:17:00:00:00:11',
      'subnet': 'fc0a::1/126'
    }
    """
    for index, port in enumerate(tx_ports):
        sid_full_path = get_complete_srv6_path(conn_graph_facts, starting_t0_dut=port['peer_device'],
                                               ending_t0_dut=rx_ports[index]['peer_device'],
                                               get_dut_sid_index=index, Common_vars=Common_vars)

        # Add the destinated tgen sid to sid_full_path
        sid_full_path = f'{sid_full_path}:{rx_ports[index]["tgen_endpoint_sid"]}'
        if len(sid_full_path.split(":")) < 8:
            sid_full_path = f'{sid_full_path}::'

        # switch-t0-1
        dut = port['peer_device']

        # This is for understanding the full path for tx-port to rx-port for getting all
        # DUt port statistic counters.
        #
        # Get the tx-port's snappi device -> in this example: peerdevice == "snappi-sonic"
        # Have to get the rx-port peerdevice too.
        # conn_graph_facts = {
        # 'device_conn': {
        #     'switch-t0-1': {
        #         'Ethernet64': {'peerdevice': 'snappi-sonic', 'peerport': 'Port1.1',
        #                        'speed': '100000', 'fec_disable': False}
        tx_port_snappi_device = conn_graph_facts['device_conn'][port['peer_device']][port['peer_port']]['peerdevice']
        rx_port_peer_port = rx_ports[index]['peer_port']  # 'peer_port': 'Ethernet80'
        rx_port_peer_device = rx_ports[index]['peer_device']  # 'peer_device': 'switch-t0-2'
        rx_port_snappi_device = conn_graph_facts['device_conn'][rx_port_peer_device][rx_port_peer_port]['peerdevice']

        Common_vars.config_data[dut]['tx_ports'].append({
            'my_snappi_port': port['location'],
            'my_snappi_device_name': tx_port_snappi_device,
            'my_dut_port': port['peer_port'],
            'my_dut_sid_to_use': Common_vars.config_data[dut]['my_sids'][index],
            'my_src_ip': port['ipAddress'],
            'my_src_ip_prefix': port['prefix'],
            'my_src_mac': port['src_mac_address'],
            'my dest_mac': port['router_mac_address'],
            'my_ipv6_srv6_dest': sid_full_path,
            'rx_port': rx_ports[index]['location'],
            'rx_port_ip_address': rx_ports[index]['ipAddress'],
            'rx_port_snappi_device_name': rx_port_snappi_device
            })


def get_complete_srv6_path(conn_graph_facts, starting_t0_dut, ending_t0_dut, get_dut_sid_index, Common_vars):
    """
    Construct full sid path for tgen port IPv6 dest IP

    Current test plan requires up to 2 T0 and 1 T1.
    This function supports just that.
    """
    # t0_duts = []
    topo = Multi_Tier_Map(conn_graph_facts)

    # snappi-sonic  ->  switch-t0-1  ->  switch-t1-1  ->  switch-t2-1  ->  switch-t1-2
    # ->  switch-t0-2  ->  snappi-sonic2
    srv6_sid_path = []

    # fcbb:bbbb:201:
    srv6_dest_sid_path = []

    logger.info((f'\nget_complete_srv6_path: index:{get_dut_sid_index} '
                 f'starting_dut:{starting_t0_dut} -> {ending_t0_dut}\n'))

    if starting_t0_dut == ending_t0_dut:
        # Single DUT
        sid = Common_vars.config_data[starting_t0_dut]['my_sids'][get_dut_sid_index]
        srv6_dest_sid_path.append(str(sid))
        logger.info(f'SRv6 on a single DUT.  SID: {sid}')
    else:
        # Multiple DUTs
        for dut_path_list in topo.all_paths(starting_t0_dut, ending_t0_dut):
            # dut_path_list: ['switch-t0-1', 'switch-t1-1', 'switch-t2-1', 'switch-t1-2', 'switch-t0-2']

            for dut in dut_path_list:
                if dut in Common_vars.t0_duts:
                    sid = Common_vars.config_data[dut]['my_sids'][get_dut_sid_index]

                if dut == Common_vars.t1_dut:
                    # Get sid from t1_sid_path
                    current_dut_index = dut_path_list.index(dut)
                    next_dut = dut_path_list[current_dut_index + 1]
                    # These SIDs are predefined for the connecting T0 DUTs
                    # 't1_sid_paths': {'switch-t0-1': ['1001', '1002', '1003', '1004', '1005', '1006', '1007', '1008'],
                    #                  'switch-t0-2': ['901', '902', '903', '904', '905', '906', '907', '908']}
                    sid = Common_vars.config_data[dut]['t1_sid_paths'][next_dut][get_dut_sid_index]

                srv6_sid_path.append(f'{dut}: SID={sid}')
                srv6_dest_sid_path.append(str(sid))

            # switch-t0-1: SID=204  ->  switch-t1-1: SID=1004  ->  switch-t2-1: SID=3004
            # ->  switch-t1-2: SID=2004  ->  switch-t0-2: SID=304
            logger.info("  ->  ".join(srv6_sid_path))

    # Returns a complete srv6 sid path minus the tgen snappi sid
    # 206:1006:3006:2006:306  <-- This does not include the tgen endpoint SID.
    #                             Added in create_snappi_flows() when this function returns
    dut_sid_path = ':'.join(srv6_dest_sid_path)
    srv6_full_sid_path = f'fcbb:bbbb:{dut_sid_path}'

    logger.info(srv6_full_sid_path)
    return srv6_full_sid_path


def get_dut_list(conn_graph_facts, Common_vars):
    for dut_name in conn_graph_facts['device_conn'].keys():
        if conn_graph_facts['device_conn'][dut_name]:
            Common_vars.dut_list.append(dut_name)

    if conn_graph_facts.get('device_linked_ports', None):
        for dut_name in conn_graph_facts['device_linked_ports'].keys():
            if conn_graph_facts['device_linked_ports'][dut_name]:
                if dut_name not in Common_vars.dut_list:
                    Common_vars.dut_list.append(dut_name)


def set_dut_tier_level(Common_vars):
    """
    Mark each dut as t0, t1, t2.
    User must name the DUTs in a format
    of switch-t0-1|switch-t0-2|switch-t1-1

    core1 = Create_Tier("core1", "core")

    # Add spine switches
    spine1 = Create_Tier(name="T1-1", type="spine")
    spine2 = Create_Tier(name="T1-2", type="spine")

    # Add leaf switches
    leaf1 = Create_Tier(name="T0-1", type="leaf")
    leaf2 = Create_Tier(name="T0-2", type="leaf")

    # leaf1.add_connection(spine2)
    # leaf2.add_connection(spine2)

    # Data representation
    #     "cores": [core1, core2],
    network_data = {
        #"cores": [None],
        "cores": [core1],
        "spines": [spine1, spine2],
        "leaves": [leaf1, leaf2]
    }

    display_topology(network_data)
    """
    # Get all DUTs and its Common_vars.tier type
    for dut in Common_vars.dut_list:
        match = re.search('.*-t0|_t0', dut)
        if match:
            dut_tier = 't0'
            Common_vars.tier[dut] = Create_Tier(name=dut, type="Leaf")
            Common_vars.leaf_list.append(Common_vars.tier[dut])

        match = re.search('.*-t1|_t1', dut)
        if match:
            dut_tier = 't1'
            Common_vars.tier[dut] = Create_Tier(name=dut, type="Spine")
            Common_vars.t1_dut = dut
            Common_vars.spine_list.append(Common_vars.tier[dut])

        match = re.search('.*-t2|_t2', dut)
        if match:
            dut_tier = 't2'
            Common_vars.tier[dut] = Create_Tier(name=dut, type="Core")
            Common_vars.core_list.append(Common_vars.tier[dut])

        Common_vars.config_data[dut]['tier_level'] = dut_tier


def get_t0_duts(conn_graph_facts, Common_vars):
    """
    T0 DUTs are from links.csv file
    T0 DUTs are connected directly to tgen ports
    """
    t0_duts = []
    for dut in conn_graph_facts['device_conn'].keys():
        if len(conn_graph_facts['device_conn'][dut]) == 0:
            continue

        if Common_vars.config_data[dut]['tier_level'] == 't0':
            t0_duts.append(dut)

    return t0_duts


def get_pairings(path):
    """
    Return consecutive pairs: [a,b,c,d] -> [(a,b), (b,c), (c,d)]
    [('switch-t0-1', 'switch-t1-1'), ('switch-t1-1', 'switch-t2-1'),
    ('switch-t2-1', 'switch-t1-2'), ('switch-t1-2', 'switch-t0-2')]
    """
    return list(zip(path, path[1:]))


def increment_hex(hex_str, by=1, width=2, prefix=False, upper=False):
    value = int(hex_str, 16) + by
    fmt = f'0{width}{"X" if upper else "x"}'   # e.g. '02x'
    out = format(value, fmt)
    return ('0x' if prefix else '') + out


def increment_to_next_hundred(number):
    """
    if number is 108, return 200
    """
    next_hundred = ((number // 100) + 1) * 100
    return next_hundred


def snappi_port_name_mapper(snappi_obj_handles, snappi_extra_params, Common_vars):
    """
    For RAW traffic and be able to select custom src and dst endpoints, have to use port_names
    as tgen endpoints generated in snappi_obj_handles.
    This is a helper function to get the port_name from snappi_obj_handle when sending
    bi-directional traffic or if having mixed traffic patterns.
    Creating a port mapper to solve the problem.
    """
    for role, pconfig in snappi_extra_params.protocol_config.items():
        is_ipv4 = pconfig['subnet_type'] == 'IPv4'
        snappi_obj_handles[role]['port_name'] = [f"Port_{p['port_id']}" for p in pconfig['ports']]
        snappi_obj_handles[role]['ethernet_mac'] = [p['src_mac_address'] for p in pconfig['ports']]
        snappi_obj_handles[role]['ipv4_address' if is_ipv4 else 'ipv6_address'] = \
            [p['ipAddress'] for p in pconfig['ports']]
        snappi_obj_handles[role]['ipv4_gateway' if is_ipv4 else 'ipv6_gateway'] = \
            [p['ipGateway'] for p in pconfig['ports']]

    for dut in Common_vars.dut_hosts:
        for port in Common_vars.config_data[dut.hostname]['tgen_ports']:
            # Look in snappi_obj_handle for the port that matches the ip address to get the port_name
            for x_type in ['Tx', 'Rx']:
                addresses = snappi_obj_handles[x_type].get('ipv6_address', [])
                port_names = snappi_obj_handles[x_type].get('port_name', [])
                if port['ipAddress'] in addresses:
                    index = addresses.index(port['ipAddress'])
                    port_name = port_names[index]
                    Common_vars.port_name_mapper[port['location']] = port_name
                    break


def _num(v):
    """
    For tracing SRv6 DUT path end-to-end for ingress and egress stats

    '8,276,951,808' -> 8276951808 ; non-numeric -> None.
    """
    v = v.replace(',', '')
    return int(v) if v.lstrip('-').isdigit() else None


def _dut_counters(all_stats, dut):
    """
    For tracing SRv6 DUT path end-to-end for ingress and egress stats

    Parse a portstat text table -> {iface: {'RX_OK': int, 'TX_OK': int}}.
    """
    c = all_stats[dut]
    if isinstance(c, dict):
        return c

    rows = {}
    for line in c.splitlines():
        parts = line.split()
        # skip blanks, header, and the dashed divider
        if len(parts) < 10 or parts[0] == 'IFACE' or set(parts[0]) <= {'-'}:
            continue
        if not parts[0].startswith('Ethernet'):
            continue
        rows[parts[0]] = {'RX_OK': _num(parts[2]), 'TX_OK': _num(parts[9])}
    return rows


def _tgen_facing_port(cfg, dut, index):
    """
    For tracing SRv6 DUT path end-to-end for ingress and egress stats

    The t0's tgen-facing Ethernet port at this index (None if out of range).
    """
    tgen_ports = cfg[dut].get('tgen_ports', [])
    if index < len(tgen_ports):
        return tgen_ports[index]['peer_port']      # DUT-side port facing the tgen
    return None


def _single_dut_stats(dut, cfg, parsed):
    """
    Single-t0 fabric: traffic enters on a tgen-facing tx port and leaves on a
    different tgen-facing rx port of the SAME dut, so there are no inter-dut
    hops to walk -- trace the dut's own tx_ports records instead.
    """
    counters = parsed[dut]
    # snappi location ('10.36.84.36/1.1') -> dut-side ethernet port ('Ethernet64')
    loc_to_port = {p['location']: p['peer_port'] for p in cfg[dut].get('tgen_ports', [])}

    aligned = []
    for index, flow in enumerate(cfg[dut].get('tx_ports', [])):
        ingress = flow['my_dut_port']                 # tgen -> t0  (RX_OK)
        egress = loc_to_port.get(flow['rx_port'])     # t0 -> tgen  (TX_OK)
        chain = [{'dut': dut,
                  'tier': Multi_Tier_Map.tier_of(dut),
                  'ingress_port': ingress,
                  'egress_port': egress,
                  'ingress_stats': counters.get(ingress, {}) if ingress else {},
                  'egress_stats': counters.get(egress, {}) if egress else {}
                  }]
        aligned.append({'index': index, 'chain': chain})

    return aligned


def config_dut_sids(duthosts, Common_vars):
    # Configure MY-SIDS on DUTs
    for dut in duthosts:
        count = 1
        for sid in Common_vars.config_data[dut.hostname]['my_sids']:
            logger.info(f'Configuring {dut.hostname}: sonic-db-cli CONFIG_DB hset '
                        f'"SRV6_MY_LOCATORS|loc{count}" prefix "fcbb:bbbb:{sid}::" func_len 0')

            dut.shell(f'sonic-db-cli CONFIG_DB hset "SRV6_MY_LOCATORS|loc{count}" '
                    f'prefix "fcbb:bbbb:{sid}::" func_len 0')

            logger.info(f'    sonic-db-cli CONFIG_DB hset "SRV6_MY_SIDS|loc{count}|fcbb:bbbb:{sid}::/48" '
                        f'action uN decap_dscp_mode pipe')

            dut.shell(f'sonic-db-cli CONFIG_DB hset "SRV6_MY_SIDS|loc{count}|fcbb:bbbb:{sid}::/48" '
                    f'action uN decap_dscp_mode pipe')
            count += 1


def get_dut_to_dut_pairs(conn_graph_facts, Common_vars):
    # For creating static routes. Need to pair up the DUT-to-DUT adjacencies
    # to create the port link ip addresses and static routes between the two DUTs.
    dut_connection_peers = []
    if len(Common_vars.t0_duts) > 1:
        topo = Multi_Tier_Map(conn_graph_facts)
        # ['switch-t0-1', 'switch-t1-1', 'switch-t2-1', 'switch-t1-2', 'switch-t0-2']
        topology_map = topo.all_paths(Common_vars.t0_duts[0], Common_vars.t0_duts[1])
        # [('switch-t0-1', 'switch-t1-1'), ('switch-t1-1', 'switch-t2-1'), ('switch-t2-1',
        # 'switch-t1-2'), ('switch-t1-2', 'switch-t0-2')]
        dut_connection_peers = get_pairings(topology_map[0])

    return dut_connection_peers


def construct_dut_to_dut_links(conn_graph_facts, Common_vars):
    """
    Get all dut-to-dut links
    """
    if conn_graph_facts.get('device_linked_ports', None):
        for dut, properties in conn_graph_facts['device_linked_ports'].items():
            # Get all the adjacent DUT links Ethernet port names
            # 'device_linked_ports': {'switch-t0-1': {}, 'switch-t0-2': {}}
            #                        {'switch-t0-1': {'Ethernet128': {'peerdevice': 'switch-t0-2',
            #                                                         'peerport': 'Ethernet128'}}
            if len(properties) == 0:
                continue

            # dut, properties:
            # dut -> switch-t0-1:
            # properties -> {'Ethernet128': {'peerdevice': 'switch-t1-1', 'peerport': 'Ethernet100',
            #                                'speed': '100000', 'fec_disable': False},
            # For each local dut port and attributes on who it's connected to
            for index, (dut_port, attributes) in enumerate(properties.items()):
                if len(attributes) == 0:
                    continue

                # DUT-to_DUT link IP addresses
                local_dut_link_ip = f'{Common_vars.static_route_subnet_start}::1/64'
                next_hop_ip = f'{Common_vars.static_route_subnet_start}::2/64'

                # Initialize dut_link_ip_addresses with dut dict() on current DUT and the adjacent DUT
                if attributes['peerdevice'] not in Common_vars.config_data[dut]['dut_link_ip_addresses']:
                    Common_vars.config_data[dut]['dut_link_ip_addresses'].update({attributes['peerdevice']: []})

                if dut not in Common_vars.config_data[attributes['peerdevice']]['dut_link_ip_addresses']:
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_ip_addresses'].update({dut: []})

                # Add link port connections and its IP addresses
                if attributes['peerdevice'] not in Common_vars.config_data[dut]['dut_link_port_connections']:
                    Common_vars.config_data[dut]['dut_link_port_connections'].update({attributes['peerdevice']: []})

                if attributes['peerdevice'] in Common_vars.dut_list:
                    if dut_port not in (
                        Common_vars.config_data[dut]['dut_link_port_connections'][attributes['peerdevice']]
                    ):
                        Common_vars.config_data[dut]['dut_link_port_connections'][attributes['peerdevice']]\
                            .append(dut_port)

                        # Add IP address
                        Common_vars.config_data[dut]['dut_link_ip_addresses'][attributes['peerdevice']]\
                            .append(local_dut_link_ip)

                # REVERSE: Adding link connection on adjacent DUT
                # {'peerdevice': 'switch-t1-1', 'peerport': 'Ethernet100', 'speed': '100000', 'fec_disable': False}
                # To the peerdevice as dut
                if dut not in Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections']:
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections'].update({dut: []})

                if attributes['peerport'] not in (
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections'][dut]
                ):
                    (
                        Common_vars.config_data[attributes['peerdevice']]['dut_link_port_connections']
                        [dut].append(attributes['peerport'])
                    )

                    # Add IP addresses on link connections between 2 DUTs
                    Common_vars.config_data[attributes['peerdevice']]['dut_link_ip_addresses'][dut].append(next_hop_ip)

                Common_vars.static_route_subnet_start = increment_hex(str(Common_vars.static_route_subnet_start))


def construct_static_route_dut_to_tgen(conn_graph_facts, Common_vars):
    # Create static routes from t0 DUT to tgen hosts
    for dut, properties in conn_graph_facts['device_conn'].items():
        # 'Ethernet128': {'peerdevice': 'switch-t1-1', 'peerport': 'Ethernet100',
        # 'speed': '100000', 'fec_disable': False},
        if len(conn_graph_facts['device_conn'][dut]) == 0:
            continue

        # Create static-routes from t0 to tgen hosts
        for index, dut_link_port_name in enumerate(Common_vars.config_data[dut]['tgen_ports']):
            # Create a static route for each tgen snappi host
            snappi_sid = Common_vars.config_data[dut]['tgen_ports'][index]['tgen_endpoint_sid']
            snappi_dest_host_ip = Common_vars.config_data[dut]['tgen_ports'][index]['ipAddress']
            snappi_dest_port = Common_vars.config_data[dut]['tgen_ports'][index]['peer_port']

            static_route = (f'sonic-db-cli CONFIG_DB hset "STATIC_ROUTE|fcbb:bbbb:{snappi_sid}::/48" '
                            f'nexthop {snappi_dest_host_ip} ifname {snappi_dest_port}')

            logger.info(f'Static route from T0 to tgen: {static_route}')
            Common_vars.config_data[dut]['static_routes'].append(static_route)
            Common_vars.static_route_subnet_start = increment_hex(str(Common_vars.static_route_subnet_start))


def construct_dut_peer_connections(dut_connection_parings, Common_vars):
    # Static routes for topologies with more than 1 DUT
    for dut_connection_pair in dut_connection_parings:
        # dut_connection: ('switch-t0-1', 'switch-t1-1')
        # [('switch-t0-1', 'switch-t1-1'), ('switch-t1-1', 'switch-t2-1'),
        #  ('switch-t2-1', 'switch-t1-2'), ('switch-t1-2', 'switch-t0-2')]

        for dut in dut_connection_pair:
            # Assign IP address to each port
            # 'dut_link_ip_addresses': {'switch-t0-1': ['5000::2/64', '5000::2/64', '5000::2/64', '5000::2/64',
            #                                           '5000::2/64', '5000::2/64', '5000::2/64', '5000::2/64']}
            for adjacent_dut, local_dut_ip_list in Common_vars.config_data[dut]['dut_link_port_connections'].items():
                for index, each_ip in enumerate(local_dut_ip_list):
                    adjacent_dut_sid = Common_vars.config_data[adjacent_dut]['my_sids'][index]

                    # 'dut_link_port_connections': {'switch-t0-1': ['Ethernet128', 'Ethernet129', 'Ethernet130',
                    # 'Ethernet131', 'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135']}
                    # next_hop_local_dut_port = (Common_vars.config_data[dut]['dut_link_port_connections']
                    #                            [adjacent_dut][index])
                    next_hop_local_dut_port = (
                        Common_vars.config_data[dut]['dut_link_port_connections'][adjacent_dut][index]
                    )

                    next_hop_ip = (
                        Common_vars.config_data[adjacent_dut]['dut_link_ip_addresses'][dut][index].split("/")[0]
                    )

                    to_route = f'fcbb:bbbb:{adjacent_dut_sid}::/48'
                    static_route = (f'sonic-db-cli CONFIG_DB hset "STATIC_ROUTE|{to_route}" '
                                    f'nexthop {next_hop_ip} ifname {next_hop_local_dut_port}')

                    if static_route not in Common_vars.config_data[dut]['static_routes']:
                        Common_vars.config_data[dut]['static_routes'].append(static_route)


def config_dut_interface_ip(duthosts, Common_vars):
    # Configure DUT links in between DUTs
    for dut in duthosts:
        # 'dut_link_ip_addresses': {
        #     'switch-t1-1': ['5010::2/64', '5011::2/64', '5012::2/64', '5013::2/64',
        #                     '5014::2/64', '5015::2/64', '5016::2/64', '5017::2/64'],
        #     'switch-t1-2': ['5018::2/64', '5019::2/64', '501a::2/64', '501b::2/64',
        #                     '501c::2/64', '501d::2/64', '501e::2/64', '501f::2/64']
        # }
        # 'dut_link_port_connections': {
        #     'switch-t1-1': ['Ethernet128', 'Ethernet129', 'Ethernet130', 'Ethernet131',
        #                     'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135'],
        #     'switch-t1-2': ['Ethernet100', 'Ethernet101', 'Ethernet102', 'Ethernet103',
        #                     'Ethernet104', 'Ethernet105', 'Ethernet106', 'Ethernet107']
        # }
        for adjacent_dut, dut_ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for index, port in enumerate(dut_ports):
                ip_address = Common_vars.config_data[dut.hostname]['dut_link_ip_addresses'][adjacent_dut][index]

                # {'dut': 'switch-t0-1', 'ip_address': '5010::1/64', 'local_dut_port': 'Ethernet128',
                #  'port': 'Ethernet128'}
                logger.info(f'DUT:{dut.hostname}: sudo config int ip add {port} {ip_address}')
                dut.shell(f'sudo config int ip add {port} {ip_address}')


def dut_ping_neighbor_links(duthosts, Common_vars):
    for dut in duthosts:
        for adjacent_dut, dut_ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for index, link in enumerate(dut_ports):
                adjacent_dut_link_ip = (
                    Common_vars.config_data[adjacent_dut]['dut_link_ip_addresses'][dut.hostname][index].split('/')[0]
                )

                logger.info((f'Ping adjacent DUT to learn ARP: {dut.hostname} -> {adjacent_dut}  '
                             f'pinging {adjacent_dut_link_ip}'))

                dut.shell(f'ping {adjacent_dut_link_ip} -c 2')


def configure_dut_static_routes(duthosts, Common_vars):
    # Configure static routes on DUTs
    # All static routes cli commands are created in a list already
    # 'sonic-db-cli CONFIG_DB hset "STATIC_ROUTE|fcbb:bbbb:1000::/48" nexthop 5010::1 ifname Ethernet128'
    for dut in duthosts:
        for static_route in Common_vars.config_data[dut.hostname]['static_routes']:
            logger.info(f'DUT:{dut.hostname} -> {static_route}')
            dut.shell(f'{static_route}')


def config_traffic_flows(pket_size, duthosts, snappi_config, Common_vars):
    for dut in duthosts:
        for flow in Common_vars.config_data[dut.hostname]['tx_ports']:
            tx_snappi_port_name_for_raw_pkts = Common_vars.port_name_mapper[flow['my_snappi_port']]
            rx_snappi_port_name_for_raw_pkts = Common_vars.port_name_mapper[flow['rx_port']]

            flow_name = (f"{flow['my_snappi_port']}:{tx_snappi_port_name_for_raw_pkts} -> "
                         f"{flow['rx_port']}:{rx_snappi_port_name_for_raw_pkts}")

            test_flow = snappi_config.flows.add(name=flow_name)

            test_flow.tx_rx.port.tx_name = tx_snappi_port_name_for_raw_pkts
            test_flow.tx_rx.port.rx_name = rx_snappi_port_name_for_raw_pkts
            test_flow.size.fixed = pket_size
            test_flow.rate.percentage = 100
            test_flow.duration.continuous

            ethernet = test_flow.packet.add()
            ethernet.choice = "ethernet"
            ethernet.ethernet.src.value = flow['my_src_mac']
            ethernet.ethernet.dst.value = Common_vars.config_data[dut.hostname]['router_mac_address']

            ipv6_outer = test_flow.packet.add()
            ipv6_outer.choice = "ipv6"
            ipv6_outer.ipv6.src.value = flow['my_src_ip']
            ipv6_outer.ipv6.dst.value = flow['my_ipv6_srv6_dest']
            ipv6_outer.ipv6.next_header.value = 43
            ipv6_outer.ipv6.hop_limit.value = 126

            ipv6_inner = test_flow.packet.add()
            ipv6_inner.choice = "ipv6"
            ipv6_inner.ipv6.src.value = flow['my_src_ip']
            ipv6_inner.ipv6.dst.value = flow['rx_port_ip_address']
            ipv6_inner.ipv6.next_header.value = 59
            ipv6_inner.ipv6.hop_limit.value = 126


def clear_dut_stats(duthosts):
    for duthost in duthosts:
        logger.info(f'sonic-clear counters on DUT: {duthost.hostname} ...')
        duthost.shell("sonic-clear counters")


def get_ingress_egress_stats(full_path_duts, Common_vars):
    """
    For tracing SRv6 DUT path end-to-end for ingress and egress stats
    """
    cfg = Common_vars.config_data

    parsed = {dut: _dut_counters(Common_vars.dut_stats, dut) for dut in full_path_duts}

    # Single-t0 fabric: no inter-dut hops, ingress/egress are both on the one dut.
    if len(full_path_duts) == 1:
        return _single_dut_stats(full_path_duts[0], cfg, parsed)

    link_counts = [len(cfg[a]['dut_link_port_connections'][b])
                   for a, b in zip(full_path_duts, full_path_duts[1:])]
    n = min(link_counts)
    if len(set(link_counts)) > 1:
        logger.warning(f"hop link counts differ {link_counts}; aligning on min={n}")

    last = len(full_path_duts) - 1

    aligned = []
    for index in range(n):
        chain = []
        for pos, dut in enumerate(full_path_duts):
            prev_dut = full_path_duts[pos - 1] if pos > 0 else None
            next_dut = full_path_duts[pos + 1] if pos < last else None

            # ingress: from previous DUT, OR the tgen-facing port on the first t0
            if prev_dut:
                ingress = cfg[dut]['dut_link_port_connections'][prev_dut][index]
            else:
                ingress = _tgen_facing_port(cfg, dut, index)     # entry t0 <- tgen

            # egress: to next DUT, OR the tgen-facing port on the last t0
            if next_dut:
                egress = cfg[dut]['dut_link_port_connections'][next_dut][index]
            else:
                egress = _tgen_facing_port(cfg, dut, index)      # exit t0 -> tgen

            counters = parsed[dut]
            chain.append({'dut': dut,
                          'tier': Multi_Tier_Map.tier_of(dut),
                          'ingress_port': ingress,
                          'egress_port': egress,
                          'ingress_stats': counters.get(ingress, {}) if ingress else {},
                          'egress_stats': counters.get(egress, {}) if egress else {}
                          })
        aligned.append({'index': index, 'chain': chain})

    return aligned


def get_dut_stat_counters(duthosts, conn_graph_facts, Common_vars):
    for dut in Common_vars.dut_hosts:
        # 'dut_link_port_connections': {'switch-t1-2': ['Ethernet128', 'Ethernet129', 'Ethernet130', 'Ethernet131',
        #                               'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135']
        # }
        # Get all the link ports on the current dut to get the link port stats
        grep_for_ports = 'grep '
        for adjacent_dut, ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for port in ports:
                grep_for_ports += f'-e {port} '

        for tx_port in Common_vars.config_data[dut.hostname]['tx_ports']:
            grep_for_ports += f'-e {tx_port["my_dut_port"]} '

        cli_command = f'show int counters | {grep_for_ports}'
        logger.info(f'Getting DUT stats on: {dut.hostname} -> {cli_command}')
        dut_stats = ('IFACE STATE RX_OK RX_BPS RX_UTIL RX_ERR RX_DRP '
                     'RX_OVR TX_OK TX_BPS TX_UTIL TX_ERR TX_DRP TX_OVR\n')
        dut_stats += dut.shell(cli_command)['stdout']
        Common_vars.dut_stats[dut.hostname] = dut_stats
        logger.info(dut_stats)


def verify_nut_stats(aligned, snappi_stats):
    """
    For tracing SRv6 DUT path end-to-end to verify ingress and egress stats
    are equal or more than the tx-port's transmitted packets

    snappi stats:
        bytes_rx: '560736539008'
        bytes_tx: '0'
        frames_rx: '260068189'
        frames_rx_rate: 0.0
        frames_tx: '260068189'
        frames_tx_rate: 0.0
        latency: {}
        loss: 0.0
        name: 10.36.84.36/1.1:Port_1 -> 10.36.84.37/3.1:Port_9
        port_rx: Port_9
        port_tx: Port_1
        rx_l1_rate_bps: 0.0
        rx_rate_bps: 0.0
        rx_rate_bytes: 0.0
        rx_rate_kbps: 0.0
        rx_rate_mbps: 0.0
        transmit: stopped
        tx_l1_rate_bps: 0.0
        tx_rate_bps: 0.0
        tx_rate_bytes: 0.0
        tx_rate_kbps: 0.0
        tx_rate_mbps: 0.0

    === link index 0 ===
    t0  switch-t0-1    in Ethernet64  (RX_OK=260068189)  ->  out Ethernet128 (TX_OK=260068307)
    t0  switch-t0-2    in Ethernet128 (RX_OK=260068310)  ->  out Ethernet80  (TX_OK=260068193)
    """
    result = True  # PASSED

    for row in aligned:
        logger.info(f"\n=== Link port index {row['index']} ===")
        snappi_tx_frames = snappi_stats[row['index']].frames_tx

        for hop in row['chain']:
            ig, eg = hop['ingress_port'], hop['egress_port']
            ig_rx = hop['ingress_stats'].get('RX_OK', '-')
            eg_tx = hop['egress_stats'].get('TX_OK', '-')
            logger.info(f"  {hop['tier']:3} {hop['dut']:14} "
                        f"in {str(ig):12}(RX_OK={ig_rx})  ->  out {str(eg):12}(TX_OK={eg_tx})")

            # The DUT counter RX/TX stats must be equal or more than the TX-port transmitted packets.
            # It is ok for DUT link ports to have a little more packets from periodic protocol packets.
            if int(ig_rx) < int(snappi_tx_frames) or int(eg_tx) < int(snappi_tx_frames):
                logger.warning('FAILED: DUT counter stats shows less packets than transmitted packets')
                result = False

    return result


def build_dut_iface_stats(aligned):
    """
    For tracing SRv6 DUT path end-to-end for ingress and egress stats

    Collapse the index-aligned chain into per-DUT interface stats:

        {
          'switch-t0-1': {'Ethernet128': {'rx_ok': 123, 'tx_ok': 456}, ...},
          'switch-t1-1': {'Ethernet0':   {'rx_ok': ...,  'tx_ok': ...}, ...},
          ...
        }
    """
    dut_stats = {}

    for row in aligned:
        for hop in row['chain']:
            dut = hop['dut']
            ifaces = dut_stats.setdefault(dut, {})

            # both ingress and egress ports of this hop
            for port, stats in ((hop['ingress_port'], hop['ingress_stats']),
                                (hop['egress_port'],  hop['egress_stats'])):
                if not port:
                    continue  # endpoint side has no ingress/egress
                ifaces[port] = {
                    'rx_ok': stats.get('RX_OK'),
                    'tx_ok': stats.get('TX_OK'),
                }

    return dut_stats


def set_duthost_interface_details(duthosts, Common_vars, get_snappi_ports):
    """
    Normally would be calling get_duthost_interface_details, but this test case
    does not expect ip addresses configured on dut interfaces. So have to
    do something like get_duthost_interface_details and insert custom ipv6
    addresses:

        snappi_ports = get_duthost_interface_details(duthosts, get_snappi_ports,
                                                     subnet_type, protocol_type='ip')
    """
    get_autoneg_fec(duthosts, get_snappi_ports)
    mac_address_generator = get_macs("101700000011", len(get_snappi_ports))

    snappi_ports = []
    ipv6_address_start = Common_vars.ixia_src_ipv6_prefix_start

    for index, snappi_port in enumerate(get_snappi_ports):
        ipv6_gateway = f'fc0a::{ipv6_address_start}'
        address = increment_hex(ipv6_address_start, by=1, width=1)
        ipv6_address = f'fc0a::{address}'

        snappi_port.update({'ipAddress': ipv6_address,
                            'ipGateway': ipv6_gateway,
                            'subnet': f'{ipv6_gateway}/126',
                            'prefix': '126',
                            'asic_value': None,
                            'src_mac_address': mac_address_generator[index],
                            'router_mac_address': snappi_port['duthost'].get_dut_iface_mac(snappi_port['peer_port'])
                            })

        snappi_ports.append(snappi_port)
        ipv6_address_start = increment_hex(str(address), by=3, width=1)

    return snappi_ports


def config_dut_ip_interface(snappi_ports):
    for snappi_port in snappi_ports:
        cli_command = f'sudo config int ip add {snappi_port["peer_port"]} {snappi_port["ipGateway"]}/{snappi_port["prefix"]}'
        logger.info(f'On DUT: {snappi_port["peer_device"]}: {cli_command}')
        snappi_port['duthost'].shell(cli_command)


def remove_srv6_config(Common_vars):
    # Remove IPv6 interfaces on DUT
    for dut in Common_vars.dut_hosts:
        for port in Common_vars.config_data[dut.hostname]['tgen_ports']:
            cli_command = f'sudo config int ip remove {port["peer_port"]} {port["ipGateway"]}/{port["prefix"]}'
            logger.info(f'Removing IPv6 int on DUT {dut.hostname}: {cli_command}')
            dut.shell(cli_command)

    # Remove SRv6 SIDs on DUT
    for dut in Common_vars.dut_hosts:
        count = 1
        for sid in Common_vars.config_data[dut.hostname]['my_sids']:
            logger.info(f'Removing SRv6 loc{count} sid fcbb:bbbb:{sid}::/48 and locator on {dut.hostname} ...')
            dut.shell(f'sudo sonic-db-cli CONFIG_DB DEL "SRV6_MY_LOCATORS|loc{count}"')
            dut.shell(f'sudo sonic-db-cli CONFIG_DB DEL "SRV6_MY_SIDS|loc{count}|fcbb:bbbb:{sid}::/48"')
            count += 1

    # Remove static routes on DUTs
    for dut in Common_vars.dut_hosts:
        for static_route in Common_vars.config_data[dut.hostname]['static_routes']:
            logger.info(f'DUT:{dut.hostname} -> sudo {static_route.replace("hset", "del")}')

            # Common_vars.dut_hosts[0].shell(f'sonic-db-cli CONFIG_DB del "STATIC_ROUTE|{route_lookup}"
            # nexthop {nexthop} ifname {ifname}')
            dut.shell(f'sudo {static_route.replace("hset", "del")}')

    # Remove configured DUT links in between DUTs
    for dut in Common_vars.dut_hosts:
        # 'dut_link_ip_addresses': {
        #     'switch-t1-1': ['5010::2/64', '5011::2/64', '5012::2/64', '5013::2/64',
        #                     '5014::2/64', '5015::2/64', '5016::2/64', '5017::2/64'],
        #     'switch-t1-2': ['5018::2/64', '5019::2/64', '501a::2/64', '501b::2/64',
        #                     '501c::2/64', '501d::2/64', '501e::2/64', '501f::2/64']
        # }
        # 'dut_link_port_connections': {
        #     'switch-t1-1': ['Ethernet128', 'Ethernet129', 'Ethernet130', 'Ethernet131',
        #                     'Ethernet132', 'Ethernet133', 'Ethernet134', 'Ethernet135'],
        #     'switch-t1-2': ['Ethernet100', 'Ethernet101', 'Ethernet102', 'Ethernet103',
        #                     'Ethernet104', 'Ethernet105', 'Ethernet106', 'Ethernet107']
        # }
        for adjacent_dut, dut_ports in Common_vars.config_data[dut.hostname]['dut_link_port_connections'].items():
            for index, port in enumerate(dut_ports):
                ip_address = Common_vars.config_data[dut.hostname]['dut_link_ip_addresses'][adjacent_dut][index]

                # {'dut': 'switch-t0-1', 'ip_address': '5010::1/64', 'local_dut_port': 'Ethernet128',
                #  'port': 'Ethernet128'}
                logger.info(f'DUT:{dut.hostname}: sudo config int ip remove {port} {ip_address}')
                dut.shell(f'sudo config int ip remove {port} {ip_address}')
