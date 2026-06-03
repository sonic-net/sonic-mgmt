import os
import pytest
import pprint
from spytest import st, tgapi, SpyTestDict
import qos_test_utils as common_util
from spytest.tgen.tg import get_ixiangpf as ixia_handle
import qos_test_utils

ONE_GBPS = 1000000000

# Note on reading link information in the dictionaries below.
# D1D2P1 means an interface on node D1 that connects to an
# interface on node D2. P1 refers to first such link
#
# D2D1P1 means an interface on node D2 that connects to an
# interface on node D1. P1 refers to first such link

# Each leaf has 2 links going to the spine
# Each leaf has 4 links going to traffic generator
one_spine_three_leaf_map = {
    # Links between spine and 3 leaves
    'D1D2P1' : '35.1.1.1',
    'D2D1P1' : '35.1.1.2',

    'D1D2P2' : '37.1.1.1',
    'D2D1P2' : '37.1.1.2',

    'D1D3P1' : '39.1.1.1',
    'D3D1P1' : '39.1.1.2',

    'D1D3P2' : '41.1.1.1',
    'D3D1P2' : '41.1.1.2',

    'D1D4P1' : '43.1.1.1',
    'D4D1P1' : '43.1.1.2',

    'D1D4P2' : '45.1.1.1',
    'D4D1P2' : '45.1.1.2',


    # Links from leaves to traffic generator
    'D2T1P1' : '11.1.1.1',
    'D2T1P2' : '13.1.1.1',
    'D2T1P3' : '15.1.1.1',
    'D2T1P4' : '17.1.1.1',

    'D3T1P1' : '19.1.1.1',
    'D3T1P2' : '21.1.1.1',
    'D3T1P3' : '23.1.1.1',
    'D3T1P4' : '25.1.1.1',

    'D4T1P1' : '27.1.1.1',
    'D4T1P2' : '29.1.1.1',
    'D4T1P3' : '31.1.1.1',
    'D4T1P4' : '33.1.1.1'
}

# Each leaf has 2 links to each pine
# Each leaf has 4 links to traffic generator
two_spine_two_leaf_map = {
    # Links between spines and leaves
    'D1D3P1' : '11.1.1.1',
    'D3D1P1' : '11.1.1.2',

    'D1D3P2' : '13.1.1.1',
    'D3D1P2' : '13.1.1.2',

    'D1D4P1' : '15.1.1.1',
    'D4D1P1' : '15.1.1.2',

    'D1D4P2' : '17.1.1.1',
    'D4D1P2' : '17.1.1.2',

    'D2D3P1' : '19.1.1.1',
    'D3D2P1' : '19.1.1.2',

    'D2D3P2' : '21.1.1.1',
    'D3D2P2' : '21.1.1.2',

    'D2D4P1' : '23.1.1.1',
    'D4D2P1' : '23.1.1.2',

    'D2D4P2' : '25.1.1.1',
    'D4D2P2' : '25.1.1.2',

    # Links from leaves to traffic generator
    'D3T1P1' : '27.1.1.1',
    'D3T1P2' : '29.1.1.1',
    'D3T1P3' : '31.1.1.1',
    'D3T1P4' : '33.1.1.1',

    'D4T1P1' : '35.1.1.1',
    'D4T1P2' : '37.1.1.1',
    'D4T1P3' : '39.1.1.1',
    'D4T1P4' : '41.1.1.1'
}

# This is used in a back 2 back setup. 2 DUTs connected to each other via
# one link and also having 4 links each to traffic generator
b2b_ip_map = {
    # Links from leaves to traffic generator
    'D3T1P1' : '27.1.1.1',
    'D3T1P2' : '29.1.1.1',
    'D3T1P3' : '31.1.1.1',
    'D3T1P4' : '33.1.1.1',

    'D4T1P1' : '35.1.1.1',
    'D4T1P2' : '37.1.1.1',
    'D4T1P3' : '39.1.1.1',
    'D4T1P4' : '41.1.1.1',
}

one_device_map = {
    'D1T1P1' : '11.1.1.1',
    'D1T1P2' : '13.1.1.1',
    'D1T1P3' : '15.1.1.1',
    'D1T1P4' : '17.1.1.1',

    'D2T1P1' : '11.1.1.1',
    'D2T1P2' : '13.1.1.1',
    'D2T1P3' : '15.1.1.1',
    'D2T1P4' : '17.1.1.1',

    'D3T1P1' : '11.1.1.1',
    'D3T1P2' : '13.1.1.1',
    'D3T1P3' : '15.1.1.1',
    'D3T1P4' : '17.1.1.1',

    'D4T1P1' : '11.1.1.1',
    'D4T1P2' : '13.1.1.1',
    'D4T1P3' : '15.1.1.1',
    'D4T1P4' : '17.1.1.1'
}

# A given tgen port can be used multiple times to create traffic streams.
# We track the usage count here to generate unique IP addresses for each
# such instance
tgen_port_usage_cnt = {
    'T1D1P1' : 0,
    'T1D1P2' : 0,
    'T1D1P3' : 0,
    'T1D1P4' : 0,
    'T1D2P1' : 0,
    'T1D2P2' : 0,
    'T1D2P3' : 0,
    'T1D2P4' : 0,
    'T1D3P1' : 0,
    'T1D3P2' : 0,
    'T1D3P3' : 0,
    'T1D3P4' : 0,
    'T1D4P1' : 0,
    'T1D4P2' : 0,
    'T1D4P3' : 0,
    'T1D4P4' : 0
}

# Cache TC-to-PG map per DUT to avoid repeated CLI queries
pg_map_cache = []
tgen_handle = None
lossless = []

# Track ports where PFC/FCoE L1 config has already been applied.
# Re-applying causes a link bounce which leads to ARP failures.
_pfc_configured_ports = set()

# Ixia supports only 4 PFC priority groups (0-3).
# PG 0 is reserved for lossy TCs.  PG 1..3 are assigned to lossless TCs.
MAX_IXIA_PG = 4

def build_tc_to_pg_map(tc_list):
    """Build a TC-to-PG map from the given lossless TC list.

    PG 0 is shared by all lossy TCs.  Each lossless TC gets its own PG
    starting from PG 1.  Ixia supports at most 4 PGs, so a maximum of
    3 lossless TCs can be mapped (PG 1, 2, 3).

    Returns:
        List of 8 strings, index=TC, value=PG.
    """
    if len(tc_list) > MAX_IXIA_PG - 1:
        st.error(f"Too many lossless TCs ({len(tc_list)}); "
                 f"Ixia supports at most {MAX_IXIA_PG - 1}")
    pg_map = ['0'] * 8
    for idx, tc in enumerate(tc_list):
        pg_map[int(tc)] = str(idx + 1)     # PG 1, 2, 3 ...
    return pg_map

def configure_tc_to_pg_map(dut, pg_map, map_name='AZURE'):
    """
    Set the router's TC-to-Priority-Group map using CLI.
    
    Args:
        dut: DUT handle
        pg_map: List of 8 PG values as strings, index=TC, value=PG
        map_name: Name of the map profile (default: AZURE)
    """
    # Build CLI string: "0:0,1:0,2:0,3:1,4:2,5:0,6:0,7:3"
    maps_str = ','.join(f'{tc}:{pg}' for tc, pg in enumerate(pg_map))
    cmd = f'config tc-to-priority-group-map update {map_name} --maps "{maps_str}"'
    st.log("Setting TC-to-PG map on {}: {}".format(dut, cmd))
    st.config(dut, cmd, skip_error_check=True)

def init_qos_on_dut(dut, tc_list=[3, 4]):
    """Reload QoS defaults and set the IXIA-compatible TC-to-PG map on a DUT."""

    global tgen_handle
    global lossless
    global pg_map_cache

    # Ensure IXIA-facing ports on leaf DUTs (D3/D4) are up
    vars = st.get_testbed_vars()
    if vars.D3 == dut:
        leaf = 'D3'
    elif vars.D4 == dut:
        leaf = 'D4'
    else:
        leaf = None
    if leaf:
        ports = ''
        port_cnt = 0
        for i in range(1, 5):
            key = f'{leaf}T1P{i}'
            if not hasattr(vars, key):
                break
            port = getattr(vars, key)
            st.config(dut, f'config interface startup {port}',
                      skip_tmpl=True, skip_error_check=True)
            ports += f'{port}|'
            port_cnt += 1

        st.log(f'IXIA port cnt {port_cnt}')
        up_cnt = 0
        # Try upto 60 seconds to ensure ports are up
        for i in range(1, port_cnt + 1):
            st.wait(15)
            result = st.show(dut, f"show int status | egrep '{ports[:-1]}'",
                             skip_tmpl=True, skip_error_check=True)
            up_cnt = 0
            for line in result.splitlines():
                if 'Ethernet' not in line:
                    continue
                tokens = line.split()
                if tokens.count('up') < 2:
                    break
                up_cnt += 1
            if up_cnt == port_cnt:
                break

        if up_cnt < port_cnt:
            # Most tests are D3 based, so allow some down ports on D4
            st.report_fail('msg',
                f"IXIA port {tokens[0]} is not up on {leaf} - aborting test")
            
    lossless = tc_list
    if len(pg_map_cache) == 0:
        pg_map_cache = build_tc_to_pg_map(tc_list)
    qos_test_utils.perform_qos_reload(dut)
    if tgen_handle is None:
        tgen_handle,_ = tgapi.get_handle_byname('T1D3P1')
    if leaf is None:
        return

    for i in range(1, 5):
        key = f'T1{leaf}P{i}'
        if not hasattr(vars, key):
            break
        _,port_handle = tgapi.get_handle_byname(key)
        _configure_pfc_raw(port_handle)

def _wait_for_vport_link_up(ixnet, vport, port_handle, timeout=30):
    """Poll vport state until the link is up or timeout expires."""
    for i in range(timeout):
        state = ixnet.getAttribute(vport, '-state')
        if str(state).lower() == 'up':
            st.log(f"Port {port_handle} link is up after {i}s")
            return True
        st.wait(1)
    st.error(f"Port {port_handle} link did not come up within {timeout}s "
             f"(state={state})")
    return False

def _configure_pfc_raw(port_handle):
    """Enable PFC/FCoE on a port using the raw ixnet API."""
    st.log(f"Configuring PFC via raw ixnet on port {port_handle} "
           f"with pg_map={pg_map_cache}")
    ixiangpf = ixia_handle()
    ixnet = ixiangpf.ixnet
    root = ixnet.getRoot()

    vport = ixnet.getFilteredList(root, 'vport', '-name', port_handle)[0]
    l1config = ixnet.getList(vport, 'l1Config')[0]

    # Read the current L1 type to derive the FCoE variant dynamically
    cur_type = ixnet.getAttribute(l1config, '-currentType')
    base_type = cur_type.replace('Fcoe', '')  # strip Fcoe if already set
    fcoe_type = base_type + 'Fcoe'
    st.log(f"Port L1 type: {cur_type} -> base={base_type}, fcoe={fcoe_type}")

    already_fcoe = 'fcoe' in str(cur_type).lower()

    ixnet.setMultiAttribute(l1config, '-currentType', fcoe_type)
    ixnet.setMultiAttribute(
        vport + '/l1Config/' + base_type + '/fcoe',
        '-supportDataCenterMode', 'true',
        '-flowControlType', 'ieee802.1Qbb',
        '-enablePFCPauseDelay', 'false',
        '-pfcPauseDelay', '1',
        '-pfcQueueGroups', pg_map_cache,
        '-pfcQueueGroupSize', 'pfcQueueGroupSize-4'
    )
    ixnet.commit()

    # Verify FCoE/PFC was actually set
    dcm = ixnet.getAttribute(vport + '/l1Config/' + base_type + '/fcoe',
                             '-supportDataCenterMode')
    cur_type = ixnet.getAttribute(l1config, '-currentType')
    st.log(f"PFC verify on port {port_handle}: "
           f"currentType={cur_type}, supportDataCenterMode={dcm}")
    if str(dcm).lower() != 'true' or 'fcoe' not in str(cur_type).lower():
        st.error(f"PFC config FAILED on port {port_handle}: "
                 f"currentType={cur_type}, supportDataCenterMode={dcm}")
        return False

    # If L1 type changed, the link will bounce — wait for it to come back
    if not already_fcoe:
        st.log(f"L1 type changed to FCoE on {port_handle}, "
               f"waiting for link up")
        if not _wait_for_vport_link_up(ixnet, vport, port_handle):
            return False

    _pfc_configured_ports.add(port_handle)
    st.log(f"PFC configured and verified on port {port_handle}")
    return True

def _disable_pfc_raw(port_handle):
    """Disable PFC/FCoE on a port using the raw ixnet API."""
    if port_handle not in _pfc_configured_ports:
        return
    st.log(f"Disabling PFC via raw ixnet on port {port_handle}")
    try:
        ixiangpf = ixia_handle()
        ixnet = ixiangpf.ixnet
        root = ixnet.getRoot()
        vport = ixnet.getFilteredList(root, 'vport', '-name', port_handle)[0]
        l1config = ixnet.getList(vport, 'l1Config')[0]

        # Read the current L1 type to derive the base type dynamically
        cur_type = ixnet.getAttribute(l1config, '-currentType')
        base_type = cur_type.replace('Fcoe', '')
        st.log(f"Port L1 type: {cur_type} -> base={base_type}")

        ixnet.setMultiAttribute(l1config, '-currentType', base_type)
        ixnet.setMultiAttribute(
            vport + '/l1Config/' + base_type + '/fcoe',
            '-supportDataCenterMode', 'false',
            '-flowControlType', 'ieee802.3x'
        )
        ixnet.commit()
        _pfc_configured_ports.discard(port_handle)
        st.log(f"PFC disabled on port {port_handle}")
    except Exception as e:
        st.log(f"Warning: Failed to disable PFC on {port_handle}: {e}")

def ip_to_net(value):
    return value[:-1] + '0'

def config_one_spine_three_leaf_topo(tb_dict):
    global net_map

    net_map = one_spine_three_leaf_map
    cfg_dut1 = ''
    cfg_dut2 = ''
    cfg_dut3 = ''
    cfg_dut4 = ''
    ping_dut1 = ''
    ping_dut2 = ''
    ping_dut3 = ''
    ping_dut4 = ''
    cfg_route_dut1 = ''
    cfg_route_dut2 = ''
    cfg_route_dut3 = ''
    cfg_route_dut4 = ''
    for key, value in net_map.items():
        if key not in tb_dict:
            continue
        cfg_str = 'config interface ip add {} {}/24\n'.format(tb_dict[key],
                                                              value) 
        p1 = key[0:2]
        p2 = key[2:4]
        if p1 == 'D1':
            cfg_dut1 += cfg_str
            continue

        net = ip_to_net(value)
        if p1 == 'D2':
            cfg_dut2 += cfg_str
            if p2 == 'D1':
                continue
            cfg_route_dut1 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D2D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D2D1P1'])
            cfg_route_dut3 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D3P1'])
            ping_dut3 += 'ping -c 3 {}\n'.format(net_map['D1D3P1'])
            cfg_route_dut4 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D4P1'])
            ping_dut4 += 'ping -c 3 {}\n'.format(net_map['D1D4P1'])
        elif p1 == 'D3':
            cfg_dut3 += cfg_str
            if p2 == 'D1':
                continue
            cfg_route_dut1 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D3D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D3D1P1'])
            cfg_route_dut2 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D1D2P1'])
            cfg_route_dut4 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D4P1'])
            ping_dut4 += 'ping -c 3 {}\n'.format(net_map['D1D4P1'])
        else:
            cfg_dut4 += cfg_str
            if p2 == 'D1':
                continue
            cfg_route_dut1 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D4D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D4D1P1'])
            cfg_route_dut2 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D1D2P1'])
            cfg_route_dut3 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D3P1'])
            ping_dut3 += 'ping -c 3 {}\n'.format(net_map['D1D3P1'])

    st.config(tb_dict.D1, cfg_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_dut4, skip_tmpl=True)
    st.config(tb_dict.D1, ping_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, ping_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, ping_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, ping_dut4, skip_tmpl=True)
    st.wait(2)
    st.config(tb_dict.D1, cfg_route_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_route_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_route_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_route_dut4, skip_tmpl=True)

def config_two_spine_two_leaf_topo(tb_dict):
    global net_map

    net_map = two_spine_two_leaf_map

    # Startup all relevant interfaces before configuring IP addresses
    # Spine-leaf links as (link, reverse_link) pairs - both ends need startup
    spine_leaf_links = [
        ('D1D3P1', 'D3D1P1'), ('D1D3P2', 'D3D1P2'),
        ('D1D4P1', 'D4D1P1'), ('D1D4P2', 'D4D1P2'),
        ('D2D3P1', 'D3D2P1'), ('D2D3P2', 'D3D2P2'),
        ('D2D4P1', 'D4D2P1'), ('D2D4P2', 'D4D2P2'),
    ]
    # IXIA links on both leaves (only one end on DUT)
    ixia_links = ['D3T1P1', 'D3T1P2', 'D3T1P3', 'D3T1P4',
                  'D4T1P1', 'D4T1P2', 'D4T1P3', 'D4T1P4']

    startup_cfg_d1 = ''
    startup_cfg_d2 = ''
    startup_cfg_d3 = ''
    startup_cfg_d4 = ''

    # Process spine-leaf links - startup both ends
    for link, reverse_link in spine_leaf_links:
        # Startup first end (e.g., D1D3P1 on D1)
        if link in tb_dict:
            intf = tb_dict[link]
            dut = link[0:2]
            if dut == 'D1':
                startup_cfg_d1 += 'config interface startup {}\n'.format(intf)
            elif dut == 'D2':
                startup_cfg_d2 += 'config interface startup {}\n'.format(intf)

        # Startup second end (e.g., D3D1P1 on D3)
        if reverse_link in tb_dict:
            intf = tb_dict[reverse_link]
            dut = reverse_link[0:2]
            if dut == 'D3':
                startup_cfg_d3 += 'config interface startup {}\n'.format(intf)
            elif dut == 'D4':
                startup_cfg_d4 += 'config interface startup {}\n'.format(intf)

    # Process IXIA links
    for link in ixia_links:
        if link not in tb_dict:
            continue
        intf = tb_dict[link]
        dut = link[0:2]
        if dut == 'D3':
            startup_cfg_d3 += 'config interface startup {}\n'.format(intf)
        elif dut == 'D4':
            startup_cfg_d4 += 'config interface startup {}\n'.format(intf)

    if startup_cfg_d1:
        st.config(tb_dict.D1, startup_cfg_d1, skip_tmpl=True, skip_error_check=True)
    if startup_cfg_d2:
        st.config(tb_dict.D2, startup_cfg_d2, skip_tmpl=True, skip_error_check=True)
    if startup_cfg_d3:
        st.config(tb_dict.D3, startup_cfg_d3, skip_tmpl=True, skip_error_check=True)
    if startup_cfg_d4:
        st.config(tb_dict.D4, startup_cfg_d4, skip_tmpl=True, skip_error_check=True)

    st.wait(5)  # Allow interfaces to come up

    cfg_dut1 = ''
    cfg_dut2 = ''
    cfg_dut3 = ''
    cfg_dut4 = ''
    ping_dut1 = ''
    ping_dut2 = ''
    ping_dut3 = ''
    ping_dut4 = ''
    cfg_route_dut1 = ''
    cfg_route_dut2 = ''
    cfg_route_dut3 = ''
    cfg_route_dut4 = ''
    for key, value in net_map.items():
        if key not in tb_dict:
            continue

        cfg_str = 'config interface ip add {} {}/24\n'.format(tb_dict[key],
                                                              value) 
        p1 = key[0:2]
        if p1 == 'D1':
            cfg_dut1 += cfg_str
            continue
        if p1 == 'D2':
            cfg_dut2 += cfg_str
            continue

        p2 = key[2:4]
        net = ip_to_net(value)
        if p1 == 'D3':
            cfg_dut3 += cfg_str
            if p2 == 'D1' or p2 == 'D2':
                continue
            cfg_route_dut1 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D3D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D3D1P1'])
            cfg_route_dut2 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D3D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D3D2P1'])
            cfg_route_dut4 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D2D4P1'])
            ping_dut4 += 'ping -c 3 {}\n'.format(net_map['D2D4P1'])
        else:
            cfg_dut4 += cfg_str
            if p2 == 'D1' or p2 == 'D2':
                continue
            cfg_route_dut1 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D4D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D4D1P1'])
            cfg_route_dut2 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D4D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D4D2P1'])
            cfg_route_dut3 += 'config route add prefix {}/24 nexthop {}\n'.format(net, net_map['D1D3P1'])
            ping_dut3 += 'ping -c 3 {}\n'.format(net_map['D1D3P1'])

    st.config(tb_dict.D1, cfg_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_dut4, skip_tmpl=True)
    st.config(tb_dict.D1, ping_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, ping_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, ping_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, ping_dut4, skip_tmpl=True)
    st.wait(2)
    st.config(tb_dict.D1, cfg_route_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_route_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_route_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_route_dut4, skip_tmpl=True)
    st.wait(2)
    st.show(tb_dict.D1, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D1, "ip route\n", skip_tmpl=True)
    st.show(tb_dict.D2, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D2, "ip route\n", skip_tmpl=True)
    st.show(tb_dict.D3, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D3, "ip route\n", skip_tmpl=True)
    st.show(tb_dict.D4, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D4, "ip route\n", skip_tmpl=True)

def config_ixia_links(tb_dict, vars):
    global net_map

    # Configure DUT to traffic generator links. This is one time setup
    # Note: cleanup_config() should be called before this to ensure clean state
    net_map = b2b_ip_map
    cfg_dut1 = ''
    cfg_dut2 = ''
    for key, value in net_map.items():
        if key not in tb_dict:
            continue
        p1 = key[0:2]
        if p1 == 'D3':
            cfg_dut1 += 'config interface ip add {} {}/24\n'.format(tb_dict[key], value)
        else:
            cfg_dut2 += 'config interface ip add {} {}/24\n'.format(tb_dict[key], value)
    if cfg_dut1:
        st.config(tb_dict.D3, cfg_dut1, skip_tmpl=True)
    if cfg_dut2:
        st.config(tb_dict.D4, cfg_dut2, skip_tmpl=True)

    # Just for debug display the interfaces
    st.show(tb_dict.D3, 'show ip interfaces', skip_tmpl=True)
    st.show(tb_dict.D4, 'show ip interfaces', skip_tmpl=True)

def config_b2b_routes(vars, dut_str):
    if dut_str == 'D3':
        peer_dut = vars.D4
        idx = 0
    else:
        peer_dut = vars.D3
        idx = 1

    # Configure routes on peer DUT to reach networks on local DUT
    num_b2b_links = len(vars.if_map)
    cfg_dut = ''
    i = 0
    for key, value in net_map.items():
        p1 = key[0:2]
        if p1 != dut_str:
            continue
        net = ip_to_net(value)
        cfg_dut += 'config route add prefix {}/24 nexthop {}\n'.format(net, vars.if_map[i][idx])
        uncfg = 'config route del prefix {}/24 nexthop {}\n'.format(net, vars.if_map[i][idx])
        if dut_str == 'D3':
            vars.route_uncfg[1] += uncfg
        else:
            vars.route_uncfg[0] += uncfg
        # We make an attempt to spread the routes across the available links
        i = (i + 1) % num_b2b_links
    st.config(peer_dut, cfg_dut, skip_tmpl=True)

def config_b2b_with_ixia_setup(tb_dict, vars):
    vars.route_uncfg = ['', '']
    config_ixia_links(tb_dict, vars)
    '''
    We don't need this code since we exercise breakout links one at a time
    config_b2b_routes(vars, 'D3')
    config_b2b_routes(vars, 'D4')

    # Just for debug display the ip route tables on both DUTs
    st.show(tb_dict.D3, 'ip route', skip_tmpl=True)
    st.show(tb_dict.D4, 'ip route', skip_tmpl=True)
    '''

def config_one_leaf(tb_dict, t_info):
    global net_map

    net_map = one_device_map

    # Startup all IXIA-facing interfaces on the leaf
    leaf = t_info['leaf']
    startup_cfg = ''
    port_cnt = 0
    for i in range(1, 5):
        key = leaf + 'T1P' + str(i)
        if key not in tb_dict:
            break

        port_cnt += 1
        startup_cfg += 'config interface startup {}\n'.format(tb_dict[key])

    if startup_cfg:
        st.config(t_info['dut'], startup_cfg, skip_tmpl=True, skip_error_check=True)
        st.wait(5)  # Allow interfaces to come up

    cfg_dut = ''
    for i in range(1, port_cnt + 1): 
        key = t_info['leaf'] + 'T1' + 'P' + str(i)
        cfg_dut += 'config interface ip add {} {}/24\n'\
            .format(tb_dict[key], one_device_map[key])
    st.config(t_info['dut'], cfg_dut, skip_tmpl=True)

def parse_tgen_port(tb_dict, port):
    if port.startswith('T1D1'):
        dut = tb_dict.D1
        rtr_key = 'D1T1'
    elif port.startswith('T1D2'):
        dut = tb_dict.D2
        rtr_key = 'D2T1'
    elif port.startswith('T1D3'):
        dut = tb_dict.D3
        rtr_key = 'D3T1'
    elif port.startswith('T1D4'):
        dut = tb_dict.D4
        rtr_key = 'D4T1'
    else:
        assert(0)
    return dut, (rtr_key + port[4:])

ip_alloc_dict = {}
def alloc_tgen_ip(tgen_key, rtr_key):
    # Always start with .2 and see if its in use
    n = 2
    while True:
        ip_str = net_map[rtr_key][:-1] + str(n)
        if ip_str not in ip_alloc_dict or (ip_alloc_dict[ip_str] == False):
            ip_alloc_dict[ip_str] = True
            return ip_str
        n += 1
        if n > 250:
            st.error('Cannot have over 250 active streams')
            return None

def dealloc_tgen_ip(ip_str):
    if ip_str not in ip_alloc_dict:
        st.error('Cannot dealloc IP {}'.format(ip_str))
        return
    ip_alloc_dict[ip_str] = False

def set_pfc_priority_group(tg_handle, traffic_result, tc):
    """Set the PFC queue field in the Ethernet header of a traffic item."""
    pg_value = int(pg_map_cache[int(tc)])
    ethernet_stack = traffic_result[traffic_result['traffic_item']]['headers'].split()[0]
    tg_handle.tg_traffic_config(
        mode='set_field_values',
        header_handle=ethernet_stack,
        pt_handle='ethernet',
        field_handle="ethernet.header.pfcQueue-4",
        field_activeFieldChoice='0',
        field_auto='0',
        field_optionalEnabled='1',
        field_fullMesh='0',
        field_trackingEnabled='0',
        field_valueType='singleValue',
        field_singleValue=pg_value)

def create_traffic_stream(tb_dict, tgen_src_port, tgen_dst_port, frame_size, pps, tc):

    st.log('create_traffic_stream: src {} dst {}'.format(tgen_src_port, tgen_dst_port))
    # stream creation assumes a 4 device setup with 1 spine node, 3 leaf nodes 
    # and 1 TGEN 4 tgen ports doing to each leaf

    src_dut, s_key = parse_tgen_port(tb_dict, tgen_src_port)
    dst_dut, d_key = parse_tgen_port(tb_dict, tgen_dst_port)
    _, src_port_h = tgapi.get_handle_byname(tgen_src_port)
    _, dst_port_h = tgapi.get_handle_byname(tgen_dst_port)

    # tgen_src_port is like 'T1D2P1'
    src_leaf_port = tb_dict[s_key]
    src_ip = alloc_tgen_ip(tgen_src_port, s_key)
    if src_ip == None:
        return None

    src_interface_config = {
        'mode': 'config',
        'port_handle': src_port_h,
        'gateway': net_map[s_key],
        'netmask': '255.255.255.0',
        'arp_send_req': 1,
        'enable_ping_response': 1,
        'resolve_gateway_mac': 1,
        'intf_ip_addr' : src_ip
    }

    result = tgen_handle.tg_interface_config(**src_interface_config)
    if result['status'] != '1':
        st.error('src if cfg failed {}'.format(result))
        return None
    src_handle = result['handle']

    # tgen_dst_port is like T1D3P1
    dst_interface_config = {
        'mode': 'config',
        'port_handle': dst_port_h,
        'gateway': net_map[d_key],
        'netmask': '255.255.255.0',
        'arp_send_req': 1,
        'enable_ping_response': 1,
        'resolve_gateway_mac': 1,
        'intf_ip_addr' : alloc_tgen_ip(tgen_dst_port, d_key)
    }
    if dst_interface_config['intf_ip_addr'] == None:
        return None

    # Configure destination interface
    result = tgen_handle.tg_interface_config(**dst_interface_config)
    if result['status'] != '1':
        st.error('dst if cfg failed {}'.format(result))
        return None

    dst_handle = result['handle']

    traffic_config = {
        'mode': 'create',
        # Traffic parameters
        'transmit_mode': 'continuous',
        'frame_size': frame_size,
        
        # Layer 3 configuration
        'l3_protocol': 'ipv4',
        
        # Enable flow tracking for statistics
        'track_by': 'traffic_item',
        'enable_pgid': 1,
        'rate_pps': pps
    }

    traffic_config['ip_dscp'] = common_util.convert_tc_to_dscp(dst_dut, tc)
    st.log(f"tc {tc} dscp {traffic_config['ip_dscp']}")
    # Configure traffic stream
    traffic_config['emulation_src_handle'] = src_handle
    traffic_config['emulation_dst_handle'] = dst_handle
    traffic_config['ip_src_addr'] = src_interface_config['intf_ip_addr']
    traffic_config['ip_dst_addr'] = dst_interface_config['intf_ip_addr']
    traffic_config['mac_dst'] = common_util.get_if_mac(src_dut, src_leaf_port)
    traffic_config['port_handle'] = src_port_h

    result = tgen_handle.tg_traffic_config(**traffic_config)
    if result['status'] != '1':
        st.error('traffic cfg failed {}'.format(result))
        return None

    set_pfc_priority_group(tgen_handle, result, tc)

    output_dict = {
        'src_handle' : src_handle,
        'dst_handle' : dst_handle,
        'src_ip' : src_interface_config['intf_ip_addr'],
        'dst_ip' : dst_interface_config['intf_ip_addr'],
        'stream_id' : result['stream_id'],
    }
    return output_dict

def start_traffic_stream(stream_info=None):
    tgen_handle.tg_traffic_control(action='apply')
    tgen_handle.tg_topology_test_control(action='start_all_protocols')
    if stream_info == None:
        # Start all streams
        tgen_handle.tg_traffic_control(action='run')
    else:
        # Start a specific stream
        tgen_handle.tg_traffic_control(action='run',
            stream_handle=stream_info['stream_id'])

def stop_traffic_stream(stream_info=None):
    if stream_info == None:
        # Stop all streams
        tgen_handle.tg_traffic_control(action='stop')
    else:
        # Stop a specific stream
        tgen_handle.tg_traffic_control(action='stop',
            stream_handle=stream_info['stream_id'])

def collect_traffic_stream_stats():
    # Wait upto 30 seconds to collect statistics
    for i in range(6):
        try:
            stats = tgen_handle.tg_traffic_stats(mode='traffic_item')
        except Exception as e:
            st.wait(5)
            continue
        if int(stats.get('waiting_for_stats', 0)) == 0:
            break
        st.wait(5)

    return stats

def clear_all_stats():
    tgen_handle.tg_traffic_control(action='clear_stats')

def modify_stream_rate(stream_info, gbps, frame_size=1350):
    """Modify the rate of an existing traffic stream in-place."""
    pps = gbps_to_pps(gbps, frame_size)
    tgen_handle.tg_traffic_config(mode='modify',
        stream_id=stream_info['stream_id'], rate_pps=pps)

# Gigabits per second to packets per second with given frame size
def gbps_to_pps(gbps, frame_size):
    return int((gbps * ONE_GBPS) / (8 * frame_size))

def gbps_to_bytes(gbps):
    return int((gbps * ONE_GBPS) / 8)

def delete_traffic_stream(stream_info):
    dealloc_tgen_ip(stream_info['src_ip'])
    dealloc_tgen_ip(stream_info['dst_ip'])
    tgen_handle.tg_traffic_config(mode='remove',
        stream_id=stream_info['stream_id'])
    tgen_handle.tg_interface_config(mode='destroy',
        handle=stream_info['src_handle'])
    tgen_handle.tg_interface_config(mode='destroy',
        handle=stream_info['dst_handle'])

# ---------------------------------------------------------------------------
# ECN Traffic Stream Utilities
# ---------------------------------------------------------------------------

# ECN/ECT bit values (lower 2 bits of TOS/Traffic Class byte)
ECN_NOT_ECT = 0b00  # Not-ECT: packet not participating in ECN
ECN_ECT_1 = 0b01    # ECT(1): ECN-Capable Transport
ECN_ECT_0 = 0b10    # ECT(0): ECN-Capable Transport (default)
ECN_CE = 0b11       # Congestion Experienced


def compute_ip_tos(dscp, ect=ECN_ECT_0):
    """
    Combine DSCP and ECT values into a single ip_tos byte.
    The TOS byte (IPv4) / Traffic Class byte (IPv6) format:
        Bits 7-2 (6 bits): DSCP (Differentiated Services Code Point)
        Bits 1-0 (2 bits): ECN (Explicit Congestion Notification)
    Args:
        dscp: DSCP value (0-63)
        ect: ECN codepoint (ECN_NOT_ECT, ECN_ECT_1, ECN_ECT_0, or ECN_CE)
    Returns:
        int: Combined ip_tos value (0-255)
    Example:
        DSCP 24 (TC 3) with ECT(0): compute_ip_tos(24, ECN_ECT_0) = 98 (0x62)
    """
    if not 0 <= dscp <= 63:
        raise ValueError(f"DSCP must be 0-63, got {dscp}")
    if not 0 <= ect <= 3:
        raise ValueError(f"ECT must be 0-3, got {ect}")
    return (dscp << 2) | ect



# ---------------------------------------------------------------------------
# PFC XOFF stream creation (moved here from qos_test_utils.py)
# ---------------------------------------------------------------------------

# PFC TC table - one entry per TC (0..7). Used as the data_pattern for raw
# L2 PFC XOFF frames. Same format as the working test_pfc_stream.py.
PFC_TC_TABLE = [
    '0101 0001 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0002 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0004 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0008 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0010 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0020 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0040 0000 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
    '0101 0080 0000 0000 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
]


def create_pfc_xoff_stream(tg_unused, tgen_port, src_mac, rate_fps, tc=3,
                           frame_count=None, reset_port=True):
    """
    Create a PFC XOFF stream for specified TC.
    Creates raw L2 traffic and directly configures L2 header via IxNetwork API
    to work around HLTAPI limitations with raw traffic.

    Args:
        tg_unused: TGEN handle (IGNORED - we get fresh handle)
        tgen_port: TGEN port name (e.g., 'T1D4P1')
        src_mac: Source MAC address in format 'xx:xx:xx:xx:xx:xx'
        rate_fps: Frame rate in frames per second
        tc: Traffic class (0-7), default 3
        frame_count: If None (default), stream is continuous and must be
            stopped explicitly. If an integer, the stream is configured as
            a single_burst that transmits exactly ``frame_count`` frames
            and self-terminates -- recommended for short bursts since
            IxNetwork's stop on a continuous PFC stream can take many
            seconds to take effect.
        reset_port: If True (default), reset the TGEN port to clear any
            existing traffic items before creating the stream. Set to
            False if a peer traffic stream (e.g. a data stream with this
            port as its destination) is already active on this port --
            the reset would otherwise wipe it.

    Returns:
        str: Stream ID
    """
    from spytest.tgen.tg import get_ixnet

    PFC_DST_MAC = '01:80:C2:00:00:01'
    PFC_ETHERTYPE = '8808'

    # Get tg_handle from the target port
    tg_handle, port_handle = tgapi.get_handle_byname(tgen_port)

    st.log(f"create_pfc_xoff_stream: port={tgen_port}, port_handle={port_handle}")
    st.log(f"  src_mac: {src_mac}, rate_fps: {rate_fps}, tc: {tc}")

    # Reset/clear any existing traffic items on this port (caller can
    # opt-out when peer streams targeting this port must be preserved).
    if reset_port:
        st.banner("Resetting port to clear existing traffic items")
        tg_handle.tg_traffic_control(action='reset', port_handle=port_handle)
    else:
        st.log("Skipping port reset (reset_port=False) to preserve peer streams")

    st.banner("Creating raw L2 PFC stream")
    tx_kwargs = dict(
        mode='create',
        port_handle=port_handle,
        l2_encap='ethernet_ii',
        mac_src=src_mac,
        mac_dst=PFC_DST_MAC,
        ether_type=PFC_ETHERTYPE,
        data_pattern=PFC_TC_TABLE[tc],
        data_pattern_mode='fixed',
        rate_pps=rate_fps,
        high_speed_result_analysis=1,
    )
    if frame_count is None:
        tx_kwargs['transmit_mode'] = 'continuous'
    else:
        tx_kwargs['transmit_mode'] = 'single_burst'
        tx_kwargs['pkts_per_burst'] = int(frame_count)
        st.log(f"  Using single_burst with pkts_per_burst={int(frame_count)}")
    result = tg_handle.tg_traffic_config(**tx_kwargs)

    stream_id = result.get('stream_id')
    st.log(f"Created PFC stream: {stream_id}")

    # WORKAROUND: HLTAPI doesn't properly set L2 fields for raw traffic.
    # We must directly configure via IxNetwork API.
    st.banner("Fixing L2 header via IxNetwork API")
    try:
        ixnet = get_ixnet()

        # Find the traffic item we just created
        traffic_items = ixnet.getList('/traffic', 'trafficItem')
        if not traffic_items:
            st.error("No traffic items found!")
            return stream_id

        # Get the last traffic item (the one we just created)
        ti = traffic_items[-1]
        st.log(f"Configuring traffic item: {ti}")

        # Get config element and ethernet stack
        ce = ixnet.getList(ti, 'configElement')[0]
        stacks = ixnet.getList(ce, 'stack')
        eth_stack = stacks[0]  # First stack is ethernet
        fields = ixnet.getList(eth_stack, 'field')

        # Find and set L2 fields
        # Check field path (not -name attribute) as it contains the field identifier
        for f in fields:
            st.log(f"Processing field: {f}")
            if 'destinationAddress' in f:
                ixnet.setAttribute(f, '-singleValue', PFC_DST_MAC)
                st.log(f"Set dst_mac: {PFC_DST_MAC}")
            elif 'sourceAddress' in f:
                ixnet.setAttribute(f, '-singleValue', src_mac)
                st.log(f"Set src_mac: {src_mac}")
            elif 'etherType' in f:
                # Must disable 'auto' mode for etherType first, then set value
                ixnet.setAttribute(f, '-auto', 'false')
                ixnet.setAttribute(f, '-singleValue', PFC_ETHERTYPE)
                st.log(f"Set etherType: {PFC_ETHERTYPE} (auto=false)")

        ixnet.commit()
        st.log("IxNetwork L2 header configuration committed")

        # CRITICAL: After modifying traffic config via low-level API, must regenerate
        # This is equivalent to "Generate" in the IxNetwork GUI
        # Must call 'generate' on each traffic item individually, then 'apply' on /traffic
        st.log("Regenerating all traffic items...")
        for traffic_item in traffic_items:
            ti_name = ixnet.getAttribute(traffic_item, '-name')
            st.log(f"  Generating: {ti_name}")
            ixnet.execute('generate', traffic_item)
        st.log("All traffic items regenerated")

        # Apply traffic to push to hardware (equivalent to "Apply" in the GUI)
        st.log("Applying traffic to hardware...")
        ixnet.execute('apply', '/traffic')
        st.log("Traffic applied to hardware")

        # Wait for IxNetwork to fully push to hardware
        st.wait(3)
        st.log("Generate/apply complete")

    except Exception as e:
        st.error(f"Failed to configure L2 header via IxNetwork API: {e}")
        import traceback
        st.log(traceback.format_exc())

    return stream_id


def create_pfc_xoff_burst_stream(tg_unused, tgen_port, src_mac, rate_fps,
                                 pkts_per_burst, burst_loop_count,
                                 inter_burst_gap_ms, tc=3, reset_port=False):
    """
    Create a multi-burst PFC XOFF stream with hardware-timed inter-burst gaps.

    Each "burst" sends exactly ``pkts_per_burst`` PFC pause frames at
    ``rate_fps``. Between bursts the TGEN port is silent for
    ``inter_burst_gap_ms`` milliseconds (timed by the IxNetwork hardware,
    not by host-side ``sleep``). The whole pattern is repeated
    ``burst_loop_count`` times and then self-terminates.

    Total transmit duration on-port is approximately:
        burst_loop_count * (pkts_per_burst / rate_fps) +
        (burst_loop_count - 1) * (inter_burst_gap_ms / 1000)

    Use this helper to build precise XOFF on/off patterns for testing
    PFCWD restoration timer accuracy.

    Args:
        tg_unused: Ignored (helper retrieves a fresh tg handle internally).
        tgen_port: TGEN port name (e.g. 'T1D3P3').
        src_mac: Source MAC address ('xx:xx:xx:xx:xx:xx').
        rate_fps: PFC frame rate during each burst (frames per second).
        pkts_per_burst: Number of PFC frames in each burst.
        burst_loop_count: How many bursts to transmit (1 == single burst).
        inter_burst_gap_ms: Gap between consecutive bursts, in milliseconds.
            For a single-burst stream pass burst_loop_count=1 (gap is unused).
        tc: Traffic class (0-7), default 3.
        reset_port: If True, reset the TGEN port before creating the stream.
            Default False so peer data streams targeting this port are kept.

    Returns:
        str: Stream ID
    """
    from spytest.tgen.tg import get_ixnet

    PFC_DST_MAC = '01:80:C2:00:00:01'
    PFC_ETHERTYPE = '8808'

    tg_handle, port_handle = tgapi.get_handle_byname(tgen_port)

    st.log(f"create_pfc_xoff_burst_stream: port={tgen_port}, "
           f"port_handle={port_handle}")
    st.log(f"  src_mac={src_mac} rate_fps={rate_fps} tc={tc}")
    st.log(f"  pkts_per_burst={pkts_per_burst} "
           f"burst_loop_count={burst_loop_count} "
           f"inter_burst_gap_ms={inter_burst_gap_ms}")

    if reset_port:
        st.banner("Resetting port to clear existing traffic items")
        tg_handle.tg_traffic_control(action='reset', port_handle=port_handle)
    else:
        st.log("Skipping port reset (reset_port=False) to preserve peer streams")

    st.banner("Creating raw L2 PFC multi-burst stream")
    tx_kwargs = dict(
        mode='create',
        port_handle=port_handle,
        l2_encap='ethernet_ii',
        mac_src=src_mac,
        mac_dst=PFC_DST_MAC,
        ether_type=PFC_ETHERTYPE,
        data_pattern=PFC_TC_TABLE[tc],
        data_pattern_mode='fixed',
        rate_pps=rate_fps,
        high_speed_result_analysis=1,
        transmit_mode='multi_burst',
        pkts_per_burst=int(pkts_per_burst),
        burst_loop_count=int(burst_loop_count),
        # IxNetwork only accepts 'bytes' or 'ns' for inter_burst_gap_unit;
        # convert milliseconds to nanoseconds.
        inter_burst_gap=int(inter_burst_gap_ms) * 1_000_000,
        inter_burst_gap_unit='ns',
    )
    st.log(f"  tg_traffic_config kwargs: transmit_mode=multi_burst "
           f"pkts_per_burst={int(pkts_per_burst)} "
           f"burst_loop_count={int(burst_loop_count)} "
           f"inter_burst_gap={int(inter_burst_gap_ms) * 1_000_000}ns "
           f"(={int(inter_burst_gap_ms)}ms)")
    result = tg_handle.tg_traffic_config(**tx_kwargs)
    stream_id = result.get('stream_id')
    st.log(f"Created PFC multi-burst stream: {stream_id}")

    # WORKAROUND: HLTAPI doesn't properly set L2 fields for raw traffic.
    # Same fixup as create_pfc_xoff_stream -- patch L2 header via IxNetwork
    # low-level API.
    st.banner("Fixing L2 header via IxNetwork API")
    try:
        ixnet = get_ixnet()

        traffic_items = ixnet.getList('/traffic', 'trafficItem')
        if not traffic_items:
            st.error("No traffic items found!")
            return stream_id

        ti = traffic_items[-1]
        st.log(f"Configuring traffic item: {ti}")

        ce = ixnet.getList(ti, 'configElement')[0]
        stacks = ixnet.getList(ce, 'stack')
        eth_stack = stacks[0]
        fields = ixnet.getList(eth_stack, 'field')

        for f in fields:
            if 'destinationAddress' in f:
                ixnet.setAttribute(f, '-singleValue', PFC_DST_MAC)
            elif 'sourceAddress' in f:
                ixnet.setAttribute(f, '-singleValue', src_mac)
            elif 'etherType' in f:
                ixnet.setAttribute(f, '-auto', 'false')
                ixnet.setAttribute(f, '-singleValue', PFC_ETHERTYPE)

        ixnet.commit()
        st.log("IxNetwork L2 header configuration committed")

        st.log("Regenerating all traffic items...")
        for traffic_item in traffic_items:
            ti_name = ixnet.getAttribute(traffic_item, '-name')
            st.log(f"  Generating: {ti_name}")
            ixnet.execute('generate', traffic_item)
        st.log("All traffic items regenerated")

        st.log("Applying traffic to hardware...")
        ixnet.execute('apply', '/traffic')
        st.log("Traffic applied to hardware")
        st.wait(3)
        st.log("Generate/apply complete")

    except Exception as e:
        st.error(f"Failed to configure L2 header via IxNetwork API: {e}")
        import traceback
        st.log(traceback.format_exc())

    return stream_id
