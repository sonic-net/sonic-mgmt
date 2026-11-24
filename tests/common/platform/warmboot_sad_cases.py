from tests.common.helpers.sad_path import (
    DutVlanMemberDown,
    NeighVlanMemberDown,
    DutLagMemberDown,
    NeighLagMemberDown,
    PhyPropsPortSelector,
    DatetimeSelector,
)

SAD_CASE_LIST = [
    "sad",
    "multi_sad",
    "sad_bgp",
    "sad_lag_member",
    "sad_lag",
    "sad_vlan_port",
    "sad_inboot"
]

LAG_SAD_CASE_TYPES = ("sad_lag", "sad_lag_member")


def _is_lag_sad_item(item):
    return (isinstance(item, str) and 'lag' in item) or \
           isinstance(item, (DutLagMemberDown, NeighLagMemberDown))


def _filter_lag_sad_cases(cases):
    if not cases:
        return cases
    return [item for item in cases if not _is_lag_sad_item(item)]


def should_skip_lag_sad_cases(duthost, tbinfo, sad_case_type, sad_preboot_list):
    """Skip when topology has no portchannels but the case still needs LAG sad paths."""
    has_portchannels = bool(
        duthost.get_extended_minigraph_facts(tbinfo).get('minigraph_portchannels', {}))
    if has_portchannels:
        return False
    if sad_case_type in LAG_SAD_CASE_TYPES:
        return True
    if not sad_preboot_list:
        return False
    return any(_is_lag_sad_item(item) for item in sad_preboot_list)


def _lag_string_cases(has_portchannels, *cases):
    return list(cases) if has_portchannels else []


def _lag_member_cases(duthost, nbrhosts, fanouthosts, has_portchannels,
                      dut_vm_count, neigh_vm_count, port_count):
    if not has_portchannels:
        return []
    return [
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(dut_vm_count),
                         PhyPropsPortSelector(duthost, port_count)),
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(neigh_vm_count),
                           PhyPropsPortSelector(duthost, port_count)),
    ]


def _full_lag_member_cases(duthost, nbrhosts, fanouthosts, has_portchannels, lag_member_cnt):
    # Only meaningful when LAG has multiple members; single-member LAGs are
    # already covered by _lag_member_cases(..., port_count=1).
    if not has_portchannels or lag_member_cnt <= 1:
        return []
    return [
        DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(2),
                         PhyPropsPortSelector(duthost, lag_member_cnt)),
        NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(3),
                           PhyPropsPortSelector(duthost, lag_member_cnt)),
    ]


def get_sad_case_list(duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    portchannels = mg_facts.get('minigraph_portchannels', {})
    has_portchannels = bool(portchannels)
    lagMemberCnt = len(list(portchannels.values())[0]['members']) if portchannels else 0

    sad_inboot_cases = {
        "sad_inboot": [
            'routing_del:50',               # Delete 50 routes IPv4/IPv6 each (100 total) from each BGP session
            'routing_add:50',               # Add 50 routes IPv4/IPv6 each (100 total) from each BGP session
        ]
    }

    if not has_portchannels and sad_case_type in LAG_SAD_CASE_TYPES:
        return None, sad_inboot_cases.get(sad_case_type)

    sad_preboot_cases = {
        "sad": [
            'neigh_bgp_down',               # Shutdown single BGP session on remote device (VM) before reboot DUT
            'dut_bgp_down',                 # Shutdown single BGP session on DUT brefore rebooting it
        ] + _lag_string_cases(has_portchannels,
                              'dut_lag_down', 'neigh_lag_down') + _lag_member_cases(
            duthost, nbrhosts, fanouthosts, has_portchannels, 1, 1, 1) + [
            # Shutdown 1 vlan port (interface) on DUT
            DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 1)),
            # Shutdown 1 vlan port (interface) on fanout
            NeighVlanMemberDown(duthost, fanouthosts, vmhost, PhyPropsPortSelector(duthost, 1))
        ],

        "multi_sad": [
            'neigh_bgp_down:2',     # Shutdown single BGP session on 2 remote devices (VMs) before reboot DUT
            'dut_bgp_down:3',       # Shutdown 3 BGP sessions on DUT before rebooting it
        ] + _lag_string_cases(has_portchannels,
                              'dut_lag_down:2', 'neigh_lag_down:3') + _lag_member_cases(
            duthost, nbrhosts, fanouthosts, has_portchannels, 3, 2, 1) + [
            DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 4)),
            NeighVlanMemberDown(duthost, fanouthosts, vmhost, PhyPropsPortSelector(duthost, 4)),
        ] + _full_lag_member_cases(duthost, nbrhosts, fanouthosts, has_portchannels, lagMemberCnt),

        "sad_bgp": [
            'neigh_bgp_down:2',     # Shutdown single BGP session on 2 remote devices (VMs) before reboot DUT
            'dut_bgp_down:3',       # Shutdown 3 BGP sessions on DUT before rebooting it
        ],

        "sad_lag_member": _lag_member_cases(
            duthost, nbrhosts, fanouthosts, has_portchannels, 3, 2, 1
        ) + _full_lag_member_cases(duthost, nbrhosts, fanouthosts, has_portchannels, lagMemberCnt),

        "sad_lag": _lag_string_cases(has_portchannels,
                                     'dut_lag_down:2', 'neigh_lag_down:3'),

        "sad_vlan_port": [
            # Shutdown 4 vlan ports (interfaces) on DUT
            DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 4)),
            # Shutdown 4 vlan ports (interfaces) on fanout
            NeighVlanMemberDown(duthost, fanouthosts, vmhost, PhyPropsPortSelector(duthost, 4)),
        ]
    }

    sad_preboot = sad_preboot_cases.get(sad_case_type)
    sad_inboot = sad_inboot_cases.get(sad_case_type)
    if not has_portchannels and sad_preboot:
        sad_preboot = _filter_lag_sad_cases(sad_preboot)

    return sad_preboot, sad_inboot
