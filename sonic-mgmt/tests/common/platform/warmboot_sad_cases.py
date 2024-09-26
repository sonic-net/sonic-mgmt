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


def get_sad_case_list(duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    lagMemberCnt = len(list(mg_facts['minigraph_portchannels'].values())[0]['members'])

    sad_preboot_cases = {
        "sad": [
            'neigh_bgp_down',               # Shutdown single BGP session on remote device (VM) before reboot DUT
            'dut_bgp_down',                 # Shutdown single BGP session on DUT brefore rebooting it
            'dut_lag_down',                 # Shutdown single LAG session on DUT brefore rebooting it
            'neigh_lag_down',               # Shutdown single LAG session on remote device (VM) before reboot DUT
            # Shutdown 1 LAG member corresponding to 1 remote device (VM) on DUT
            DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(1), PhyPropsPortSelector(duthost, 1)),
            # Shutdown 1 LAG member on 1 remote device (VM)
            NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(1), PhyPropsPortSelector(duthost, 1)),
            # Shutdown 1 vlan port (interface) on DUT
            DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 1)),
            # Shutdown 1 vlan port (interface) on fanout
            NeighVlanMemberDown(duthost, fanouthosts, vmhost, PhyPropsPortSelector(duthost, 1))
        ],

        "multi_sad": [
                'neigh_bgp_down:2',     # Shutdown single BGP session on 2 remote devices (VMs) before reboot DUT
                'dut_bgp_down:3',       # Shutdown 3 BGP sessions on DUT brefore rebooting it
                'dut_lag_down:2',       # Shutdown 2 LAG sessions on DUT brefore rebooting it
                'neigh_lag_down:3',     # Shutdown 1 LAG session on 3 remote devices (VMs) before reboot DUT
                # Shutdown 1 LAG member of 3 LAG sessions corresponding to 3 remote devices (VM)
                # on DUT
                DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(3), PhyPropsPortSelector(duthost, 1)),
                # Shutdown 1 LAG member of 2 LAG sessions on 2 remote devices (VM) (1 each)
                NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(2),
                                   PhyPropsPortSelector(duthost, 1)),
                DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 4)),
                NeighVlanMemberDown(duthost, fanouthosts, vmhost, PhyPropsPortSelector(duthost, 4)),
            ] + ([
                # Shutdown <lag count> LAG member(s) of 2 LAG sessions corresponding to 2 remote
                # devices (VM) on DUT
                DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(2), PhyPropsPortSelector(duthost, lagMemberCnt)),
                # Shutdown <lag count> LAG member(s) of 3 LAG sessions on 3 remote devices (VM)
                # (1 each)
                NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(3),
                                   PhyPropsPortSelector(duthost, lagMemberCnt)),
            ] if tbinfo['topo']['name'] in ['t0-64', 't0-116', 't0-64-32'] else []),

        "sad_bgp": [
                'neigh_bgp_down:2',     # Shutdown single BGP session on 2 remote devices (VMs) before reboot DUT
                'dut_bgp_down:3',       # Shutdown 3 BGP sessions on DUT brefore rebooting it
            ],

        "sad_lag_member": [
                # Shutdown 1 LAG member of 3 LAG sessions corresponding to 3 remote devices (VM)
                # on DUT
                DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(3), PhyPropsPortSelector(duthost, 1)),
                # Shutdown 1 LAG member of 2 LAG sessions on 2 remote devices (VM) (1 each)
                NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(2),
                                   PhyPropsPortSelector(duthost, 1)),
            ] + ([
                # Shutdown <lag count> LAG member(s) of 2 LAG sessions corresponding to 2 remote
                # devices (VM) on DUT
                DutLagMemberDown(duthost, nbrhosts, DatetimeSelector(2), PhyPropsPortSelector(duthost, lagMemberCnt)),
                # Shutdown <lag count> LAG member(s) of 3 LAG sessions on 3 remote devices (VM)
                # (1 each)
                NeighLagMemberDown(duthost, nbrhosts, fanouthosts, DatetimeSelector(3),
                                   PhyPropsPortSelector(duthost, lagMemberCnt)),
            ] if tbinfo['topo']['name'] in ['t0-64', 't0-116', 't0-64-32'] else []),

        "sad_lag": [
                'dut_lag_down:2',               # Shutdown 2 LAG sessions on DUT brefore rebooting it
                'neigh_lag_down:3',             # Shutdown 1 LAG session on 3 remote devices (VMs) before reboot DUT
            ],

        "sad_vlan_port": [
                # Shutdown 4 vlan ports (interfaces) on DUT
                DutVlanMemberDown(duthost, PhyPropsPortSelector(duthost, 4)),
                # Shutdown 4 vlan ports (interfaces) on fanout
                NeighVlanMemberDown(duthost, fanouthosts, vmhost, PhyPropsPortSelector(duthost, 4)),
            ]
    }

    sad_inboot_cases = {
        "sad_inboot": [
            'routing_del:50',               # Delete 50 routes IPv4/IPv6 each (100 total) from each BGP session
            'routing_add:50',               # Add 50 routes IPv4/IPv6 each (100 total) from each BGP session
        ]
    }

    return sad_preboot_cases.get(sad_case_type), sad_inboot_cases.get(sad_case_type)
