"""
Test bgp no-export community in SONiC.
"""

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DOWNSTREAM_ALL_NEIGHBOR_MAP
from tests.common.utilities import is_ipv6_only_topology, wait_until
from bgp_helpers import apply_bgp_config
from bgp_helpers import get_no_export_output
from bgp_helpers import BGP_ANNOUNCE_TIME

pytestmark = [
    pytest.mark.topology('t1')
]


def get_downstream_vm(duthost, nbrhosts, tbinfo):
    downstream_type = [t.upper() for t in DOWNSTREAM_ALL_NEIGHBOR_MAP[tbinfo["topo"]["type"]]]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    connected_neighbors = set(neigh['name'] for neigh in list(mg_facts['minigraph_neighbors'].values()))
    downstream_neighbors = sorted(
        [vm_name for vm_name in list(nbrhosts.keys())
         if vm_name in connected_neighbors and vm_name.upper().endswith(tuple(downstream_type))]
    )
    pytest_assert(downstream_neighbors, "No downstream neighbor found for topology {}".format(tbinfo["topo"]["type"]))
    # Pick deterministically so failures are reproducible.
    return nbrhosts[downstream_neighbors[0]]['host']


def check_no_export_routes(vm_host, is_v6_topo, expected):
    def _no_export_state_matches():
        routes = get_no_export_output(vm_host, ipv6=is_v6_topo)
        return bool(routes) == expected

    pytest_assert(wait_until(BGP_ANNOUNCE_TIME, 5, 0, _no_export_state_matches),
                  "No-export route state did not become {}".format("present" if expected else "absent"))


@pytest.mark.disable_loganalyzer  # apply_bgp_config restarts BGP and can log expected transient errors.
def test_bgp_bounce(duthost, nbrhosts, tbinfo, deploy_plain_bgp_config, deploy_no_export_bgp_config,
                    backup_bgp_config):
    """
    Verify bgp community no export functionality

    Test steps:
        1.) Generate bgp plain config
        2.) Generate bgp no export config
        3.) Apply bgp plain config
        4.) Get no export routes on one of the ToR VM
        5.) Apply bgp no export config
        6.) Get no export routes on one of the ToR VM
        7.) Apply default bgp config

    Pass Criteria: After applying bgp no export config ToR VM gets no export routes
    """
    bgp_plain_config = deploy_plain_bgp_config
    bgp_no_export_config = deploy_no_export_bgp_config

    # Check if this is an IPv6-only topology
    is_v6_topo = is_ipv6_only_topology(tbinfo)

    # Get downstream VM
    vm_host = get_downstream_vm(duthost, nbrhosts, tbinfo)

    # Start all bgp sessions
    duthost.shell('config bgp startup all')

    # Apply bgp plain config
    apply_bgp_config(duthost, bgp_plain_config)

    # Verify downstream VM has no no-export routes yet
    check_no_export_routes(vm_host, is_v6_topo, expected=False)

    # Apply bgp no export config
    apply_bgp_config(duthost, bgp_no_export_config)

    # Verify downstream VM now sees the no-export community
    check_no_export_routes(vm_host, is_v6_topo, expected=True)
