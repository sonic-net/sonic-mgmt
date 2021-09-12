"""
Test bgp no-export community in SONiC.
"""

import random
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from bgp_helpers import apply_bgp_config
from bgp_helpers import get_no_export_output
from bgp_helpers import BGP_ANNOUNCE_TIME

pytestmark = [
    pytest.mark.topology('t1')
]


def test_bgp_bounce(duthost, nbrhosts, deploy_plain_bgp_config, deploy_no_export_bgp_config, backup_bgp_config):
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

    Pass Criteria: After appling bgp no export config ToR VM gets no export routes
    """
    bgp_plain_config = deploy_plain_bgp_config
    bgp_no_export_config = deploy_no_export_bgp_config

    # Get random ToR VM
    vm_names = [vm_name for vm_name in nbrhosts.keys() if vm_name.endswith('T0')]
    vm_hosts = [nbrhosts[vm_name]['host'] for vm_name in vm_names]

    for i in range(20):

        # Apply bgp plain config
        apply_bgp_config(duthost, bgp_plain_config)

        # Give additional delay for routes to be propogated
        time.sleep(BGP_ANNOUNCE_TIME)

        # Take action on one of the ToR VM
        for vm_host in vm_hosts:
            try:
                no_export_route_num = get_no_export_output(vm_host)
            except Exception as detail:
                vm_host.ping()
                vm_host.eos_command(commands=['show version'])
                vm_host.eos_command(commands=['show ip bgp sum'])
                vm_host.eos_command(commands=['show run'])
                no_export_route_num = get_no_export_output(vm_host)
                raise detail
            pytest_assert(not no_export_route_num, "Routes has no_export attribute")

        # Apply bgp no export config
        apply_bgp_config(duthost, bgp_no_export_config)

        # Give additional delay for routes to be propogated
        time.sleep(BGP_ANNOUNCE_TIME)

        # Take action on one of the ToR VM
        for vm_host in vm_hosts:
            try:
                no_export_route_num = get_no_export_output(vm_host)
            except Exception as detail:
                vm_host.ping()
                vm_host.eos_command(commands=['show version'])
                vm_host.eos_command(commands=['show run'])
                vm_host.eos_command(commands=['show ip bgp sum'])
                no_export_route_num = get_no_export_output(vm_host)
                raise detail
            pytest_assert(no_export_route_num, "Routes received on T1 are no-export")

