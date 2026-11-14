'''

This script is to Verify BGP facts are not altered when docker container restarts.

Step 1: Verify BGP is up and gather basic facts
Step 2: Restart docker container for BGP service
Step 3: Verify BGP facts are same as before restart

'''
import logging
import pytest
import time
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
bgp_sleep = 30

pytestmark = [
    pytest.mark.topology('t2')
]


def docker_check(duthost, cli_option):
    output = duthost.shell("docker ps")['stdout']
    return f"bgp{cli_option}" in output


def test_docker_restart(duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    baseline_neighs = []
    for neigh in bgp_facts['bgp_neighbors']:
        if bgp_facts['bgp_neighbors'][neigh]['state'] == 'established':
            baseline_neighs.append(neigh)

    # perform the container restart
    cli_option = ''
    if asic_index:
        cli_option = asic_index
    duthost.shell("docker restart bgp{}".format(cli_option))
    time.sleep(bgp_sleep)
    wait_until(bgp_sleep, 5, 0, lambda: docker_check(duthost, cli_option))
    time.sleep(bgp_sleep)

    # get list of established neighbors after restart
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    test_neighs = []
    for neigh in bgp_facts['bgp_neighbors']:
        if bgp_facts['bgp_neighbors'][neigh]['state'] == 'established':
            test_neighs.append(neigh)

    # verify both pre and post test neighbor lists are the same
    lacks = set(baseline_neighs) - set(test_neighs)
    extra = set(test_neighs) - set(baseline_neighs)
    message = f"Lacks elements {lacks} " if lacks else ''
    message += f"Extra elements {extra}" if extra else ''
    logger.debug(f"Differential message: {message}")
    assert not message
