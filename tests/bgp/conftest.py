import pytest
import logging
from common.utilities import wait_until

logger = logging.getLogger(__name__)

@pytest.fixture(scope='module')
def setup_keepalive_and_hold_timer(duthost, nbrhosts):
    # incrase the keepalive and hold timer
    duthost.command("vtysh -c \"configure terminal\" \
                           -c \"router bgp {}\" \
                           -c \"neighbor {} timers 60 180\"".format(
                               metadata['localhost']['bgp_asn'], \
                               bgp_nbr_ip))

    for k, nbr in nbrhosts.items():
        nbr['host'].eos_config(lines=["timers 60 180"], parents=["router bgp {}".format(bgp_nbr['asn'])])

    yield

@pytest.fixture(scope='module')
def setup_bgp_graceful_restart(duthost, nbrhosts):

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})

    for k, nbr in nbrhosts.items():
        logger.info("enable graceful restart on neighbor {}".format(k))
        logger.info("bgp asn {}".format(nbr['conf']['bgp']['asn']))
        res = nbr['host'].eos_config(lines=["graceful-restart restart-time 300"], \
                               parents=["router bgp {}".format(nbr['conf']['bgp']['asn'])])
        logger.info("abc {}".format(res))
        res = nbr['host'].eos_config(lines=["graceful-restart"], \
                               parents=["router bgp {}".format(nbr['conf']['bgp']['asn']), "address-family ipv4"])
        logger.info("abc {}".format(res))
        res = nbr['host'].eos_config(lines=["graceful-restart"], \
                               parents=["router bgp {}".format(nbr['conf']['bgp']['asn']), "address-family ipv6"])
        logger.info("abc {}".format(res))

    # change graceful restart option will clear the bgp session.
    # so, let's wait for all bgp sessions to be up
    logger.info("bgp neighbors: {}".format(bgp_neighbors.keys()))
    if not wait_until(300, 10, duthost.check_bgp_session_state, bgp_neighbors.keys()):
        pytest.fail("not all bgp sessions are up after enable graceful restart")

    yield

    for k, nbr in nbrhosts.items():
        # start bgpd if not started
        nbr['host'].start_bgpd()
        logger.info("disable graceful restart on neighbor {}".format(k))
        nbr['host'].eos_config(lines=["no graceful-restart"], \
                               parents=["router bgp {}".format(nbr['conf']['bgp']['asn']), "address-family ipv4"])
        nbr['host'].eos_config(lines=["no graceful-restart"], \
                               parents=["router bgp {}".format(nbr['conf']['bgp']['asn']), "address-family ipv6"])

    if not wait_until(300, 10, duthost.check_bgp_session_state, bgp_neighbors.keys()):
        pytest.fail("not all bgp sessions are up after disable graceful restart")
