import pytest
import logging
import json
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.parallel import parallel_run

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


def check_results(results):
    """Helper function for checking results of parallel run.

    Args:
        results (Proxy to shared dict): Results of parallel run, indexed by node name.
    """
    failed_results = {}
    for node_name, node_results in results.items():
        failed_node_results = [res for res in node_results if res['failed']]
        if len(failed_node_results) > 0:
            failed_results[node_name] = failed_node_results
    if failed_results:
        logger.error('failed_results => {}'.format(json.dumps(failed_results, indent=2)))
        pt_assert(False, 'Some processes for updating nbr hosts configuration returned failed results')


@pytest.fixture(scope='module')
def setup_bgp_graceful_restart(duthost, nbrhosts):

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})

    def configure_nbr_gr(node=None, results=None):
        """Target function will be used by multiprocessing for configuring VM hosts.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        logger.info('enable graceful restart on neighbor host {}'.format(node['host'].hostname))
        logger.info('bgp asn {}'.format(node['conf']['bgp']['asn']))
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart restart-time 300'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn'])], \
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv4'], \
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv6'], \
                module_ignore_errors=True)
            )
        results[node['host'].hostname] = node_results

    results = parallel_run(configure_nbr_gr, (), {}, nbrhosts.values(), timeout=120)

    check_results(results)

    logger.info("bgp neighbors: {}".format(bgp_neighbors.keys()))
    if not wait_until(300, 10, duthost.check_bgp_session_state, bgp_neighbors.keys()):
        pytest.fail("not all bgp sessions are up after enable graceful restart")

    if not wait_until(60, 5, duthost.check_default_route):
        pytest.fail("ipv4 or ipv6 default route not available")

    yield

    def restore_nbr_gr(node=None, results=None):
        """Target function will be used by multiprocessing for restoring configuration for the VM hosts.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        # start bgpd if not started
        node_results = []
        node['host'].start_bgpd()
        logger.info('disable graceful restart on neighbor {}'.format(k))
        node_results.append(node['host'].eos_config(
                lines=['no graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv4'], \
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['no graceful-restart'], \
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv6'], \
                module_ignore_errors=True)
            )
        results[node['host'].hostname] = node_results

    results = parallel_run(restore_nbr_gr, (), {}, nbrhosts.values(), timeout=120)

    check_results(results)

    if not wait_until(300, 10, duthost.check_bgp_session_state, bgp_neighbors.keys()):
        pytest.fail("not all bgp sessions are up after disable graceful restart")
