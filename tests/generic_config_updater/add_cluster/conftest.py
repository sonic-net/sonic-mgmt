import logging
import os
import pytest
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import restore_backup_test_config, save_backup_test_config

logger = logging.getLogger(__name__)


def pytest_configure(config):
    """Register custom markers used by the Add-MOR scaling tests."""
    config.addinivalue_line(
        "markers",
        "gcu_scaling_nightly: Add-MOR scaling — runs in nightly pipeline")
    config.addinivalue_line(
        "markers",
        "gcu_scaling_weekly: Add-MOR scaling — runs weekly / on-demand")
    config.addinivalue_line(
        "markers",
        "gcu_scaling_sanity: Add-MOR scaling — one-time test-validation only")


# -----------------------------
# Fixtures that return random values for selected asic namespace, neighbors and cfg data for these selections
# -----------------------------

@pytest.fixture(scope="module")
def enum_rand_one_asic_namespace(enum_rand_one_frontend_asic_index):
    # Optional deterministic override for scaling runs on testbeds where
    # only one asic has enough external PortChannels for the requested N.
    # Set GCU_FORCE_ASIC="asic1" (or "asic0", or "host" for None) in the
    # test environment to skip the random pick.  Nightly on production
    # testbeds should leave this unset.
    forced = os.environ.get("GCU_FORCE_ASIC")
    if forced:
        if forced.lower() == "host":
            logger.info("GCU_FORCE_ASIC=host -> using None (localhost)")
            return None
        logger.info("GCU_FORCE_ASIC=%s -> overriding random asic pick", forced)
        return forced
    return None if enum_rand_one_frontend_asic_index is None else 'asic{}'.format(enum_rand_one_frontend_asic_index)


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_downstream_dut_hostname, enum_rand_one_asic_namespace):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.config_facts(
        host=duthost.hostname, source="running", namespace=enum_rand_one_asic_namespace
        )['ansible_facts']


@pytest.fixture(scope="module")
def config_facts_localhost(duthosts, enum_downstream_dut_hostname):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running", namespace=None)['ansible_facts']


@pytest.fixture(scope="module")
def mg_facts(duthosts, enum_downstream_dut_hostname, enum_rand_one_asic_namespace, tbinfo):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.get_extended_minigraph_facts(tbinfo, namespace=enum_rand_one_asic_namespace)


@pytest.fixture(scope="module")
def rand_bgp_neigh_ip_name(config_facts):
    '''Returns a random bgp neighbor ip, name from the namespace'''
    bgp_neighbors = config_facts["BGP_NEIGHBOR"]
    random_bgp_neigh_ip = list(bgp_neighbors.keys())[0]
    random_bgp_neigh_name = config_facts['BGP_NEIGHBOR'][random_bgp_neigh_ip]['name']
    logger.info("rand_bgp_neigh_ip_name : {}, {} "
                .format(random_bgp_neigh_ip, random_bgp_neigh_name))
    return random_bgp_neigh_ip, random_bgp_neigh_name


# -----------------------------
# Setup Fixtures
# -----------------------------

@pytest.fixture(scope="module", autouse=True)
def setup_env(duthosts, rand_one_dut_front_end_hostname):
    """
    Setup/teardown fixture for add cluster test cases.
    Args:
        duthosts: list of DUTs.
        rand_one_dut_front_end_hostname: A random linecard.
    """

    duthost = duthosts[rand_one_dut_front_end_hostname]
    create_checkpoint(duthost)
    save_backup_test_config(duthost, file_postfix="{}_before_add_cluster_test".format(duthost.hostname))

    yield

    restore_backup_test_config(duthost, file_postfix="{}_before_add_cluster_test".format(duthost.hostname),
                               config_reload=False)
    try:
        logger.info("{}:Rolling back to original checkpoint".format(duthost.hostname))
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)
