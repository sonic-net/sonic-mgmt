"""
Fixtures for the disaggregated-T2 (UT2 / LT2, non-chassis) GCU neighbor tests.

The DUT under test is the one with downstream neighbors: the UT2 on a ut2 / t2 testbed,
the LT2 on an lt2 testbed. A module-scoped checkpoint and config backup guard that DUT so
a failed test never leaves it without its neighbor, on top of the per-test config_reload
in the shared flow.
"""
import logging
import pytest
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import restore_backup_test_config, save_backup_test_config
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# TSC prints one "System Mode: <state>" line per ASIC (prefixed "BGP<n> : " on multi-ASIC).
TSC_SHIFTED_STATES = ("System Mode: Maintenance", "System Mode: Not consistent")


def traffic_shift_normal(duthost):
    """True when no ASIC reports TSA (maintenance) or an inconsistent state in TSC."""
    lines = duthost.shell("TSC")["stdout_lines"]
    return not any(state in line for line in lines for state in TSC_SHIFTED_STATES)


def ensure_traffic_shift_normal(duthost):
    """
    Leave the DUT out of TSA. A config reload on platforms with startup-tsa-tsb.conf puts
    every ASIC into maintenance for minutes, which would break whatever runs next.
    """
    if traffic_shift_normal(duthost):
        return
    logger.info("%s: in TSA after the module teardown, running TSB", duthost.hostname)
    duthost.shell("TSB")
    # Plain pytest.fail: importing pytest_assert here would register it as a pytest hook.
    if not wait_until(120, 10, 0, traffic_shift_normal, duthost):
        pytest.fail(f"{duthost.hostname} is still in TSA after TSB")


@pytest.fixture(scope="module")
def enum_rand_one_asic_namespace(enum_rand_one_frontend_asic_index):
    return None if enum_rand_one_frontend_asic_index is None else "asic{}".format(enum_rand_one_frontend_asic_index)


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_downstream_dut_hostname, enum_rand_one_asic_namespace):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.config_facts(
        host=duthost.hostname, source="running", namespace=enum_rand_one_asic_namespace,
    )["ansible_facts"]


@pytest.fixture(scope="module")
def config_facts_localhost(duthosts, enum_downstream_dut_hostname):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running", namespace=None)["ansible_facts"]


@pytest.fixture(scope="module")
def mg_facts(duthosts, enum_downstream_dut_hostname, enum_rand_one_asic_namespace, tbinfo):
    duthost = duthosts[enum_downstream_dut_hostname]
    return duthost.get_extended_minigraph_facts(tbinfo, namespace=enum_rand_one_asic_namespace)


@pytest.fixture(scope="module", autouse=True)
def setup_env(duthosts, enum_downstream_dut_hostname):
    """Checkpoint and back up the DUT's config for the module; roll back afterwards."""
    duthost = duthosts[enum_downstream_dut_hostname]
    postfix = "{}_before_dt2_test".format(duthost.hostname)
    create_checkpoint(duthost)
    save_backup_test_config(duthost, file_postfix=postfix)

    yield

    restore_backup_test_config(duthost, file_postfix=postfix, config_reload=False)
    try:
        logger.info("%s: rolling back to the original checkpoint", duthost.hostname)
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)
    ensure_traffic_shift_normal(duthost)
