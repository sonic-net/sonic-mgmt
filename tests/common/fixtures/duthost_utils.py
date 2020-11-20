import pytest
import logging

logger = logging.getLogger(__name__)


def _backup_and_restore_config_db(duthost):
    """Back up the existing config_db.json file and restore it once the test ends.

    Some cases will update the running config during the test and save the config
    to be recovered aftet reboot. In such a case we need to backup config_db.json before
    the test starts and then restore it after the test ends.
    """
    CONFIG_DB = "/etc/sonic/config_db.json"
    CONFIG_DB_BAK = "/etc/sonic/config_db.json.before_test"
    logger.info("Backup {} to {}".format(CONFIG_DB, CONFIG_DB_BAK))
    duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))

    yield

    logger.info("Restore {} with {}".format(CONFIG_DB, CONFIG_DB_BAK))
    duthost.shell("mv {} {}".format(CONFIG_DB_BAK, CONFIG_DB))


@pytest.fixture
def backup_and_restore_config_db(duthosts, rand_one_dut_hostname):
    """Back up and restore config DB at the function level."""
    duthost = duthosts[rand_one_dut_hostname]
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost):
        yield func


@pytest.fixture(scope="module")
def backup_and_restore_config_db_module(duthosts, rand_one_dut_hostname):
    """Back up and restore config DB at the module level."""
    duthost = duthosts[rand_one_dut_hostname]
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost):
        yield func


def _disable_route_checker(duthost):
    """
        Some test cases will add static routes for test, which may trigger route_checker
        to report error. This function is to disable route_checker before test, and recover it
        after test.

        Args:
            duthost: DUT fixture
    """
    duthost.command('monit stop routeCheck', module_ignore_errors=True)
    yield
    duthost.command('monit start routeCheck', module_ignore_errors=True)


@pytest.fixture
def disable_route_checker(duthosts, rand_one_dut_hostname):
    """
    Wrapper for _disable_route_checker, function level
    """
    duthost = duthosts[rand_one_dut_hostname]
    for func in _disable_route_checker(duthost):
        yield func


@pytest.fixture(scope='module')
def disable_route_checker_module(duthosts, rand_one_dut_hostname):
    """
    Wrapper for _disable_route_checker, module level
    """
    duthost = duthosts[rand_one_dut_hostname]
    for func in _disable_route_checker(duthost):
        yield func
