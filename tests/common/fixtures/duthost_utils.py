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
def backup_and_restore_config_db(duthost):
    """Back up and restore config DB at the function level."""
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost):
        yield func


@pytest.fixture(scope="module")
def backup_and_restore_config_db_module(duthost):
    """Back up and restore config DB at the module level."""
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost):
        yield func
