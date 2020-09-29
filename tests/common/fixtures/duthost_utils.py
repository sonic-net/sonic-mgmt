import pytest
import logging

logger = logging.getLogger(__name__)

@pytest.fixture
def backup_and_restore_config_db(duthost):
    """
    Some cases will shutdown interfaces or BGP in test, and the change is writen to
    config db after warm-reboot. Therefore, we need to backup config_db.json before
    test starts and then restore after test ends
    """
    CONFIG_DB = "/etc/sonic/config_db.json"
    CONFIG_DB_BAK = "/etc/sonic/config_db.json.before_test"
    logger.info("Backup {} to {}".format(CONFIG_DB, CONFIG_DB_BAK))
    duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))
    yield
    logger.info("Restore {} with {}".format(CONFIG_DB, CONFIG_DB_BAK))
    duthost.shell("mv {} {}".format(CONFIG_DB_BAK, CONFIG_DB))
