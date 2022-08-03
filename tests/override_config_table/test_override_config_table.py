import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.common.utilities import skip_release

GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_BACKUP = "/etc/sonic/golden_config_db.json_before_override"
CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json_before_override"

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
]


@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202111

    Args:
        duthost: DUT host object.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)


@pytest.fixture(scope="module")
def golden_config_exists_on_dut(duthost):
    return file_exists_on_dut(duthost, GOLDEN_CONFIG)


def backup_config(duthost, config, config_backup):
    logger.info("Backup {} to {} on {}".format(
        config, config_backup, duthost.hostname))
    duthost.shell("cp {} {}".format(config, config_backup))


def restore_config(duthost, config, config_backup):
    logger.info("Restore {} with {} on {}".format(
        config, config_backup, duthost.hostname))
    duthost.shell("mv {} {}".format(config_backup, config))


def get_running_config(duthost):
    return json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])


def reload_minigraph_with_golden_config(duthost, json_data):
    duthost.copy(content=json.dumps(json_data, indent=4), dest=GOLDEN_CONFIG)
    config_reload(duthost, config_source="minigraph", safe_reload=True)


@pytest.fixture(scope="module")
def setup_env(duthost, golden_config_exists_on_dut):
    """
    Setup/teardown
    Args:
        duthost: DUT.
        golden_config_exists_on_dut: Check if golden config exists on DUT.
    """
    # Backup configDB
    backup_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    # Backup Golden Config if exists.
    if golden_config_exists_on_dut:
        backup_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)

    # Reload test env with minigraph
    config_reload(duthost, config_source="minigraph", safe_reload=True)
    running_config = get_running_config(duthost)

    yield running_config

    # Restore configDB after test.
    restore_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    # Restore Golden Config after test, else cleanup test file.
    if golden_config_exists_on_dut:
        restore_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)
    else:
        duthost.file(path=GOLDEN_CONFIG, state='absent')

    # Restore config before test
    config_reload(duthost)


def load_minigraph_with_golden_empty_input(duthost):
    """Test Golden Config with empty input
    """
    initial_config = get_running_config(duthost)

    empty_input = {}
    reload_minigraph_with_golden_config(duthost, empty_input)

    current_config = get_running_config(duthost)
    pytest_assert(initial_config == current_config,
                  "Running config differs.")


def load_minigraph_with_golden_partial_config(duthost):
    """Test Golden Config with partial config.

    Here we assume all config contain SYSLOG_SERVER table
    """
    partial_config = {
        "SYSLOG_SERVER": {
            "10.0.0.100": {},
            "10.0.0.200": {}
        }
    }
    reload_minigraph_with_golden_config(duthost, partial_config)

    current_config = get_running_config(duthost)
    pytest_assert(
        current_config['SYSLOG_SERVER'] == partial_config['SYSLOG_SERVER'],
        "Partial config override fail: {}".format(current_config['SYSLOG_SERVER'])
    )


def load_minigraph_with_golden_new_feature(duthost):
    """Test Golden Config with new feature
    """
    new_feature_config = {
        "NEW_FEATURE_TABLE": {
            "entry": {
                "field": "value",
                "state": "disabled"
            }
        }
    }
    reload_minigraph_with_golden_config(duthost, new_feature_config)

    current_config = get_running_config(duthost)
    pytest_assert(
        'NEW_FEATURE_TABLE' in current_config and
        current_config['NEW_FEATURE_TABLE'] == new_feature_config['NEW_FEATURE_TABLE'],
        "new feature config update fail: {}".format(current_config['NEW_FEATURE_TABLE'])
    )


def load_minigraph_with_golden_full_config(duthost, full_config):
    """Test Golden Config fully override minigraph config
    """
    # Test if the config has been override by full_config
    reload_minigraph_with_golden_config(duthost, full_config)

    current_config = get_running_config(duthost)
    for table in full_config:
        pytest_assert(
            full_config[table] == current_config[table],
            "full config override fail! {}".format(table)
        )


def load_minigraph_with_golden_empty_table_removal(duthost):
    """Test Golden Config with empty table removal.

    Here we assume all config contain SYSLOG_SERVER table
    """
    empty_table_removal = {
        "SYSLOG_SERVER": {
        }
    }
    reload_minigraph_with_golden_config(duthost, empty_table_removal)

    current_config = get_running_config(duthost)
    pytest_assert(
        current_config.get('SYSLOG_SERVER', None) is None,
        "Empty table removal fail: {}".format(current_config['SYSLOG_SERVER'])
    )


def test_load_minigraph_with_golden_config(duthost, setup_env):
    """Test Golden Config override during load minigraph
    """
    load_minigraph_with_golden_empty_input(duthost)
    load_minigraph_with_golden_partial_config(duthost)
    load_minigraph_with_golden_new_feature(duthost)
    full_config = setup_env
    load_minigraph_with_golden_full_config(duthost, full_config)
