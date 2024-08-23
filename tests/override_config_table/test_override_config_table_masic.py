import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common.utilities import update_pfcwd_default_state
from tests.common.config_reload import config_reload
from tests.override_config_table.utilities import backup_config, restore_config, get_running_config,\
    reload_minigraph_with_golden_config, file_exists_on_dut, NON_USER_CONFIG_TABLES

GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_BACKUP = "/etc/sonic/golden_config_db.json_before_override"
CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json_before_override"

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2', 't1'),
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


@pytest.fixture(scope="module")
def setup_env(duthosts, tbinfo, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Setup/teardown
    Args:
        duthost: DUT.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    topo_type = tbinfo["topo"]["type"]
    if topo_type in ["m0", "mx"]:
        original_pfcwd_value = update_pfcwd_default_state(duthost, "/etc/sonic/init_cfg.json", "disable")
    # Backup configDB
    for asic_id in duthost.get_asic_ids():
        if asic_id is None:
            continue
        config = "/etc/sonic/config_db{}.json".format(asic_id)
        config_backup = "/etc/sonic/config_db{}.json_before_override".format(asic_id)
        backup_config(duthost, config, config_backup)
    backup_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    # Backup Golden Config if exists. golden config only exists on host
    if file_exists_on_dut(duthost, GOLDEN_CONFIG):
        backup_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)

    # Reload test env with minigraph
    config_reload(duthost, config_source="minigraph", safe_reload=True)
    running_config = get_running_config(duthost)

    yield running_config

    if topo_type in ["m0", "mx"]:
        update_pfcwd_default_state(duthost, "/etc/sonic/init_cfg.json", original_pfcwd_value)
    # Restore configDB after test.
    for asic_id in duthost.get_asic_ids():
        if asic_id is None:
            continue
        config = "/etc/sonic/config_db{}.json".format(asic_id)
        config_backup = "/etc/sonic/config_db{}.json_before_override".format(asic_id)
        restore_config(duthost, config, config_backup)
    restore_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    # Restore Golden Config after test, else cleanup test file.
    if file_exists_on_dut(duthost, GOLDEN_CONFIG_BACKUP):
        restore_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)
    else:
        duthost.file(path=GOLDEN_CONFIG, state='absent')
    # Restore config before test
    config_reload(duthost)


def load_minigraph_with_golden_empty_input(duthost):
    """Test Golden Config with empty input
    """
    initial_host_config = get_running_config(duthost)
    initial_asic0_config = get_running_config(duthost, "asic0")

    empty_input = {}
    reload_minigraph_with_golden_config(duthost, empty_input)

    # Test host running config override
    host_current_config = get_running_config(duthost)
    for table in initial_host_config:
        if table in NON_USER_CONFIG_TABLES:
            continue
        pytest_assert(
            initial_host_config[table] == host_current_config[table],
            "empty input compare fail! {}".format(table)
        )

    # Test asic0 running config override
    asic0_current_config = get_running_config(duthost, "asic0")
    for table in initial_asic0_config:
        if table in NON_USER_CONFIG_TABLES:
            continue
        pytest_assert(
            initial_asic0_config[table] == asic0_current_config[table],
            "empty input compare fail! {}".format(table)
        )


def load_minigraph_with_golden_partial_config(duthost):
    """Test Golden Config with partial config.

    Here we assume all config contain TELEMETRY table
    """
    partial_config = {
        "localhost": {
            "TELEMETRY": {
                "gnmi": {},
                "certs": {
                    "server_key": "/etc/sonic/telemetry/streamingtelemetryserver.key",
                    "ca_crt": "/etc/sonic/telemetry/dsmsroot.cer",
                    "server_crt": "/etc/sonic/telemetry/streamingtelemetryserver.cer"
                }
            },
        },
        "asic0": {
            "TELEMETRY": {
                "gnmi": {},
                "certs": {
                    "server_key": "/etc/sonic/telemetry/streamingtelemetryserver.key",
                    "ca_crt": "/etc/sonic/telemetry/dsmsroot.cer",
                    "server_crt": "/etc/sonic/telemetry/streamingtelemetryserver.cer"
                }
            },
        }
    }
    reload_minigraph_with_golden_config(duthost, partial_config)

    host_current_config = get_running_config(duthost)
    pytest_assert(
        host_current_config['TELEMETRY'] == partial_config["localhost"]['TELEMETRY'],
        "Partial config override fail: {}".format(host_current_config['TELEMETRY'])
    )

    asic0_current_config = get_running_config(duthost, "asic0")
    pytest_assert(
        asic0_current_config['TELEMETRY'] == partial_config["asic0"]['TELEMETRY'],
        "Partial config override fail: {}".format(asic0_current_config['TELEMETRY'])
    )


def load_minigraph_with_golden_new_feature(duthost):
    """Test Golden Config with new feature
    """
    new_feature_config = {
        "localhost": {
            "NEW_FEATURE_TABLE": {
                "entry": {
                    "field": "value",
                    "state": "disabled"
                }
            }
        },
        "asic0": {
            "NEW_FEATURE_TABLE": {
                "entry": {
                    "field": "value",
                    "state": "disabled"
                }
            }
        }
    }
    reload_minigraph_with_golden_config(duthost, new_feature_config)

    host_current_config = get_running_config(duthost)
    pytest_assert(
        'NEW_FEATURE_TABLE' in host_current_config and
        host_current_config['NEW_FEATURE_TABLE'] == new_feature_config['localhost']['NEW_FEATURE_TABLE'],
        "new feature config update fail: {}".format(host_current_config['NEW_FEATURE_TABLE'])
    )

    asic0_current_config = get_running_config(duthost, "asic0")
    pytest_assert(
        'NEW_FEATURE_TABLE' in asic0_current_config and
        asic0_current_config['NEW_FEATURE_TABLE'] == new_feature_config['asic0']['NEW_FEATURE_TABLE'],
        "new feature config update fail: {}".format(asic0_current_config['NEW_FEATURE_TABLE'])
    )


def load_minigraph_with_golden_empty_table_removal(duthost):
    """Test Golden Config with empty table removal.

    Here we assume all config contain FEATURE table
    """
    empty_table_removal = {
        "localhost": {
            "TELEMETRY": {}
        },
        "asic0": {
            "TELEMETRY": {}
        }
    }
    reload_minigraph_with_golden_config(duthost, empty_table_removal)

    host_current_config = get_running_config(duthost)
    pytest_assert(
        host_current_config.get('TELEMETRY', None) is None,
        "Empty table removal fail: {}".format(host_current_config)
    )

    asic0_current_config = get_running_config(duthost, "asic0")
    pytest_assert(
        asic0_current_config.get('TELEMETRY', None) is None,
        "Empty table removal fail: {}".format(asic0_current_config)
    )


def test_load_minigraph_with_golden_config(duthosts, setup_env,
                                           enum_rand_one_per_hwsku_frontend_hostname):
    """
    Test Golden Config override during load minigraph
    Note: Skip full config override for multi-asic duts for now, because we
    don't have CLI to get new golden config that contains 'localhost' and 'asicxx'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if not duthost.is_multi_asic:
        pytest.skip("Skip override-config-table multi-asic testing on single-asic platforms,\
                    test provided golden config format is not compatible with single-asics")
    load_minigraph_with_golden_empty_input(duthost)
    load_minigraph_with_golden_partial_config(duthost)
    load_minigraph_with_golden_new_feature(duthost)
    load_minigraph_with_golden_empty_table_removal(duthost)
