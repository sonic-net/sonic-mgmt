import pytest
import logging
import json
import os

from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload, config_reload_minigraph_with_rendered_golden_config_override
from tests.override_config_table.utilities import backup_config, restore_config, get_running_config
from tests.common.utilities import update_pfcwd_default_state

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

NON_USER_CONFIG_TABLES = ["FLEX_COUNTER_TABLE", "ASIC_SENSORS"]
GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_BACKUP = "/etc/sonic/golden_config_db.json_before_override"


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)


@pytest.fixture(scope="module")
def setup_env(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Setup/teardown
    Args:
        duthost: DUT.
        golden_config_exists_on_dut: Check if golden config exists on DUT.
    """
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_multi_asic:
        pytest.skip("Skip test on multi-asic platforms as it is designed for single asic.")

    topo_type = tbinfo["topo"]["type"]
    if topo_type in ["m0", "mx"]:
        original_pfcwd_value = update_pfcwd_default_state(duthost, "/etc/sonic/init_cfg.json", "disable")

    if file_exists_on_dut(duthost, GOLDEN_CONFIG):
        backup_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)

    # Reload test env with minigraph
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    running_config = get_running_config(duthost)

    yield running_config

    if topo_type in ["m0", "mx"]:
        update_pfcwd_default_state(duthost, "/etc/sonic/init_cfg.json", original_pfcwd_value)

    if file_exists_on_dut(duthost, GOLDEN_CONFIG_BACKUP):
        restore_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)
    else:
        duthost.file(path=GOLDEN_CONFIG, state='absent')

    # Restore config before test
    config_reload(duthost)


def compare_dicts_ignore_list_order(dict1, dict2):
    def normalize(data):
        if isinstance(data, list):
            return set(data)
        elif isinstance(data, dict):
            return {k: normalize(v) for k, v in data.items()}
        else:
            return data

    dict1_normalized = normalize(dict1)
    dict2_normalized = normalize(dict2)

    return dict1_normalized == dict2_normalized


def config_compare(golden_config, running_config):
    for table in golden_config:
        if table in NON_USER_CONFIG_TABLES:
            continue

        if table == "ACL_TABLE":
            pytest_assert(
                compare_dicts_ignore_list_order(golden_config[table], running_config[table]),
                "empty input ACL_TABLE compare fail!"
            )
        else:
            pytest_assert(
                golden_config[table] == running_config[table],
                "empty input compare fail! {}".format(table)
            )


def golden_config_override_with_general_template(duthost, initial_config):
    config_reload_minigraph_with_rendered_golden_config_override(
        duthost, safe_reload=True, check_intf_up_ports=True
    )
    overrided_config = get_running_config(duthost)
    with open("/etc/sonic/golden_config_db.json") as f:
        golden_config = json.load(f)

    config_compare(golden_config, overrided_config)


# need to update test for common and sample, then trim the code to align
def golden_config_override_with_specific_template(duthost, initial_config):
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    golden_config_j2 = os.path.join(template_dir, 'sample_goldel_config_db.j2')
    config_reload_minigraph_with_rendered_golden_config_override(
        duthost, safe_reload=True, check_intf_up_ports=True,
        golden_config_template=golden_config_j2
    )
    overrided_config = get_running_config(duthost)
    with open("/etc/sonic/golden_config_db.json") as f:
        golden_config = json.load(f)

    config_compare(golden_config, overrided_config)


def test_rendered_golden_config_override(duthosts, rand_one_dut_hostname, setup_env):
    duthost = duthosts[rand_one_dut_hostname]
    initial_config = setup_env

    golden_config_override_with_general_template(duthost, initial_config)
    golden_config_override_with_specific_template(duthost, initial_config)
