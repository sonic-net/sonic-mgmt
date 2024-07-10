import json
import logging

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

NON_USER_CONFIG_TABLES = ["FLEX_COUNTER_TABLE", "ASIC_SENSORS"]


def backup_config(duthost, config, config_backup):
    logger.info("Backup {} to {} on {}".format(
        config, config_backup, duthost.hostname))
    duthost.shell("cp {} {}".format(config, config_backup))


def restore_config(duthost, config, config_backup):
    logger.info("Restore {} with {} on {}".format(
        config, config_backup, duthost.hostname))
    duthost.shell("mv {} {}".format(config_backup, config))


def get_running_config(duthost, asic=None):
    ns = "-n " + asic if asic else ""
    return json.loads(duthost.shell("sonic-cfggen {} -d --print-data".format(ns))['stdout'])


def reload_minigraph_with_golden_config(duthost, json_data, safe_reload=True):
    """
    for multi-asic/single-asic devices, we only have 1 golden_config_db.json
    """
    golden_config = "/etc/sonic/golden_config_db.json"
    duthost.copy(content=json.dumps(json_data, indent=4), dest=golden_config)
    config_reload(duthost, config_source="minigraph", safe_reload=safe_reload, override_config=True)


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)


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
