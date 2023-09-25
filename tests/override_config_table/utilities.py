import json
import logging

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)


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


def reload_minigraph_with_golden_config(duthost, json_data):
    """
    for multi-asic devices, we copy config db from host and asics
    for single-asic devices, we copy only config_db.json
    """
    if duthost.is_multi_asic:
        for asic_id in duthost.get_frontend_asic_ids():
            golden_config = "/etc/sonic/golden_config_db{}.json".format(asic_id)
            duthost.copy(content=json.dumps(json_data, indent=4), dest=golden_config)
    golden_config = "/etc/sonic/golden_config_db.json"
    duthost.copy(content=json.dumps(json_data, indent=4), dest=golden_config)
    config_reload(duthost, config_source="minigraph", safe_reload=True, override_config=True)


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)
