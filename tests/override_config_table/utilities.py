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


def reload_minigraph_with_golden_config(duthost, json_data, safe_reload=True):
    """
    for multi-asic/single-asic devices, we only have 1 golden_config_db.json
    """
    golden_config = "/etc/sonic/golden_config_db.json"
    duthost.copy(content=json.dumps(json_data, indent=4), dest=golden_config)
    config_reload(duthost, config_source="minigraph", safe_reload=safe_reload, override_config=True)
    # Cleanup golden config because some other test or device recover may reload config with golden config
    duthost.command('mv {} {}_backup'.format(golden_config, golden_config))


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)
