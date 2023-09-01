import json
import logging
import pytest

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"

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
    config_reload(duthost, config_source="minigraph", safe_reload=True, override_config=True)


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)
