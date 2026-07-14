"""Switch a single-ASIC DUT between traditional (bgpcfgd) and frr_mgmt_framework
(frrcfgd) BGP config modes, entirely from sonic-mgmt (no on-DUT migrator tool).

This drives the pure :func:`translate_config_db` translation with data gathered
from the DUT and applies it with a ``config reload``. The mode is made to survive
``config reload`` by writing ``docker_routing_config_mode`` into both
``config_db.json`` and ``golden_config_db.json`` -- ``db_migrator`` (run by
``config reload``) takes the routing mode from its config source (golden config
overriding minigraph), NOT from the freshly-loaded ``config_db``, so setting
``config_db`` alone would be reverted on the next reload.

Reverse (frr -> traditional) restores the pre-switch ``config_db.json`` and
``golden_config_db.json`` backups and reloads, returning the DUT to exactly its
original config.

Scope / assumptions (the ``frr_config_mode`` fixture enforces these by skipping):
  * single-ASIC DUT (no per-namespace handling);
  * the DUT's *original* mode is traditional (we translate traditional -> frr,
    and return via backup restore -- we do not translate frr -> traditional);
  * a ``golden_config_db.json`` is present so the mode persists across reload.
"""
import json
import logging

from tests.common.helpers.frr.bgp_config_translation import (
    translate_config_db,
    FrrTranslationError,
)

logger = logging.getLogger(__name__)

CONFIG_DB_FILE = "/etc/sonic/config_db.json"
GOLDEN_CFG_FILE = "/etc/sonic/golden_config_db.json"
_BAK_SUFFIX = ".frr_config_mode.bak"

MODE_FRR_MGMT_FRAMEWORK = "frr_mgmt_framework"
MODE_TRADITIONAL = "traditional"


class FrrConfigModeMigrator(object):
    """Owns the traditional<->frr switch for one DUT across a test module."""

    def __init__(self, duthost):
        self.duthost = duthost
        self._backed_up = False

    # -- low-level DUT helpers ------------------------------------------------

    def _read_json_file(self, path):
        out = self.duthost.shell("sudo cat {}".format(path), module_ignore_errors=True)
        if out["rc"] != 0 or not out["stdout"].strip():
            return None
        return json.loads(out["stdout"])

    def _write_json_file(self, path, data):
        self.duthost.copy(content=json.dumps(data, indent=2), dest=path)

    def _vtysh_json(self, cmd):
        out = self.duthost.shell('sudo vtysh -c "{}"'.format(cmd))["stdout"]
        try:
            return json.loads(out)
        except ValueError:
            raise FrrTranslationError("vtysh command {!r} did not return JSON".format(cmd))

    def _vtysh_text(self, cmd):
        return self.duthost.shell('sudo vtysh -c "{}"'.format(cmd))["stdout"]

    def _golden_config_present(self):
        return self.duthost.is_file_existed(GOLDEN_CFG_FILE)

    def _backup(self):
        if self._backed_up:
            return
        self.duthost.shell("sudo cp {0} {0}{1}".format(CONFIG_DB_FILE, _BAK_SUFFIX))
        if self._golden_config_present():
            self.duthost.shell("sudo cp {0} {0}{1}".format(GOLDEN_CFG_FILE, _BAK_SUFFIX))
        self._backed_up = True

    def _config_reload(self):
        # -f bypasses the SwSS readiness check; frrcfgd only needs FRR ready. This
        # mirrors how the routing-mode switch is applied on the box.
        self.duthost.shell("sudo config reload -y -f")

    @staticmethod
    def _set_mode_metadata(config, routing_mode, frr_mgmt):
        meta = config.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})
        meta["docker_routing_config_mode"] = routing_mode
        meta["frr_mgmt_framework_config"] = frr_mgmt

    # -- public API -----------------------------------------------------------

    def to_frr_mgmt_framework(self):
        """Translate the DUT's traditional BGP config to frr_mgmt_framework and
        apply it. Raises FrrTranslationError if the config cannot be translated."""
        if not self._golden_config_present():
            raise FrrTranslationError(
                "{} not present; cannot persist unified routing mode across config "
                "reload".format(GOLDEN_CFG_FILE))
        self._backup()

        # Persist the running DB to disk, then read it as the translation source.
        self.duthost.shell("sudo config save -y")
        config_db = self._read_json_file(CONFIG_DB_FILE)
        if config_db is None:
            raise FrrTranslationError("Could not read {}".format(CONFIG_DB_FILE))
        running_config = self._vtysh_text("show running-config")
        peer_group_json = self._vtysh_json("show bgp peer-group json")

        logger.info("Translating traditional BGP config to frr_mgmt_framework on %s",
                    self.duthost.hostname)
        new_config = translate_config_db(config_db, running_config, peer_group_json)
        self._set_mode_metadata(new_config, "unified", "true")
        self._write_json_file(CONFIG_DB_FILE, new_config)

        # golden config must also carry the mode, else db_migrator reverts it on reload.
        golden = self._read_json_file(GOLDEN_CFG_FILE) or {}
        self._set_mode_metadata(golden, "unified", "true")
        self._write_json_file(GOLDEN_CFG_FILE, golden)

        self._config_reload()

    def to_traditional(self):
        """Return the DUT to its original traditional config by restoring the
        pre-switch backups and reloading."""
        if not self._backed_up:
            logger.warning("to_traditional() with no backup taken; nothing to restore")
            return
        self.duthost.shell("sudo cp {0}{1} {0}".format(CONFIG_DB_FILE, _BAK_SUFFIX))
        if self.duthost.is_file_existed(GOLDEN_CFG_FILE + _BAK_SUFFIX):
            self.duthost.shell("sudo cp {0}{1} {0}".format(GOLDEN_CFG_FILE, _BAK_SUFFIX))
        self._config_reload()

    def cleanup(self):
        """Remove backup files left on the DUT."""
        self.duthost.shell("sudo rm -f {0}{1} {2}{1}".format(
            CONFIG_DB_FILE, _BAK_SUFFIX, GOLDEN_CFG_FILE), module_ignore_errors=True)
