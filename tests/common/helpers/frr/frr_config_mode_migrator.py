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
from tests.common.helpers.frr.frr_28543_compat import strip_unsupported_by_image  # noqa: DELETE-WITH-28543

logger = logging.getLogger(__name__)

CONFIG_DB_FILE = "/etc/sonic/config_db.json"
GOLDEN_CFG_FILE = "/etc/sonic/golden_config_db.json"
# tests/conftest.py's module-scoped autouse restore_golden_config_db fixture copies this over
# GOLDEN_CFG_FILE at *every module setup*. A routing mode written only into GOLDEN_CFG_FILE
# therefore survives at most one module: the next module's setup reverts golden to its original
# (traditional) baseline while config_db.json still holds translated frr config, and the first
# `config reload` after that flips the DUT back to traditional behind this migrator's back.
# The mode has to be written into both files to actually persist.
GOLDEN_CFG_ORIGIN_FILE = GOLDEN_CFG_FILE + ".origin.backup"
_BAK_SUFFIX = ".frr_config_mode.bak"

MODE_FRR_MGMT_FRAMEWORK = "frr_mgmt_framework"
MODE_TRADITIONAL = "traditional"

# CONFIG_DB tables that only ever exist in frr_mgmt_framework mode -- bgpcfgd neither reads nor
# writes them. Finding any of these while the DUT claims to be traditional means a previous
# switch left translated config behind, which is not merely cosmetic: GCU (``apply_patch``)
# validates the *whole* CONFIG_DB through sonic_yang, so one orphaned frr-schema key makes every
# later GCU patch in the run fail with an error that points at the innocent patch instead.
FRR_ONLY_TABLES = (
    "BGP_GLOBALS",
    "BGP_GLOBALS_AF",
    "BGP_GLOBALS_AF_AGGREGATE_ADDR",
    "BGP_GLOBALS_AF_NETWORK",
    "BGP_GLOBALS_LISTEN_PREFIX",
    "BGP_NEIGHBOR_AF",
    "BGP_PEER_GROUP_AF",
)


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

    def _golden_origin_present(self):
        return self.duthost.is_file_existed(GOLDEN_CFG_ORIGIN_FILE)

    def _backup_present(self):
        return self.duthost.is_file_existed(CONFIG_DB_FILE + _BAK_SUFFIX)

    def _backup(self):
        if self._backed_up:
            return
        if self._backup_present():
            # A backup we did not take is a previous run's pristine pre-switch config. Never
            # overwrite it with the current config, which may already be translated -- adopt it
            # instead so the eventual restore still lands on real traditional config.
            logger.warning("%s%s already exists; adopting it rather than overwriting",
                           CONFIG_DB_FILE, _BAK_SUFFIX)
            self._backed_up = True
            return
        self.duthost.shell("sudo cp {0} {0}{1}".format(CONFIG_DB_FILE, _BAK_SUFFIX))
        if self._golden_config_present():
            self.duthost.shell("sudo cp {0} {0}{1}".format(GOLDEN_CFG_FILE, _BAK_SUFFIX))
        if self._golden_origin_present():
            self.duthost.shell("sudo cp {0} {0}{1}".format(GOLDEN_CFG_ORIGIN_FILE, _BAK_SUFFIX))
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
        # Persist the running DB to disk FIRST, then back it up, so the backup captures the
        # true pre-switch running config (not a stale on-disk copy). The traditional-mode
        # restore reinstates this backup, so it must reflect what was actually running.
        self.duthost.shell("sudo config save -y")
        self._backup()
        config_db = self._read_json_file(CONFIG_DB_FILE)
        if config_db is None:
            raise FrrTranslationError("Could not read {}".format(CONFIG_DB_FILE))
        running_config = self._vtysh_text("show running-config")
        peer_group_json = self._vtysh_json("show bgp peer-group json")

        logger.info("Translating traditional BGP config to frr_mgmt_framework on %s",
                    self.duthost.hostname)
        new_config = translate_config_db(config_db, running_config, peer_group_json)
        new_config = strip_unsupported_by_image(self.duthost, new_config)  # noqa: DELETE-WITH-28543
        self._set_mode_metadata(new_config, "unified", "true")
        self._write_json_file(CONFIG_DB_FILE, new_config)

        # golden config must also carry the mode, else db_migrator reverts it on reload.
        golden = self._read_json_file(GOLDEN_CFG_FILE) or {}
        self._set_mode_metadata(golden, "unified", "true")
        self._write_json_file(GOLDEN_CFG_FILE, golden)

        # ...and so must its origin backup, which restore_golden_config_db copies back over
        # golden at every module setup. See GOLDEN_CFG_ORIGIN_FILE.
        if self._golden_origin_present():
            origin = self._read_json_file(GOLDEN_CFG_ORIGIN_FILE) or {}
            self._set_mode_metadata(origin, "unified", "true")
            self._write_json_file(GOLDEN_CFG_ORIGIN_FILE, origin)

        self._config_reload()

    def to_traditional(self):
        """Return the DUT to its original traditional config by restoring the
        pre-switch backups and reloading. Returns True if a restore happened.

        Restorability is decided by the backup *file* on the DUT, not by ``self._backed_up``.
        That flag only records whether *this* process took the backup, and the recovery path
        (:meth:`recover_interrupted_run`) runs on a freshly constructed migrator whose flag is
        always False -- gating on it made recovery a silent no-op that then deleted the only
        pristine copy of the config, stranding the DUT in translated config for every
        subsequent run.
        """
        if not self._backup_present():
            logger.warning("to_traditional(): %s%s absent; nothing to restore",
                           CONFIG_DB_FILE, _BAK_SUFFIX)
            return False
        self.duthost.shell("sudo cp {0}{1} {0}".format(CONFIG_DB_FILE, _BAK_SUFFIX))
        if self.duthost.is_file_existed(GOLDEN_CFG_FILE + _BAK_SUFFIX):
            self.duthost.shell("sudo cp {0}{1} {0}".format(GOLDEN_CFG_FILE, _BAK_SUFFIX))
        if self.duthost.is_file_existed(GOLDEN_CFG_ORIGIN_FILE + _BAK_SUFFIX):
            self.duthost.shell("sudo cp {0}{1} {0}".format(GOLDEN_CFG_ORIGIN_FILE, _BAK_SUFFIX))
        self._config_reload()
        self.assert_no_frr_schema_residue()
        return True

    def assert_no_frr_schema_residue(self):
        """Raise if the running CONFIG_DB still holds frr-only tables.

        Called right after the traditional restore so a lossy switch-back is reported here,
        against the switch that caused it, instead of silently poisoning GCU for the rest of
        the run. See :data:`FRR_ONLY_TABLES`.
        """
        out = self.duthost.shell(
            "sonic-db-cli CONFIG_DB KEYS '*' | cut -d'|' -f1 | sort -u",
            module_ignore_errors=True)
        if out.get("rc"):
            logger.warning("Could not list CONFIG_DB tables to check for frr residue")
            return
        present = set(out["stdout"].split())
        residue = sorted(present.intersection(FRR_ONLY_TABLES))
        if residue:
            raise FrrTranslationError(
                "traditional restore left frr_mgmt_framework tables in CONFIG_DB: {}. The "
                "restored {} is inconsistent with its own traditional DEVICE_METADATA; every "
                "later GCU patch would fail sonic_yang validation because of it.".format(
                    ", ".join(residue), CONFIG_DB_FILE))

    def interrupted_run_pending(self):
        """True if a previous run left switch backups behind.

        The backups only exist between ``to_frr_mgmt_framework()`` and ``cleanup()``, so
        finding them at the start of a run means an earlier session died before its teardown
        could restore the DUT -- a killed harness, a CI timeout, a DUT crash, an interrupted
        background run. Fixture teardown cannot cover any of those, so recovery has to be
        idempotent and happen at setup instead.
        """
        return self._backup_present()

    def recover_interrupted_run(self):
        """Restore the DUT from a previous run's leftover backups. Returns True if it did.

        Safe to call unconditionally at the start of a run: a no-op when no backups exist.
        """
        if not self.interrupted_run_pending():
            return False
        logger.warning(
            "Found %s on %s: a previous run switched the FRR config mode and did not restore "
            "it (killed process, CI timeout, or DUT crash -- fixture teardown cannot cover "
            "those). Restoring the backed-up config before continuing.",
            CONFIG_DB_FILE + _BAK_SUFFIX, self.duthost.hostname)
        if not self.to_traditional():
            # Keep the backups: they are the only pristine copy of the pre-switch config, and
            # deleting them on a failed restore is what turns a recoverable interruption into a
            # permanently mis-configured DUT.
            raise FrrTranslationError(
                "found {} but could not restore from it; leaving the backups in place for "
                "manual recovery".format(CONFIG_DB_FILE + _BAK_SUFFIX))
        self.cleanup()
        return True

    def cleanup(self):
        """Remove backup files left on the DUT."""
        self.duthost.shell("sudo rm -f {0}{1} {2}{1} {3}{1}".format(
            CONFIG_DB_FILE, _BAK_SUFFIX, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE),
            module_ignore_errors=True)
