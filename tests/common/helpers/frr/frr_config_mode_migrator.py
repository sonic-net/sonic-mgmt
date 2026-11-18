"""Switch a single-ASIC DUT between traditional (bgpcfgd) and frr_mgmt_framework (frrcfgd) BGP config modes.

Forward translates with :func:`translate_config_db` and reloads; reverse restores the pre-switch backups.
Assumes a single-ASIC DUT, originally traditional, with a ``golden_config_db.json`` (the fixture skips otherwise).
"""
import json
import logging
import time

from tests.common.helpers.frr.bgp_config_translation import (
    translate_config_db,
    FrrTranslationError,
)
from tests.common.helpers.frr.frr_parity_compat import strip_unsupported_by_image  # noqa: DELETE-WITH-FRR-PARITY

logger = logging.getLogger(__name__)

CONFIG_DB_FILE = "/etc/sonic/config_db.json"
GOLDEN_CFG_FILE = "/etc/sonic/golden_config_db.json"
# restore_golden_config_db copies this over GOLDEN_CFG_FILE at every module setup, so the mode goes here too.
GOLDEN_CFG_ORIGIN_FILE = GOLDEN_CFG_FILE + ".origin.backup"
_BAK_SUFFIX = ".frr_config_mode.bak"
# Exists only between the forward switch and a verified restore; interrupted-run recovery keys on it.
SWITCHED_MARKER_FILE = "/etc/sonic/frr_config_mode.switched"

MODE_FRR_MGMT_FRAMEWORK = "frr_mgmt_framework"
MODE_TRADITIONAL = "traditional"

# Tables only frrcfgd uses; leftovers after a restore break GCU's whole-config YANG validation.
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

    def _vtysh(self, cmd, attempts=6, interval=10):
        """Run a vtysh command, retrying while vtysh is unreachable (e.g. after a bgp container restart)."""
        last = None
        for attempt in range(attempts):
            last = self.duthost.shell('sudo vtysh -c "{}"'.format(cmd), module_ignore_errors=True)
            if last.get("rc") == 0:
                return last["stdout"]
            logger.warning("vtysh %r failed on %s (rc=%s, attempt %d/%d)", cmd,
                           self.duthost.hostname, last.get("rc"), attempt + 1, attempts)
            time.sleep(interval)

        raise FrrTranslationError(
            "vtysh command {!r} kept failing on {} (rc={}, stderr={!r})".format(
                cmd, self.duthost.hostname, last.get("rc"), (last.get("stderr") or "")[:200]))

    def _vtysh_json(self, cmd):
        out = self._vtysh(cmd)
        try:
            return json.loads(out)
        except ValueError:
            raise FrrTranslationError("vtysh command {!r} did not return JSON".format(cmd))

    def _vtysh_text(self, cmd):
        return self._vtysh(cmd)

    def _golden_config_present(self):
        return self.duthost.is_file_existed(GOLDEN_CFG_FILE)

    def _golden_origin_present(self):
        return self.duthost.is_file_existed(GOLDEN_CFG_ORIGIN_FILE)

    def _backup_present(self):
        return self.duthost.is_file_existed(CONFIG_DB_FILE + _BAK_SUFFIX)

    def _backup(self):
        if self._backed_up:
            return
        for path in (CONFIG_DB_FILE, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE):
            if self.duthost.is_file_existed(path + _BAK_SUFFIX):
                # A previous run's pristine copy; the current file may already be translated.
                logger.warning("%s%s already exists; adopting it rather than overwriting",
                               path, _BAK_SUFFIX)
            elif path == CONFIG_DB_FILE or self.duthost.is_file_existed(path):
                self.duthost.shell("sudo cp {0} {0}{1}".format(path, _BAK_SUFFIX))
        self._backed_up = True

    def capture_pristine_backup(self):
        """Save and back up the running config once at session start, before any test mutates it."""
        self.duthost.shell("sudo config save -y")
        self._backup()

    def _config_reload(self):
        # -f bypasses the SwSS readiness check; frrcfgd only needs FRR ready.
        self.duthost.shell("sudo config reload -y -f")

    @staticmethod
    def _set_mode_metadata(config, routing_mode, frr_mgmt):
        meta = config.setdefault("DEVICE_METADATA", {}).setdefault("localhost", {})
        meta["docker_routing_config_mode"] = routing_mode
        meta["frr_mgmt_framework_config"] = frr_mgmt

    # -- public API -----------------------------------------------------------

    def to_frr_mgmt_framework(self):
        """Translate and apply the DUT's BGP config in frr_mgmt_framework mode (FrrTranslationError on failure)."""
        if not self._golden_config_present():
            raise FrrTranslationError(
                "{} not present; cannot persist unified routing mode across config "
                "reload".format(GOLDEN_CFG_FILE))
        # Save first so the backup is the true running config.
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
        new_config = strip_unsupported_by_image(self.duthost, new_config)  # noqa: DELETE-WITH-FRR-PARITY
        self._set_mode_metadata(new_config, "unified", "true")
        # Mark switched before touching any persistent file, so a run that dies from here is recoverable.
        self.duthost.shell("sudo touch {}".format(SWITCHED_MARKER_FILE))
        self._write_json_file(CONFIG_DB_FILE, new_config)

        # golden config must also carry the mode, else db_migrator reverts it on reload.
        golden = self._read_json_file(GOLDEN_CFG_FILE) or {}
        self._set_mode_metadata(golden, "unified", "true")
        self._write_json_file(GOLDEN_CFG_FILE, golden)

        # ...and so must its origin backup. See GOLDEN_CFG_ORIGIN_FILE.
        if self._golden_origin_present():
            origin = self._read_json_file(GOLDEN_CFG_ORIGIN_FILE) or {}
            self._set_mode_metadata(origin, "unified", "true")
            self._write_json_file(GOLDEN_CFG_ORIGIN_FILE, origin)

        self._config_reload()

    def to_traditional(self):
        """Restore the pre-switch backups and reload; True if a restore happened.

        Keyed on the backup file on the DUT, not ``self._backed_up`` (recovery uses a fresh migrator).
        """
        # Restore golden files unconditionally, else 'config load_minigraph -o' would bring frr mode back.
        restored_golden = False
        for path in (GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE):
            if self.duthost.is_file_existed(path + _BAK_SUFFIX):
                self.duthost.shell("sudo cp {0}{1} {0}".format(path, _BAK_SUFFIX))
                restored_golden = True
        if not self._backup_present():
            logger.warning("to_traditional(): %s%s absent; restored golden files only (%s)",
                           CONFIG_DB_FILE, _BAK_SUFFIX, restored_golden)
            return False
        self.duthost.shell("sudo cp {0}{1} {0}".format(CONFIG_DB_FILE, _BAK_SUFFIX))
        self._config_reload()
        # Clear the marker only after the residue check passes, so a failed restore is retried next run.
        self.assert_no_frr_schema_residue()
        self.duthost.shell("sudo rm -f {}".format(SWITCHED_MARKER_FILE),
                           module_ignore_errors=True)
        return True

    def _frr_tables_in_backup(self):
        """FRR-schema tables the pre-switch backup already contained (the residue baseline; may be non-empty)."""
        backup = self._read_json_file(CONFIG_DB_FILE + _BAK_SUFFIX)
        if backup is None:
            return set()
        return {table for table in backup if table in FRR_ONLY_TABLES}

    def assert_no_frr_schema_residue(self):
        """Raise if the traditional restore left frr-only tables that the backup did not have."""
        out = self.duthost.shell(
            "sonic-db-cli CONFIG_DB KEYS '*' | cut -d'|' -f1 | sort -u",
            module_ignore_errors=True)
        if out.get("rc"):
            logger.warning("Could not list CONFIG_DB tables to check for frr residue")
            return
        present = set(out["stdout"].split())
        baseline = self._frr_tables_in_backup()
        if baseline:
            logger.info("Pre-switch config already carried frr-schema tables %s; they are the "
                        "baseline, not residue", sorted(baseline))
        residue = sorted(present.intersection(FRR_ONLY_TABLES) - baseline)
        if residue:
            raise FrrTranslationError(
                "traditional restore left frr_mgmt_framework tables in CONFIG_DB that the "
                "pre-switch backup did not have: {}. The restored {} is inconsistent with its "
                "own traditional DEVICE_METADATA; every later GCU patch would fail sonic_yang "
                "validation because of it.".format(", ".join(residue), CONFIG_DB_FILE))

    def interrupted_run_pending(self):
        """True if a previous run left the DUT switched (keyed on SWITCHED_MARKER_FILE, not the backup)."""
        return self.duthost.is_file_existed(SWITCHED_MARKER_FILE)

    def recover_interrupted_run(self):
        """Restore the DUT from a previous run's leftover backups; True if it did, else a no-op."""
        if not self.interrupted_run_pending():
            return False
        logger.warning(
            "Found %s on %s: a previous run switched the FRR config mode and did not restore "
            "it (killed process, CI timeout, or DUT crash -- fixture teardown cannot cover "
            "those). Restoring the backed-up config before continuing.",
            SWITCHED_MARKER_FILE, self.duthost.hostname)
        if not self.to_traditional():
            # Keep the backups: they are the only pristine copy of the pre-switch config.
            raise FrrTranslationError(
                "found {} but could not restore from it; leaving the backups in place for "
                "manual recovery".format(CONFIG_DB_FILE + _BAK_SUFFIX))
        self.cleanup()
        return True

    def cleanup(self):
        """Remove the backup and switch-marker files left on the DUT."""
        self.duthost.shell("sudo rm -f {4} {0}{1} {2}{1} {3}{1}".format(
            CONFIG_DB_FILE, _BAK_SUFFIX, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE,
            SWITCHED_MARKER_FILE),
            module_ignore_errors=True)
