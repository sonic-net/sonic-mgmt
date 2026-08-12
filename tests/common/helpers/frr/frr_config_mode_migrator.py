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
import time

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
# Written just before the forward (traditional -> frr) switch reloads, and removed once the
# DUT is restored. Interrupted-run recovery keys on THIS, not on the presence of the config
# backup: capture_pristine_backup() takes that backup at session start, before any switch is
# attempted, so on a DUT that boots frrcfgd a killed run would otherwise look like an
# unfinished switch -- and "recovery" would reload the DUT's own native frr config and then
# reject its legitimate frr tables in assert_no_frr_schema_residue().
SWITCHED_MARKER_FILE = "/etc/sonic/frr_config_mode.switched"

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

    def _vtysh(self, cmd, attempts=6, interval=10):
        """Run a vtysh command, retrying while vtysh is unreachable.

        vtysh talks to the FRR daemons over their vty sockets, so it fails outright for a
        while after anything restarts the bgp container -- a mode switch, a config reload, or
        the tail of a previous module's teardown. Failing the first call turns that transient
        into a module error before a single test runs, which is what happened on a t2 when a
        run started ~2 minutes after the DUT was repaired.
        """
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

    def capture_pristine_backup(self):
        """Save the running config and back it up, before any test has mutated it.

        Call once at session start. Taking the backup lazily inside to_frr_mgmt_framework()
        instead captures whatever module fixtures have already done to CONFIG_DB by the time of
        the first switch -- observed on a t1 as subinterfaces moved into a test's VRFs, which
        made the "restore" reinstate the broken config and left a BGP neighbor unable to
        establish because the interface holding its local_addr was still in a VRF. The backup
        has to predate the tests for a restore to mean "put the DUT back the way we found it".
        """
        self.duthost.shell("sudo config save -y")
        self._backup()

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

        # Mark the DUT as switched BEFORE the reload, so a run killed anywhere from here on
        # is recoverable. See SWITCHED_MARKER_FILE.
        self.duthost.shell("sudo touch {}".format(SWITCHED_MARKER_FILE))
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
        # Restore the golden files even when the CONFIG_DB backup is gone. to_frr_mgmt_framework()
        # stamps the routing mode into golden_config_db.json *and* its .origin.backup so the mode
        # survives a reload, which means a half-finished teardown leaves both claiming frr mode.
        # Anyone then recovering the DUT with 'config load_minigraph -o' -- the documented repair
        # -- silently gets frr mode back, because -o applies golden. Seen on a t2: recovery
        # returned frr=true routing=unified twice before the contaminated origin backup was
        # spotted. These restores are independent of the CONFIG_DB one, so do them first and
        # unconditionally.
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
        # Only now clear the switch marker -- after the reload AND after the residue check
        # below have proved the DUT is genuinely back on traditional config. Clearing it
        # earlier means a restore that then fails leaves the backups but no marker, so
        # interrupted_run_pending() reads False on the next run and recovery never retries:
        # the DUT stays stranded in translated frr config with nothing left to notice.
        self.assert_no_frr_schema_residue()
        self.duthost.shell("sudo rm -f {}".format(SWITCHED_MARKER_FILE),
                           module_ignore_errors=True)
        return True

    def _frr_tables_in_backup(self):
        """FRR-schema tables the pre-switch backup already contained.

        This is the baseline the restore is measured against. It is NOT always empty: a DUT
        that natively boots frrcfgd carries the frr schema in CONFIG_DB as its normal state,
        and a hand-migrated box can run bgpcfgd over an frr-shaped CONFIG_DB. Those tables
        were there before anything switched, so their presence afterwards is not residue.
        """
        backup = self._read_json_file(CONFIG_DB_FILE + _BAK_SUFFIX)
        if backup is None:
            return set()
        return {table for table in backup if table in FRR_ONLY_TABLES}

    def assert_no_frr_schema_residue(self):
        """Raise if the traditional restore ADDED frr-only tables that the backup did not have.

        Called right after the traditional restore so a lossy switch-back is reported here,
        against the switch that caused it, instead of silently poisoning GCU for the rest of
        the run. See :data:`FRR_ONLY_TABLES`.

        Measured against the backup rather than against "no frr tables at all". The restore
        reinstates the backup and reloads, so the invariant that actually holds is
        "CONFIG_DB matches the backup" -- anything else is a false positive on any DUT whose
        pre-switch config legitimately contains frr tables. Getting this wrong is expensive:
        the check runs inside to_traditional(), so one false positive fails the restore, and
        every later module then errors at setup via recover_interrupted_run().
        """
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
        """True if a previous run left the DUT in a switched FRR config mode.

        Keyed on :data:`SWITCHED_MARKER_FILE`, which exists only between the forward switch
        in ``to_frr_mgmt_framework()`` and the restore in ``to_traditional()``. Finding it at
        the start of a run means an earlier session died before its teardown could restore
        the DUT -- a killed harness, a CI timeout, a DUT crash, an interrupted background run.
        Fixture teardown cannot cover any of those, so recovery has to be idempotent and
        happen at setup instead.

        Deliberately NOT keyed on the config backup: ``capture_pristine_backup()`` writes
        that at session start, before any switch is attempted, so on a DUT that natively
        boots frrcfgd -- where no switch ever happens -- an interrupted run would otherwise
        look like an unfinished switch, and "recovery" would reload the DUT's own native frr
        config only for ``assert_no_frr_schema_residue()`` to reject its legitimate frr
        tables.
        """
        return self.duthost.is_file_existed(SWITCHED_MARKER_FILE)

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
            SWITCHED_MARKER_FILE, self.duthost.hostname)
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
        """Remove the backup and switch-marker files left on the DUT."""
        self.duthost.shell("sudo rm -f {4} {0}{1} {2}{1} {3}{1}".format(
            CONFIG_DB_FILE, _BAK_SUFFIX, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE,
            SWITCHED_MARKER_FILE),
            module_ignore_errors=True)
