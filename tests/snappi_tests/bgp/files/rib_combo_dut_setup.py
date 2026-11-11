"""
Multi-ASIC / multidut support (ported from data3).

DUT setup helpers for rib_combo perf tests (config_db profiles, orchagent -b/-k).

Supports single-ASIC and multi-ASIC; targets only ASICs referenced by the
port list used for the test (e.g. multipath + 1 tgen ports).
"""
import json
import logging
import os
import tempfile

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

ORCHAGENT_PATH = "/usr/bin/orchagent.sh"
SWSS_SERVICE = "swss"
DEFAULT_BACKUP_TAG = "rib_combo_v1"


def asic_instance_from_port(duthost, port_entry):
    """Resolve SonicAsic for a tgen_ports entry."""
    return _asic_instance_from_port(duthost, port_entry)


def _asic_instance_from_port(duthost, port_entry):
    if not duthost.is_multi_asic:
        return duthost.asic_instance()
    asic_value = port_entry.get("asic_value")
    if asic_value:
        asic_index = int(str(asic_value).replace("asic", ""))
        return duthost.asic_instance(asic_index)
    peer_port = port_entry.get("peer_port")
    if peer_port:
        return duthost.get_port_asic_instance(peer_port)
    return duthost.asic_instance()


def config_db_remote_path(duthost, asic_index):
    """Path on DUT for a given ASIC config_db file."""
    if not duthost.is_multi_asic:
        return "/etc/sonic/config_db.json"
    return "/etc/sonic/config_db{}.json".format(asic_index)


def config_db_backup_remote_path(duthost, asic_index, backup_tag=DEFAULT_BACKUP_TAG):
    if not duthost.is_multi_asic:
        return "/etc/sonic/config_db_{}_backup.json".format(backup_tag)
    return "/etc/sonic/config_db{}_{}_backup.json".format(asic_index, backup_tag)


def affected_setup_targets(tgen_ports, port_count, default_duthost=None):
    """
    Unique (duthost, asic_instance) for the first ``port_count`` tgen_ports entries.
    """
    seen = set()
    pairs = []
    for port in tgen_ports[:port_count]:
        duthost = port.get("duthost") or default_duthost
        if duthost is None:
            logger.warning("tgen_ports entry missing duthost and no default_duthost")
            continue
        asic_inst = asic_instance_from_port(duthost, port)
        asic_key = asic_inst.asic_index if duthost.is_multi_asic else 0
        key = (duthost.hostname, asic_key)
        if key in seen:
            continue
        seen.add(key)
        pairs.append((duthost, asic_inst))
    return pairs


def unique_duthosts_from_targets(targets):
    duthosts = []
    seen = set()
    for duthost, _asic in targets:
        if duthost.hostname not in seen:
            seen.add(duthost.hostname)
            duthosts.append(duthost)
    return duthosts


def asic_indices_for_duthost(duthost, targets):
    indices = []
    for target_dut, asic_inst in targets:
        if target_dut.hostname != duthost.hostname:
            continue
        if duthost.is_multi_asic:
            indices.append(asic_inst.asic_index)
        else:
            return [0]
    return sorted(set(indices))


def get_config_db(duthost, asic_index=0):
    path = config_db_remote_path(duthost, asic_index)
    out = duthost.shell("cat {}".format(path))["stdout"]
    return json.loads(out)


def apply_config_db_profile(duthost, profile_config, original_config, asic_index=0):
    config = json.loads(json.dumps(original_config))
    if "DEVICE_METADATA" not in config:
        config["DEVICE_METADATA"] = {}
    if "localhost" not in config["DEVICE_METADATA"]:
        config["DEVICE_METADATA"]["localhost"] = {}
    meta = profile_config.get("DEVICE_METADATA", {}).get("localhost", {})
    config["DEVICE_METADATA"]["localhost"].update(meta)
    # Added for multi-asic support: keep data1 profile parity - SYSTEM_DEFAULTS holds the consolidated
    # swss_zmq route-performance knob (merged into every targeted ASIC config_db).
    sys_defaults = profile_config.get("SYSTEM_DEFAULTS", {})
    if sys_defaults:
        if "SYSTEM_DEFAULTS" not in config:
            config["SYSTEM_DEFAULTS"] = {}
        for entry, fields in sys_defaults.items():
            config["SYSTEM_DEFAULTS"].setdefault(entry, {}).update(fields)
    dest = config_db_remote_path(duthost, asic_index)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f, indent=4)
        tmp_path = f.name
    try:
        duthost.copy(src=tmp_path, dest=dest)
    finally:
        os.unlink(tmp_path)


def backup_config_dbs(duthost, asic_indices, backup_tag=DEFAULT_BACKUP_TAG):
    for asic_index in asic_indices:
        src = config_db_remote_path(duthost, asic_index)
        dest = config_db_backup_remote_path(duthost, asic_index, backup_tag)
        duthost.shell("sudo cp {} {}".format(src, dest))


def revert_config_db(duthost, asic_indices, backup_tag=DEFAULT_BACKUP_TAG):
    for asic_index in asic_indices:
        backup = config_db_backup_remote_path(duthost, asic_index, backup_tag)
        dest = config_db_remote_path(duthost, asic_index)
        duthost.shell("sudo cp {} {}".format(backup, dest))
    duthost.shell("sudo config reload -y")
    pytest_assert(
        wait_until(600, 30, 1, duthost.critical_services_fully_started),
        "Not all critical services are fully started after config revert",
    )
    for asic_index in asic_indices:
        backup = config_db_backup_remote_path(duthost, asic_index, backup_tag)
        duthost.shell("sudo rm -f {}".format(backup), module_ignore_errors=True)


def apply_profile_to_targets(profile_config, targets, skip_when_wo_tuning=True):
    """
    Merge fine-tuning profile into config_db for each (duthost, asic) target.
    """
    if skip_when_wo_tuning and profile_config.get("config_db_wo_tuning"):
        return
    by_dut = {}
    for duthost, asic_inst in targets:
        by_dut.setdefault(duthost.hostname, []).append((duthost, asic_inst))
    for _hostname, dut_targets in by_dut.items():
        duthost = dut_targets[0][0]
        for _dut, asic_inst in dut_targets:
            asic_index = asic_inst.asic_index if duthost.is_multi_asic else 0
            original = get_config_db(duthost, asic_index)
            apply_config_db_profile(duthost, profile_config, original, asic_index)


def swss_docker_cmd(duthost, asic_inst, cmd):
    """
    Wrap ``cmd`` so it runs inside the swss container of ``asic_inst``.

    ``SonicAsic.get_docker_cmd`` only wraps the command with ``docker exec`` on multi-asic DUTs
    and returns it unchanged on single-asic DUTs, which would run it on the host instead.
    """
    if duthost.is_multi_asic:
        return asic_inst.get_docker_cmd(cmd, SWSS_SERVICE)
    return "sudo docker exec {} {}".format(SWSS_SERVICE, cmd)


def apply_bk_value(duthost, asic_inst, bulk_value, batch_value):
    logger.info(
        "Applying bulk (b):%s, batch (k):%s on %s asic %s",
        bulk_value,
        batch_value,
        duthost.hostname,
        asic_inst.asic_index,
    )
    cp_cmd = "cp {} {}.bak".format(ORCHAGENT_PATH, ORCHAGENT_PATH)
    duthost.shell(swss_docker_cmd(duthost, asic_inst, cp_cmd))
    if bulk_value != "default" or batch_value != "default":
        sed_cmd = (
            r"sed -i 's/ORCHAGENT_ARGS+=\"-b 1024 \"/ORCHAGENT_ARGS+=\"-b {} -k {} \"/' {}"
        ).format(bulk_value, batch_value, ORCHAGENT_PATH)
        duthost.shell(swss_docker_cmd(duthost, asic_inst, sed_cmd))


def revert_bk_value(duthost, asic_inst):
    logger.info(
        "Reverting orchagent.sh from backup on %s asic %s",
        duthost.hostname,
        asic_inst.asic_index,
    )
    revert_cmd = "cp {}.bak {}".format(ORCHAGENT_PATH, ORCHAGENT_PATH)
    duthost.shell(
        swss_docker_cmd(duthost, asic_inst, revert_cmd),
        module_ignore_errors=True,
    )


def apply_bk_to_targets(targets, bulk_value, batch_value):
    for duthost, asic_inst in targets:
        apply_bk_value(duthost, asic_inst, bulk_value, batch_value)


def revert_bk_on_targets(targets):
    for duthost, asic_inst in targets:
        revert_bk_value(duthost, asic_inst)
