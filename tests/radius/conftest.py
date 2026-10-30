"""
conftest.py for tests/radius -- module-scoped fixtures for the RADIUS test suite.
"""
import json
import logging
import time
import pytest

from tests.radius.utils import (
    start_radius_server,
    stop_radius_server,
    configure_dut_radius,
    restore_dut_aaa_config,
    block_radius_server,
    unblock_radius_server,
    ssh_connect_remote_retry,
    ssh_run_command,
    close_ssh,
    delete_jit_user,
    _save_local_aaa,
    _radius_del,
)

logger = logging.getLogger(__name__)

# Synthetic test credentials. These accounts exist only on the FreeRADIUS
# server provisioned by the test harness on the PTF and on a throwaway local
# Linux account on the DUT. They do not grant access to any real system and
# are scoped to the lifetime of the test run. Mirrors the same convention
# used by tests/common/fixtures/tacacs.py for the tacacs_creds fixture.
_RADIUS_TEST_CREDS = {
    "radius_rw_user": "radius_rwuser",
    "radius_rw_user_passwd": "123456",
    "radius_ro_user": "radius_rouser",
    "radius_ro_user_passwd": "123456",
    "passkey": "testing123",
    "local_user": "test_louser",
    "local_user_passwd": "123456",
}


@pytest.fixture(scope="module")
def radius_creds(creds_all_duts):
    """Return creds_all_duts enriched with RADIUS test credentials."""
    creds_all_duts.update(_RADIUS_TEST_CREDS)
    return creds_all_duts


@pytest.fixture(scope="session", autouse=True)
def _radius_ensure_local_user(duthosts):
    """Provision local fallback user for RADIUS failthrough tests."""
    user = _RADIUS_TEST_CREDS["local_user"]
    pwd = _RADIUS_TEST_CREDS["local_user_passwd"]
    for duthost in duthosts:
        duthost.shell(
            "id -u {u} >/dev/null 2>&1 || "
            "(sudo useradd -m -s /bin/bash {u} && "
            "echo '{u}:{p}' | sudo chpasswd)".format(u=user, p=pwd),
            module_ignore_errors=True,
        )
    yield
    for duthost in duthosts:
        duthost.shell(
            "sudo userdel -r {} 2>/dev/null || true".format(user),
            module_ignore_errors=True,
        )


def _admin_safety_entries(creds_all_duts):
    """Build FreeRADIUS users-file entries for the DUT admin account(s).

    SONiC's auto-generated PAM stack contains ``auth_err=die`` on
    ``pam_radius_auth.so``. If FreeRADIUS issues an Access-Reject for the
    operator's admin account -- which it will by default, since the test users
    file only contains the synthesized RADIUS test users -- the PAM auth chain
    aborts immediately and the operator is locked out of SSH on the DUT, even
    with the correct local Unix password. By registering admin with FreeRADIUS
    using its real local password, RADIUS always returns Access-Accept for
    admin, the PAM chain proceeds normally, and the operator can never be
    locked out by the test harness.
    """
    admin_user = (
        creds_all_duts.get("sonicadmin_user")
        or creds_all_duts.get("sonic_login")
        or "admin"
    )
    admin_pwd = (
        creds_all_duts.get("sonicadmin_password")
        or creds_all_duts.get("sonic_password")
        or creds_all_duts.get("sonicadmin_initial_password")
    )
    if not admin_pwd:
        # No admin password available from inventory creds. Skip the
        # safety-net entry rather than ship a default password literal in
        # source: PAM ``auth_err=die`` will still fire if RADIUS rejects
        # the admin user, but at least we are not hard-coding credentials.
        logger.warning(
            "No admin password found in creds_all_duts; skipping RADIUS "
            "admin safety entries. Set sonicadmin_password in inventory "
            "to enable lockout protection."
        )
        return []
    entries = [{"username": admin_user, "password": admin_pwd, "priv_lvl": 15}]
    # Some inventories ship multiple candidate admin passwords (e.g. a default
    # and a post-install password). Include each so any of them satisfies
    # RADIUS during password-rotation windows.
    extra_pwds = []
    for key in ("sonicadmin_password", "sonicadmin_initial_password", "sonic_password"):
        v = creds_all_duts.get(key)
        if v and v != admin_pwd and v not in extra_pwds:
            extra_pwds.append(v)
    # Single user-file entry can only encode one Cleartext-Password, so we
    # emit additional synthesized entries with a username suffix that PAM will
    # never request -- they exist only to leave a documentation trail.
    for idx, extra in enumerate(extra_pwds, start=1):
        entries.append({
            "username": "{}__alt{}".format(admin_user, idx),
            "password": extra,
            "priv_lvl": 15,
        })
    return entries


def _read_table(duthost, table):
    """Return CONFIG_DB <table> as a dict (empty if absent)."""
    out = duthost.shell(
        "sonic-cfggen -d --var-json '{}'".format(table),
        module_ignore_errors=True,
    )
    if out.get("rc", 1) != 0 or not out.get("stdout", "").strip():
        return {}
    try:
        return json.loads(out["stdout"])
    except (ValueError, TypeError):
        return {}


def _apply_table(duthost, table, snapshot):
    """Replace CONFIG_DB <table> with <snapshot> exactly (no merge semantics)."""
    keys_out = duthost.shell(
        "sonic-db-cli CONFIG_DB keys '{}|*'".format(table),
        module_ignore_errors=True,
    )
    cur_full_keys = [k for k in keys_out.get("stdout", "").splitlines() if k.strip()]
    expected_full_keys = {"{}|{}".format(table, sub) for sub in snapshot.keys()}

    for full_key in cur_full_keys:
        if full_key not in expected_full_keys:
            duthost.shell(
                "sonic-db-cli CONFIG_DB del '{}'".format(full_key),
                module_ignore_errors=True,
            )

    for sub_key, fields in snapshot.items():
        full_key = "{}|{}".format(table, sub_key)
        hkeys_out = duthost.shell(
            "sonic-db-cli CONFIG_DB hkeys '{}'".format(full_key),
            module_ignore_errors=True,
        )
        cur_fields = {f for f in hkeys_out.get("stdout", "").splitlines() if f.strip()}
        expected_fields = set(fields.keys())

        for extra in cur_fields - expected_fields:
            duthost.shell(
                "sonic-db-cli CONFIG_DB hdel '{}' '{}'".format(full_key, extra),
                module_ignore_errors=True,
            )

        for f_name, f_val in fields.items():
            if isinstance(f_val, (list, dict)):
                continue
            duthost.shell(
                "sonic-db-cli CONFIG_DB hset '{}' '{}' '{}'".format(
                    full_key, f_name, str(f_val)
                ),
                module_ignore_errors=True,
            )


@pytest.fixture(scope="module", autouse=True)
def _radius_snapshot_restore(duthosts, enum_rand_one_per_hwsku_hostname):
    """Snapshot RADIUS tables at module start, restore on teardown."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    snapshots = {
        "RADIUS": _read_table(duthost, "RADIUS"),
        "RADIUS_SERVER": _read_table(duthost, "RADIUS_SERVER"),
    }
    logger.info("RADIUS snapshot captured: %s", {k: bool(v) for k, v in snapshots.items()})

    yield

    logger.info("Restoring RADIUS snapshot to prevent core_dump_and_config_check drift")
    for table, snap in snapshots.items():
        try:
            _apply_table(duthost, table, snap)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to restore %s table: %s", table, exc)


@pytest.fixture(scope="module")
def radius_server_setup(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, radius_creds):
    """
    Start freeradius on PTF with test users and configure DUT to use it.
    Saves local AAA config first and after -- prevents DUT lockout.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ptf_ip = ptfhost.mgmt_ip

    _save_local_aaa(duthost)
    _radius_del(duthost, ptf_ip)
    delete_jit_user(duthost, radius_creds["radius_rw_user"])
    delete_jit_user(duthost, radius_creds["radius_ro_user"])

    users = [
        {"username": radius_creds["radius_rw_user"],
         "password": radius_creds["radius_rw_user_passwd"],
         "priv_lvl": 15},
        {"username": radius_creds["radius_ro_user"],
         "password": radius_creds["radius_ro_user_passwd"],
         "priv_lvl": 1},
    ]
    clients = [{"name": "sonic-dut", "ipaddr": duthost.mgmt_ip}]

    admin_users = _admin_safety_entries(radius_creds)
    start_radius_server(
        ptfhost, users, clients,
        secret=radius_creds["passkey"],
        admin_users=admin_users,
    )
    configure_dut_radius(duthost, ptf_ip, passkey=radius_creds["passkey"])

    yield {"duthost": duthost, "ptf_ip": ptf_ip}

    restore_dut_aaa_config(duthost, ptf_ip)
    delete_jit_user(duthost, radius_creds["radius_rw_user"])
    delete_jit_user(duthost, radius_creds["radius_ro_user"])
    stop_radius_server(ptfhost)


@pytest.fixture(scope="function")
def rw_user_ssh(radius_server_setup, radius_creds):
    """Open an SSH session to DUT as the RW RADIUS user."""
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]
    delete_jit_user(duthost, username)
    client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        username,
        radius_creds["radius_rw_user_passwd"])
    # Some SONiC images apply MPL/group mapping on the second login after JIT
    # account creation; retry once if priv-lvl=15 groups are not present yet.
    if client is not None:
        _, out, _ = ssh_run_command(client, "id")
        if "sudo" not in out:
            close_ssh(client)
            delete_jit_user(duthost, username)
            time.sleep(2)
            client = ssh_connect_remote_retry(
                duthost.mgmt_ip,
                username,
                radius_creds["radius_rw_user_passwd"])
    yield client
    close_ssh(client)


@pytest.fixture(scope="function")
def ro_user_ssh(radius_server_setup, radius_creds):
    """Open an SSH session to DUT as the RO RADIUS user."""
    duthost = radius_server_setup["duthost"]
    delete_jit_user(duthost, radius_creds["radius_ro_user"])
    client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["radius_ro_user"],
        radius_creds["radius_ro_user_passwd"])
    yield client
    close_ssh(client)


@pytest.fixture(scope="function")
def radius_server_unreachable(ptfhost):
    """Block UDP 1812 on PTF to simulate server unreachable. Removes block on teardown."""
    block_radius_server(ptfhost)
    yield
    unblock_radius_server(ptfhost)


# ---------------------------------------------------------------------------
# Lockout-prevention safety net
# ---------------------------------------------------------------------------
# This fixture is the last line of defense against locking the operator out of
# the DUT. It is session-scoped and ``autouse=True`` so every pytest invocation
# under this directory gets it for free, and its teardown runs even when the
# test session fails catastrophically (pytest yield-teardown executes as long
# as fixture setup completed). The teardown:
#   1. Forces AAA back to ``local`` on every DUT and persists with ``config
#      save -y`` so a subsequent reboot does not resurrect a broken RADIUS
#      config.
#   2. Stops freeradius on the PTF and clears any iptables block the test
#      suite may have left, so admin SSH cannot be killed by a leftover
#      Access-Reject from a daemon nobody is talking to.
# Every command is wrapped with ``module_ignore_errors=True`` and a broad
# ``try/except`` -- the safety net must never raise, or it would mask the real
# test failure and leave the DUT in the broken state we are trying to undo.
@pytest.fixture(scope="session", autouse=True)
def _radius_lockout_safety_net(duthosts, ptfhost):
    """ALWAYS restore local AAA + stop freeradius on session teardown."""
    yield
    logger.info("RADIUS safety-net: restoring local AAA on all DUTs")
    for duthost in duthosts:
        for cmd in (
            "config aaa authentication login local",
            "config aaa authentication failthrough disable",
            "config aaa authorization local",
            "config save -y",
        ):
            try:
                duthost.shell(cmd, module_ignore_errors=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning("safety-net cmd '%s' failed: %s", cmd, exc)
        # Drop any RADIUS_SERVER rows that hostcfgd would re-render PAM from.
        try:
            duthost.shell(
                "for k in $(sonic-db-cli CONFIG_DB keys 'RADIUS_SERVER|*'); do "
                "sonic-db-cli CONFIG_DB del \"$k\"; done",
                module_ignore_errors=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("safety-net RADIUS_SERVER purge failed: %s", exc)
    logger.info("RADIUS safety-net: stopping freeradius on PTF")
    try:
        ptfhost.shell(
            "service freeradius stop 2>/dev/null || pkill freeradius 2>/dev/null; "
            "iptables -D INPUT -p udp --dport 1812 -j DROP 2>/dev/null || true",
            module_ignore_errors=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("safety-net PTF cleanup failed: %s", exc)
