"""
Shared utility functions for RADIUS AAA tests.
"""
import base64
import logging
import time
import paramiko

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 3


# ---------------------------------------------------------------------------
# File write helper (avoids shell quoting issues)
# ---------------------------------------------------------------------------

def _write_file_b64(ptfhost, path, content):
    """Write content to path on PTF using base64 — avoids all shell quoting issues."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    ptfhost.shell("echo '{}' | base64 -d > {}".format(encoded, path))


def _freeradius_running(ptfhost):
    """Return True if freeradius is running on PTF."""
    return ptfhost.shell("pgrep freeradius", module_ignore_errors=True)["rc"] == 0


def _write_users_file(ptfhost, users):
    """Write freeradius users/authorize file — auto-detects correct path."""
    content = ""
    for u in users:
        content += '{}\tCleartext-Password := "{}"\n'.format(u["username"], u["password"])
        content += '\tCisco-AVPair = "shell:priv-lvl={}"\n\n'.format(u["priv_lvl"])
    for path in [
        "/etc/freeradius/3.0/mods-config/files/authorize",
        "/etc/freeradius/3.0/users",
        "/etc/freeradius/users",
    ]:
        parent = "/".join(path.split("/")[:-1])
        if ptfhost.shell("test -d {}".format(parent), module_ignore_errors=True)["rc"] == 0:
            _write_file_b64(ptfhost, path, content)
            logger.info("Wrote freeradius users to %s", path)
            return
    raise RuntimeError("Could not find freeradius users path on PTF")


def _radius_del(duthost, server_ip):
    """
    Remove a RADIUS server from DUT. Tries del, delete, then sonic-db-cli fallback.
    Handles different SONiC version syntax differences.
    """
    for cmd in [
        "config radius del {}".format(server_ip),
        "config radius delete {}".format(server_ip),
    ]:
        r = duthost.shell(cmd, module_ignore_errors=True)
        if r["rc"] == 0:
            return
    # Fallback: direct ConfigDB deletion
    duthost.shell(
        'sonic-db-cli CONFIG_DB del "RADIUS_SERVER|{}"'.format(server_ip),
        module_ignore_errors=True)


def _save_local_aaa(duthost):
    """
    Set AAA to local-only and save config.
    Critical — prevents DUT lockout after any framework config reload.
    Tries multiple SONiC CLI syntax variants for authorization/accounting
    since different builds use different keyword forms.
    """
    duthost.shell("config aaa authentication login local", module_ignore_errors=True)
    duthost.shell("config aaa authentication failthrough disable", module_ignore_errors=True)
    duthost.shell("config radius passkey ''", module_ignore_errors=True)

    # Authorization — try without 'login' first (this build), then with
    for cmd in [
        "config aaa authorization local",
        "config aaa authorization login local",
    ]:
        r = duthost.shell(cmd, module_ignore_errors=True)
        if r["rc"] == 0:
            logger.info("AAA authorization reset via: %s", cmd)
            break
    else:
        # Fallback: direct ConfigDB write
        duthost.shell(
            'sonic-db-cli CONFIG_DB hset "AAA|authorization" login local',
            module_ignore_errors=True)
        logger.warning("AAA authorization reset via sonic-db-cli fallback")

    # Accounting — try without 'login' first (this build), then with
    for cmd in [
        "config aaa accounting disable",
        "config aaa accounting login disable",
    ]:
        r = duthost.shell(cmd, module_ignore_errors=True)
        if r["rc"] == 0:
            logger.info("AAA accounting disabled via: %s", cmd)
            break
    else:
        # Fallback: direct ConfigDB write
        duthost.shell(
            'sonic-db-cli CONFIG_DB hset "AAA|accounting" login disable',
            module_ignore_errors=True)
        logger.warning("AAA accounting disabled via sonic-db-cli fallback")

    duthost.shell("config save -y", module_ignore_errors=True)
    logger.info("AAA set to local-only and config saved")


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def ssh_connect_remote(host, username, password, port=22, timeout=DEFAULT_TIMEOUT):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, port=port, username=username, password=password,
                       timeout=timeout, allow_agent=False, look_for_keys=False)
        logger.info("SSH connected: %s@%s", username, host)
        return client
    except Exception as e:
        logger.warning("SSH connect failed: %s@%s — %s", username, host, e)
        return None


def ssh_connect_remote_retry(host, username, password, duthost=None,
                              port=22, retries=DEFAULT_RETRIES, delay=5, timeout=DEFAULT_TIMEOUT):
    for attempt in range(1, retries + 1):
        client = ssh_connect_remote(host, username, password, port=port, timeout=timeout)
        if client:
            return client
        logger.warning("Attempt %d/%d failed, retrying in %ds...", attempt, retries, delay)
        time.sleep(delay)
    logger.error("All %d SSH attempts failed for %s@%s", retries, username, host)
    return None


def ssh_run_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    rc = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    return rc, out, err


def close_ssh(client):
    try:
        if client:
            client.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# DUT configuration helpers
# ---------------------------------------------------------------------------

def configure_dut_radius(duthost, server_ip, passkey="testing123", timeout=5, priority=1):
    """
    Add RADIUS server to DUT and enable AAA.
    Saves clean local config FIRST so any subsequent reload is safe.
    Enables failthrough so RADIUS timeout falls back to local auth.
    """
    _save_local_aaa(duthost)
    # Ensure sonic-launch-shell exists — required for RADIUS JIT user login
    duthost.shell(
        "test -f /usr/bin/sonic-launch-shell || ln -s /bin/bash /usr/bin/sonic-launch-shell",
        module_ignore_errors=True)
    # Set global passkey — SONiC PAM uses global passkey for encryption, not per-server
    duthost.shell("config radius passkey {}".format(passkey), module_ignore_errors=True)
    duthost.shell("config radius add {} -k {} -t {} -p {}".format(
        server_ip, passkey, timeout, priority))
    duthost.shell("config aaa authentication login radius local")
    # Enable failthrough — critical: without this, RADIUS timeout blocks ALL logins
    # including local admin (failthrough=False is the default)
    duthost.shell("config aaa authentication failthrough enable", module_ignore_errors=True)
    logger.info("DUT RADIUS configured: server=%s dut_mgmt_ip=%s", server_ip, duthost.mgmt_ip)


def restore_dut_aaa_config(duthost, server_ip):
    """
    Restore DUT to local-only AAA and SAVE config.
    config save -y is mandatory — prevents DUT lockout after framework reload.
    """
    _radius_del(duthost, server_ip)
    _save_local_aaa(duthost)
    logger.info("DUT AAA fully restored and saved")


# ---------------------------------------------------------------------------
# RADIUS server helpers (PTF)
# ---------------------------------------------------------------------------

def start_radius_server(ptfhost, users, clients, secret="testing123"):
    """
    Write freeradius config and start daemon on PTF.
    Uses base64 file writes and wait_until polling.
    """
    from tests.common.utilities import wait_until

    ptfhost.shell("apt-get install -y freeradius 2>/dev/null || true")
    ptfhost.shell(
        "service freeradius stop 2>/dev/null || pkill freeradius 2>/dev/null; sleep 1",
        module_ignore_errors=True)

    _write_users_file(ptfhost, users)

    clients_content = "client localhost {{\n    ipaddr = 127.0.0.1\n    secret = {}\n}}\n\n".format(secret)
    for c in clients:
        clients_content += "client {} {{\n    ipaddr = {}\n    secret = {}\n}}\n\n".format(
            c["name"], c["ipaddr"], secret)
    for path in ["/etc/freeradius/3.0/clients.conf", "/etc/freeradius/clients.conf"]:
        if ptfhost.shell("test -f {}".format(path), module_ignore_errors=True)["rc"] == 0:
            _write_file_b64(ptfhost, path, clients_content)
            break

    ptfhost.shell(
        "service freeradius start 2>/dev/null || freeradius 2>/dev/null",
        module_ignore_errors=True)

    if not wait_until(30, 2, 0, _freeradius_running, ptfhost):
        log = ptfhost.shell(
            "timeout 5 freeradius -X 2>&1 | tail -30 || true",
            module_ignore_errors=True)["stdout"]
        raise RuntimeError("freeradius failed to start on PTF.\nDebug:\n{}".format(log))
    logger.info("freeradius started on PTF")


def stop_radius_server(ptfhost):
    """Stop freeradius on PTF."""
    ptfhost.shell(
        "service freeradius stop 2>/dev/null || pkill freeradius 2>/dev/null; sleep 1",
        module_ignore_errors=True)
    logger.info("freeradius stopped on PTF")


def block_radius_server(ptfhost):
    """Block UDP 1812 on PTF to simulate server unreachable."""
    ptfhost.shell("iptables -I INPUT -p udp --dport 1812 -j DROP")
    logger.info("Blocked UDP 1812 on PTF")


def unblock_radius_server(ptfhost):
    """Remove UDP 1812 iptables block on PTF."""
    ptfhost.shell("iptables -D INPUT -p udp --dport 1812 -j DROP", module_ignore_errors=True)
    logger.info("Unblocked UDP 1812 on PTF")


def radtest_verify(ptfhost, username, password, server="127.0.0.1", secret="testing123"):
    """Run radtest and return True if Access-Accept received."""
    cmd = "radtest {} {} {} 0 {}".format(username, password, server, secret)
    result = ptfhost.shell(cmd, module_ignore_errors=True)
    return "Access-Accept" in result["stdout"]


# ---------------------------------------------------------------------------
# JIT user helpers
# ---------------------------------------------------------------------------

def user_exists_on_dut(duthost, username):
    result = duthost.shell("getent passwd {}".format(username), module_ignore_errors=True)
    return result["rc"] == 0


def delete_jit_user(duthost, username):
    if user_exists_on_dut(duthost, username):
        duthost.shell("userdel -r {}".format(username), module_ignore_errors=True)
        logger.info("Deleted JIT user: %s", username)


def get_user_groups(duthost, username):
    result = duthost.shell("id -Gn {}".format(username), module_ignore_errors=True)
    if result["rc"] == 0:
        return result["stdout"].strip().split()
    return []


# ---------------------------------------------------------------------------
# Accounting helpers
# ---------------------------------------------------------------------------

def get_acct_log_entries(ptfhost, username):
    result = ptfhost.shell(
        "grep -r '{}' /var/log/freeradius/radacct/ 2>/dev/null || true".format(username),
        module_ignore_errors=True)
    return result["stdout"]
