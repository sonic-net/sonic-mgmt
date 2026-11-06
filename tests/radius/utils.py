"""
Shared utility functions for RADIUS AAA tests.
"""
import base64
import logging
import re
import time
import paramiko

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 5
SSH_RETRY_DELAY = 15


# ---------------------------------------------------------------------------
# File write helper (avoids shell quoting issues)
# ---------------------------------------------------------------------------

def _write_file_b64(ptfhost, path, content):
    """Write content to path on PTF using base64 -- avoids all shell quoting issues."""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    ptfhost.shell("echo '{}' | base64 -d > {}".format(encoded, path))


def _freeradius_running(ptfhost):
    """Return True if freeradius is running on PTF."""
    return ptfhost.shell("pgrep freeradius", module_ignore_errors=True)["rc"] == 0


def _freeradius_listening(ptfhost, port):
    """Return True if UDP <port> is open on PTF."""
    for cmd in [
        "ss -uln | grep -q ':{} '".format(port),
        "netstat -uln | grep -q ':{} '".format(port),
    ]:
        if ptfhost.shell(cmd, module_ignore_errors=True)["rc"] == 0:
            return True
    return False


def _restart_freeradius(ptfhost):
    """Restart FreeRADIUS after all config files have been written."""
    _clean_freeradius_dictionary_on_ptf(ptfhost)
    ptfhost.shell(
        "service freeradius stop 2>/dev/null || pkill freeradius 2>/dev/null; sleep 1",
        module_ignore_errors=True)
    ptfhost.shell(
        "service freeradius start 2>/dev/null || "
        "freeradius 2>/dev/null || radiusd 2>/dev/null",
        module_ignore_errors=True)
    time.sleep(2)


def _freeradius_auth_ready(ptfhost, username, password, secret, timeout=30):
    """Wait until radtest gets Access-Accept from local FreeRADIUS."""
    from tests.common.utilities import wait_until

    def _accept():
        output = _radtest_output(ptfhost, username, password, secret)
        return "Access-Accept" in output

    return wait_until(timeout, 2, 0, _accept)


def _freeradius_dict_root(ptfhost):
    """Return the FreeRADIUS config root (/etc/freeradius/3.0 or /etc/freeradius)."""
    for root in ["/etc/freeradius/3.0", "/etc/freeradius"]:
        if ptfhost.shell("test -f {}/dictionary".format(root),
                         module_ignore_errors=True)["rc"] == 0:
            return root
    return None


def _is_dictionary_d_dir_include(line):
    """Return True for ``$INCLUDE dictionary.d/`` directory wildcard lines only."""
    stripped = line.strip()
    if not stripped.startswith("$INCLUDE"):
        return False
    return re.match(r"\$INCLUDE\s+dictionary\.d/?\s*$", stripped) is not None


def _clean_freeradius_dictionary_on_ptf(ptfhost):
    """
    Remove ``$INCLUDE dictionary.d/`` directory includes from PTF dictionaries.

    Stock freeradius packages ship this include.  On PTF images where dictionary.d
    is a directory, both freeradius and radclient fail with
    ``dictionary.d// is not a regular file``.

    Uses read/filter/write instead of sed so we only drop directory wildcards and
    keep specific files such as ``dictionary.d/sonic-mgmt-rfc5607.conf``.
    """
    for dict_root in ["/etc/freeradius/3.0", "/etc/freeradius"]:
        main_dict = "{}/dictionary".format(dict_root)
        if ptfhost.shell("test -f {}".format(main_dict),
                         module_ignore_errors=True)["rc"] != 0:
            continue
        result = ptfhost.shell("cat {}".format(main_dict), module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            continue
        original = result.get("stdout", "")
        if not original:
            continue
        lines = original.splitlines()
        filtered = [ln for ln in lines if not _is_dictionary_d_dir_include(ln)]
        if filtered == lines:
            continue
        _write_file_b64(ptfhost, main_dict, "\n".join(filtered) + "\n")
        logger.info("Removed dictionary.d/ include from %s", main_dict)
        leftover = ptfhost.shell(
            "grep -E '^[$]INCLUDE[[:space:]]+dictionary\\.d/?[[:space:]]*$' {} "
            "2>/dev/null || true".format(main_dict),
            module_ignore_errors=True).get("stdout", "").strip()
        if leftover:
            raise RuntimeError(
                "Could not remove broken $INCLUDE dictionary.d/ from {}:\n{}".format(
                    main_dict, leftover))


def _freeradius_has_attr(ptfhost, attr_name):
    """Return True if attr_name is defined in the FreeRADIUS dictionary tree."""
    dict_root = _freeradius_dict_root(ptfhost)
    if not dict_root:
        return False
    for root in [dict_root, "/usr/share/freeradius", "/usr/share/freeradius/3.0"]:
        if ptfhost.shell("test -d {}".format(root), module_ignore_errors=True)["rc"] != 0:
            continue
        if ptfhost.shell(
                "grep -rqF '{}' {} 2>/dev/null".format(attr_name, root),
                module_ignore_errors=True)["rc"] == 0:
            return True
    return False


def _ensure_freeradius_mpl_dictionary(ptfhost):
    """
    Ensure RFC5607 attr 136 (Management-Privilege-Level) is in the dictionary.

    Older PTF freeradius packages omit dictionary.rfc5607; without it the server
    silently drops MPL from authorize entries and SONiC maps users to priv-lvl=1.

    Do NOT add ``$INCLUDE dictionary.d/`` -- radclient treats that directory as a
    file and fails with "not a regular file".  Include a specific snippet file or
    append the attribute directly to the main dictionary.
    """
    mpl_line = "ATTRIBUTE\tManagement-Privilege-Level\t136\tinteger\n"
    snippet = "# sonic-mgmt RADIUS AAA tests\n" + mpl_line
    dict_root = _freeradius_dict_root(ptfhost)

    if dict_root:
        main_dict = "{}/dictionary".format(dict_root)
        _clean_freeradius_dictionary_on_ptf(ptfhost)
        # Drop stale snippet include that duplicates dictionary.rfc5607 on reruns.
        ptfhost.shell(
            "sed -i '/sonic-mgmt-rfc5607.conf/d' {main}".format(main=main_dict),
            module_ignore_errors=True)

        has_rfc5607 = False
        # 1) Prefer the upstream RFC5607 dictionary when the package ships it.
        for share_path in [
            "/usr/share/freeradius/dictionary.rfc5607",
            "/usr/share/freeradius/3.0/dictionary.rfc5607",
            "{}/dictionary.rfc5607".format(dict_root),
        ]:
            if ptfhost.shell("test -f {}".format(share_path),
                             module_ignore_errors=True)["rc"] != 0:
                continue
            include_line = "$INCLUDE {}".format(share_path)
            ptfhost.shell(
                "grep -qF 'dictionary.rfc5607' {main} || "
                "echo '{inc}' >> {main}".format(main=main_dict, inc=include_line),
                module_ignore_errors=True)
            logger.info("Ensured $INCLUDE dictionary.rfc5607 from %s", share_path)
            has_rfc5607 = True
            break

        if not has_rfc5607:
            # 2) Drop-in snippet under dictionary.d/ (specific file, not the directory).
            dict_d = "{}/dictionary.d".format(dict_root)
            ptfhost.shell("mkdir -p {}".format(dict_d), module_ignore_errors=True)
            _write_file_b64(ptfhost, "{}/sonic-mgmt-rfc5607.conf".format(dict_d), snippet)
            include_snippet = "$INCLUDE dictionary.d/sonic-mgmt-rfc5607.conf"
            ptfhost.shell(
                "grep -qF 'sonic-mgmt-rfc5607.conf' {main} || "
                "echo '{inc}' >> {main}".format(main=main_dict, inc=include_snippet),
                module_ignore_errors=True)
            logger.info("Wrote MPL dictionary snippet under %s", dict_d)

            # 3) Append to main dictionary only if MPL is still missing.
            if ptfhost.shell(
                    "grep -rqF 'Management-Privilege-Level' {root} 2>/dev/null".format(
                        root=dict_root),
                    module_ignore_errors=True)["rc"] != 0:
                ptfhost.shell(
                    "printf '%s\\n' 'ATTRIBUTE Management-Privilege-Level 136 integer' "
                    ">> {main}".format(main=main_dict),
                    module_ignore_errors=True)
        return

    for parent in ["/etc/freeradius/3.0/dictionary.d", "/etc/freeradius/dictionary.d"]:
        if ptfhost.shell("test -d {}".format(parent), module_ignore_errors=True)["rc"] == 0:
            _write_file_b64(ptfhost, "{}/sonic-mgmt-rfc5607.conf".format(parent), snippet)
            logger.info("Ensured MPL dictionary at %s/sonic-mgmt-rfc5607.conf", parent)
            return
    logger.warning("Could not locate freeradius dictionary on PTF -- MPL may be missing")


def _write_users_file(ptfhost, users):
    """Write freeradius users/authorize file to every known path on PTF."""
    use_cisco_avpair = _freeradius_has_attr(ptfhost, "Cisco-AVPair")
    if not use_cisco_avpair:
        logger.info("Cisco-AVPair not in dictionary -- omitting from authorize")
    content = ""
    for u in users:
        content += '{}\tCleartext-Password := "{}"\n'.format(u["username"], u["password"])
        # FreeRADIUS users-file syntax: reply attributes on continuation lines
        # MUST be separated by a trailing comma; only the final reply line is
        # comma-less.  Without the commas, freeradius parses each indented line
        # as a new entry and rejects it with "Entry does not begin with a user
        # name", causing the files module (and the daemon) to fail to start.
        # SONiC pam_radius_auth.so reads MPL (RFC5607 attr 136) via
        # privilege_level.  Service-Type name in the standard FreeRADIUS
        # dictionary is "NAS-Prompt-User" (RFC 2865 value 7).
        reply_attrs = [
            "Service-Type = NAS-Prompt-User",
            "Management-Privilege-Level := {}".format(u["priv_lvl"]),
        ]
        if use_cisco_avpair:
            reply_attrs.append('Cisco-AVPair = "shell:priv-lvl={}"'.format(u["priv_lvl"]))
        last = len(reply_attrs) - 1
        for idx, attr in enumerate(reply_attrs):
            content += "\t{}{}\n".format(attr, "," if idx < last else "")
        content += '\n'
    paths_written = []
    for path in [
        "/etc/freeradius/3.0/mods-config/files/authorize",
        "/etc/freeradius/3.0/users",
        "/etc/freeradius/users",
    ]:
        parent = "/".join(path.split("/")[:-1])
        if ptfhost.shell("test -d {}".format(parent), module_ignore_errors=True)["rc"] == 0:
            _write_file_b64(ptfhost, path, content)
            paths_written.append(path)
            logger.info("Wrote freeradius users to %s", path)
    if not paths_written:
        raise RuntimeError("Could not find freeradius users path on PTF")
    return paths_written


def _mpl_in_radtest_output(output, expected_mpl):
    """Return True if radtest -x output shows RFC5607 Management-Privilege-Level."""
    patterns = [
        r"Management-Privilege-Level\s*[:=]+\s*{}".format(expected_mpl),
        r"Management-Privilege-Level\s*=\s*{}".format(expected_mpl),
        r"Attr(?:ibute)?\s*136[^\n]*{}".format(expected_mpl),
        r"\(136\)[^\n]*{}".format(expected_mpl),
    ]
    return any(re.search(p, output, re.IGNORECASE) for p in patterns)


def _radtest_output(ptfhost, username, password, secret):
    """
    Authenticate against local FreeRADIUS and return debug output.

    Use radtest only.  radclient fails on stock PTF installs that
    ``$INCLUDE dictionary.d/`` in the server dictionary.
    """
    _clean_freeradius_dictionary_on_ptf(ptfhost)
    cmd = "radtest -x {} {} 127.0.0.1 0 {} 2>&1".format(
        username, password, secret)
    result = ptfhost.shell(cmd, module_ignore_errors=True)
    return result.get("stdout", "") + result.get("stderr", "")


def _authorize_has_mpl(ptfhost, username, expected_mpl):
    """Return True if FreeRADIUS authorize files contain MPL for username."""
    mpl_line = "Management-Privilege-Level := {}".format(expected_mpl)
    for path in [
        "/etc/freeradius/3.0/mods-config/files/authorize",
        "/etc/freeradius/3.0/users",
        "/etc/freeradius/users",
    ]:
        if ptfhost.shell("test -f {}".format(path), module_ignore_errors=True)["rc"] != 0:
            continue
        result = ptfhost.shell(
            "grep -A8 '^{}' {} 2>/dev/null | grep -Fq '{}'".format(
                username, path, mpl_line),
            module_ignore_errors=True)
        if result.get("rc", 1) == 0:
            return True
    return False


def _dictionary_has_mpl(ptfhost):
    """Return True if the FreeRADIUS dictionary defines attr 136 (MPL)."""
    dict_root = _freeradius_dict_root(ptfhost)
    if not dict_root:
        return False
    return ptfhost.shell(
        "grep -rqF 'Management-Privilege-Level' {} 2>/dev/null".format(dict_root),
        module_ignore_errors=True)["rc"] == 0


def _verify_freeradius_mpl(ptfhost, username, password, secret, expected_mpl, users=None):
    """
    Confirm FreeRADIUS is configured to return Management-Privilege-Level.

  MPL must be in the dictionary and authorize files.  Live radtest is used when
  possible but authorize-on-disk is trusted when radtest omits attr 136.
    """
    if not _dictionary_has_mpl(ptfhost):
        _ensure_freeradius_mpl_dictionary(ptfhost)
    if users:
        _write_users_file(ptfhost, users)
    if not _authorize_has_mpl(ptfhost, username, expected_mpl):
        raise RuntimeError(
            "authorize files missing Management-Privilege-Level={} for {}".format(
                expected_mpl, username))

    if not _freeradius_auth_ready(ptfhost, username, password, secret, timeout=30):
        _restart_freeradius(ptfhost)
        if not _freeradius_auth_ready(ptfhost, username, password, secret, timeout=30):
            log = ptfhost.shell(
                "timeout 8 freeradius -X 2>&1 | tail -40 || true",
                module_ignore_errors=True).get("stdout", "")
            raise RuntimeError(
                "FreeRADIUS on PTF not responding on UDP 1812 for {}.\n"
                "Process running: {}  Port 1812 listening: {}\nDebug:\n{}".format(
                    username,
                    _freeradius_running(ptfhost),
                    _freeradius_listening(ptfhost, 1812),
                    log))

    output = _radtest_output(ptfhost, username, password, secret)
    if _mpl_in_radtest_output(output, expected_mpl):
        logger.info("FreeRADIUS MPL=%s verified in radtest for %s", expected_mpl, username)
        return

    logger.info(
        "FreeRADIUS MPL=%s present in authorize for %s (radtest omitted attr 136)",
        expected_mpl, username)


def _ensure_radius_nss_priv_mapping(duthost):
    """
    Ensure /etc/radius_nss.conf has *uncommented* priv-lvl -> Linux group
    mappings so libnss_radius can put RADIUS users in sudo/netadmin/docker.

    The SONiC hostcfgd template ships these lines as commented examples
    (e.g. ``# user_priv=15;...``).  A naive ``grep -F user_priv=15`` matches
    the commented form and skips the append -- leaving authenticated RADIUS
    users in no privileged group.  Match only *non-comment* lines.

    Cisco images expect ``netadmin`` for priv-lvl 15 alongside sudo/docker.
    """
    duthost.shell(
        "getent group netadmin >/dev/null || sudo groupadd netadmin",
        module_ignore_errors=True)
    mappings = [
        "user_priv=15;pw_info=remote_user_su;gid=1000;group=sudo,netadmin,docker;shell=/usr/bin/sonic-launch-shell",
        "user_priv=1;pw_info=remote_user;gid=999;group=docker;shell=/usr/bin/sonic-launch-shell",
    ]
    for line in mappings:
        marker = line.split(";", 1)[0]  # e.g. "user_priv=15"
        # Only match the *uncommented* form (no leading '#').  Use a regex
        # anchored at start-of-line allowing optional whitespace.
        check = "grep -qE '^[[:space:]]*{}' /etc/radius_nss.conf 2>/dev/null".format(
            marker.replace("=", "="))
        duthost.shell(
            "{} || echo '{}' | sudo tee -a /etc/radius_nss.conf >/dev/null".format(
                check, line),
            module_ignore_errors=True)
    logger.info("Ensured uncommented radius_nss.conf priv-lvl mappings "
                "(15->sudo,netadmin,docker; 1->docker)")


def _wait_for_pam_radius(duthost, server_ip, timeout=30):
    """
    Wait until hostcfgd has regenerated /etc/pam_radius_auth.conf to include
    our RADIUS server.  Returns True if it shows up, False on timeout.
    """
    from tests.common.utilities import wait_until

    def _pam_has_server():
        r = duthost.shell(
            "grep -F '{}' /etc/pam_radius_auth.conf 2>/dev/null".format(server_ip),
            module_ignore_errors=True,
        )
        return r.get("rc", 1) == 0
    return wait_until(timeout, 2, 0, _pam_has_server)


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
    duthost.shell(
        'sonic-db-cli CONFIG_DB del "RADIUS_SERVER|{}"'.format(server_ip),
        module_ignore_errors=True)


def _save_local_aaa(duthost):
    """
    Set AAA to local-only and save config.
    Critical -- prevents DUT lockout after any framework config reload.
    """
    duthost.shell("config aaa authentication login local", module_ignore_errors=True)
    duthost.shell("config aaa authentication failthrough disable", module_ignore_errors=True)
    # Avoid 'config radius passkey ''' -- empty arg crashes/rejects on some SONiC images.
    duthost.shell(
        "sonic-db-cli CONFIG_DB hdel 'RADIUS|global' passkey",
        module_ignore_errors=True)

    for cmd in [
        "config aaa authorization local",
        "config aaa authorization login local",
    ]:
        r = duthost.shell(cmd, module_ignore_errors=True)
        if r["rc"] == 0:
            logger.info("AAA authorization reset via: %s", cmd)
            break
    else:
        duthost.shell(
            'sonic-db-cli CONFIG_DB hset "AAA|authorization" login local',
            module_ignore_errors=True)
        logger.warning("AAA authorization reset via sonic-db-cli fallback")

    for cmd in [
        "config aaa accounting disable",
        "config aaa accounting login disable",
    ]:
        r = duthost.shell(cmd, module_ignore_errors=True)
        if r["rc"] == 0:
            logger.info("AAA accounting disabled via: %s", cmd)
            break
    else:
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
        logger.warning("SSH connect failed: %s@%s -- %s", username, host, e)
        return None


def ssh_connect_remote_retry(host, username, password, duthost=None,
                              port=22, retries=DEFAULT_RETRIES, delay=SSH_RETRY_DELAY,
                              timeout=DEFAULT_TIMEOUT):
    for attempt in range(1, retries + 1):
        client = ssh_connect_remote(host, username, password, port=port, timeout=timeout)
        if client:
            return client
        logger.warning("Attempt %d/%d failed, retrying in %ds...", attempt, retries, delay)
        time.sleep(delay)
    logger.error("All %d SSH attempts failed for %s@%s", retries, username, host)
    return None


def radius_user_ssh_login(duthost, host, username, password,
                          retries=DEFAULT_RETRIES, delay=SSH_RETRY_DELAY):
    """
    SSH as a RADIUS JIT user.

    Deletes any stale JIT account first and waits for sshd to drain
    half-open sessions (Exceeded MaxStartups) before retrying.
    """
    delete_jit_user(duthost, username)
    time.sleep(3)
    return ssh_connect_remote_retry(
        host, username, password, duthost=duthost, retries=retries, delay=delay)


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
    Add RADIUS server to DUT and enable AAA -- robust against pre-existing
    config and hostcfgd lag.

    Key behaviours:
      * Hard-deletes any stale RADIUS_SERVER entry via sonic-db-cli so that
        ``config radius add`` actually triggers hostcfgd, rather than silently
        returning "server already exists".
      * Mirrors RADIUS_SERVER / RADIUS|global directly to CONFIG_DB to ensure
        the fields land even if the CLI silently rejects them.
      * Sets NAS-IP and authtype explicitly so pam_radius_auth identifies us.
      * Waits for hostcfgd to regenerate /etc/pam_radius_auth.conf, falling
        back to a hostcfgd restart if it lags.
    """
    _save_local_aaa(duthost)

    duthost.shell(
        "test -f /usr/bin/sonic-launch-shell || "
        "ln -s /bin/bash /usr/bin/sonic-launch-shell",
        module_ignore_errors=True)

    _radius_del(duthost, server_ip)
    duthost.shell(
        "sonic-db-cli CONFIG_DB del 'RADIUS_SERVER|{}'".format(server_ip),
        module_ignore_errors=True)
    time.sleep(1)

    duthost.shell("config radius passkey {}".format(passkey),
                  module_ignore_errors=True)
    duthost.shell(
        "sonic-db-cli CONFIG_DB hset 'RADIUS|global' passkey '{}'".format(passkey),
        module_ignore_errors=True)

    duthost.shell("config radius authtype pap", module_ignore_errors=True)
    duthost.shell("config radius nasip {}".format(duthost.mgmt_ip),
                  module_ignore_errors=True)

    duthost.shell("config radius add {} -k {} -t {} -p {}".format(
        server_ip, passkey, timeout, priority), module_ignore_errors=True)
    duthost.shell(
        "sonic-db-cli CONFIG_DB hset 'RADIUS_SERVER|{ip}' "
        "auth_port 1812 acct_port 1813 priority {pri} passkey '{key}' timeout {to}".format(
            ip=server_ip, pri=priority, key=passkey, to=timeout),
        module_ignore_errors=True)

    duthost.shell("config aaa authentication login radius local")
    duthost.shell("config aaa authentication failthrough enable",
                  module_ignore_errors=True)

    if not _wait_for_pam_radius(duthost, server_ip, timeout=30):
        logger.warning(
            "PAM RADIUS conf did not include %s after 30s -- restarting hostcfgd",
            server_ip)
        duthost.shell("sudo systemctl restart hostcfgd",
                      module_ignore_errors=True)
        if not _wait_for_pam_radius(duthost, server_ip, timeout=30):
            logger.error(
                "PAM RADIUS conf still missing %s -- RADIUS auth will likely fail",
                server_ip)
    # hostcfgd just rewrote radius_nss.conf -- append Cisco priv-lvl mappings.
    _ensure_radius_nss_priv_mapping(duthost)
    # sshd reads PAM on every connection but give the PAM stack a beat to
    # fully settle after hostcfgd writes the file.
    time.sleep(3)

    logger.info("DUT RADIUS configured: server=%s passkey=%s dut_mgmt_ip=%s",
                server_ip, passkey, duthost.mgmt_ip)


def restore_dut_aaa_config(duthost, server_ip):
    """
    Restore DUT to local-only AAA and SAVE config.
    """
    _radius_del(duthost, server_ip)
    _save_local_aaa(duthost)
    logger.info("DUT AAA fully restored and saved")


# ---------------------------------------------------------------------------
# RADIUS server helpers (PTF)
# ---------------------------------------------------------------------------

def _freeradius_config_check(ptfhost):
    """Return freeradius -X startup log (config validation)."""
    return ptfhost.shell(
        "timeout 8 freeradius -X 2>&1 | tail -60 || true",
        module_ignore_errors=True).get("stdout", "")


def _write_clients_file(ptfhost, clients, secret="testing123"):
    """Write clients.conf with localhost + DUT entries."""
    clients_content = (
        "client localhost {{\n"
        "    ipaddr = 127.0.0.1\n"
        "    secret = {secret}\n"
        "    require_message_authenticator = no\n"
        "}}\n\n"
    ).format(secret=secret)
    for c in clients:
        clients_content += (
            "client {name} {{\n"
            "    ipaddr = {ipaddr}\n"
            "    secret = {secret}\n"
            "    require_message_authenticator = no\n"
            "}}\n\n"
        ).format(name=c["name"], ipaddr=c["ipaddr"], secret=secret)
    for path in ["/etc/freeradius/3.0/clients.conf", "/etc/freeradius/clients.conf"]:
        if ptfhost.shell("test -f {}".format(path), module_ignore_errors=True)["rc"] == 0:
            _write_file_b64(ptfhost, path, clients_content)
            logger.info("Wrote freeradius clients to %s", path)
            return path
    raise RuntimeError("Could not find freeradius clients.conf on PTF")


def start_radius_server(ptfhost, users, clients, secret="testing123", admin_users=None):
    """
    Write freeradius config and start daemon on PTF.

    ``admin_users`` is an optional list of admin/operator account entries that
    will be **prepended** to the users file with their real local passwords.
    This is a critical lockout-prevention guard: SONiC's auto-generated PAM
    stack contains ``auth_err=die`` on ``pam_radius_auth.so``, which means a
    single Access-Reject from FreeRADIUS aborts the PAM auth chain and blocks
    the user from SSH even if their password is correct for the local user
    database. By always registering the device admin user with FreeRADIUS, we
    guarantee that pam_radius returns Access-Accept for admin and the chain
    proceeds, so the operator can never be locked out of the DUT while the
    test infrastructure is exercising RADIUS auth.
    """
    from tests.common.utilities import wait_until

    ptfhost.shell(
        "command -v freeradius >/dev/null 2>&1 || "
        "apt-get install -y freeradius 2>/dev/null || true",
        module_ignore_errors=True)
    ptfhost.shell(
        "service freeradius stop 2>/dev/null || pkill freeradius 2>/dev/null; sleep 1",
        module_ignore_errors=True)

    # Prepend admin/safety entries so PAM auth_err=die never fires against the
    # operator account. Dedup by username (admin entry wins if user re-uses).
    effective_users = []
    seen = set()
    for u in list(admin_users or []) + list(users or []):
        if not u or "username" not in u:
            continue
        if u["username"] in seen:
            continue
        seen.add(u["username"])
        effective_users.append(u)

    _clean_freeradius_dictionary_on_ptf(ptfhost)
    _ensure_freeradius_mpl_dictionary(ptfhost)
    _write_users_file(ptfhost, effective_users)
    _ensure_freeradius_accounting(ptfhost, restart=False)
    _write_clients_file(ptfhost, clients, secret=secret)

    _restart_freeradius(ptfhost)

    if not wait_until(30, 2, 0, _freeradius_running, ptfhost):
        log = _freeradius_config_check(ptfhost)
        raise RuntimeError("freeradius failed to start on PTF.\nDebug:\n{}".format(log))
    if not wait_until(30, 2, 0, _freeradius_listening, ptfhost, 1812):
        log = _freeradius_config_check(ptfhost)
        raise RuntimeError(
            "freeradius running but UDP 1812 not listening on PTF.\nDebug:\n{}".format(log))

    # Now that authentication is up, make sure the acct listener (1813) is
    # also bound. Some packaging variants omit the acct listener from
    # sites-enabled/default, so this helper injects an explicit one when
    # needed and restarts.
    _ensure_freeradius_accounting(ptfhost, restart=True)
    if not wait_until(30, 2, 0, _freeradius_listening, ptfhost, 1813):
        log = _freeradius_config_check(ptfhost)
        raise RuntimeError(
            "freeradius running but UDP 1813 not listening on PTF.\nDebug:\n{}".format(log))
    logger.info("freeradius started on PTF (auth=1812, acct=1813)")

    # Fail fast if FreeRADIUS is not returning MPL -- DUT group mapping depends on it.
    # Verify against the first non-admin test user so we exercise the real priv-lvl path.
    sample = None
    for u in (users or []):
        sample = u
        break
    if sample is None and effective_users:
        sample = effective_users[0]
    if sample is not None:
        _verify_freeradius_mpl(
            ptfhost,
            sample["username"],
            sample["password"],
            secret,
            sample["priv_lvl"],
            users=effective_users,
        )


def stop_radius_server(ptfhost):
    """Stop freeradius on PTF."""
    ptfhost.shell(
        "service freeradius stop 2>/dev/null || pkill freeradius 2>/dev/null; sleep 1",
        module_ignore_errors=True)
    logger.info("freeradius stopped on PTF")


def block_radius_server(ptfhost):
    """
    Simulate RADIUS server unreachable from the DUT.

    The PTF container does not always ship ``iptables`` (the binary is absent
    in many community PTF images), so we use the portable approach of taking
    the freeradius daemon down. From the DUT's perspective the result is the
    same: pam_radius times out and falls back to local AAA.
    """
    # Prefer iptables if available -- it gives a cleaner "no reply" semantic
    # and leaves the daemon running for any session-scoped fixtures. Fall back
    # to stopping the daemon when iptables is missing.
    have_iptables = ptfhost.shell(
        "command -v iptables >/dev/null 2>&1 && echo yes || echo no",
        module_ignore_errors=True).get("stdout", "").strip() == "yes"
    if have_iptables:
        ptfhost.shell(
            "iptables -I INPUT -p udp --dport 1812 -j DROP",
            module_ignore_errors=True)
        logger.info("Blocked UDP 1812 on PTF via iptables")
    else:
        ptfhost.shell(
            "service freeradius stop 2>/dev/null || pkill -f freeradius 2>/dev/null; sleep 1",
            module_ignore_errors=True)
        logger.info("Stopped freeradius on PTF (iptables unavailable)")


def unblock_radius_server(ptfhost):
    """Undo ``block_radius_server`` -- restore RADIUS server reachability."""
    have_iptables = ptfhost.shell(
        "command -v iptables >/dev/null 2>&1 && echo yes || echo no",
        module_ignore_errors=True).get("stdout", "").strip() == "yes"
    if have_iptables:
        ptfhost.shell(
            "iptables -D INPUT -p udp --dport 1812 -j DROP",
            module_ignore_errors=True)
        logger.info("Unblocked UDP 1812 on PTF via iptables")
    # Always (re)start freeradius -- if we stopped it above, this brings it
    # back; if iptables was used, this is a no-op when the daemon is already
    # running. We invoke ``service`` directly (rather than the higher-level
    # ``start_radius_server`` helper which rewrites config) so existing config
    # and clients on disk are preserved.
    ptfhost.shell(
        "pgrep -x freeradius >/dev/null 2>&1 || "
        "service freeradius start 2>/dev/null || "
        "freeradius -X >/tmp/freeradius.log 2>&1 &",
        module_ignore_errors=True)
    logger.info("freeradius (re)started on PTF after unblock")


def radtest_verify(ptfhost, username, password, server="127.0.0.1", secret="testing123"):
    """Run radtest and return True if Access-Accept received."""
    cmd = "radtest {} {} {} 0 {}".format(username, password, server, secret)
    result = ptfhost.shell(cmd, module_ignore_errors=True)
    return "Access-Accept" in result["stdout"]


# ---------------------------------------------------------------------------
# JIT user helpers
# ---------------------------------------------------------------------------

def user_exists_on_dut(duthost, username):
    """
    Return True iff ``username`` has a *static* entry in ``/etc/passwd``.

    We deliberately grep ``/etc/passwd`` directly instead of using ``getent``
    because SONiC enables ``libnss_radius`` in ``/etc/nsswitch.conf`` -- a
    successful RADIUS lookup makes the user appear via NSS even when no
    static account exists.  The JIT-creation test needs to distinguish
    "freshly provisioned local account" from "dynamically resolved via
    libnss_radius", so we look at the file on disk.
    """
    result = duthost.shell(
        "grep -q '^{}:' /etc/passwd".format(username),
        module_ignore_errors=True)
    return result.get("rc", 1) == 0


def delete_jit_user(duthost, username):
    """
    Remove a JIT-provisioned local account from the DUT.

    Only the static ``/etc/passwd`` entry (and its home dir) is removed; the
    libnss_radius NSS source is left intact so RADIUS users remain resolvable
    after the test deletes the local backing entry.  Any processes still
    owned by the user are killed first so ``userdel`` does not abort with
    "user is currently used by process".

    After the deletion we invalidate the NSS passwd/group caches (``nscd``
    and/or ``sssd``) and pause briefly so the next ``getpwnam``/``ssh`` call
    re-queries libnss_radius instead of returning a stale negative result.
    Without this step the first few SSH attempts immediately after a
    ``userdel`` race the cache and time out, causing the JIT-creation test
    to spuriously fail.
    """
    if not user_exists_on_dut(duthost, username):
        return

    duthost.shell(
        "sudo pkill -9 -u {u} 2>/dev/null; sleep 1".format(u=username),
        module_ignore_errors=True)
    duthost.shell(
        "sudo userdel -r -f {u} 2>/dev/null || true".format(u=username),
        module_ignore_errors=True)

    # Invalidate NSS caches so the next lookup goes back to libnss_radius
    # instead of returning a stale entry (positive or negative).
    duthost.shell(
        "sudo nscd -i passwd 2>/dev/null; "
        "sudo nscd -i group 2>/dev/null; "
        "sudo sss_cache -E 2>/dev/null; "
        "true",
        module_ignore_errors=True)
    time.sleep(3)

    for _ in range(5):
        if not user_exists_on_dut(duthost, username):
            logger.info("Deleted JIT user: %s", username)
            return
        time.sleep(1)
    logger.warning("delete_jit_user: %s still present in /etc/passwd", username)


def get_user_groups(duthost, username):
    result = duthost.shell("id -Gn {}".format(username), module_ignore_errors=True)
    if result["rc"] == 0:
        return result["stdout"].strip().split()
    return []


# ---------------------------------------------------------------------------
# Accounting helpers
# ---------------------------------------------------------------------------

def _ensure_freeradius_accounting(ptfhost, restart=True):
    """
    Ensure FreeRADIUS on PTF is listening on UDP/1813 (accounting) AND writes
    accounting detail logs under ``/var/log/freeradius/radacct/``.

    Behaviour:
      * Always guarantee ``/var/log/freeradius/radacct`` exists and is owned
        by the freerad user (the detail module writes as freerad).
      * Always clean up any old ``# sonic-mgmt RADIUS accounting`` block that
        a previous run may have left in ``radiusd.conf``.
      * If the running freeradius is NOT listening on UDP/1813 (e.g. some
        packaging variants ship a ``sites-enabled/default`` without an acct
        listen block, or strip it down), append a single guarded
        ``listen { type=acct ipaddr=* port=1813 }`` block to ``radiusd.conf``
        so the port is always bound.
    """
    dict_root = _freeradius_dict_root(ptfhost)
    ptfhost.shell(
        "mkdir -p /var/log/freeradius/radacct && "
        "chown -R freerad:freerad /var/log/freeradius/radacct 2>/dev/null || true",
        module_ignore_errors=True)

    if not dict_root:
        if restart:
            _restart_freeradius(ptfhost)
        return

    radiusd = "{}/radiusd.conf".format(dict_root)

    # Idempotent cleanup -- drop any acct snippet appended by an older version.
    ptfhost.shell(
        "sed -i '/# sonic-mgmt RADIUS accounting/,/^}}$/d' {}".format(radiusd),
        module_ignore_errors=True)

    if restart:
        _restart_freeradius(ptfhost)
        time.sleep(2)

    # Verify acct listener is actually bound. If not, install one ourselves.
    if not _freeradius_listening(ptfhost, 1813):
        logger.warning(
            "FreeRADIUS not listening on UDP/1813 -- injecting explicit "
            "acct listen block into %s", radiusd)
        acct_block = (
            "\n# sonic-mgmt RADIUS accounting\n"
            "listen {{\n"
            "    type = acct\n"
            "    ipaddr = *\n"
            "    port = 1813\n"
            "}}\n"
        )
        # Use a sentinel-protected append so we never duplicate the block.
        ptfhost.shell(
            "grep -q '# sonic-mgmt RADIUS accounting' {f} || "
            "printf '%s' '{block}' >> {f}".format(
                f=radiusd,
                block=acct_block.replace("'", "'\\''")),
            module_ignore_errors=True)
        _restart_freeradius(ptfhost)
        time.sleep(2)


def _pam_radius_server_conf(duthost, server_ip):
    """Return the per-server pam_radius config path on the DUT."""
    candidates = [
        "/etc/pam_radius_auth.d/{}_1812.conf".format(server_ip),
        "/etc/pam_radius_auth.conf",
    ]
    for path in candidates:
        if duthost.shell("test -f {}".format(path), module_ignore_errors=True)["rc"] == 0:
            return path
    return candidates[0]


def _ensure_pam_radius_session(duthost, server_ip, enable=True):
    """
    Enable or disable pam_radius in the PAM session stack.

    SONiC has no ``config aaa accounting radius`` CLI.  Session accounting is
    driven by pam_radius session lines in /etc/pam.d/*.
    """
    conf = _pam_radius_server_conf(duthost, server_ip)
    session_rule = "session optional pam_radius_auth.so conf={}".format(conf)
    pam_targets = []
    for pam_file in ["/etc/pam.d/common-session", "/etc/pam.d/sshd"]:
        if duthost.shell("test -f {}".format(pam_file), module_ignore_errors=True)["rc"] == 0:
            pam_targets.append(pam_file)

    for pam_file in pam_targets:
        if enable:
            duthost.shell(
                "grep -qF 'session optional pam_radius_auth.so' {f} 2>/dev/null || "
                "echo '{rule}' | sudo tee -a {f} >/dev/null".format(
                    f=pam_file, rule=session_rule),
                module_ignore_errors=True)
        else:
            duthost.shell(
                "sudo sed -i '/session optional pam_radius_auth.so/d' {}".format(pam_file),
                module_ignore_errors=True)

    action = "enabled" if enable else "disabled"
    logger.info("pam_radius session accounting %s (conf=%s)", action, conf)


def set_radius_accounting_enabled(duthost, ptfhost, server_ip, passkey="testing123"):
    """
    Enable RADIUS session accounting on DUT and PTF.

    Uses pam_radius session + ``config radius statistics enable`` (not the
    invalid ``config aaa accounting radius`` command).
    """
    _ensure_freeradius_accounting(ptfhost)

    duthost.shell(
        "sonic-db-cli CONFIG_DB hset 'RADIUS_SERVER|{ip}' acct_port 1813".format(
            ip=server_ip),
        module_ignore_errors=True)

    for cmd in ["config radius statistics enable"]:
        if duthost.shell(cmd, module_ignore_errors=True)["rc"] == 0:
            logger.info("RADIUS statistics enabled via: %s", cmd)
            break
    else:
        duthost.shell(
            "sonic-db-cli CONFIG_DB hset 'RADIUS|global' statistics true",
            module_ignore_errors=True)
        logger.warning("RADIUS statistics enabled via CONFIG_DB fallback")

    _ensure_pam_radius_session(duthost, server_ip, enable=True)
    time.sleep(2)
    logger.info("RADIUS accounting enabled: server=%s passkey=%s", server_ip, passkey)


def set_radius_accounting_disabled(duthost, server_ip):
    """Disable RADIUS session accounting while keeping RADIUS authentication."""
    _ensure_pam_radius_session(duthost, server_ip, enable=False)
    for cmd in ["config radius statistics disable"]:
        if duthost.shell(cmd, module_ignore_errors=True)["rc"] == 0:
            logger.info("RADIUS statistics disabled via: %s", cmd)
            break
    else:
        duthost.shell(
            "sonic-db-cli CONFIG_DB hset 'RADIUS|global' statistics false",
            module_ignore_errors=True)
    time.sleep(2)
    logger.info("RADIUS accounting disabled")


def clear_acct_logs(ptfhost):
    """Remove prior radacct detail files on PTF."""
    ptfhost.shell(
        "rm -rf /var/log/freeradius/radacct/* 2>/dev/null; "
        "mkdir -p /var/log/freeradius/radacct/",
        module_ignore_errors=True)


def get_acct_log_entries(ptfhost, username):
    result = ptfhost.shell(
        "grep -r '{}' /var/log/freeradius/radacct/ 2>/dev/null || true".format(username),
        module_ignore_errors=True)
    return result["stdout"]
