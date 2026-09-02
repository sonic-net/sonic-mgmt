"""
Integration test for the configurable OpenSSH ListenAddress support
(SSH_SERVER|POLICIES > listen_addresses).

The test:
  1. Picks assigned management and/or loopback addresses (addresses that will
     keep working) and an assigned VLAN interface (gateway) address that will
     intentionally be left out of the configured list.
  2. Applies `listen_addresses` restricted to the management/loopback
     addresses only.
  3. Confirms SSH still succeeds through every configured address.
  4. Confirms SSH fails through the omitted VLAN address, and that this is
     because sshd isn't listening there (not a routing/ACL failure).
  5. Removes `listen_addresses` and confirms both IPv4/IPv6 wildcard
     listening is restored.
  6. Always restores the original SSH_SERVER configuration in a `finally`
     block, even if an assertion fails, so the DUT is never left
     inaccessible. The management address is always part of the configured
     `listen_addresses` set, so ansible/mgmt connectivity (this test's own
     transport) is never at risk of being locked out.
"""
import ipaddress
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, paramiko_ssh

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs'),
]

SSH_SERVER_POLICIES_KEY = "SSH_SERVER|POLICIES"
HOSTCFGD_APPLY_TIMEOUT = 30
HOSTCFGD_APPLY_INTERVAL = 2
SSH_CONNECT_TIMEOUT = 10


def _get_listen_addresses_field(duthost):
    """ Return the current listen_addresses@ value (comma separated string,
        possibly empty) or None if the field isn't present. """
    result = duthost.shell(
        'sonic-db-cli CONFIG_DB HGET "{}" listen_addresses@'.format(SSH_SERVER_POLICIES_KEY),
        module_ignore_errors=True
    )
    value = result['stdout'].strip()
    return value if value else None


def _set_listen_addresses(duthost, addresses):
    duthost.shell(
        'sonic-db-cli CONFIG_DB HSET "{}" listen_addresses@ "{}"'.format(
            SSH_SERVER_POLICIES_KEY, ",".join(addresses))
    )


def _delete_listen_addresses(duthost):
    duthost.shell(
        'sonic-db-cli CONFIG_DB HDEL "{}" listen_addresses@'.format(SSH_SERVER_POLICIES_KEY),
        module_ignore_errors=True
    )


def _get_sshd_listen_bindings(duthost):
    """ Return the set of (addr, port) tuples sshd is currently bound to,
        parsed from `ss -lntp`. """
    result = duthost.shell("sudo ss -lntp | grep sshd", module_ignore_errors=True)
    bindings = set()
    for line in result['stdout_lines']:
        fields = line.split()
        if len(fields) < 4:
            continue
        local_addr_port = fields[3]
        # IPv6 addresses are wrapped in brackets: [::]:22 or [fe80::1]:22
        if local_addr_port.startswith('['):
            addr, _, port = local_addr_port.rpartition(']:')
            addr = addr.lstrip('[')
        else:
            addr, _, port = local_addr_port.rpartition(':')
        bindings.add((addr, port))
    return bindings


def _wait_for_sshd_bindings(duthost, expected_addrs, port="22"):
    def _bindings_match():
        bindings = _get_sshd_listen_bindings(duthost)
        bound_addrs = {addr for addr, p in bindings if p == port}
        return bound_addrs == set(expected_addrs)

    return wait_until(HOSTCFGD_APPLY_TIMEOUT, HOSTCFGD_APPLY_INTERVAL, 0, _bindings_match)


def _pick_assigned_addresses(duthost):
    """ Identify assigned management/loopback addresses to keep working, and
        an assigned VLAN interface (gateway) address to intentionally omit. """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    keep_addresses = []
    mgmt_ip = duthost.mgmt_ip
    if mgmt_ip:
        keep_addresses.append(str(ipaddress.ip_address(mgmt_ip)))

    for lo_name, lo_ips in config_facts.get('LOOPBACK_INTERFACE', {}).items():
        for ip_prefix in lo_ips:
            if '/' not in ip_prefix:
                continue
            addr = ipaddress.ip_address(ip_prefix.split('/')[0])
            # Skip the all-zeros loopback key entries (interface-only rows)
            if str(addr) not in keep_addresses:
                keep_addresses.append(str(addr))

    omit_address = None
    for vlan_name, vlan_ips in config_facts.get('VLAN_INTERFACE', {}).items():
        for ip_prefix in vlan_ips:
            if '/' not in ip_prefix:
                continue
            addr = ipaddress.ip_address(ip_prefix.split('/')[0])
            if isinstance(addr, ipaddress.IPv4Address):
                omit_address = str(addr)
                break
        if omit_address:
            break

    return keep_addresses, omit_address


@pytest.fixture
def restore_ssh_server_policies(duthosts, rand_one_dut_hostname):
    """ Always restore the original SSH_SERVER|POLICIES listen_addresses
        state, even if the test body raises. """
    duthost = duthosts[rand_one_dut_hostname]
    original_listen_addresses = _get_listen_addresses_field(duthost)
    try:
        yield
    finally:
        if original_listen_addresses is not None:
            _set_listen_addresses(duthost, original_listen_addresses.split(','))
        else:
            _delete_listen_addresses(duthost)
        # Give hostcfgd time to re-apply the restored/removed configuration
        # and confirm the wildcard listeners are back before finishing.
        wait_until(HOSTCFGD_APPLY_TIMEOUT, HOSTCFGD_APPLY_INTERVAL, 0,
                   lambda: _wait_for_sshd_bindings(duthost, ["0.0.0.0", "::"]) or
                   original_listen_addresses is not None)


def test_ssh_listen_addresses(duthosts, rand_one_dut_hostname, creds, restore_ssh_server_policies):
    """
    Validate SSH_SERVER|POLICIES listen_addresses:
      - sshd only listens on the configured (assigned) addresses
      - SSH succeeds via the configured addresses
      - SSH fails via an assigned-but-omitted VLAN gateway address, because
        sshd isn't listening there (confirmed via ss, not routing/ACL)
      - removing listen_addresses restores both IPv4/IPv6 wildcards
    """
    duthost = duthosts[rand_one_dut_hostname]
    dutuser = creds['sonicadmin_user']
    dutpass = creds['sonicadmin_password']

    keep_addresses, omit_address = _pick_assigned_addresses(duthost)
    pytest_assert(len(keep_addresses) > 0,
                  "Could not identify an assigned management/loopback address to keep listening on")
    pytest_assert(omit_address is not None,
                  "Could not identify an assigned VLAN gateway address to intentionally omit")

    # Sanity: sshd should currently be listening on the wildcards (default,
    # untouched state) before we narrow it down.
    logger.info("Configuring listen_addresses={} (omitting VLAN address {})".format(
        keep_addresses, omit_address))
    _set_listen_addresses(duthost, keep_addresses)

    pytest_assert(
        wait_until(HOSTCFGD_APPLY_TIMEOUT, HOSTCFGD_APPLY_INTERVAL, 0,
                   lambda: _wait_for_sshd_bindings(duthost, keep_addresses)),
        "sshd did not converge to listening only on the configured addresses {}".format(keep_addresses)
    )

    # SSH must succeed through every configured (kept) address.
    for addr in keep_addresses:
        ssh = None
        try:
            ssh = paramiko_ssh(addr, dutuser, [dutpass] + creds.get("ansible_altpasswords", []))
        except Exception as e:
            pytest.fail("SSH via configured listen address {} failed unexpectedly: {}".format(addr, e))
        finally:
            if ssh:
                ssh.close()

    # SSH must fail through the intentionally omitted VLAN gateway address,
    # and it must fail because nothing is listening there (connection
    # refused/timeout), not because of routing/ACL issues.
    bindings = _get_sshd_listen_bindings(duthost)
    bound_addrs = {addr for addr, port in bindings}
    pytest_assert(omit_address not in bound_addrs,
                  "sshd is unexpectedly still bound to the omitted VLAN address {}".format(omit_address))

    with pytest.raises(Exception):
        ssh = paramiko_ssh(omit_address, dutuser, [dutpass] + creds.get("ansible_altpasswords", []))
        ssh.close()

    # Remove listen_addresses entirely and confirm both wildcards are restored.
    logger.info("Removing listen_addresses to confirm wildcard listeners are restored")
    _delete_listen_addresses(duthost)
    pytest_assert(
        wait_until(HOSTCFGD_APPLY_TIMEOUT, HOSTCFGD_APPLY_INTERVAL, 0,
                   lambda: _wait_for_sshd_bindings(duthost, ["0.0.0.0", "::"])),
        "sshd did not restore the IPv4/IPv6 wildcard listeners after removing listen_addresses"
    )

    # Confirm the previously omitted VLAN address is reachable again now
    # that sshd is back to wildcard listening (proves the earlier failure
    # was due to sshd not listening, not routing/ACL).
    ssh = None
    try:
        ssh = paramiko_ssh(omit_address, dutuser, [dutpass] + creds.get("ansible_altpasswords", []))
    except Exception as e:
        pytest.fail("SSH via VLAN address {} failed after restoring wildcard listeners: {}".format(
            omit_address, e))
    finally:
        if ssh:
            ssh.close()
