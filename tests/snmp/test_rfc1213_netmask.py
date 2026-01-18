import pytest
import ipaddress
import re

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

# Requirement example:
# snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.34.1.5.1
IP_NET_TO_NETMASK_OID = "1.3.6.1.2.1.4.34.1.5.1"

# Left-hand side example:
# iso.3.6.1.2.1.4.34.1.5.1.4.<ip> = OID: iso.3.6.1.2.1.4.32.1.5.<ifIndex>.1.4.<netip>.<prefix>
LHS_PREFIX = "iso.3.6.1.2.1.4.34.1.5.1.4."


def _get_dut_mgmt_ip(duthost):
    """
    Best-effort way to get DUT management IP from pytest-ansible host vars.
    (Matches the user's manual command which walks against the DUT mgmt IP, not localhost.)
    """
    host = duthost.host.options["inventory_manager"].get_host(duthost.hostname)
    mgmt_ip = host.vars.get("ansible_host")
    assert mgmt_ip, f"Unable to determine DUT mgmt IP for {duthost.hostname} (ansible_host is empty)"
    return mgmt_ip


def snmpwalk(duthost, community, oid):
    """
    Run snmpwalk against the DUT mgmt IP (not localhost) so it matches the requirement/result.
    Also assert on return code so we don't silently convert failures into empty output.
    """
    dut_ip = _get_dut_mgmt_ip(duthost)
    cmd = f"snmpwalk -v2c -c {community} {dut_ip} {oid}"
    res = duthost.shell(cmd, module_ignore_errors=True)

    assert res["rc"] == 0, (
        f"snmpwalk failed rc={res['rc']} cmd={cmd} "
        f"stdout={res.get('stdout', '')} stderr={res.get('stderr', '')}"
    )
    return res["stdout_lines"]


def test_ipNetToNetMask_exists(duthost, creds):
    """
    Verify ipNetToNetMask MIB is present and walkable
    """
    output = snmpwalk(duthost, creds["snmp_rocommunity"], IP_NET_TO_NETMASK_OID)

    assert output, "ipNetToNetMask SNMP walk returned no output"

    # In the requirement/result, each line contains "= OID:"
    for line in output:
        assert "= OID:" in line, f"Unexpected snmpwalk line (expected OID value): {line}"


def test_ipNetToNetMask_oid_format(duthost, creds):
    """
    Validate returned OID format (based on actual output):

    LHS:
      iso.3.6.1.2.1.4.34.1.5.1.4.<ip> = OID: ...

    RHS:
      OID: iso.3.6.1.2.1.4.32.1.5.<ifIndex>.1.4.<netip>.<prefix>

    We validate:
      - LHS IP is valid IPv4
      - RHS ends with a prefix length between 0..32
    """
    output = snmpwalk(duthost, creds["snmp_rocommunity"], IP_NET_TO_NETMASK_OID)

    oid_regex = re.compile(
        r"^iso\.3\.6\.1\.2\.1\.4\.34\.1\.5\.1\.4\.(\d+\.\d+\.\d+\.\d+)\s+=\s+OID:\s+iso\.(.+)$"
    )

    for line in output:
        m = oid_regex.match(line.strip())
        assert m, f"OID format mismatch: {line}"

        ip = m.group(1)
        returned_oid_tail = m.group(2)  # everything after "iso."
        returned_oid = "iso." + returned_oid_tail

        # Basic sanity: IP must be valid
        ipaddress.ip_address(ip)

        # Returned OID must include prefix length at the end
        prefix = int(returned_oid.split(".")[-1])
        assert 0 <= prefix <= 32, f"Invalid prefix length {prefix} in returned OID: {returned_oid}"


def test_ipNetToNetMask_matches_interface_config(duthost, creds):
    """
    Cross-check SNMP netmask prefix with 'ip addr show' output.

    We only assert for IPs that appear in 'ip -o -4 addr show' to avoid failing on
    extra SNMP rows (e.g., broadcast-like entries) that may not be listed by `ip addr`.
    """
    ip_addr_output = duthost.shell("ip -o -4 addr show | awk '{print $4}'")["stdout_lines"]

    expected_prefixes = {}
    for entry in ip_addr_output:
        ip, prefix = entry.split("/")
        expected_prefixes[ip] = int(prefix)

    snmp_output = snmpwalk(duthost, creds["snmp_rocommunity"], IP_NET_TO_NETMASK_OID)

    for line in snmp_output:
        line = line.strip()
        if "= OID:" not in line:
            continue

        # Parse LHS IP reliably:
        # iso.3.6.1.2.1.4.34.1.5.1.4.<ip> = OID: ...
        lhs = line.split(" = ")[0]
        if not lhs.startswith(LHS_PREFIX):
            continue
        ip = lhs[len(LHS_PREFIX):]

        # Parse prefix reliably from RHS:
        # ... = OID: iso.<...>.<prefix>
        rhs = line.split("OID:")[1].strip()
        prefix = int(rhs.split(".")[-1])

        if ip in expected_prefixes:
            assert prefix == expected_prefixes[ip], (
                f"Prefix mismatch for {ip}: expected {expected_prefixes[ip]}, got {prefix}. "
                f"Line: {line}"
            )
