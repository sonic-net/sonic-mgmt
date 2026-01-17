import pytest
import ipaddress
import re

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs'),
]

IP_NET_TO_NETMASK_OID = "1.3.6.1.2.1.4.34.1.5.1"


def snmpwalk(duthost, community, oid):
    return duthost.shell(
        f"snmpwalk -v2c -c {community} localhost {oid}",
        module_ignore_errors=True
    )["stdout_lines"]


def test_ipNetToNetMask_exists(duthost, creds):
    """
    Verify ipNetToNetMask MIB is present and walkable
    """
    output = snmpwalk(duthost, creds["snmp_rocommunity"], IP_NET_TO_NETMASK_OID)

    assert output, "ipNetToNetMask SNMP walk returned no output"

    for line in output:
        assert "OBJECT IDENTIFIER" in line, \
            f"Unexpected value type: {line}"


def test_ipNetToNetMask_oid_format(duthost, creds):
    """
    Validate returned OID format:
    ipNetToNetMask.<addrType>.<ip> = OID ...<ifIndex>.<1>.<4>.<netip>.<mask>
    """
    output = snmpwalk(duthost, creds["snmp_rocommunity"], IP_NET_TO_NETMASK_OID)

    oid_regex = re.compile(
        r"::ipNetToNetMask\.4\.(\d+\.\d+\.\d+\.\d+)\s+=\s+OID:\s+([\d\.]+)"
    )

    for line in output:
        match = oid_regex.search(line)
        assert match, f"OID format mismatch: {line}"

        ip = match.group(1)
        returned_oid = match.group(2)

        # Basic sanity: IP must be valid
        ipaddress.ip_address(ip)

        # Returned OID must include prefix length at the end
        prefix = int(returned_oid.split(".")[-1])
        assert 0 <= prefix <= 32, f"Invalid prefix length {prefix}"


def test_ipNetToNetMask_matches_interface_config(duthost, creds):
    """
    Cross-check SNMP netmask prefix with 'ip addr show'
    """
    ip_addr_output = duthost.shell(
        "ip -o -4 addr show | awk '{print $4}'"
    )["stdout_lines"]

    expected_prefixes = {}
    for entry in ip_addr_output:
        ip, prefix = entry.split("/")
        expected_prefixes[ip] = int(prefix)

    snmp_output = snmpwalk(duthost, creds["snmp_rocommunity"], IP_NET_TO_NETMASK_OID)

    for line in snmp_output:
        if "ipNetToNetMask.4." not in line:
            continue

        ip = line.split("ipNetToNetMask.4.")[1].split(" ")[0]
        prefix = int(line.split(".")[-1])

        if ip in expected_prefixes:
            assert prefix == expected_prefixes[ip], \
                f"Prefix mismatch for {ip}: expected {expected_prefixes[ip]}, got {prefix}"
