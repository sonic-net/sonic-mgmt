"""Tests for ACL arbitrary (non-contiguous) IP mask support.

Verifies that SRC_IP_MASK / DST_IP_MASK / SRC_IPV6_MASK / DST_IPV6_MASK fields
are accepted by orchagent, programmed correctly into ASIC DB, and that traffic
is actually dropped or forwarded according to the non-contiguous mask.

Test topology: any topology with front-panel PTF ports.

Traffic test logic for mask 255.0.255.0 on SRC_IP=10.1.2.3:
  - The masked value is:  10.1.2.3  & 255.0.255.0 = 10.0.2.0
  - Matching IPs:         10.x.2.y  & 255.0.255.0 = 10.0.2.0  → DROP
  - Non-matching IPs:     10.1.3.x  & 255.0.255.0 = 10.0.3.0  → FORWARD

Traffic test logic for mask ffff::ffff on SRC_IPV6=2001::1:
  - Matching:   2001:xxxx::1   & ffff::ffff = 2001::1  → DROP
  - Non-match:  2002::1        & ffff::ffff = 2002::1  → FORWARD
"""

import json
import logging
import pytest
import ptf.testutils as testutils
from ptf import mask, packet

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import AsicDbCli
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]

TMP_DIR = '/tmp'
ACL_TABLE_NAME = "ARB_MASK_TEST_TABLE"
ACL_CONFIG_FILE = "acl_arb_mask_config.json"
ACL_COUNTERS_UPDATE_INTERVAL = 10  # seconds

# Mask used for IPv4 tests: 255.0.255.0
# Matched value: ip & 255.0.255.0 = 10.0.2.0
IPV4_SRC_IP = "10.1.2.3"
IPV4_SRC_MASK = "255.0.255.0"
IPV4_DST_IP = "192.168.1.1"
IPV4_DST_MASK = "255.0.255.0"

# Traffic IPs for IPv4 mask tests
IPV4_SRC_MATCH_EXACT = "10.1.2.3"          # exact match
IPV4_SRC_MATCH_ARBITRARY = "10.99.2.77"    # different octets, same masked value
IPV4_SRC_NO_MATCH = "10.1.3.5"             # third octet differs → no match

# Mask used for IPv6 tests: ffff::ffff
IPV6_SRC_IP = "2001::1"
IPV6_SRC_MASK = "ffff::ffff"
IPV6_DST_IP = "2001:db8::1"
IPV6_DST_MASK = "ffff::ffff"

# Traffic IPs for IPv6 mask tests
IPV6_SRC_MATCH_EXACT = "2001::1"            # exact match
IPV6_SRC_MATCH_ARBITRARY = "2001:dead::1"   # different middle groups, same masked value
IPV6_SRC_NO_MATCH = "2002::1"              # first group differs → no match


def _make_acl_config(front_ports):
    return {
        "ACL_TABLE": {
            ACL_TABLE_NAME: {
                "policy_desc": "Arbitrary mask test table (IPv4)",
                "type": "L3",
                "stage": "ingress",
                "ports": front_ports
            },
            ACL_TABLE_NAME + "_V6": {
                "policy_desc": "Arbitrary mask test table (IPv6)",
                "type": "L3V6",
                "stage": "ingress",
                "ports": front_ports
            }
        },
        "ACL_RULE": {
            ACL_TABLE_NAME + "|rule_src_ipv4_mask": {
                "PRIORITY": "100",
                "PACKET_ACTION": "DROP",
                "SRC_IP": IPV4_SRC_IP,
                "SRC_IP_MASK": IPV4_SRC_MASK
            },
            ACL_TABLE_NAME + "|rule_dst_ipv4_mask": {
                "PRIORITY": "200",
                "PACKET_ACTION": "DROP",
                "DST_IP": IPV4_DST_IP,
                "DST_IP_MASK": IPV4_DST_MASK
            },
            ACL_TABLE_NAME + "|rule_cidr_compat_v4": {
                "PRIORITY": "300",
                "PACKET_ACTION": "DROP",
                "SRC_IP": "10.2.3.4/24"
            },
            ACL_TABLE_NAME + "_V6|rule_src_ipv6_mask": {
                "PRIORITY": "100",
                "PACKET_ACTION": "DROP",
                "SRC_IPV6": IPV6_SRC_IP,
                "SRC_IPV6_MASK": IPV6_SRC_MASK
            },
            ACL_TABLE_NAME + "_V6|rule_dst_ipv6_mask": {
                "PRIORITY": "200",
                "PACKET_ACTION": "DROP",
                "DST_IPV6": IPV6_DST_IP,
                "DST_IPV6_MASK": IPV6_DST_MASK
            },
            ACL_TABLE_NAME + "_V6|rule_cidr_compat_v6": {
                "PRIORITY": "300",
                "PACKET_ACTION": "DROP",
                "SRC_IPV6": "2001:db8::/32"
            }
        }
    }


def _rule_active_in_state_db(duthost, table_name, rule_name):
    result = duthost.shell(
        f'redis-cli -n 6 KEYS "ACL_RULE_TABLE|{table_name}|{rule_name}"',
        module_ignore_errors=True
    )["stdout"]
    return rule_name in result


def _get_acl_counter(duthost, table_name, rule_name):
    """Return the current packet counter for a given ACL rule (0 if not found)."""
    result = duthost.show_and_parse('aclshow -a')
    for entry in result:
        if entry.get('table name') == table_name and entry.get('rule name') == rule_name:
            try:
                return int(entry.get('packets count', 0))
            except ValueError:
                return 0
    return 0


def _get_acl_entry_keys(duthost):
    result = duthost.shell(
        'sonic-db-cli ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY*"',
        module_ignore_errors=True
    )["stdout"]
    return [k.strip() for k in result.splitlines() if k.strip()]


def _find_asic_entry_with_field(duthost, sai_field, expected_value):
    """Return the first ASIC entry whose sai_field contains expected_value."""
    asicdb = AsicDbCli(duthost)
    for key in _get_acl_entry_keys(duthost):
        try:
            attrs = asicdb.hget_all(key)
        except Exception:
            continue
        val = attrs.get(sai_field, "")
        if expected_value.lower() in val.lower():
            return attrs
    return None


@pytest.fixture(scope="module")
def acl_setup(duthosts, rand_selected_dut, tbinfo, ptfadapter):
    """Create ACL tables and rules; expose PTF port info; tear down on exit."""
    duthost = rand_selected_dut

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_indices = mg_facts.get("minigraph_ptf_indices", {})

    # Pick up to 2 front-panel ports for table binding
    front_ports = [i["name"] for i in mg_facts.get("minigraph_interfaces", [])
                   if not i["name"].startswith("Loopback")][:2]
    if not front_ports:
        pytest.skip("No front-panel ports available for ACL binding")

    # PTF port index for sending packets (first bound port)
    ptf_send_port = ptf_indices.get(front_ports[0])
    if ptf_send_port is None:
        pytest.skip(f"No PTF port mapping for {front_ports[0]}")

    all_ptf_ports = list(ptf_indices.values())

    config = _make_acl_config(front_ports)
    config_json = json.dumps(config, indent=4)
    dest_path = f"{TMP_DIR}/{ACL_CONFIG_FILE}"

    logger.info("Loading ACL arbitrary-mask config:\n%s", config_json)
    duthost.copy(content=config_json, dest=dest_path)
    duthost.shell(f"config load -y {dest_path}")

    expected_rules = [
        (ACL_TABLE_NAME,        "rule_src_ipv4_mask"),
        (ACL_TABLE_NAME,        "rule_dst_ipv4_mask"),
        (ACL_TABLE_NAME,        "rule_cidr_compat_v4"),
        (ACL_TABLE_NAME + "_V6", "rule_src_ipv6_mask"),
        (ACL_TABLE_NAME + "_V6", "rule_dst_ipv6_mask"),
        (ACL_TABLE_NAME + "_V6", "rule_cidr_compat_v6"),
    ]
    for table, rule in expected_rules:
        pytest_assert(
            wait_until(60, 5, 2, _rule_active_in_state_db, duthost, table, rule),
            f"ACL rule {table}|{rule} did not become active in STATE_DB"
        )

    setup_data = {
        "duthost": duthost,
        "ptf_send_port": ptf_send_port,
        "all_ptf_ports": all_ptf_ports,
        "router_mac": duthost.facts["router_mac"],
    }

    yield setup_data

    logger.info("Removing ACL arbitrary-mask config")
    for table_rule_key in config["ACL_RULE"].keys():
        table, rule = table_rule_key.split("|", 1)
        duthost.shell(f'config acl delete rule {table} {rule}', module_ignore_errors=True)
    for table in config["ACL_TABLE"].keys():
        duthost.shell(f'config acl delete table {table}', module_ignore_errors=True)
    duthost.shell(f"rm -f {dest_path}", module_ignore_errors=True)


class TestAclArbitraryMask:
    """Verify arbitrary (non-contiguous) IP mask: Config DB → ASIC DB → traffic."""

    # ------------------------------------------------------------------
    # Config DB field storage
    # ------------------------------------------------------------------

    def test_config_db_ipv4_src_mask_fields(self, acl_setup):
        """Config DB must store SRC_IP and SRC_IP_MASK as separate fields."""
        duthost = acl_setup["duthost"]
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|rule_src_ipv4_mask"

        src_ip = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" SRC_IP')["stdout"].strip()
        src_mask = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" SRC_IP_MASK')["stdout"].strip()

        pytest_assert(src_ip == IPV4_SRC_IP,
                      f"Expected SRC_IP '{IPV4_SRC_IP}', got '{src_ip}'")
        pytest_assert(src_mask == IPV4_SRC_MASK,
                      f"Expected SRC_IP_MASK '{IPV4_SRC_MASK}', got '{src_mask}'")

    def test_config_db_ipv4_dst_mask_fields(self, acl_setup):
        """Config DB must store DST_IP and DST_IP_MASK as separate fields."""
        duthost = acl_setup["duthost"]
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}|rule_dst_ipv4_mask"

        dst_ip = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" DST_IP')["stdout"].strip()
        dst_mask = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" DST_IP_MASK')["stdout"].strip()

        pytest_assert(dst_ip == IPV4_DST_IP,
                      f"Expected DST_IP '{IPV4_DST_IP}', got '{dst_ip}'")
        pytest_assert(dst_mask == IPV4_DST_MASK,
                      f"Expected DST_IP_MASK '{IPV4_DST_MASK}', got '{dst_mask}'")

    def test_config_db_ipv6_src_mask_fields(self, acl_setup):
        """Config DB must store SRC_IPV6 and SRC_IPV6_MASK as separate fields."""
        duthost = acl_setup["duthost"]
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}_V6|rule_src_ipv6_mask"

        src_ip = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" SRC_IPV6')["stdout"].strip()
        src_mask = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" SRC_IPV6_MASK')["stdout"].strip()

        pytest_assert(src_ip == IPV6_SRC_IP,
                      f"Expected SRC_IPV6 '{IPV6_SRC_IP}', got '{src_ip}'")
        pytest_assert(src_mask == IPV6_SRC_MASK,
                      f"Expected SRC_IPV6_MASK '{IPV6_SRC_MASK}', got '{src_mask}'")

    def test_config_db_ipv6_dst_mask_fields(self, acl_setup):
        """Config DB must store DST_IPV6 and DST_IPV6_MASK as separate fields."""
        duthost = acl_setup["duthost"]
        rule_key = f"ACL_RULE|{ACL_TABLE_NAME}_V6|rule_dst_ipv6_mask"

        dst_ip = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" DST_IPV6')["stdout"].strip()
        dst_mask = duthost.shell(f'redis-cli -n 4 HGET "{rule_key}" DST_IPV6_MASK')["stdout"].strip()

        pytest_assert(dst_ip == IPV6_DST_IP,
                      f"Expected DST_IPV6 '{IPV6_DST_IP}', got '{dst_ip}'")
        pytest_assert(dst_mask == IPV6_DST_MASK,
                      f"Expected DST_IPV6_MASK '{IPV6_DST_MASK}', got '{dst_mask}'")

    # ------------------------------------------------------------------
    # ASIC DB SAI attribute verification
    # ------------------------------------------------------------------

    def test_asic_db_ipv4_src_mask_programmed(self, acl_setup):
        """ASIC DB entry for IPv4 SRC mask must carry the non-contiguous mask value."""
        duthost = acl_setup["duthost"]
        entry = _find_asic_entry_with_field(
            duthost, "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP",
            f"{IPV4_SRC_IP}&mask:{IPV4_SRC_MASK}"
        )
        pytest_assert(entry is not None,
                      f"ASIC DB: FIELD_SRC_IP with mask {IPV4_SRC_MASK} not found")

    def test_asic_db_ipv4_dst_mask_programmed(self, acl_setup):
        """ASIC DB entry for IPv4 DST mask must carry the non-contiguous mask value."""
        duthost = acl_setup["duthost"]
        entry = _find_asic_entry_with_field(
            duthost, "SAI_ACL_ENTRY_ATTR_FIELD_DST_IP",
            f"{IPV4_DST_IP}&mask:{IPV4_DST_MASK}"
        )
        pytest_assert(entry is not None,
                      f"ASIC DB: FIELD_DST_IP with mask {IPV4_DST_MASK} not found")

    def test_asic_db_ipv6_src_mask_programmed(self, acl_setup):
        """ASIC DB entry for IPv6 SRC mask must carry the non-contiguous mask value."""
        duthost = acl_setup["duthost"]
        entry = _find_asic_entry_with_field(
            duthost, "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6",
            f"{IPV6_SRC_IP}&mask:{IPV6_SRC_MASK}"
        )
        pytest_assert(entry is not None,
                      f"ASIC DB: FIELD_SRC_IPV6 with mask {IPV6_SRC_MASK} not found")

    def test_asic_db_ipv6_dst_mask_programmed(self, acl_setup):
        """ASIC DB entry for IPv6 DST mask must carry the non-contiguous mask value."""
        duthost = acl_setup["duthost"]
        entry = _find_asic_entry_with_field(
            duthost, "SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6",
            f"{IPV6_DST_IP}&mask:{IPV6_DST_MASK}"
        )
        pytest_assert(entry is not None,
                      f"ASIC DB: FIELD_DST_IPV6 with mask {IPV6_DST_MASK} not found")

    def test_asic_db_cidr_compat_ipv4(self, acl_setup):
        """CIDR notation (10.2.3.4/24) must still produce a /24 mask in ASIC DB."""
        duthost = acl_setup["duthost"]
        entry = _find_asic_entry_with_field(
            duthost, "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP",
            "10.2.3.4&mask:255.255.255.0"
        )
        pytest_assert(entry is not None,
                      "ASIC DB: CIDR rule 10.2.3.4/24 not programmed with mask 255.255.255.0")

    def test_asic_db_cidr_compat_ipv6(self, acl_setup):
        """IPv6 CIDR notation (2001:db8::/32) must still produce the correct mask in ASIC DB."""
        duthost = acl_setup["duthost"]
        entry = _find_asic_entry_with_field(
            duthost, "SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6",
            "2001:db8::&mask:ffff:ffff::"
        )
        pytest_assert(entry is not None,
                      "ASIC DB: CIDR rule 2001:db8::/32 not programmed with mask ffff:ffff::")

    # ------------------------------------------------------------------
    # PTF traffic tests
    # Mask 255.0.255.0 on SRC_IP 10.1.2.3 → masked value 10.0.2.0
    #   Matching:     IP & 255.0.255.0 == 10.0.2.0  (e.g. 10.1.2.3, 10.99.2.77)  → DROP
    #   Non-matching: IP & 255.0.255.0 != 10.0.2.0  (e.g. 10.1.3.5)               → FORWARD
    # ------------------------------------------------------------------

    def _build_ipv4_pkt(self, router_mac, src_ip, dst_ip="192.0.2.1"):
        return testutils.simple_tcp_packet(
            eth_dst=router_mac,
            ip_src=src_ip,
            ip_dst=dst_ip,
            ip_ttl=64
        )

    def _build_ipv6_pkt(self, router_mac, src_ip, dst_ip="2001:db8:ff::1"):
        return testutils.simple_tcpv6_packet(
            eth_dst=router_mac,
            ipv6_src=src_ip,
            ipv6_dst=dst_ip,
            ipv6_hlim=64
        )

    def _drop_mask(self, pkt, ip_version):
        """Mask that ignores L2 headers and TTL/checksum for drop verification."""
        exp = mask.Mask(pkt)
        exp.set_do_not_care_scapy(packet.Ether, "dst")
        exp.set_do_not_care_scapy(packet.Ether, "src")
        if ip_version == "ipv4":
            exp.set_do_not_care_scapy(packet.IP, "chksum")
            exp.set_do_not_care_scapy(packet.IP, "ttl")
        else:
            exp.set_do_not_care_scapy(packet.IPv6, "hlim")
        return exp

    def test_ptf_ipv4_src_exact_match_dropped(self, acl_setup, ptfadapter):
        """Packet with SRC_IP exactly equal to the rule IP must be dropped."""
        router_mac = acl_setup["router_mac"]
        src_port = acl_setup["ptf_send_port"]
        all_ports = acl_setup["all_ptf_ports"]

        pkt = self._build_ipv4_pkt(router_mac, IPV4_SRC_MATCH_EXACT)
        exp = self._drop_mask(pkt, "ipv4")

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_port, pkt)
        testutils.verify_no_packet_any(ptfadapter, exp, ports=all_ports)

    def test_ptf_ipv4_src_arbitrary_match_dropped(self, acl_setup, ptfadapter):
        """Packet with SRC_IP that shares masked bits must also be dropped.

        10.99.2.77 & 255.0.255.0 = 10.0.2.0  ==  10.1.2.3 & 255.0.255.0  → match → DROP
        """
        router_mac = acl_setup["router_mac"]
        src_port = acl_setup["ptf_send_port"]
        all_ports = acl_setup["all_ptf_ports"]

        pkt = self._build_ipv4_pkt(router_mac, IPV4_SRC_MATCH_ARBITRARY)
        exp = self._drop_mask(pkt, "ipv4")

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_port, pkt)
        testutils.verify_no_packet_any(ptfadapter, exp, ports=all_ports)

    def test_ptf_ipv4_src_no_match_not_dropped_by_mask_rule(self, acl_setup, ptfadapter):
        """Packet with SRC_IP that doesn't match the mask must NOT hit the mask rule.

        10.1.3.5 & 255.0.255.0 = 10.0.3.0  !=  10.0.2.0  → no match → counter unchanged
        """
        duthost = acl_setup["duthost"]
        router_mac = acl_setup["router_mac"]
        src_port = acl_setup["ptf_send_port"]

        counter_before = _get_acl_counter(duthost, ACL_TABLE_NAME, "rule_src_ipv4_mask")

        pkt = self._build_ipv4_pkt(router_mac, IPV4_SRC_NO_MATCH)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_port, pkt)

        # Give orchagent time to update counters, then check it didn't increment
        import time
        time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)
        counter_after = _get_acl_counter(duthost, ACL_TABLE_NAME, "rule_src_ipv4_mask")
        pytest_assert(counter_after == counter_before,
                      f"Mask rule counter incremented unexpectedly: {counter_before} → {counter_after}")

    def test_ptf_ipv6_src_exact_match_dropped(self, acl_setup, ptfadapter):
        """IPv6 packet with SRC_IPV6 exactly equal to the rule IP must be dropped."""
        router_mac = acl_setup["router_mac"]
        src_port = acl_setup["ptf_send_port"]
        all_ports = acl_setup["all_ptf_ports"]

        pkt = self._build_ipv6_pkt(router_mac, IPV6_SRC_MATCH_EXACT)
        exp = self._drop_mask(pkt, "ipv6")

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_port, pkt)
        testutils.verify_no_packet_any(ptfadapter, exp, ports=all_ports)

    def test_ptf_ipv6_src_arbitrary_match_dropped(self, acl_setup, ptfadapter):
        """IPv6 packet sharing masked bits with the rule IP must be dropped.

        2001:dead::1 & ffff::ffff = 2001::1  ==  2001::1 & ffff::ffff  → match → DROP
        """
        router_mac = acl_setup["router_mac"]
        src_port = acl_setup["ptf_send_port"]
        all_ports = acl_setup["all_ptf_ports"]

        pkt = self._build_ipv6_pkt(router_mac, IPV6_SRC_MATCH_ARBITRARY)
        exp = self._drop_mask(pkt, "ipv6")

        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_port, pkt)
        testutils.verify_no_packet_any(ptfadapter, exp, ports=all_ports)

    def test_ptf_ipv6_src_no_match_not_dropped_by_mask_rule(self, acl_setup, ptfadapter):
        """IPv6 packet that doesn't match the mask must NOT hit the mask rule.

        2002::1 & ffff::ffff = 2002::1  !=  2001::1  → no match → counter unchanged
        """
        duthost = acl_setup["duthost"]
        router_mac = acl_setup["router_mac"]
        src_port = acl_setup["ptf_send_port"]

        counter_before = _get_acl_counter(duthost, ACL_TABLE_NAME + "_V6", "rule_src_ipv6_mask")

        pkt = self._build_ipv6_pkt(router_mac, IPV6_SRC_NO_MATCH)
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, src_port, pkt)

        import time
        time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)
        counter_after = _get_acl_counter(duthost, ACL_TABLE_NAME + "_V6", "rule_src_ipv6_mask")
        pytest_assert(counter_after == counter_before,
                      f"Mask rule counter incremented unexpectedly: {counter_before} → {counter_after}")
