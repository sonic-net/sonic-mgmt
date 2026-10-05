"""
Generic Config Updater (GCU) tests for the SRv6 Link Isolation ingress ACL.

In the Fairwater AI backend network, customer traffic is forwarded via SRv6 and
static routes, so the traditional BGP shut/unshut link isolation does not apply.
Link isolation is instead performed with an ingress ACL table (type L3V6LITE)
that drops all IPv6 traffic except ICMPv6. The table is provisioned statically
with no bound ports, and links are isolated/unisolated at runtime by dynamically
binding/unbinding ports to the table via GCU.

Note on two GCU/YANG constraints exercised here:
    * The ACL_TABLE "ports" leaf-list cannot be empty ([]); it must be omitted
      when creating the table, added to bind ports, and removed to unbind.
    * Removing the last ACL_TABLE_TYPE entry would leave an empty container,
      which GCU rejects, so the whole /ACL_TABLE_TYPE container is removed.

This module exercises the GCU-driven lifecycle of that table:
    * Adding and removing the ACL table (and its custom table type).
    * Dynamically changing the port bindings of the ACL table.

These are config-plane tests; they validate CONFIG_DB state and `show acl table`
output rather than data-plane forwarding.
"""

import logging
import pytest

from tests.common.gu_utils import apply_formed_json_patch, expect_op_success
from tests.common.gu_utils import create_path
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.gu_utils import expect_acl_table_match_multiple_bindings
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1'),
]

# Naming from the SRv6 Link Isolation design.
ACL_TABLE_NAME = "LINK_ISOLATION_TABLE"
ACL_TABLE_TYPE = "L3V6LITE"
# Keep the description free of whitespace so `show acl table` does not wrap it
# onto extra lines (which would confuse the binding-column parser).
ACL_TABLE_POLICY_DESC = "SRv6_link_isolation"

ACL_TABLE_TYPE_VALUE = {
    "MATCHES": ["IP_PROTOCOL", "IP_TYPE"],
    "ACTIONS": ["PACKET_ACTION", "COUNTER"],
    "BIND_POINTS": ["PORT"],
}

# The "ports" leaf-list is intentionally omitted: SONiC YANG rejects an empty
# leaf-list, so the table is created with no ports and bound dynamically later.
ACL_TABLE_VALUE = {
    "policy_desc": ACL_TABLE_POLICY_DESC,
    "type": ACL_TABLE_TYPE,
    "stage": "ingress",
}

# Ingress ACL rules that implement link isolation: drop all IPv6 traffic while
# permitting ICMPv6 (which covers IPv6 NDP). Keyed by rule name; the CONFIG_DB
# key is "<table>|<rule name>".
ACL_RULES = {
    "DENY_ALL_IPV6": {
        "PRIORITY": "999",
        "PACKET_ACTION": "DROP",
        "IP_TYPE": "IPV6ANY",
    },
    "PERMIT_ALL_ICMPV6": {
        "PRIORITY": "1000",
        "PACKET_ACTION": "FORWARD",
        "IP_PROTOCOL": "58",
    },
}


@pytest.fixture(scope="module")
def setup(rand_selected_dut, rand_unselected_dut, tbinfo):
    """Minimal setup context consumed by the shared GCU helpers."""
    pytest_require(not rand_selected_dut.is_multi_asic,
                   "SRv6 link isolation ACL GCU test only supports single-asic devices")

    is_dualtor = "dualtor" in tbinfo["topo"]["name"]
    return {
        "is_dualtor": is_dualtor,
        "rand_unselected_dut": rand_unselected_dut,
    }


@pytest.fixture(scope="module")
def bind_ports(rand_selected_dut, tbinfo):
    """All physical ports of the DUT that are not portchannel members."""
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    config_facts = rand_selected_dut.config_facts(
        host=rand_selected_dut.hostname, source="running")["ansible_facts"]

    portchannel_members = set()
    for _, members in config_facts.get("PORTCHANNEL_MEMBER", {}).items():
        portchannel_members.update(members.keys())

    ports = [p for p in mg_facts["minigraph_ports"].keys()
             if "BP" not in p and p not in portchannel_members]
    ports = sorted(ports, key=lambda item: int(item.replace("Ethernet", "")))

    if not ports:
        pytest.skip("No eligible physical ports to run the test")

    logger.info("Selected ports for ACL binding: {}".format(ports))
    return ports


@pytest.fixture(autouse=True)
def setup_env(rand_selected_dut, rand_unselected_dut, setup):
    """Checkpoint before each test and roll back afterwards."""
    create_checkpoint(rand_selected_dut)
    if setup["is_dualtor"]:
        create_checkpoint(rand_unselected_dut)

    yield

    try:
        logger.info("Rolling back to original checkpoint")
        rollback_or_reload(rand_selected_dut)
        if setup["is_dualtor"]:
            rollback_or_reload(rand_unselected_dut)
    finally:
        delete_checkpoint(rand_selected_dut)
        if setup["is_dualtor"]:
            delete_checkpoint(rand_unselected_dut)


def _apply_patch(duthost, json_patch, setup):
    """Apply a GCU patch and assert success on every target DUT."""
    logger.info("Applying GCU patch: {}".format(json_patch))
    outputs = apply_formed_json_patch(duthost, json_patch, setup)
    for output in outputs:
        expect_op_success(duthost, output)


def _acl_table_exists(duthost):
    """Return True only if the ACL table is present and programmed (Active)."""
    rows = duthost.show_and_parse("show acl table {}".format(ACL_TABLE_NAME))
    # With multiple port bindings the table spans several rows; the primary row
    # (name == table name) carries the status, continuation rows do not.
    primary = [row for row in rows if row.get("name") == ACL_TABLE_NAME]
    return bool(primary) and primary[0].get("status") == "Active"


def _acl_table_type_exists(duthost):
    keys = duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'ACL_TABLE_TYPE|{}'".format(ACL_TABLE_TYPE))["stdout"]
    return bool(keys.strip())


def _configdb_keys(duthost, pattern):
    """Return the list of CONFIG_DB keys matching the given pattern."""
    out = duthost.shell("sonic-db-cli CONFIG_DB keys '{}'".format(pattern))["stdout"]
    return [line for line in out.splitlines() if line.strip()]


def _acl_rules_exist(duthost):
    """Return True only if every isolation rule is present and Active."""
    rows = duthost.show_and_parse("show acl rule {}".format(ACL_TABLE_NAME))
    status_by_rule = {row.get("rule"): row.get("status") for row in rows if row.get("rule")}
    return all(status_by_rule.get(rule) == "Active" for rule in ACL_RULES)


def _add_isolation_table_patch():
    """GCU patch that provisions the isolation ACL table type, table (with no
    bound ports) and the link-isolation ACL rules."""
    patch = [
        {
            "op": "add",
            "path": create_path(["ACL_TABLE_TYPE"]),
            "value": {ACL_TABLE_TYPE: ACL_TABLE_TYPE_VALUE},
        },
        {
            "op": "add",
            "path": create_path(["ACL_TABLE", ACL_TABLE_NAME]),
            "value": ACL_TABLE_VALUE,
        },
    ]
    # Add each rule as an individual key. GCU creates the parent /ACL_RULE
    # container automatically whether or not it already exists.
    for rule_name, rule_value in ACL_RULES.items():
        patch.append({
            "op": "add",
            "path": create_path(["ACL_RULE", "{}|{}".format(ACL_TABLE_NAME, rule_name)]),
            "value": rule_value,
        })
    return patch


def _remove_isolation_config_patch(duthost):
    """GCU patch that removes the isolation rules, table and table type.

    A container (ACL_RULE / ACL_TABLE_TYPE) is removed as a whole when our
    entries are the only ones left, because GCU rejects leaving an empty table
    in CONFIG_DB. Otherwise the individual keys are removed.
    """
    patch = []

    # ACL rules.
    our_rule_keys = ["ACL_RULE|{}|{}".format(ACL_TABLE_NAME, rule) for rule in ACL_RULES]
    remaining_rules = [k for k in _configdb_keys(duthost, "ACL_RULE|*") if k not in our_rule_keys]
    if remaining_rules:
        for rule_name in ACL_RULES:
            patch.append({
                "op": "remove",
                "path": create_path(["ACL_RULE", "{}|{}".format(ACL_TABLE_NAME, rule_name)]),
            })
    else:
        patch.append({"op": "remove", "path": create_path(["ACL_RULE"])})

    # ACL table (other tables such as DATAACL keep the container non-empty).
    patch.append({"op": "remove", "path": create_path(["ACL_TABLE", ACL_TABLE_NAME])})

    # ACL table type.
    remaining_types = [k for k in _configdb_keys(duthost, "ACL_TABLE_TYPE|*")
                       if k != "ACL_TABLE_TYPE|{}".format(ACL_TABLE_TYPE)]
    if remaining_types:
        patch.append({"op": "remove", "path": create_path(["ACL_TABLE_TYPE", ACL_TABLE_TYPE])})
    else:
        patch.append({"op": "remove", "path": create_path(["ACL_TABLE_TYPE"])})

    return patch


def test_acl_table_add_and_remove(rand_selected_dut, setup):
    """
    Verify the isolation ACL table (and its custom type) can be added and
    removed at runtime via GCU without rebooting/reloading the switch.

    Test steps:
    1. Apply a GCU patch adding ACL_TABLE_TYPE L3V6LITE, ACL_TABLE
       LINK_ISOLATION_TABLE (no bound ports) and the isolation ACL rules.
    2. Verify the table type, table and rules are present in CONFIG_DB.
    3. Apply a GCU patch removing the ACL rules, table and custom table type.
    4. Verify they are gone from CONFIG_DB.
    """
    duthost = rand_selected_dut

    _apply_patch(duthost, _add_isolation_table_patch(), setup)

    pytest_assert(wait_until(30, 2, 0, _acl_table_type_exists, duthost),
                  "ACL table type {} was not created".format(ACL_TABLE_TYPE))
    pytest_assert(wait_until(30, 2, 0, _acl_table_exists, duthost),
                  "ACL table {} was not created".format(ACL_TABLE_NAME))
    pytest_assert(wait_until(30, 2, 0, _acl_rules_exist, duthost),
                  "ACL rules for {} were not created".format(ACL_TABLE_NAME))

    _apply_patch(duthost, _remove_isolation_config_patch(duthost), setup)

    pytest_assert(wait_until(30, 2, 0, lambda: not _acl_rules_exist(duthost)),
                  "ACL rules for {} were not removed".format(ACL_TABLE_NAME))
    pytest_assert(wait_until(30, 2, 0, lambda: not _acl_table_exists(duthost)),
                  "ACL table {} was not removed".format(ACL_TABLE_NAME))
    pytest_assert(wait_until(30, 2, 0, lambda: not _acl_table_type_exists(duthost)),
                  "ACL table type {} was not removed".format(ACL_TABLE_TYPE))


def test_acl_table_dynamic_port_binding(rand_selected_dut, setup, bind_ports):
    """
    Verify links can be isolated/unisolated by dynamically changing the port
    bindings of a statically-provisioned isolation ACL table via GCU.

    Test steps:
    1. Provision the ACL table type and table with no bound ports.
    2. Apply a GCU add patch that binds the table to all ports (isolate).
    3. Verify `show acl table` reflects both port bindings.
    4. Apply a GCU remove patch that clears the "ports" field (unisolate).
    5. Verify the table has no port bindings.
    """
    duthost = rand_selected_dut

    # Provision the isolation table (no bound ports) first.
    _apply_patch(duthost, _add_isolation_table_patch(), setup)
    pytest_assert(wait_until(30, 2, 0, _acl_table_exists, duthost),
                  "ACL table {} was not created".format(ACL_TABLE_NAME))

    # Isolate: bind the table to the selected ports. Use "add" because the
    # "ports" field does not exist on the freshly-created table.
    bind_patch = [
        {
            "op": "add",
            "path": create_path(["ACL_TABLE", ACL_TABLE_NAME, "ports"]),
            "value": bind_ports,
        }
    ]
    _apply_patch(duthost, bind_patch, setup)

    expected_first_line = [
        ACL_TABLE_NAME,
        ACL_TABLE_TYPE,
        bind_ports[0],
        ACL_TABLE_POLICY_DESC,
        "ingress",
        "Active",
    ]
    expect_acl_table_match_multiple_bindings(
        duthost, ACL_TABLE_NAME, expected_first_line, bind_ports, setup)

    # Unisolate: remove the "ports" field entirely (an empty leaf-list is
    # rejected by YANG validation).
    unbind_patch = [
        {
            "op": "remove",
            "path": create_path(["ACL_TABLE", ACL_TABLE_NAME, "ports"]),
        }
    ]
    _apply_patch(duthost, unbind_patch, setup)

    def _no_bindings():
        rows = duthost.show_and_parse("show acl table {}".format(ACL_TABLE_NAME))
        if not rows:
            return False
        return all(not row.get("binding", "").strip() for row in rows)

    pytest_assert(wait_until(30, 5, 0, _no_bindings),
                  "ACL table {} still has port bindings after unbinding".format(ACL_TABLE_NAME))
