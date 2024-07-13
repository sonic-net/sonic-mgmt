import pytest
import ipaddress
from spytest import st, SpyTestDict
import apis.qos.acl as acl_obj


data = SpyTestDict()


def setup_module():
    global vars
    vars = st.ensure_min_topology("D1")
    data.update({
        "tables": ["control-plane-v4", "control-plane-v6"],
        "tables_new": ["control-plane-new-v4", "control-plane-new-v6"],
        "rule_no": "1000",
        "ip_addr": "172.60.60.60/24",
        "ipv6_addr": "1720:6000::/64"
    })


def verify_iptable(proto, source, jump, present=True):
    """
    Verify iptable data for control plane acl rules
    Args:
        proto: Protocol number
        source: Source IP address
        jump: ACCEPT/DROP action
        present: Acl rule should be present in iptable or not. Default True

    Returns: None

    """
    addr = source.split("/")[0]
    try:
        ipaddress.IPv4Network(addr)
        command = "iptables"
    except ValueError:
        try:
            ipaddress.IPv6Network(addr)
            command = "ip6tables"
        except ValueError:
            st.report_fail("Source address is not correct")

    output = st.config(vars.D1, f"sudo {command} -C INPUT -p {proto} -s {source} -j {jump}")
    if "bad rule" in output.lower():
        if present:
            st.report_fail(f"Rule not found in {command} output")


@pytest.mark.drop_1
def test_cacl_table_rules():
    """
    Verify control plane acl policies applied as part of default configuration
    """
    acl_tables = acl_obj.show_acl_table(vars.D1)[0]
    acl_rules = acl_obj.show_acl_rule(vars.D1)

    for table in data['tables']:
        if table not in acl_tables:
            st.report_fail(f"ACL table: {table}, not present on the device")

    for _, rule in acl_rules.items():
        if rule["table"] not in data['tables']:
            st.report_fail(f"ACL table: {rule['table']}, not present on the device, but present in rule {rule}")

    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_adding_new_cacl_table_rule():
    """
    Verify adding new cacl table and rule.
    Verify that rule are translated to iptables
    """
    acl_json = {
        "ACL_TABLE": {
            f"{data['tables_new'][0]}": {
                "policy_desc": "new control plane acl v4",
                "services": [
                    "MATCH"
                ],
                "stage": "ingress",
                "type": "CTRLPLANE"
            },
            f"{data['tables_new'][1]}": {
                "policy_desc": "new control plane acl v6",
                "services": [
                    "MATCH"
                ],
                "stage": "ingress",
                "type": "CTRLPLANE"
            }
        },
        "ACL_RULE": {
            f"{data['tables_new'][0]}|{data['rule_no']}": {
                "IP_PROTOCOL": "89",
                "SRC_IP": data["ip_addr"],
                "PACKET_ACTION": "DROP",
                "PRIORITY": "100"
            },
            f"{data['tables_new'][1]}|{data['rule_no']}": {
                "IP_PROTOCOL": "103",
                "SRC_IPV6": data["ipv6_addr"],
                "PACKET_ACTION": "ACCEPT",
                "PRIORITY": "100"
            }
        }
    }

    st.log("Applying new acl rules, one accept and one drop rule")
    acl_obj.apply_acl_config(vars.D1, acl_json)

    acl_tables = acl_obj.show_acl_table(vars.D1)[0]
    for table in data['tables_new']:
        if table not in acl_tables:
            st.report_fail(f"Failed to add new cacl table: {table}")

    acl_rules = acl_obj.show_acl_rule(vars.D1)
    for table in data['tables_new']:
        if f"{table}|{data['rule_no']}" not in acl_rules:
            st.report_fail(f"Failed to add new cacl rule: {table}|{data['rule_no']}")

    st.log("Verifying acl rule translated to iptables successfully")

    verify_iptable(proto=89, source=data["ip_addr"], jump="DROP")
    verify_iptable(proto=103, source=data["ipv6_addr"], jump="ACCEPT")

    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_deleting_cacl_table_rule():
    """
    Verify control plane acl policies get deleted
    """

    acl_tables = ["control-plane-new-v4", "control-plane-new-v6"]
    st.log("Deleting newly added acl rules")
    for acl_table in acl_tables:
        acl_obj.delete_acl_rule(vars.D1, acl_table_name=acl_table, acl_rule_name=data["rule_no"])

    acl_rules_out = acl_obj.show_acl_rule(vars.D1)
    for table in data['tables_new']:
        if f"{table}|{data['rule_no']}" in acl_rules_out:
            st.report_fail(f"Failed to delete cacl rule: {table}|{data['rule_no']}")

    st.log("Deleting newly added acl tables")
    for acl_table in acl_tables:
        acl_obj.delete_acl_table(vars.D1, acl_table_name=acl_table)

    acl_tables_out = acl_obj.show_acl_table(vars.D1)[0]
    for table in data['tables_new']:
        if table in acl_tables_out:
            st.report_fail(f"Failed to delete cacl table: {table}")

    st.log("Verifying acl rule deleted from iptables successfully")

    verify_iptable(proto=89, source=data["ip_addr"], jump="DROP", present=False)
    verify_iptable(proto=103, source=data["ipv6_addr"], jump="ACCEPT", present=False)

    st.report_pass("test_case_passed")
