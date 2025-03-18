import logging
import pytest
import json
import time
import netaddr
import ptf.testutils as testutils
from ptf import mask, packet
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa F401
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology("t0")
]

logger = logging.getLogger(__name__)


STRESS_ACL_TABLE_TYPE_NAME = "STRESS_ACL_TABLE_TYPE"
STRESS_ACL_TABLE_NAME = "STRESS_ACL_TABLE"

STRESS_ACL_TABLE_TYPE_SRC = "acl/templates/stress_table_type.json"
STRESS_ACL_TABLE_TYPE_DST = "/tmp/stress_table_type.json"

STRESS_ACL_TABLE_CREATE_JSON_SRC = "acl/templates/create_stress_acl_table.j2"
STRESS_ACL_TABLE_CREATE_JSON_DST = "/tmp/create_stress_acl_table.json"

STRESS_ACL_RULE_JSON_FILE = "/tmp/stress_acl_rules.json"
STRESS_ACL_RULE_V4_REMOVE_JSON_FILE = "/tmp/stress_acl_rules_v4_remove.json"
STRESS_ACL_RULE_V6_REMOVE_JSON_FILE = "/tmp/stress_acl_rules_v6_remove.json"
STRESS_ACL_RULE_V4_ADD_JSON_FILE = "/tmp/stress_acl_rules_v4_add.json"
STRESS_ACL_RULE_V6_ADD_JSON_FILE = "/tmp/stress_acl_rules_v6_add.json"
STRESS_ACL_RULE_V4_UPDATE_JSON_FILE = "/tmp/stress_acl_rules_v4_update.json"
STRESS_ACL_RULE_V6_UPDATE_JSON_FILE = "/tmp/stress_acl_rules_v6_update.json"

STRESS_ACL_RULE_GROUPS = {
    # IPv4 rules that never changed
    "RULE_IPV4_GROUP_1": [],
    # IPv4 rules that will be updated
    "RULE_IPV4_GROUP_2": [],
    # IPv4 rules that will be used to overwrite rules in group 2
    "RULE_IPV4_GROUP_3": [],
    # IPv6 rules that never changed
    "RULE_IPV6_GROUP_1": [],
    # IPv6 rules that will be updated
    "RULE_IPV6_GROUP_2": [],
    # IPv6 rules that will be used to overwrite rules in group 2
    "RULE_IPV6_GROUP_3": []
}


def prepare_stress_acl_rules():
    """
    A helper function to generate 700 stress acl rules
    """
    global STRESS_ACL_RULE_GROUPS
    count = 1
    # 250 IPv4 rules in group 1
    RULE_TEMPLATE = "123.1.1.{}"
    for i in range(1, 251):
        STRESS_ACL_RULE_GROUPS["RULE_IPV4_GROUP_1"].append((count, RULE_TEMPLATE.format(i)))
        count += 1
    # 100 IPv4 rules in group 2
    RULE_TEMPLATE = "123.1.2.{}"
    for i in range(1, 101):
        STRESS_ACL_RULE_GROUPS["RULE_IPV4_GROUP_2"].append((count, RULE_TEMPLATE.format(i)))
        count += 1
    # 100 IPv4 rules in group 3
    RULE_TEMPLATE = "123.1.3.{}"
    for i in range(1, 101):
        STRESS_ACL_RULE_GROUPS["RULE_IPV4_GROUP_3"].append(
            (STRESS_ACL_RULE_GROUPS["RULE_IPV4_GROUP_2"][i - 1][0], RULE_TEMPLATE.format(i)))
    # 250 IPv6 rules in group 1
    RULE_TEMPLATE = "2001:db8:1:1::{}"
    for i in range(1, 251):
        STRESS_ACL_RULE_GROUPS["RULE_IPV6_GROUP_1"].append((count, RULE_TEMPLATE.format(i)))
        count += 1
    # 100 IPv6 rules in group 2
    RULE_TEMPLATE = "2001:db8:1:2::{}"
    for i in range(1, 101):
        STRESS_ACL_RULE_GROUPS["RULE_IPV6_GROUP_2"].append((count, RULE_TEMPLATE.format(i)))
        count += 1
    # 100 IPv6 rules in group 3
    RULE_TEMPLATE = "2001:db8:1:3::{}"
    for i in range(1, 101):
        STRESS_ACL_RULE_GROUPS["RULE_IPV6_GROUP_3"].append(
            (STRESS_ACL_RULE_GROUPS["RULE_IPV6_GROUP_2"][i - 1][0], RULE_TEMPLATE.format(i)))


@pytest.fixture(scope="module", autouse=True)
def remove_dataacl_table(duthosts, rand_selected_dut):
    """
    Remove DATAACL to free TCAM resources.
    The change is written to configdb as we don't want DATAACL recovered after reboot
    """
    TABLE_NAME_1 = "DATAACL"
    for duthost in duthosts:
        lines = duthost.shell(cmd="show acl table {}".format(TABLE_NAME_1))['stdout_lines']
        data_acl_existing = False
        for line in lines:
            if TABLE_NAME_1 in line:
                data_acl_existing = True
                break

        if data_acl_existing:
            # Remove DATAACL
            logger.info("Removing ACL table {}".format(TABLE_NAME_1))
            rand_selected_dut.shell(cmd="config acl remove table {}".format(TABLE_NAME_1))

    if not data_acl_existing:
        yield
        return

    yield
    # Recover DATAACL
    config_db_json = "/etc/sonic/config_db.json"
    output = rand_selected_dut.shell("sonic-cfggen -j {} --var-json \"ACL_TABLE\"".format(config_db_json))['stdout']
    entry_json = json.loads(output)
    if TABLE_NAME_1 in entry_json:
        entry = entry_json[TABLE_NAME_1]
        cmd_create_table = "config acl add table {} {} -p {} -s {}"\
            .format(TABLE_NAME_1, entry['type'], ",".join(entry['ports']), entry['stage'])
        logger.info("Restoring ACL table {}".format(TABLE_NAME_1))
        rand_selected_dut.shell(cmd_create_table)


@pytest.fixture(scope="module")
def setup_info(rand_selected_dut, tbinfo):
    """
    A fixture to get test setup info
    """
    setup_info = {}

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)

    # Get router MAC
    vlan_name = list(mg_facts['minigraph_vlans'].keys())[0]
    if "dualtor" in tbinfo["topo"]["name"]:
        # Use VLAN MAC as router MAC on dual-tor testbed
        setup_info['router_mac'] = rand_selected_dut.get_dut_iface_mac(vlan_name)
        setup_info['is_dualtor'] = True
    else:
        setup_info['router_mac'] = rand_selected_dut.facts['router_mac']
        setup_info['is_dualtor'] = False

    # Get the list of upstream/downstream ports
    downstream_ports = []
    upstream_ports = []
    downstream_port_ids = []
    upstream_port_ids = []

    # Put all VLAN members into downstream_ports
    downstream_ports = list(mg_facts["minigraph_vlans"][vlan_name]["members"])
    downstream_port_ids = [mg_facts['minigraph_ptf_indices'][port_name] for port_name in downstream_ports]
    # Put all portchannel members into dst_ports
    for _, v in mg_facts['minigraph_portchannels'].items():
        for member in v['members']:
            upstream_port_ids.append(mg_facts['minigraph_ptf_indices'][member])
            upstream_ports.append(member)

    setup_info['downstream_ports'] = downstream_ports
    setup_info['upstream_ports'] = upstream_ports
    setup_info['downstream_port_ids'] = downstream_port_ids
    setup_info['upstream_port_ids'] = upstream_port_ids

    yield setup_info


@pytest.fixture(scope="module")
def setup_stress_acl_table(rand_selected_dut, setup_info):
    """
    Create a custom ACL table (combined V4 and V6) for testing
    """
    # Step 1: Define a custom ACL table type STRESS_ACL_TABLE_TYPE by loading a json configuration
    rand_selected_dut.copy(src=STRESS_ACL_TABLE_TYPE_SRC, dest=STRESS_ACL_TABLE_TYPE_DST, mode="0755")
    rand_selected_dut.shell("config apply-patch {}".format(STRESS_ACL_TABLE_TYPE_DST))
    time.sleep(5)
    # Step 2: Create a custom ACL table of type STRESS_ACL_TABLE_TYPE. The table is bound to all Vlan ports
    extra_vars = {
        'bind_ports': setup_info['downstream_ports']
        }
    rand_selected_dut.host.options['variable_manager'].extra_vars.update(extra_vars)
    rand_selected_dut.template(src=STRESS_ACL_TABLE_CREATE_JSON_SRC, dest=STRESS_ACL_TABLE_CREATE_JSON_DST)
    rand_selected_dut.shell("sed -i \"s/'/\\\"/g\" " + STRESS_ACL_TABLE_CREATE_JSON_DST)
    rand_selected_dut.shell("config apply-patch {}".format(STRESS_ACL_TABLE_CREATE_JSON_DST))
    time.sleep(5)
    # Check if the table is created successfully
    acl_table_status = rand_selected_dut.show_and_parse('show acl table {}'.format(STRESS_ACL_TABLE_NAME))
    pytest_assert(acl_table_status[0]['status'].lower() == 'active', "Failed to create ACL table")

    yield

    # Remove ACL table STRESS_ACL_TABLE
    rand_selected_dut.shell("config acl remove table {}".format(STRESS_ACL_TABLE_NAME))
    # Remove custom ACL table type STRESS_ACL_TABLE_TYPE
    rand_selected_dut.shell("sonic-db-cli CONFIG_DB del \"ACL_TABLE_TYPE|{}\"".format(STRESS_ACL_TABLE_TYPE_NAME))


def prepare_acl_rule_update_files(duthost, group_names, file_name, oper="add", default_drop_rule=False):
    """
    Copy json files for update test to DUT
    """
    patch = []

    if oper == "add":
        patch.append({})
        patch[0]["path"] = "/ACL_RULE"
        patch[0]["value"] = {}
        patch[0]["op"] = "add"

    for group in group_names:
        for id, ip in STRESS_ACL_RULE_GROUPS[group]:
            if oper == "add":
                if netaddr.IPAddress(ip).version == 4:
                    key = "DST_IP"
                    ip_mask = ip + "/32"
                else:
                    key = "DST_IPV6"
                    ip_mask = ip + "/128"
                rule = {
                        "{}|RULE_{}".format(STRESS_ACL_TABLE_NAME, id): {
                            "PRIORITY": 900 - id,
                            "PACKET_ACTION": "FORWARD",
                            key: ip_mask
                        }
                        }
                patch[0]["value"].update(rule)
            else:
                rule = {
                    "op": "remove",
                    "path": "/ACL_RULE/{}|RULE_{}".format(STRESS_ACL_TABLE_NAME, id)
                }
                patch.append(rule)
    if default_drop_rule:
        # Add a default rule to drop all other traffic
        patch[0]["value"].update({
                "{}|RULE_DROP_2".format(STRESS_ACL_TABLE_NAME): {
                    "PRIORITY": 2,
                    "IP_TYPE": "IPV6ANY",
                    "PACKET_ACTION": "DROP"
                },
                "{}|RULE_DROP_1".format(STRESS_ACL_TABLE_NAME): {
                    "PRIORITY": 1,
                    "ETHER_TYPE": 0x0800,
                    "PACKET_ACTION": "DROP"
                    }
                })
    # Dump json to file
    TMP_FILE = "/tmp/tmp_acl_rules.json"
    with open(TMP_FILE, "w") as f:
        json.dump(patch, f)
    # Copy json file to DUT
    duthost.copy(src=TMP_FILE, dest=file_name, mode="0755")
    duthost.shell("sed -i \"s/'/\\\"/g\" " + file_name)


def apply_acl_rule_patch(duthost, file_name, group_names=(), oper="add"):
    """
    Apply patch to DUT
    """
    duthost.shell("config apply-patch {}".format(file_name), module_ignore_errors=True)
    rule_list = []
    for group_name in group_names:
        for id, _ in STRESS_ACL_RULE_GROUPS[group_name]:
            rule_list.append("RULE_{}".format(id))
    if oper == "add":
        # For add operation, check and confirm all rules are active
        def _check_acl_rule_status():
            count = 0
            acl_rule_status = duthost.show_and_parse('show acl rule {}'.format(STRESS_ACL_TABLE_NAME))
            for rule in acl_rule_status:
                if rule['rule'] in rule_list and rule['status'].lower() == 'active':
                    count += 1
            return count == len(rule_list)
        wait_until(60, 5, 10, _check_acl_rule_status, "Not all ACL rules are active")
    else:
        # For remove operation, delay for 30 seconds to let the rules removed
        time.sleep(30)


@pytest.fixture(scope="module")
def setup_stress_acl_rules_cli(rand_selected_dut, setup_stress_acl_table):
    """
    Fixture to create stress acl rules with redis-db cli
    """
    prepare_stress_acl_rules()
    yield
    # Remove all ACL rules
    rand_selected_dut.shell("acl-loader delete {}".format(STRESS_ACL_TABLE_NAME))


@pytest.fixture(scope="module")
def setup_stress_acl_rules(rand_selected_dut, setup_stress_acl_table):
    """
    Fixture to create stress acl rules
    """
    prepare_stress_acl_rules()
    group_names = ["RULE_IPV4_GROUP_1", "RULE_IPV4_GROUP_2", "RULE_IPV6_GROUP_1", "RULE_IPV6_GROUP_2"]
    prepare_acl_rule_update_files(rand_selected_dut,
                                  group_names,
                                  file_name=STRESS_ACL_RULE_JSON_FILE,
                                  default_drop_rule=True)
    # Copy other json files to DUT
    prepare_acl_rule_update_files(rand_selected_dut, ["RULE_IPV4_GROUP_2"],
                                  STRESS_ACL_RULE_V4_REMOVE_JSON_FILE, oper="remove"),
    prepare_acl_rule_update_files(rand_selected_dut, ["RULE_IPV6_GROUP_2"],
                                  STRESS_ACL_RULE_V6_REMOVE_JSON_FILE, oper="remove"),
    prepare_acl_rule_update_files(rand_selected_dut, ["RULE_IPV4_GROUP_3"],
                                  STRESS_ACL_RULE_V4_ADD_JSON_FILE, oper="add"),
    prepare_acl_rule_update_files(rand_selected_dut, ["RULE_IPV6_GROUP_3"],
                                  STRESS_ACL_RULE_V6_ADD_JSON_FILE, oper="add")

    yield
    # Remove all ACL rules
    rand_selected_dut.shell("acl-loader delete {}".format(STRESS_ACL_TABLE_NAME))


def add_acl_rules(duthost, group_name, fwd=True, default_drop_rule=False):
    """
    Add ACL rules
    """
    cmds = []
    rule_list = []
    if fwd:
        action = "FORWARD"
    else:
        action = "DROP"
    for id, ip in STRESS_ACL_RULE_GROUPS[group_name]:
        if netaddr.IPAddress(ip).version == 4:
            key = "DST_IP"
            ip_mask = ip + "/32"
        else:
            key = "DST_IPV6"
            ip_mask = ip + "/128"
        cmds.append(
            "sonic-db-cli CONFIG_DB hmset \'ACL_RULE|{}|RULE_{}\' {} {} PRIORITY {} PACKET_ACTION {}".format(
                STRESS_ACL_TABLE_NAME, id, key, ip_mask, 900 - id, action))
        rule_list.append("RULE_{}".format(id))

    if default_drop_rule:
        cmds.append(
            "sonic-db-cli CONFIG_DB hmset \'ACL_RULE|{}|RULE_DROP_2\' IP_TYPE IPV6ANY PRIORITY 2 PACKET_ACTION DROP"
            .format(STRESS_ACL_TABLE_NAME))
        cmds.append(
            "sonic-db-cli CONFIG_DB hmset \'ACL_RULE|{}|RULE_DROP_1\' ETHER_TYPE 0x0800 PRIORITY 1 PACKET_ACTION DROP"
            .format(STRESS_ACL_TABLE_NAME))
        rule_list.extend(["RULE_DROP_1", "RULE_DROP_2"])

    duthost.shell_cmds(cmds=cmds)

    # Verify all rules are active
    def _check_acl_rule_status():
        count = 0
        acl_rule_status = duthost.show_and_parse('show acl rule {}'.format(STRESS_ACL_TABLE_NAME))
        for rule in acl_rule_status:
            if rule['rule'] in rule_list and rule['status'].lower() == 'active':
                count += 1
        return count == len(rule_list)

    pytest_assert(wait_until(0.5*len(rule_list), 5, 10, _check_acl_rule_status), "Not all ACL rules are active")


def remove_acl_rules(duthost, group_name):
    """
    Remove ACL rules
    """
    cmds = []
    for id, _ in STRESS_ACL_RULE_GROUPS[group_name]:
        cmds.append("sonic-db-cli CONFIG_DB del \'ACL_RULE|{}|RULE_{}\'".format(STRESS_ACL_TABLE_NAME, id))
    duthost.shell_cmds(cmds=cmds)
    # There is no way to verify rules are removed from ASIC, so we just wait for a few seconds
    time.sleep(0.5 * len(cmds))


def verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports, router_mac, ip, fwd=True):
    """
    Build testing packet to veryfy ACL rule
    """
    if netaddr.IPAddress(ip).version == 4:
        pkt = testutils.simple_udp_packet(
            eth_dst=router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
            ip_src="192.168.0.100",
            ip_dst=ip
        )

        pkt_copy = pkt.copy()
        pkt_copy['IP'].ttl -= 1
        exp_pkt = mask.Mask(pkt_copy)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.IP, "chksum")
    else:
        pkt = testutils.simple_udpv6_packet(
            eth_dst=router_mac,
            eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port),
            ipv6_src="fc02:1000::100",
            ipv6_dst=ip
        )
        pkt_copy = pkt.copy()
        pkt_copy['IPv6'].hlim -= 1
        exp_pkt = mask.Mask(pkt_copy)
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
        exp_pkt.set_do_not_care_scapy(packet.UDP, "chksum")

    RETRY = 3
    while RETRY > 0:
        ptfadapter.dataplane.flush()
        testutils.send(test=ptfadapter, port_id=ptf_src_port, pkt=pkt)
        if fwd:
            try:
                testutils.verify_packet_any_port(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)
            except Exception as e:
                if RETRY == 0:
                    raise e
                else:
                    logger.info("Retrying...")
                    RETRY -= 1
            else:
                break
        else:
            testutils.verify_no_packet_any(test=ptfadapter, pkt=exp_pkt, ports=ptf_dst_ports)
            break


def verify_acl_rules_group(rand_selected_dut, ptfadapter, setup_info, group_name, fwd=True):
    """
    Verify ACL rules in a group
    """
    ptf_src_port, ptf_dst_ports, router_mac = setup_info['downstream_port_ids'][0], setup_info['upstream_port_ids'], \
        setup_info['router_mac']
    for id, ip in STRESS_ACL_RULE_GROUPS[group_name]:
        verify_acl_rules(rand_selected_dut, ptfadapter, ptf_src_port, ptf_dst_ports, router_mac, ip, fwd=fwd)


def test_stress_acl_with_custom_acl_table(rand_selected_dut, tbinfo, ptfadapter, setup_info, setup_stress_acl_rules_cli,
                                          toggle_all_simulator_ports_to_rand_selected_tor):   # noqa F811
    """
    Test stress acl with custom acl table
    """
    LOOP = 1000
    group_names = ["RULE_IPV4_GROUP_1", "RULE_IPV4_GROUP_2", "RULE_IPV6_GROUP_1", "RULE_IPV6_GROUP_2"]

    for i in range(LOOP):
        logger.info("Stress ACL test loop: {}".format(i))
        logger.info("Creating ACL rules")
        # Apply patch
        for group in group_names:
            add_acl_rules(rand_selected_dut, group, fwd=True, default_drop_rule=True)
        # Verify all ACL rules
        logger.info("Verifying all ACL rules")
        for group in group_names:
            verify_acl_rules_group(rand_selected_dut, ptfadapter, setup_info, group, fwd=True)

        # Update 1: Remove all the rules in "RULE_IPV4_GROUP_2"
        logger.info("Removing IPv4 ACL rules")
        remove_acl_rules(rand_selected_dut, "RULE_IPV4_GROUP_2")
        logger.info("Verifying IPv4 ACL rules are removed")
        verify_acl_rules_group(rand_selected_dut, ptfadapter, setup_info, "RULE_IPV4_GROUP_2", fwd=False)

        # Update 2: Add a new set of IPv4 rules in "RULE_IPV4_GROUP_3"
        logger.info("Adding new IPv4 ACL rules")
        add_acl_rules(rand_selected_dut, "RULE_IPV4_GROUP_3", fwd=True)
        logger.info("Verifying new IPv4 ACL rules")
        verify_acl_rules_group(rand_selected_dut, ptfadapter, setup_info, "RULE_IPV4_GROUP_3", fwd=True)

        # Update 3: Remove all the rules in "RULE_IPV6_GROUP_2"
        logger.info("Removing IPv6 ACL rules")
        remove_acl_rules(rand_selected_dut, "RULE_IPV6_GROUP_2")
        logger.info("Verifying IPv6 ACL rules are removed")
        verify_acl_rules_group(rand_selected_dut, ptfadapter, setup_info, "RULE_IPV6_GROUP_2", fwd=False)

        # Update 4: Add a new set of IPv6 rules in "RULE_IPV6_GROUP_3"
        logger.info("Adding new IPv6 ACL rules")
        add_acl_rules(rand_selected_dut, "RULE_IPV6_GROUP_3", fwd=True)
        logger.info("Verifying new IPv6 ACL rules")
        verify_acl_rules_group(rand_selected_dut, ptfadapter, setup_info, "RULE_IPV6_GROUP_3", fwd=True)

        # Update 5: Remove all ACL rules
        logger.info("Removing all ACL rules")
        rand_selected_dut.shell("acl-loader delete {}".format(STRESS_ACL_TABLE_NAME))

        logger.info("Stress ACL test loop {} done".format(i))
