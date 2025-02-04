import pytest
import time
import json
import ipaddress
import netaddr
import copy
import logging
import os
import tempfile

from jinja2 import Template
from tests.common.cisco_data import is_cisco_device
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.crm import get_used_percent, CRM_UPDATE_TIME, CRM_POLLING_INTERVAL, EXPECT_EXCEEDED, \
     EXPECT_CLEAR, THR_VERIFY_CMDS
from tests.common.fixtures.duthost_utils import disable_route_checker   # noqa F401
from tests.common.fixtures.duthost_utils import disable_fdb_aging       # noqa F401
from tests.common.utilities import wait_until, get_data_acl
from tests.common.mellanox_data import is_mellanox_device
from tests.common.helpers.dut_utils import get_sai_sdk_dump_file


pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

SONIC_RES_UPDATE_TIME = 50
CISCO_8000_ADD_NEIGHBORS = 3000
ACL_TABLE_NAME = "DATAACL"

RESTORE_CMDS = {"test_crm_route": [],
                "test_crm_nexthop": [],
                "test_crm_neighbor": [],
                "test_crm_nexthop_group": [],
                "test_acl_entry": [],
                "test_acl_counter": [],
                "test_crm_fdb_entry": [],
                "crm_cli_res": None,
                "wait": 0}

NS_PREFIX_TEMPLATE = """
    {% set ns_prefix = '' %}
    {% set ns_option = '-n '%}
    {% if namespace %}
    {% set ns_prefix = ns_option ~ namespace %}
    {% endif %}"""


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
    """Ignore expected failures logs during test execution.

    We don't have control over the order events are received by orchagent, so it is
    possible that we attempt to remove the VLAN before its members are removed. This results
    in error messages initially, but subsequent retries will succeed once the VLAN member is
    removed.

    Args:
        enum_rand_one_per_hwsku_frontend_hostname: Fixture to randomly pick a frontend DUT from the testbed
        loganalyzer: Loganalyzer utility fixture

    """
    ignoreRegex = [
        ".*ERR swss#orchagent.*removeVlan: Failed to remove non-empty VLAN.*"
    ]
    # Ignore in KVM test
    KVMIgnoreRegex = [
        ".*flushFdbEntries: failed to find fdb entry in info set.*"
    ]
    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        if duthost.facts["asic_type"] == "vs":
            loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(KVMIgnoreRegex)


@pytest.fixture(scope="function")
def handle_default_acl_rules(duthost, tbinfo):
    """
    Cleanup all the existing DATAACL rules and re-create them at the end of the test
    """
    data_acl = get_data_acl(duthost)
    if data_acl:
        duthost.shell('acl-loader delete DATAACL')
        RESTORE_CMDS["test_acl_counter"].append({"data_acl": data_acl})


def apply_acl_config(duthost, asichost, test_name, collector, entry_num=1):
    """ Create acl rule defined in config file. Return ACL table key. """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, "templates")
    acl_rules_template = "acl.json"
    dut_tmp_dir = "/tmp-{}".format(asichost.asic_index)

    duthost.command("mkdir -p {}".format(dut_tmp_dir))
    dut_conf_file_path = os.path.join(dut_tmp_dir, acl_rules_template)

    # Define test cleanup commands
    RESTORE_CMDS[test_name].append("rm -rf {}".format(dut_conf_file_path))
    RESTORE_CMDS[test_name].append("acl-loader delete")

    if entry_num == 1:
        logger.info("Generating config for ACL rule, ACL table - DATAACL")
        duthost.template(src=os.path.join(template_dir, acl_rules_template), dest=dut_conf_file_path, force=True)
    elif entry_num > 1:
        acl_config = json.loads(open(os.path.join(template_dir, acl_rules_template)).read())
        acl_entry_template = acl_config["acl"]["acl-sets"]["acl-set"]["dataacl"]["acl-entries"]["acl-entry"]["1"]
        acl_entry_config = acl_config["acl"]["acl-sets"]["acl-set"]["dataacl"]["acl-entries"]["acl-entry"]
        for seq_id in range(2, entry_num + 2):
            acl_entry_config[str(seq_id)] = copy.deepcopy(acl_entry_template)
            acl_entry_config[str(seq_id)]["config"]["sequence-id"] = seq_id

        with tempfile.NamedTemporaryFile(suffix=".json", prefix="acl_config", mode="w") as fp:
            json.dump(acl_config, fp)
            fp.flush()
            logger.info("Generating config for ACL rule, ACL table - DATAACL")
            duthost.template(src=fp.name, dest=dut_conf_file_path, force=True)
    else:
        raise Exception("Incorrect number of ACL entries specified - {}".format(entry_num))

    logger.info("Applying {}".format(dut_conf_file_path))
    output = duthost.command("acl-loader update full {}".format(dut_conf_file_path))['stdout']
    if 'DATAACL table does not exist' in output:
        pytest.skip("DATAACL does not exist")

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    collector["acl_tbl_key"] = get_acl_tbl_key(asichost)


def generate_mac(num):
    """ Generate list of MAC addresses in format XX-XX-XX-XX-XX-XX """
    mac_list = list()
    for mac_postfix in range(1, num + 1):
        mac_list.append(str(netaddr.EUI(mac_postfix)))
    return mac_list


def is_cel_e1031_device(duthost):
    return duthost.facts["platform"] == "x86_64-cel_e1031-r0"


def generate_fdb_config(duthost, entry_num, vlan_id, iface, op, dest):
    """ Generate FDB config file to apply it using 'swssconfig' tool.
    Generated config file template:
    [
        {
            "FDB_TABLE:Vlan[VID]:XX-XX-XX-XX-XX-XX": {
                "port": "Ethernet0",
                "type": "dynamic"
            },
            "OP": "SET"
        }
    ]
    """
    fdb_config_json = []
    entry_key_template = "FDB_TABLE:Vlan{vid}:{mac}"

    for mac_address in generate_mac(entry_num):
        fdb_entry_json = {entry_key_template.format(vid=vlan_id, mac=mac_address):
                          {"port": iface, "type": "dynamic"},
                          "OP": op
                          }
        fdb_config_json.append(fdb_entry_json)

    with tempfile.NamedTemporaryFile(suffix=".json", prefix="fdb_config", mode="w") as fp:
        logger.info("Generating FDB config")
        json.dump(fdb_config_json, fp)
        fp.flush()

        # Copy FDB JSON config to switch
        duthost.template(src=fp.name, dest=dest, force=True)


def apply_fdb_config(duthost, test_name, vlan_id, iface, entry_num):
    """ Creates FDB config and applies it on DUT """
    dut_tmp_dir = "/tmp"
    fdb_json = "fdb.json"
    dut_fdb_config = os.path.join(dut_tmp_dir, fdb_json)
    rm_fdb_swss = "docker exec -i swss rm /fdb.json"

    # Remove FDB JSON config from switch.
    if "rm {}".format(dut_fdb_config) not in RESTORE_CMDS[test_name]:
        RESTORE_CMDS[test_name].append("rm {}".format(dut_fdb_config))
    # Remove FDB JSON config from SWSS container
    if rm_fdb_swss not in RESTORE_CMDS[test_name]:
        RESTORE_CMDS[test_name].append(rm_fdb_swss)

    duthost.command("mkdir -p {}".format(dut_tmp_dir))

    if entry_num < 1:
        raise Exception("Incorrect number of FDB entries specified - {}".format(entry_num))

    # Generate FDB config and store it to DUT
    generate_fdb_config(duthost, entry_num, vlan_id, iface, "SET", dut_fdb_config)

    # Copy FDB JSON config to SWSS container
    cmd = "docker cp {} swss:/".format(dut_fdb_config)
    duthost.command(cmd)

    # Add FDB entry
    cmd = "docker exec -i swss swssconfig /fdb.json"
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)


def get_acl_tbl_key(asichost):
    """ Get ACL entry keys """
    cmd = "{} ASIC_DB KEYS \"*SAI_OBJECT_TYPE_ACL_ENTRY*\"".format(asichost.sonic_db_cli)
    acl_tbl_keys = asichost.shell(cmd)["stdout"].split()

    # Get ethertype for ACL entry and match ACL which was configured to ethertype value
    cmd = "{db_cli} ASIC_DB HGET {item} \"SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE\""
    for item in acl_tbl_keys:
        out = asichost.shell(cmd.format(db_cli=asichost.sonic_db_cli, item=item))["stdout"]
        logging.info(out)
        if "2048" in out:
            key = item
            break
    else:
        pytest.fail("Ether type was not found in SAI ACL Entry table")

    # Get ACL table key
    cmd = "{db_cli} ASIC_DB HGET {key} \"SAI_ACL_ENTRY_ATTR_TABLE_ID\""
    oid = asichost.shell(cmd.format(db_cli=asichost.sonic_db_cli, key=key))["stdout"]
    logging.info(oid)
    acl_tbl_key = "CRM:ACL_TABLE_STATS:{0}".format(oid.replace("oid:", ""))

    return acl_tbl_key


def verify_thresholds(duthost, asichost, **kwargs):
    """
    Verifies that WARNING message logged if there are any resources that exceeds a pre-defined threshold value.
    Verifies the following threshold parameters: percentage, actual used, actual free
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='crm_test')
    for key, value in list(THR_VERIFY_CMDS.items()):
        logger.info("Verifying CRM threshold '{}'".format(key))
        template = Template(value)
        if "exceeded" in key:
            loganalyzer.expect_regex = [EXPECT_EXCEEDED]
        elif "clear" in key:
            loganalyzer.expect_regex = [EXPECT_CLEAR]

        if "percentage" in key:
            if "nexthop_group" in kwargs["crm_cli_res"] and "mellanox" in duthost.facts["asic_type"].lower():
                # TODO: Fix this. Temporal skip percentage verification for 'test_crm_nexthop_group' test case
                # Max supported ECMP group values is less then number of entries we need to configure
                # in order to test percentage threshold (Can't even reach 1 percent)
                # For test case used 'nexthop_group' need to be configured at least 1 percent from available
                continue
            if kwargs["crm_cli_res"] in ["ipv4 neighbor", "ipv6 neighbor"] and \
                    "cisco-8000" in duthost.facts["asic_type"].lower():
                # Skip the percentage check for Cisco-8000 devices
                continue
            used_percent = get_used_percent(kwargs["crm_used"], kwargs["crm_avail"])
            if key == "exceeded_percentage":
                if used_percent < 1:
                    logger.warning("The used percentage for {} is {} and \
                                   verification for exceeded_percentage is skipped"
                                   .format(kwargs["crm_cli_res"], used_percent))
                    continue
                kwargs["th_lo"] = used_percent - 1
                kwargs["th_hi"] = used_percent
                loganalyzer.expect_regex = [EXPECT_EXCEEDED]
            elif key == "clear_percentage":
                if used_percent >= 100 or used_percent < 1:
                    logger.warning("The used percentage for {} is {} and verification for clear_percentage is skipped"
                                   .format(kwargs["crm_cli_res"], used_percent))
                    continue
                kwargs["th_lo"] = used_percent
                kwargs["th_hi"] = used_percent + 1
                loganalyzer.expect_regex = [EXPECT_CLEAR]

        kwargs['crm_used'], kwargs['crm_avail'] = get_crm_stats(kwargs['crm_cmd'], duthost)
        cmd = template.render(**kwargs)

        with loganalyzer:
            asichost.command(cmd)
            # Make sure CRM counters updated
            time.sleep(CRM_UPDATE_TIME)


def get_crm_stats(cmd, duthost):
    """ Return used and available CRM statistics from command result """
    out = duthost.command(cmd)
    crm_stats_used = int(out["stdout_lines"][0])
    crm_stats_available = int(out["stdout_lines"][1])
    return crm_stats_used, crm_stats_available


def check_crm_stats(cmd, duthost, origin_crm_stats_used, origin_crm_stats_available,
                    oper_used="==", oper_ava="==", skip_stats_check=False):
    if skip_stats_check is True:
        logger.info("Skip CRM stats check")
        return True
    crm_stats_used, crm_stats_available = get_crm_stats(cmd, duthost)
    if eval("{} {} {}".format(crm_stats_used, oper_used, origin_crm_stats_used)) and \
            eval("{} {} {}".format(crm_stats_available, oper_ava, origin_crm_stats_available)):
        return True
    else:
        return False


def generate_neighbors(amount, ip_ver):
    """ Generate list of IPv4 or IPv6 addresses """
    if ip_ver == "4":
        ip_addr_list = list(ipaddress.IPv4Network("%s" % "2.0.0.0/8").hosts())[0:amount]
    elif ip_ver == "6":
        ip_addr_list = list(ipaddress.IPv6Network("%s" % "2001::/112").hosts())[0:amount]
    else:
        pytest.fail("Incorrect IP version specified - {}".format(ip_ver))
    return ip_addr_list


def configure_nexthop_groups(amount, interface, asichost, test_name):
    """ Configure bunch of nexthop groups on DUT. Bash template is used to speedup configuration """
    # Template used to speedup execution many similar commands on DUT
    del_template = """
    %s
    ip -4 {{ns_prefix}} route del 2.0.0.0/8 dev {{iface}}
    ip {{ns_prefix}} neigh del 2.0.0.1 lladdr 11:22:33:44:55:66 dev {{iface}}
    for s in {{neigh_ip_list}}
    do
        ip {{ns_prefix}} neigh del ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        ip -4 {{ns_prefix}} route del ${s}/32 nexthop via ${s} nexthop via 2.0.0.1
    done""" % (NS_PREFIX_TEMPLATE)

    add_template = """
    %s
    ip -4 {{ns_prefix}} route add 2.0.0.0/8 dev {{iface}}
    ip {{ns_prefix}} neigh replace 2.0.0.1 lladdr 11:22:33:44:55:66 dev {{iface}}
    for s in {{neigh_ip_list}}
    do
        ip  {{ns_prefix}} neigh replace ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        ip -4 {{ns_prefix}} route add ${s}/32 nexthop via ${s} nexthop via 2.0.0.1
    done""" % (NS_PREFIX_TEMPLATE)

    del_template = Template(del_template)
    add_template = Template(add_template)

    ip_addr_list = generate_neighbors(amount + 1, "4")
    ip_addr_list = " ".join([str(item) for item in ip_addr_list[1:]])
    # Store CLI command to delete all created neighbors if test case will fail
    RESTORE_CMDS[test_name].append(del_template.render(iface=interface,
                                                       neigh_ip_list=ip_addr_list,
                                                       namespace=asichost.namespace))
    logger.info("Configuring {} nexthop groups".format(amount))
    asichost.shell(add_template.render(iface=interface,
                                       neigh_ip_list=ip_addr_list,
                                       namespace=asichost.namespace))


def increase_arp_cache(duthost, max_value, ip_ver, test_name):
    # Increase default Linux configuration for ARP cache
    set_cmd = "sysctl -w net.ipv{}.neigh.default.gc_thresh{}={}"
    get_cmd = "sysctl net.ipv{}.neigh.default.gc_thresh{}"
    logger.info("Increase ARP cache")
    for thresh_id in range(1, 4):
        res = duthost.shell(get_cmd.format(ip_ver, thresh_id))
        if res["rc"] != 0:
            logger.warning("Unable to get kernel ARP cache size: \n{}".format(res))
            continue

        try:
            # Sample output: net.ipv4.neigh.default.gc_thresh1 = 1024
            cur_th = int(res["stdout"].split()[-1])
        except ValueError:
            logger.warning("Unable to determine kernel ARP cache size: \n{}".format(res))
            continue

        if cur_th >= max_value + 100:
            logger.info("Skipping setting ARP cache size to {}, current {}".format(max_value, res['stdout']))
            continue

        # Add cleanup step to restore ARP cache
        RESTORE_CMDS[test_name].append("sysctl -w " + res["stdout"].replace(" ", ""))
        cmd = set_cmd.format(ip_ver, thresh_id, max_value + 100)
        duthost.shell(cmd)
        logger.info("{}".format(cmd))


def configure_neighbors(amount, interface, ip_ver, asichost, test_name):
    """ Configure bunch of IP neighbors on DUT. Bash template is used to speedup configuration """
    # Template used to speedup execution many similar commands on DUT
    del_template = """
    %s
    for s in {{neigh_ip_list}}
    do
        ip {{ns_prefix}} neigh del ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        echo deleted - ${s}
    done""" % (NS_PREFIX_TEMPLATE)

    add_template = """
    %s
    for s in {{neigh_ip_list}}
    do
        ip {{ns_prefix}} neigh replace ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        echo added - ${s}
    done""" % (NS_PREFIX_TEMPLATE)

    del_neighbors_template = Template(del_template)
    add_neighbors_template = Template(add_template)

    ip_addr_list = generate_neighbors(amount, ip_ver)
    ip_addr_list = " ".join([str(item) for item in ip_addr_list])

    # Store CLI command to delete all created neighbors
    RESTORE_CMDS[test_name].append(del_neighbors_template.render(
                            neigh_ip_list=ip_addr_list,
                            iface=interface,
                            namespace=asichost.namespace))

    # Increase default Linux configuration for ARP cache
    increase_arp_cache(asichost, amount, ip_ver, test_name)

    asichost.shell(add_neighbors_template.render(
                        neigh_ip_list=ip_addr_list,
                        iface=interface,
                        namespace=asichost.namespace))
    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)


def get_entries_num(used, available):
    """ Get number of entries needed to be created that 'used' counter reached one percent """
    return ((used + available) // 100) + 1


def get_crm_resources_fdb_and_ip_route(duthost, asic_ix):
    keys = ['ipv4_route', 'ipv6_route', 'fdb_entry']
    output = duthost.shell("crm show resources all")
    result = {}
    asic_str = ""
    asic_matched = False

    if duthost.sonichost.is_multi_asic:
        asic_str = 'ASIC' + str(asic_ix)

    for line in output['stdout_lines']:
        if line:
            line = line.split()
            if duthost.sonichost.is_multi_asic and asic_matched is False:
                if line[0] == asic_str:
                    asic_matched = True
                continue
            if line[0] in keys:
                counters = {'used': int(line[1]), 'available': int(line[2])}
                result[line[0]] = counters
                keys.remove(line[0])
                if not keys:
                    break
    pytest_assert(keys == [], "Failed to get crm resource for {}".format(str(keys)))
    return result


def get_nh_ip(duthost, asichost, crm_interface, ip_ver):
    # Get NH IP
    cmd = "{ip_cmd} -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale \
                        | grep -v fe80".format(ip_cmd=asichost.ip_cmd, ip_ver=ip_ver, crm_intf=crm_interface[0])
    out = duthost.shell(cmd)
    assert out["stdout"] != "", "Get Next Hop IP failed. Neighbor not found"
    nh_ip = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]
    return nh_ip


@pytest.mark.usefixtures('disable_route_checker')
@pytest.mark.parametrize("ip_ver,route_add_cmd,route_del_cmd", [("4", "{} route add 2.{}.2.0/24 via {}",
                                                                "{} route del 2.{}.2.0/24 via {}"),
                                                                ("6", "{} -6 route add 2001:{}::/126 via {}",
                                                                "{} -6 route del 2001:{}::/126 via {}")],
                         ids=["ipv4", "ipv6"])
def test_crm_route(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
                   crm_interface, ip_ver, route_add_cmd, route_del_cmd):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False
    RESTORE_CMDS["crm_threshold_name"] = "ipv{ip_ver}_route".format(ip_ver=ip_ver)

    # Template used to speedup execution of many similar commands on DUT
    del_template = """
    %s
    for s in {{routes_list}}
    do
        ip {{ns_prefix}} route del ${s} dev {{interface}}
        echo deleted route - ${s}
    done""" % (NS_PREFIX_TEMPLATE)

    add_template = """
    %s
    for s in {{routes_list}}
    do
        ip {{ns_prefix}} route add ${s} dev {{interface}}
        echo added route - ${s}
    done""" % (NS_PREFIX_TEMPLATE)

    del_routes_template = Template(del_template)
    add_routes_template = Template(add_template)

    # Get ipv[4/6]_route/fdb_entry used and available counter value
    crm_stats = get_crm_resources_fdb_and_ip_route(duthost, enum_frontend_asic_index)
    crm_stats_route_used = crm_stats['ipv{}_route'.format(ip_ver)]['used']
    crm_stats_route_available = crm_stats['ipv{}_route'.format(ip_ver)]['available']
    crm_stats_fdb_used = crm_stats['fdb_entry']['used']
    logging.info("crm_stats_route_used {}, crm_stats_route_available {}, crm_stats_fdb_used {}".format(
        crm_stats_route_used, crm_stats_route_available, crm_stats_fdb_used))
    # Get NH IP
    nh_ip = get_nh_ip(duthost, asichost, crm_interface, ip_ver)

    # Add IPv[4/6] routes
    # Cisco platforms need an upward of 64 routes for crm_stats_ipv4_route_available to decrement
    # Similar change is needed for broadcom DNX family based devices where by the higher routes helps
    # to get the correct used and available resource count.
    if is_cisco_device(duthost) and ip_ver == '4' or 'platform_asic' in duthost.facts \
            and duthost.facts['platform_asic'] == 'broadcom-dnx':
        total_routes = 64
    else:
        total_routes = 1
    for i in range(total_routes):
        route_add = route_add_cmd.format(asichost.ip_cmd, i, nh_ip)
        logging.info("route add cmd: {}".format(route_add))
        duthost.command(route_add)

    check_available_counters = True
    if duthost.facts['asic_type'] == 'broadcom':
        check_available_counters = False

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new ipv[4/6]_route/fdb_entry used and available counter value
    crm_stats = get_crm_resources_fdb_and_ip_route(duthost, enum_frontend_asic_index)
    new_crm_stats_route_used = crm_stats['ipv{}_route'.format(ip_ver)]['used']
    new_crm_stats_route_available = crm_stats['ipv{}_route'.format(ip_ver)]['available']
    crm_stats_fdb_used_after_add_route = crm_stats['fdb_entry']['used']
    logging.info("new_crm_stats_route_used {}, new_crm_stats_route_available {}, crm_stats_fdb_used_after_add_route {}".
                 format(new_crm_stats_route_used, new_crm_stats_route_available, crm_stats_fdb_used_after_add_route))

    # Get CRM available route diff in case when FDB updated during test run
    crm_stats_route_available = get_expected_crm_stats_route_available(crm_stats_route_available, crm_stats_fdb_used,
                                                                       crm_stats_fdb_used_after_add_route)

    if skip_stats_check is False:
        # Verify "crm_stats_ipv[4/6]_route_used" counter was incremented
        if not (new_crm_stats_route_used - crm_stats_route_used == total_routes):
            for i in range(total_routes):
                RESTORE_CMDS["test_crm_route"].append(route_del_cmd.format(asichost.ip_cmd, i, nh_ip))
            pytest.fail("\"crm_stats_ipv{}_route_used\" counter was not incremented".format(ip_ver))
        # Verify "crm_stats_ipv[4/6]_route_available" counter was decremented
        if check_available_counters and not (crm_stats_route_available - new_crm_stats_route_available >= 1):
            if is_mellanox_device(duthost):
                # Get sai sdk dump file in case test fail, we can get the LPM tree information
                get_sai_sdk_dump_file(duthost, f"sai_sdk_dump_after_add_v{ip_ver}_router")
            for i in range(total_routes):
                RESTORE_CMDS["test_crm_route"].append(route_del_cmd.format(asichost.ip_cmd, i, nh_ip))
            pytest.fail("\"crm_stats_ipv{}_route_available\" counter was not decremented".format(ip_ver))

    # Remove IPv[4/6] routes
    for i in range(total_routes):
        duthost.command(route_del_cmd.format(asichost.ip_cmd, i, nh_ip))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new ipv[4/6]_route/fdb_entry used and available counter value
    crm_stats = get_crm_resources_fdb_and_ip_route(duthost, enum_frontend_asic_index)
    new_crm_stats_route_used = crm_stats['ipv{}_route'.format(ip_ver)]['used']
    new_crm_stats_route_available = crm_stats['ipv{}_route'.format(ip_ver)]['available']
    crm_stats_fdb_used_after_del_route = crm_stats['fdb_entry']['used']
    # Get CRM available route diff in case when FDB updated during test run
    crm_stats_route_available = get_expected_crm_stats_route_available(crm_stats_route_available,
                                                                       crm_stats_fdb_used_after_add_route,
                                                                       crm_stats_fdb_used_after_del_route)

    # Verify "crm_stats_ipv[4/6]_route_used" counter was decremented
    pytest_assert(new_crm_stats_route_used - crm_stats_route_used == 0,
                  "\"crm_stats_ipv{}_route_used\" counter was not decremented".format(ip_ver))
    if check_available_counters:
        # Verify "crm_stats_ipv[4/6]_route_available" counter was incremented
        pytest_assert(new_crm_stats_route_available - crm_stats_route_available == 0,
                      "\"crm_stats_ipv{}_route_available\" counter was not incremented".format(ip_ver))

    used_percent = get_used_percent(new_crm_stats_route_used, new_crm_stats_route_available)
    if used_percent < 1:
        routes_num = get_entries_num(new_crm_stats_route_used, new_crm_stats_route_available)
        if ip_ver == "4":
            routes_list_raw = [str(ipaddress.IPv4Address(u'2.0.0.1') + item) + "/32"
                               for item in range(1, routes_num + 1)]
        elif ip_ver == "6":
            routes_list_raw = [str(ipaddress.IPv6Address(u'2001::') + item) + "/128"
                               for item in range(1, routes_num + 1)]
        else:
            pytest.fail("Incorrect IP version specified - {}".format(ip_ver))
        # Group commands to avoid command line too long errors
        num_cmds_to_run_at_once = 100
        routes_list_list = [" ".join(routes_list_raw[i:i+num_cmds_to_run_at_once])
                            for i in range(0, len(routes_list_raw), num_cmds_to_run_at_once)]
        # Store CLI command to delete all created neighbours if test case will fail
        for routes_list in routes_list_list:
            RESTORE_CMDS["test_crm_route"].append(
                del_routes_template.render(routes_list=routes_list,
                                           interface=crm_interface[0],
                                           namespace=asichost.namespace))

        # Add test routes entries to correctly calculate used CRM resources in percentage
        for routes_list in routes_list_list:
            duthost.shell(add_routes_template.render(routes_list=routes_list,
                                                     interface=crm_interface[0],
                                                     namespace=asichost.namespace))
        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "IPv[4/6] route" CRM resource
    # Get "crm_stats_ipv[4/6]_route" used and available counter value
    get_route_stats = "{redis_cli} COUNTERS_DB HMGET \
                            CRM:STATS crm_stats_ipv{ip_ver}_route_used \
                            crm_stats_ipv{ip_ver}_route_available"\
        .format(redis_cli=asichost.sonic_db_cli, ip_ver=ip_ver)
    verify_thresholds(duthost, asichost, crm_cli_res="ipv{ip_ver} route".format(ip_ver=ip_ver), crm_cmd=get_route_stats)


def get_expected_crm_stats_route_available(crm_stats_route_available, crm_stats_fdb_used, crm_stats_fdb_used_new):
    fdb_entries_diff = crm_stats_fdb_used_new - crm_stats_fdb_used
    crm_stats_route_available = crm_stats_route_available - fdb_entries_diff
    return crm_stats_route_available


@pytest.mark.parametrize("ip_ver,nexthop", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_nexthop(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                     enum_frontend_asic_index, crm_interface, ip_ver, nexthop, ptfhost, cleanup_ptf_interface):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False
    RESTORE_CMDS["crm_threshold_name"] = "ipv{ip_ver}_nexthop".format(ip_ver=ip_ver)
    if duthost.facts["asic_type"] == "marvell":
        if ip_ver == "4":
            ptfhost.add_ip_to_dev('eth1', nexthop+'/24')
            ptfhost.set_dev_up_or_down('eth1', 'is_up')
            ip_add_cmd = "config interface ip add Ethernet1 2.2.2.1/24"
            ip_remove_cmd = "config interface ip remove Ethernet1 2.2.2.1/24"
            nexthop_add_cmd = "config route add prefix 99.99.99.0/24 nexthop {}".format(nexthop)
            nexthop_del_cmd = "config route del prefix 99.99.99.0/24 nexthop {}".format(nexthop)
        else:
            ptfhost.add_ip_to_dev('eth1', nexthop+'/96')
            ptfhost.set_dev_up_or_down('eth1', 'is_up')
            ip_add_cmd = "config interface ip add Ethernet1 2001::2/64"
            ip_remove_cmd = "config interface ip remove Ethernet1 2001::2/64"
            nexthop_add_cmd = "config route add prefix 3001::0/64 nexthop {}".format(nexthop)
            nexthop_del_cmd = "config route del prefix 3001::0/64 nexthop {}".format(nexthop)
        asichost.sonichost.del_member_from_vlan(1000, 'Ethernet1')
        asichost.shell(ip_add_cmd)
        asichost.shell("config interface startup Ethernet1")
    else:
        nexthop_add_cmd = "{ip_cmd} neigh replace {nexthop} \
                        lladdr 11:22:33:44:55:66 dev {iface}"\
                            .format(ip_cmd=asichost.ip_cmd,
                                    nexthop=nexthop,
                                    iface=crm_interface[0])
        nexthop_del_cmd = "{ip_cmd} neigh del {nexthop} \
                        lladdr 11:22:33:44:55:66 dev {iface}"\
                            .format(ip_cmd=asichost.ip_cmd,
                                    nexthop=nexthop,
                                    iface=crm_interface[0])
    # Get "crm_stats_ipv[4/6]_nexthop" used and available counter value
    get_nexthop_stats = "{db_cli} COUNTERS_DB HMGET CRM:STATS \
                            crm_stats_ipv{ip_ver}_nexthop_used \
                            crm_stats_ipv{ip_ver}_nexthop_available"\
                                .format(db_cli=asichost.sonic_db_cli,
                                        ip_ver=ip_ver)
    crm_stats_nexthop_used, crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)
    # Add nexthop
    asichost.shell(nexthop_add_cmd)

    logger.info("original crm_stats_nexthop_used is: {}, original crm_stats_nexthop_available is {}".format(
        crm_stats_nexthop_used, crm_stats_nexthop_available))
    crm_stats_checker = wait_until(60, 5, 0, check_crm_stats, get_nexthop_stats, duthost,
                                   crm_stats_nexthop_used + 1, crm_stats_nexthop_available - 1, ">=", "<=",
                                   skip_stats_check=skip_stats_check)
    if not crm_stats_checker:
        RESTORE_CMDS["test_crm_nexthop"].append(nexthop_del_cmd)
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_ipv{}_nexthop_used\" counter was not incremented or "
                  "\"crm_stats_ipv{}_nexthop_available\" counter was not decremented".format(ip_ver, ip_ver))
    # Remove nexthop
    asichost.shell(nexthop_del_cmd)
    if duthost.facts["asic_type"] == "marvell":
        asichost.shell(ip_remove_cmd)
        asichost.sonichost.add_member_to_vlan(1000, 'Ethernet1', is_tagged=False)
        ptfhost.remove_ip_addresses()
    crm_stats_checker = wait_until(60, 5, 0, check_crm_stats, get_nexthop_stats, duthost,
                                   crm_stats_nexthop_used, crm_stats_nexthop_available,
                                   skip_stats_check=skip_stats_check)
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_ipv{}_nexthop_used\" counter was not decremented or "
                  "\"crm_stats_ipv{}_nexthop_available\" counter was not incremented".format(ip_ver, ip_ver))

    # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
    new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)
    used_percent = get_used_percent(new_crm_stats_nexthop_used, new_crm_stats_nexthop_available)
    if used_percent < 1:
        neighbours_num = get_entries_num(new_crm_stats_nexthop_used, new_crm_stats_nexthop_available)
        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        configure_neighbors(amount=neighbours_num, interface=crm_interface[0], ip_ver=ip_ver,
                            asichost=asichost, test_name="test_crm_nexthop")

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "IPv[4/6] nexthop" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="ipv{ip_ver} nexthop".format(ip_ver=ip_ver),
                      crm_cmd=get_nexthop_stats)


@pytest.mark.parametrize("ip_ver,neighbor,host", [("4", "2.2.2.2", "2.2.2.1/8"), ("6", "2001::1", "2001::2/64")])
def test_crm_neighbor(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                      enum_frontend_asic_index,  crm_interface, ip_ver, neighbor, host):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False
    RESTORE_CMDS["crm_threshold_name"] = "ipv{ip_ver}_neighbor".format(ip_ver=ip_ver)
    neighbor_add_cmd = "{ip_cmd} neigh replace {neighbor} lladdr 11:22:33:44:55:66 dev {iface}"\
                       .format(ip_cmd=asichost.ip_cmd, neighbor=neighbor, iface=crm_interface[0])
    neighbor_del_cmd = "{ip_cmd} neigh del {neighbor} lladdr 11:22:33:44:55:66 dev {iface}"\
                       .format(ip_cmd=asichost.ip_cmd, neighbor=neighbor, iface=crm_interface[0])

    # Get "crm_stats_ipv[4/6]_neighbor" used and available counter value
    get_neighbor_stats = "{db_cli} COUNTERS_DB HMGET CRM:STATS \
                         crm_stats_ipv{ip_ver}_neighbor_used \
                         crm_stats_ipv{ip_ver}_neighbor_available"\
                         .format(db_cli=asichost.sonic_db_cli, ip_ver=ip_ver)
    crm_stats_neighbor_used, crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Add reachability to the neighbor
    if is_cisco_device(duthost):
        asichost.config_ip_intf(crm_interface[0], host, "add")
    # Add neighbor
    asichost.shell(neighbor_add_cmd)

    crm_stats_checker = wait_until(60, 5, 0, check_crm_stats, get_neighbor_stats, duthost,
                                   crm_stats_neighbor_used, crm_stats_neighbor_available, ">", "<",
                                   skip_stats_check=skip_stats_check)
    if not crm_stats_checker:
        RESTORE_CMDS["test_crm_nexthop"].append(neighbor_del_cmd)
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_ipv4_neighbor_used\" counter was not incremented or "
                  "\"crm_stats_ipv4_neighbor_available\" counter was not decremented")

    # Remove reachability to the neighbor
    if is_cisco_device(duthost):
        asichost.config_ip_intf(crm_interface[0], host, "remove")
    # Remove neighbor
    asichost.shell(neighbor_del_cmd)

    crm_stats_checker = wait_until(60, 5, 0, check_crm_stats, get_neighbor_stats, duthost,
                                   crm_stats_neighbor_used, crm_stats_neighbor_available, ">=", "==",
                                   skip_stats_check=skip_stats_check)
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_ipv4_neighbor_used\" counter was not decremented or "
                  "\"crm_stats_ipv4_neighbor_available\" counter was not incremented")

    # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)
    used_percent = get_used_percent(new_crm_stats_neighbor_used, new_crm_stats_neighbor_available)
    if used_percent < 1:
        #  Add 3k neighbors instead of 1 percentage for Cisco-8000 devices
        neighbours_num = CISCO_8000_ADD_NEIGHBORS if is_cisco_device(duthost) \
                         else get_entries_num(new_crm_stats_neighbor_used, new_crm_stats_neighbor_available)

        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        configure_neighbors(amount=neighbours_num, interface=crm_interface[0], ip_ver=ip_ver,
                            asichost=asichost, test_name="test_crm_neighbor")

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "IPv[4/6] neighbor" CRM resource
    verify_thresholds(duthost, asichost,  crm_cli_res="ipv{ip_ver} neighbor".format(ip_ver=ip_ver),
                      crm_cmd=get_neighbor_stats)


@pytest.mark.parametrize("group_member,network", [(False, "2.2.2.0/24"), (True, "2.2.2.0/24")])
def test_crm_nexthop_group(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                           enum_frontend_asic_index, crm_interface, group_member, network):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False

    nhg_del_template = """
        %s
        ip -4 {{ns_prefix}} route del 5.5.5.0/24 dev {{iface}}
        ip -4 {{ns_prefix}} route del 4.4.4.0/24 dev {{iface2}}
        ip {{ns_prefix}} neigh del 5.5.5.1 lladdr 11:22:33:44:55:66 dev {{iface}}
        ip {{ns_prefix}} neigh del 4.4.4.1 lladdr 77:22:33:44:55:66 dev {{iface2}}
        ip -4 {{ns_prefix}} route del {{prefix}} nexthop via 5.5.5.1 nexthop via 4.4.4.1""" % (NS_PREFIX_TEMPLATE)

    nhg_add_template = """
        %s
        ip -4 {{ns_prefix}} route add 5.5.5.0/24 dev {{iface}}
        ip -4 {{ns_prefix}} route add 4.4.4.0/24 dev {{iface2}}
        ip {{ns_prefix}} neigh replace 5.5.5.1 lladdr 11:22:33:44:55:66 dev {{iface}}
        ip {{ns_prefix}} neigh replace 4.4.4.1 lladdr 77:22:33:44:55:66 dev {{iface2}}
        ip -4 {{ns_prefix}} route add {{prefix}} nexthop via 5.5.5.1 nexthop via 4.4.4.1""" % (NS_PREFIX_TEMPLATE)

    add_template = Template(nhg_add_template)
    del_template = Template(nhg_del_template)

    RESTORE_CMDS["crm_threshold_name"] = "nexthop_group_member" if group_member else "nexthop_group"
    redis_threshold = "nexthop group member" if group_member else "nexthop group object"
    get_group_stats = "{} COUNTERS_DB HMGET CRM:STATS crm_stats_nexthop_group_used \
                        crm_stats_nexthop_group_available".format(asichost.sonic_db_cli)

    get_group_member_stats = "{} COUNTERS_DB HMGET CRM:STATS \
                                crm_stats_nexthop_group_member_used \
                                crm_stats_nexthop_group_member_available" \
                                    .format(asichost.sonic_db_cli)

    # Get "crm_stats_nexthop_group_[member]" used and available counter value
    get_nexthop_group_stats = get_group_member_stats if group_member else get_group_stats
    get_nexthop_group_another_stats = get_group_stats if group_member else get_group_member_stats
    nexthop_group_used, nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)
    logging.info("{} {}".format(nexthop_group_used, nexthop_group_available))

    cmd = add_template.render(iface=crm_interface[0],
                              iface2=crm_interface[1],
                              prefix=network,
                              namespace=asichost.namespace)
    # Add nexthop group members
    logger.info("Add nexthop groups")
    duthost.shell(cmd)

    if group_member:
        template_resource = 2
    else:
        template_resource = 1
    crm_stats_checker = wait_until(60, 5, 0, check_crm_stats, get_nexthop_group_stats, duthost,
                                   nexthop_group_used + template_resource,
                                   nexthop_group_available + template_resource, "==", "<=",
                                   skip_stats_check=skip_stats_check)
    if not crm_stats_checker:
        RESTORE_CMDS["test_crm_nexthop_group"].append(del_template.render(
            iface=crm_interface[0], iface2=crm_interface[1], prefix=network, namespace=asichost.namespace))
    nexthop_group_name = "member_" if group_member else ""
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_nexthop_group_{}used\" counter was not incremented or "
                  "\"crm_stats_nexthop_group_{}available\" counter was not decremented".format(nexthop_group_name,
                                                                                               nexthop_group_name))

    # Remove nexthop group members
    logger.info("Removing nexthop groups")
    duthost.shell(del_template.render(iface=crm_interface[0], iface2=crm_interface[1],
                                      prefix=network, namespace=asichost.namespace))

    crm_stats_checker = wait_until(60, 5, 0, check_crm_stats, get_nexthop_group_stats, duthost,
                                   nexthop_group_used, nexthop_group_available,
                                   skip_stats_check=skip_stats_check)
    nexthop_group_name = "member_" if group_member else ""
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_nexthop_group_{}used\" counter was not decremented or "
                  "\"crm_stats_nexthop_group_{}available\" counter was not incremented".format(
                      nexthop_group_name, nexthop_group_name))

    # Get new "crm_stats_nexthop_group_[member]" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Preconfiguration needed for used percentage verification
    used_percent = get_used_percent(new_nexthop_group_used, new_nexthop_group_available)
    if used_percent < 1:
        nexthop_group_num = get_entries_num(new_nexthop_group_used, new_nexthop_group_available)
        _, nexthop_available_resource_num = get_crm_stats(get_nexthop_group_another_stats, duthost)
        nexthop_group_num = min(nexthop_group_num, nexthop_available_resource_num)
        logger.info(f"Next hop group number: {nexthop_group_num}")
        # Increase default Linux configuration for ARP cache
        increase_arp_cache(duthost, nexthop_group_num, 4, "test_crm_nexthop_group")

        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        configure_nexthop_groups(amount=nexthop_group_num, interface=crm_interface[0],
                                 asichost=asichost, test_name="test_crm_nexthop_group")

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    verify_thresholds(duthost, asichost, crm_cli_res=redis_threshold, crm_cmd=get_nexthop_group_stats)


def recreate_acl_table(duthost, ports):
    cmds = [
        "config acl remove table {}".format(ACL_TABLE_NAME),
        "config acl add table {} L3 -p {}".format(ACL_TABLE_NAME, ports)
    ]
    duthost.shell_cmds(cmds=cmds)


def test_acl_entry(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,
                   collector, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    data_acl = get_data_acl(duthost)
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_collector = collector[asichost.asic_index]
    try:
        if duthost.facts["asic_type"] == "marvell":
            # Remove DATA ACL Table and add it again with ports in same port group
            mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
            tmp_ports = sorted(mg_facts["minigraph_ports"], key=lambda x: int(x[8:]))
            for i in range(4):
                if i == 0:
                    ports = ",".join(tmp_ports[17:19])
                elif i == 1:
                    ports = ",".join(tmp_ports[24:26])
                elif i == 2:
                    ports = ",".join([tmp_ports[20], tmp_ports[25]])
                recreate_acl_table(duthost, ports)
                verify_acl_crm_stats(duthost, asichost, enum_rand_one_per_hwsku_frontend_hostname,
                                     enum_frontend_asic_index, asic_collector, tbinfo)
                # Rebind DATA ACL at end to recover original config
                recreate_acl_table(duthost, ports)
                apply_acl_config(duthost, asichost, "test_acl_entry", asic_collector)
                duthost.command("acl-loader delete")
        else:
            verify_acl_crm_stats(duthost, asichost, enum_rand_one_per_hwsku_frontend_hostname,
                                 enum_frontend_asic_index, asic_collector, tbinfo)

        pytest_assert(crm_stats_checker,
                      "\"crm_stats_acl_entry_used\" counter was not decremented or "
                      "\"crm_stats_acl_entry_available\" counter was not incremented")
    finally:
        if data_acl:
            RESTORE_CMDS["test_acl_entry"].append({"data_acl": data_acl})


def verify_acl_crm_stats(duthost, asichost, enum_rand_one_per_hwsku_frontend_hostname,
                         enum_frontend_asic_index, asic_collector, tbinfo):
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False
    apply_acl_config(duthost, asichost, "test_acl_entry", asic_collector, entry_num=2)
    acl_tbl_key = asic_collector["acl_tbl_key"]
    get_acl_entry_stats = "{db_cli} COUNTERS_DB HMGET {acl_tbl_key} \
                            crm_stats_acl_entry_used \
                            crm_stats_acl_entry_available"\
                            .format(db_cli=asichost.sonic_db_cli, acl_tbl_key=acl_tbl_key)

    RESTORE_CMDS["crm_threshold_name"] = "acl_entry"
    crm_stats_acl_entry_used = 0
    crm_stats_acl_entry_available = 0

    # Get new "crm_stats_acl_entry" used and available counter value
    new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available = get_crm_stats(get_acl_entry_stats, duthost)
    # Verify "crm_stats_acl_entry_used" counter was incremented
    pytest_assert(new_crm_stats_acl_entry_used - crm_stats_acl_entry_used == 4,
                  "\"crm_stats_acl_entry_used\" counter was not incremented")

    used_percent = get_used_percent(new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available)
    if used_percent < 1:
        # Preconfiguration needed for used percentage verification
        nexthop_group_num = get_entries_num(new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available)
        logger.info(f"Next hop group number: {nexthop_group_num}")
        apply_acl_config(duthost, asichost, "test_acl_entry", asic_collector, nexthop_group_num)

        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

    # Verify thresholds for "ACL entry" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="acl group entry", crm_cmd=get_acl_entry_stats)

    # Reduce ACL to one rule (plus default)
    crm_stats_acl_entry_used = 2
    apply_acl_config(duthost, asichost, "test_acl_entry", asic_collector, entry_num=1)
    if duthost.facts.get("platform_asic", None) == "broadcom-dnx":
        # Each ACL rule consumes an acl entry per bind point
        asicAclBindings = set()
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        # PCs are a single bind point
        portToLag = {}
        for lag, lagData in mg_facts["minigraph_portchannels"].items():
            # Check if Portchannel belongs to this namespace
            if duthost.sonichost.is_multi_asic and lagData['namespace'] != asichost.namespace:
                continue
            for member in lagData['members']:
                portToLag[member] = lag
        aclBindings = mg_facts["minigraph_acls"]["DataAcl"]
        for port in aclBindings:
            if port in portToLag:
                if asichost.portchannel_on_asic(portToLag[port]):
                    asicAclBindings.add(portToLag[port])
            else:
                if asichost.port_on_asic(port):
                    asicAclBindings.add(port)

        freed_acl_entries = (new_crm_stats_acl_entry_used - crm_stats_acl_entry_used) * len(asicAclBindings)
    else:
        freed_acl_entries = new_crm_stats_acl_entry_used - crm_stats_acl_entry_used

    crm_stats_acl_entry_available = new_crm_stats_acl_entry_available + freed_acl_entries

    acl_tbl_key = asic_collector["acl_tbl_key"]
    get_acl_entry_stats = "{db_cli} COUNTERS_DB HMGET {acl_tbl_key} \
                            crm_stats_acl_entry_used \
                            crm_stats_acl_entry_available"\
                            .format(db_cli=asichost.sonic_db_cli, acl_tbl_key=acl_tbl_key)

    global crm_stats_checker
    if duthost.facts["asic_type"] == "marvell":
        crm_stats_checker = wait_until(
            30,
            5,
            0,
            check_crm_stats,
            get_acl_entry_stats,
            duthost,
            crm_stats_acl_entry_used,
            crm_stats_acl_entry_available,
            "==",
            ">=",
        )
    else:
        crm_stats_checker = wait_until(
            30,
            5,
            0,
            check_crm_stats,
            get_acl_entry_stats,
            duthost,
            crm_stats_acl_entry_used,
            crm_stats_acl_entry_available,
            skip_stats_check=skip_stats_check
        )

    # Remove ACL
    duthost.command("acl-loader delete")


def test_acl_counter(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, collector,
                     handle_default_acl_rules):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_collector = collector[asichost.asic_index]
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False

    if "acl_tbl_key" not in asic_collector:
        pytest.skip("acl_tbl_key is not retrieved")
    acl_tbl_key = asic_collector["acl_tbl_key"]

    RESTORE_CMDS["crm_threshold_name"] = "acl_counter"

    crm_stats_acl_counter_used = 0
    crm_stats_acl_counter_available = 0

    # Get original "crm_stats_acl_counter_available" counter value
    cmd = "{db_cli} COUNTERS_DB HGET {acl_tbl_key} crm_stats_acl_counter_available"
    std_out = int(duthost.command(cmd.format(db_cli=asichost.sonic_db_cli,
                                  acl_tbl_key=acl_tbl_key))["stdout"])
    original_crm_stats_acl_counter_available = std_out

    apply_acl_config(duthost, asichost, "test_acl_counter", asic_collector)

    # Get new "crm_stats_acl_counter" used and available counter value
    get_acl_counter_stats = "{db_cli} COUNTERS_DB HMGET \
                                {acl_tbl_key} crm_stats_acl_counter_used \
                                crm_stats_acl_counter_available"\
                                    .format(db_cli=asichost.sonic_db_cli,
                                            acl_tbl_key=acl_tbl_key)
    new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available = \
        get_crm_stats(get_acl_counter_stats, duthost)

    # Verify "crm_stats_acl_counter_used" counter was incremented
    pytest_assert(new_crm_stats_acl_counter_used - crm_stats_acl_counter_used == 2,
                  "\"crm_stats_acl_counter_used\" counter was not incremented")

    used_percent = get_used_percent(new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available)
    if used_percent < 1:
        # Preconfiguration needed for used percentage verification
        needed_acl_counter_num = get_entries_num(new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available)

        get_acl_entry_stats = "{db_cli} COUNTERS_DB HMGET {acl_tbl_key} crm_stats_acl_entry_used \
        crm_stats_acl_entry_available".format(db_cli=asichost.sonic_db_cli, acl_tbl_key=acl_tbl_key)
        _, available_acl_entry_num = get_crm_stats(get_acl_entry_stats, duthost)
        # The number we can applied is limited to available_acl_entry_num
        apply_acl_config(duthost, asichost, "test_acl_counter", asic_collector,
                         min(needed_acl_counter_num, available_acl_entry_num))

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available = \
            get_crm_stats(get_acl_counter_stats, duthost)

    crm_stats_acl_counter_available = new_crm_stats_acl_counter_available + new_crm_stats_acl_counter_used

    # Verify thresholds for "ACL entry" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="acl group counter", crm_cmd=get_acl_counter_stats)

    # Remove ACL
    duthost.command("acl-loader delete")
    crm_stats_checker = wait_until(30, 5, 0, check_crm_stats, get_acl_counter_stats, duthost,
                                   crm_stats_acl_counter_used, crm_stats_acl_counter_available, "==", ">=",
                                   skip_stats_check=skip_stats_check)
    pytest_assert(crm_stats_checker,
                  "\"crm_stats_acl_counter_used\" counter was not decremented or "
                  "\"crm_stats_acl_counter_available\" counter was not incremented")

    if skip_stats_check is False:
        # Verify "crm_stats_acl_counter_available" counter was equal to original value
        _, new_crm_stats_acl_counter_available = get_crm_stats(get_acl_counter_stats, duthost)
        pytest_assert(original_crm_stats_acl_counter_available - new_crm_stats_acl_counter_available == 0,
                      "\"crm_stats_acl_counter_available\" counter is not equal to original value")


@pytest.mark.usefixtures('disable_fdb_aging')
def test_crm_fdb_entry(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_type = duthost.facts['asic_type']
    skip_stats_check = True if asic_type == "vs" else False

    get_fdb_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_fdb_entry_used crm_stats_fdb_entry_available"
    topology = tbinfo["topo"]["properties"]["topology"]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    port_dict = dict(list(zip(list(cfg_facts['port_index_map'].values()), list(cfg_facts['port_index_map'].keys()))))
    # Use for test 1st in list hosts interface port to add into dummy VLAN
    host_port_id = [id for id in topology["host_interfaces"]][0]
    iface = port_dict[host_port_id]
    vlan_id = 2
    cmd_add_vlan_member = "config vlan member add {vid} {iface}"
    cmd_add_vlan = "config vlan add {}".format(vlan_id)

    # Configure test restore commands
    RESTORE_CMDS["crm_threshold_name"] = "fdb_entry"
    # Remove FDB entry
    RESTORE_CMDS["test_crm_fdb_entry"].append("fdbclear")
    # Restart arp_update
    # RESTORE_CMDS["test_crm_fdb_entry"].append("docker exec -i swss supervisorctl start arp_update")
    # Remove VLAN member required for FDB entry
    RESTORE_CMDS["test_crm_fdb_entry"].append("config vlan member del {} {}".format(vlan_id, iface))
    # Remove VLAN required for FDB entry
    RESTORE_CMDS["test_crm_fdb_entry"].append("config vlan del {}".format(vlan_id))

    # Add VLAN required for FDB entry
    duthost.command(cmd_add_vlan)
    # Add VLAN member required for FDB entry
    duthost.command(cmd_add_vlan_member.format(vid=vlan_id, iface=iface))

    # Stop arp_update
    cmd = "docker exec -i swss supervisorctl stop arp_update"
    duthost.command(cmd)

    # Remove FDB entry
    cmd = "fdbclear"
    duthost.command(cmd)
    time.sleep(5)
    if is_cel_e1031_device(duthost):
        # Sleep more time for E1031 device after fdbclear
        time.sleep(10)

    # Get "crm_stats_fdb_entry" used and available counter value
    crm_stats_fdb_entry_used, crm_stats_fdb_entry_available = get_crm_stats(get_fdb_stats, duthost)
    # Generate FDB json file with one entry and apply it on DUT
    apply_fdb_config(duthost, "test_crm_fdb_entry", vlan_id, iface, 1)

    # Get new "crm_stats_fdb_entry" used and available counter value
    new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available = get_crm_stats(get_fdb_stats, duthost)

    if skip_stats_check is False:
        # Verify "crm_stats_fdb_entry_used" counter was incremented
        # For Cisco-8000 devices, hardware FDB counter is statistical-based with +/- 1 entry tolerance.
        # Hence, the used counter can increase by more than 1.
        # For E1031, refer CS00012270660, SDK for Helix4 chip does not support retrieving  max l2 entry,
        # HW and SW CRM available counter would be out of sync and increase by more than 1.
        if is_cisco_device(duthost) or is_cel_e1031_device(duthost):
            pytest_assert(new_crm_stats_fdb_entry_used - crm_stats_fdb_entry_used >= 1,
                          "Counter 'crm_stats_fdb_entry_used' was not incremented")
        else:
            pytest_assert(new_crm_stats_fdb_entry_used - crm_stats_fdb_entry_used == 1,
                          "Counter 'crm_stats_fdb_entry_used' was not incremented")

        # Verify "crm_stats_fdb_entry_available" counter was decremented
        # For Cisco-8000 devices, hardware FDB counter is statistical-based with +/- 1 entry tolerance.
        # Hence, the available counter can decrease by more than 1.
        # For E1031, refer CS00012270660, SDK for Helix4 chip does not support retrieving  max l2 entry,
        # HW and SW CRM available counter would be out of sync and decrease by more than 1.
        if is_cisco_device(duthost) or is_cel_e1031_device(duthost):
            pytest_assert(crm_stats_fdb_entry_available - new_crm_stats_fdb_entry_available >= 1,
                          "Counter 'crm_stats_fdb_entry_available' was not decremented")
        else:
            pytest_assert(crm_stats_fdb_entry_available - new_crm_stats_fdb_entry_available == 1,
                          "Counter 'crm_stats_fdb_entry_available' was not decremented")

    used_percent = get_used_percent(new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available)
    if used_percent < 1:
        # Clear pre-set fdb entry
        duthost.command("fdbclear")
        time.sleep(5)
        # Preconfiguration needed for used percentage verification
        fdb_entries_num = get_entries_num(new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available)
        # Generate FDB json file with 'fdb_entries_num' entries and apply it on DUT
        apply_fdb_config(duthost, "test_crm_fdb_entry", vlan_id, iface, fdb_entries_num)
        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "FDB entry" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="fdb", crm_cmd=get_fdb_stats)

    # Remove FDB entry
    cmd = "fdbclear"
    duthost.command(cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)
    # Timeout for asyc fdb clear
    FDB_CLEAR_TIMEOUT = 10
    while FDB_CLEAR_TIMEOUT > 0:
        # Get new "crm_stats_fdb_entry" used and available counter value
        new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available = get_crm_stats(get_fdb_stats, duthost)
        if new_crm_stats_fdb_entry_used == 0:
            break
        FDB_CLEAR_TIMEOUT -= CRM_POLLING_INTERVAL
        time.sleep(CRM_POLLING_INTERVAL)

    # Verify "crm_stats_fdb_entry_used" counter was decremented
    pytest_assert(new_crm_stats_fdb_entry_used == 0, "FDB entry is not completely cleared. \
                  Used == {}".format(new_crm_stats_fdb_entry_used))

    # Verify "crm_stats_fdb_entry_available" counter was incremented
    # For E1031, refer CS00012270660, SDK for Helix4 chip does not support retrieving max l2 entry, HW and
    # SW CRM available counter would be out of sync, so this is not applicable for e1031 device
    if not is_cel_e1031_device(duthost):
        pytest_assert(new_crm_stats_fdb_entry_available - crm_stats_fdb_entry_available >= 0,
                      "Counter 'crm_stats_fdb_entry_available' was not incremented")
