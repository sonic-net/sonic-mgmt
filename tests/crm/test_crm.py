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
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.assertions import pytest_assert
from collections import OrderedDict
from tests.common.fixtures.duthost_utils import disable_route_checker
from tests.common.fixtures.duthost_utils import disable_fdb_aging


pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

CRM_POLLING_INTERVAL = 1
CRM_UPDATE_TIME = 4
SONIC_RES_UPDATE_TIME = 50

THR_VERIFY_CMDS = OrderedDict([
    ("exceeded_used", "bash -c \"crm config thresholds {{crm_cli_res}}  type used; crm config thresholds {{crm_cli_res}} low {{crm_used|int - 1}}; crm config thresholds {{crm_cli_res}} high {{crm_used|int}}\""),
    ("clear_used", "bash -c \"crm config thresholds {{crm_cli_res}} type used && crm config thresholds {{crm_cli_res}} low {{crm_used|int}} && crm config thresholds {{crm_cli_res}} high {{crm_used|int + 1}}\""),
    ("exceeded_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && crm config thresholds {{crm_cli_res}} low {{crm_avail|int - 1}} && crm config thresholds {{crm_cli_res}} high {{crm_avail|int}}\""),
    ("clear_free", "bash -c \"crm config thresholds {{crm_cli_res}} type free && crm config thresholds {{crm_cli_res}} low {{crm_avail|int}} && crm config thresholds {{crm_cli_res}} high {{crm_avail|int + 1}}\""),
    ("exceeded_percentage", "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\""),
    ("clear_percentage", "bash -c \"crm config thresholds {{crm_cli_res}} type percentage && crm config thresholds {{crm_cli_res}} low {{th_lo|int}} && crm config thresholds {{crm_cli_res}} high {{th_hi|int}}\"")
])

EXPECT_EXCEEDED = ".* THRESHOLD_EXCEEDED .*"
EXPECT_CLEAR = ".* THRESHOLD_CLEAR .*"

RESTORE_CMDS = {"test_crm_route": [],
                "test_crm_nexthop": [],
                "test_crm_neighbor": [],
                "test_crm_nexthop_group": [],
                "test_acl_entry": [],
                "test_acl_counter": [],
                "test_crm_fdb_entry": [],
                "crm_cli_res": None,
                "wait": 0}

NS_PREFIX_TEMPLATE="""
    {% set ns_prefix = '' %}
    {% set ns_option = '-n '%}
    {% if namespace %}
    {% set ns_prefix = ns_option ~ namespace %}
    {% endif %}"""

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(enum_rand_one_per_hwsku_frontend_hostname, loganalyzer):
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

    if loganalyzer:  # Skip if loganalyzer is disabled
        loganalyzer[enum_rand_one_per_hwsku_frontend_hostname].ignore_regex.extend(ignoreRegex)


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

        with tempfile.NamedTemporaryFile(suffix=".json", prefix="acl_config") as fp:
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

    with tempfile.NamedTemporaryFile(suffix=".json", prefix="fdb_config") as fp:
        logger.info("Generating FDB config")
        json.dump(fdb_config_json, fp)
        fp.flush()

        # Copy FDB JSON config to switch
        duthost.template(src=fp.name, dest=dest, force=True)


def apply_fdb_config(duthost, test_name, vlan_id, iface, entry_num):
    """ Creates FDB config and applies it on DUT """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, "templates")
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
        out = asichost.shell(cmd.format(db_cli = asichost.sonic_db_cli, item=item))["stdout"]
        logging.info(out)
        if "2048" in out:
            key = item
            break
    else:
        pytest.fail("Ether type was not found in SAI ACL Entry table")

    # Get ACL table key
    cmd = "{db_cli} ASIC_DB HGET {key} \"SAI_ACL_ENTRY_ATTR_TABLE_ID\""
    oid = asichost.shell(cmd.format(db_cli = asichost.sonic_db_cli, key=key))["stdout"]
    logging.info(oid)
    acl_tbl_key = "CRM:ACL_TABLE_STATS:{0}".format(oid.replace("oid:", ""))

    return acl_tbl_key


def get_used_percent(crm_used, crm_available):
    """ Returns percentage of used entries """
    return crm_used * 100 / (crm_used + crm_available)


def verify_thresholds(duthost, asichost, **kwargs):
    """
    Verifies that WARNING message logged if there are any resources that exceeds a pre-defined threshold value.
    Verifies the following threshold parameters: percentage, actual used, actual free
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='crm_test')
    for key, value in THR_VERIFY_CMDS.items():
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
            used_percent = get_used_percent(kwargs["crm_used"], kwargs["crm_avail"])
            if key == "exceeded_percentage":
                if used_percent < 1:
                    logger.warning("The used percentage for {} is {} and verification for exceeded_percentage is skipped" \
                               .format(kwargs["crm_cli_res"], used_percent))
                    continue
                kwargs["th_lo"] = used_percent - 1
                kwargs["th_hi"] = used_percent
                loganalyzer.expect_regex = [EXPECT_EXCEEDED]
            elif key == "clear_percentage":
                if used_percent >= 100:
                    logger.warning("The used percentage for {} is {} and verification for clear_percentage is skipped" \
                               .format(kwargs["crm_cli_res"], used_percent))
                    continue
                kwargs["th_lo"] = used_percent
                kwargs["th_hi"] = used_percent + 1
                loganalyzer.expect_regex = [EXPECT_CLEAR]
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


def generate_neighbors(amount, ip_ver):
    """ Generate list of IPv4 or IPv6 addresses """
    if ip_ver == "4":
        ip_addr_list = list(ipaddress.IPv4Network(u"%s" % "2.0.0.0/8").hosts())[0:amount]
    elif ip_ver == "6":
        ip_addr_list = list(ipaddress.IPv6Network(u"%s" % "2001::/112").hosts())[0:amount]
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
    done""" %(NS_PREFIX_TEMPLATE)

    add_template = """
    %s
    ip -4 {{ns_prefix}} route add 2.0.0.0/8 dev {{iface}}
    ip {{ns_prefix}} neigh replace 2.0.0.1 lladdr 11:22:33:44:55:66 dev {{iface}}
    for s in {{neigh_ip_list}}
    do
        ip  {{ns_prefix}} neigh replace ${s} lladdr 11:22:33:44:55:66 dev {{iface}}
        ip -4 {{ns_prefix}} route add ${s}/32 nexthop via ${s} nexthop via 2.0.0.1
    done""" %(NS_PREFIX_TEMPLATE)

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
        else:
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
    done""" %(NS_PREFIX_TEMPLATE)


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
    return ((used + available) / 100) + 1

@pytest.mark.usefixtures('disable_route_checker')
@pytest.mark.parametrize("ip_ver,route_add_cmd,route_del_cmd", [("4", "{} route add 2.2.2.0/24 via {}",
                                                                "{} route del 2.2.2.0/24 via {}"),
                                                                ("6", "{} -6 route add 2001::/126 via {}",
                                                                "{} -6 route del 2001::/126 via {}")],
                                                                ids=["ipv4", "ipv6"])
def test_crm_route(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, crm_interface, ip_ver, route_add_cmd, route_del_cmd):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
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


    # Get "crm_stats_ipv[4/6]_route" used and available counter value
    get_route_stats = "{redis_cli} COUNTERS_DB HMGET \
                            CRM:STATS crm_stats_ipv{ip_ver}_route_used \
                            crm_stats_ipv{ip_ver}_route_available"\
                                .format(redis_cli=asichost.sonic_db_cli,
                                        ip_ver=ip_ver)
    crm_stats_route_used, crm_stats_route_available = get_crm_stats(get_route_stats, duthost)
    logging.info("crm_stats_route_used {} crm_stats_route_available {} ".format(crm_stats_route_used, crm_stats_route_available))

    # Get NH IP
    cmd = "{ip_cmd} -{ip_ver} neigh show dev {crm_intf} nud reachable nud stale \
            | grep -v fe80".format(ip_cmd = asichost.ip_cmd,
                                    ip_ver=ip_ver, 
                                    crm_intf=crm_interface[0])
    out = duthost.shell(cmd)
    pytest_assert(out["stdout"] != "", "Get Next Hop IP failed. Neighbor not found")
    nh_ip = [item.split()[0] for item in out["stdout"].split("\n") if "REACHABLE" in item][0]

    # Add IPv[4/6] route
    route_add = route_add_cmd.format(asichost.ip_cmd, nh_ip)
    logging.info("route add cmd: {}".format(route_add))
    duthost.command(route_add)
    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_route" used and available counter value
    new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)
    logging.info(" new_crm_stats_route_used {}, new_crm_stats_route_available{} ".format( new_crm_stats_route_used, new_crm_stats_route_available))
    

    # Verify "crm_stats_ipv[4/6]_route_used" counter was incremented
    if not (new_crm_stats_route_used - crm_stats_route_used == 1):
        RESTORE_CMDS["test_crm_route"].append(route_del_cmd.format(asichost.ip_cmd, nh_ip))
        pytest.fail("\"crm_stats_ipv{}_route_used\" counter was not incremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_route_available" counter was decremented
    if not (crm_stats_route_available - new_crm_stats_route_available >= 1):
        RESTORE_CMDS["test_crm_route"].append(route_del_cmd.format(asichost.ip_cmd, nh_ip))
        pytest.fail("\"crm_stats_ipv{}_route_available\" counter was not decremented".format(ip_ver))

    # Remove IPv[4/6] route
    duthost.command(route_del_cmd.format(asichost.ip_cmd, nh_ip))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_route" used and available counter value
    new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_route_used" counter was decremented
    pytest_assert(new_crm_stats_route_used - crm_stats_route_used == 0, \
        "\"crm_stats_ipv{}_route_used\" counter was not decremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_route_available" counter was incremented
    pytest_assert(new_crm_stats_route_available - crm_stats_route_available == 0, \
        "\"crm_stats_ipv{}_route_available\" counter was not incremented".format(ip_ver))

    used_percent = get_used_percent(new_crm_stats_route_used, new_crm_stats_route_available)
    if used_percent < 1:
        routes_num = get_entries_num(new_crm_stats_route_used, new_crm_stats_route_available)
        if ip_ver == "4":
            routes_list = " ".join([str(ipaddress.IPv4Address(u'2.0.0.1') + item) + "/32"
                for item in range(1, routes_num + 1)])
        elif ip_ver == "6":
            routes_list = " ".join([str(ipaddress.IPv6Address(u'2001::') + item) + "/128"
                for item in range(1, routes_num + 1)])
        else:
            pytest.fail("Incorrect IP version specified - {}".format(ip_ver))
        # Store CLI command to delete all created neighbours if test case will fail
        RESTORE_CMDS["test_crm_route"].append(
            del_routes_template.render(routes_list=routes_list,
              interface=crm_interface[0],  namespace = asichost.namespace))

        # Add test routes entries to correctly calculate used CRM resources in percentage
        duthost.shell(add_routes_template.render(routes_list=routes_list,
                                         interface=crm_interface[0],
                                         namespace=asichost.namespace))

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        # Get new "crm_stats_ipv[4/6]_route" used and available counter value
        new_crm_stats_route_used, new_crm_stats_route_available = get_crm_stats(get_route_stats, duthost)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "IPv[4/6] route" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="ipv{ip_ver} route".format(ip_ver=ip_ver),
        crm_used=new_crm_stats_route_used, crm_avail=new_crm_stats_route_available)


@pytest.mark.parametrize("ip_ver,nexthop", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_nexthop(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, crm_interface, ip_ver, nexthop):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    RESTORE_CMDS["crm_threshold_name"] = "ipv{ip_ver}_nexthop".format(ip_ver=ip_ver)
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

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
    new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_nexthop_used" counter was incremented
    if not (new_crm_stats_nexthop_used - crm_stats_nexthop_used >= 1):
        RESTORE_CMDS["test_crm_nexthop"].append(nexthop_del_cmd)
        pytest.fail("\"crm_stats_ipv{}_nexthop_used\" counter was not incremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_nexthop_available" counter was decremented
    if not (crm_stats_nexthop_available - new_crm_stats_nexthop_available >= 1):
        RESTORE_CMDS["test_crm_nexthop"].append(nexthop_del_cmd)
        pytest.fail("\"crm_stats_ipv{}_nexthop_available\" counter was not decremented".format(ip_ver))

    # Remove nexthop
    asichost.shell(nexthop_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
    new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

    # Verify "crm_stats_ipv[4/6]_nexthop_used" counter was decremented
    pytest_assert(new_crm_stats_nexthop_used - crm_stats_nexthop_used == 0, \
        "\"crm_stats_ipv{}_nexthop_used\" counter was not decremented".format(ip_ver))
    # Verify "crm_stats_ipv[4/6]_nexthop_available" counter was incremented
    pytest_assert(new_crm_stats_nexthop_available - crm_stats_nexthop_available == 0, \
        "\"crm_stats_ipv{}_nexthop_available\" counter was not incremented".format(ip_ver))

    used_percent = get_used_percent(new_crm_stats_nexthop_used, new_crm_stats_nexthop_available)
    if used_percent < 1:
        neighbours_num = get_entries_num(new_crm_stats_nexthop_used, new_crm_stats_nexthop_available)
        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        configure_neighbors(amount=neighbours_num, interface=crm_interface[0], ip_ver=ip_ver, asichost=asichost,
            test_name="test_crm_nexthop")

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        # Get new "crm_stats_ipv[4/6]_nexthop" used and available counter value
        new_crm_stats_nexthop_used, new_crm_stats_nexthop_available = get_crm_stats(get_nexthop_stats, duthost)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "IPv[4/6] nexthop" CRM resource
    verify_thresholds(duthost,asichost, crm_cli_res="ipv{ip_ver} nexthop".format(ip_ver=ip_ver), crm_used=new_crm_stats_nexthop_used,
        crm_avail=new_crm_stats_nexthop_available)


@pytest.mark.parametrize("ip_ver,neighbor", [("4", "2.2.2.2"), ("6", "2001::1")])
def test_crm_neighbor(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index,  crm_interface, ip_ver, neighbor):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    RESTORE_CMDS["crm_threshold_name"] = "ipv{ip_ver}_neighbor".format(ip_ver=ip_ver)
    neighbor_add_cmd = "{ip_cmd} neigh replace {neighbor} lladdr 11:22:33:44:55:66 dev {iface}"\
                        .format(ip_cmd=asichost.ip_cmd, neighbor=neighbor, iface=crm_interface[0])
    neighbor_del_cmd = "{ip_cmd} neigh del {neighbor} lladdr 11:22:33:44:55:66 dev {iface}"\
                        .format(ip_cmd=asichost.ip_cmd, neighbor=neighbor, iface=crm_interface[0])

    # Get "crm_stats_ipv[4/6]_neighbor" used and available counter value
    get_neighbor_stats = "{db_cli} COUNTERS_DB HMGET CRM:STATS \
                        crm_stats_ipv{ip_ver}_neighbor_used \
                        crm_stats_ipv{ip_ver}_neighbor_available"\
                            .format(db_cli=asichost.sonic_db_cli,
                                    ip_ver=ip_ver)
    crm_stats_neighbor_used, crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Add neighbor
    asichost.shell(neighbor_add_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Verify "crm_stats_ipv4_neighbor_used" counter was incremented
    if not (new_crm_stats_neighbor_used - crm_stats_neighbor_used >= 1):
        RESTORE_CMDS["test_crm_neighbor"].append(neighbor_del_cmd)
        pytest.fail("\"crm_stats_ipv4_neighbor_used\" counter was not incremented")
    # Verify "crm_stats_ipv4_neighbor_available" counter was decremented
    if not (crm_stats_neighbor_available - new_crm_stats_neighbor_available >= 1):
        RESTORE_CMDS["test_crm_neighbor"].append(neighbor_del_cmd)
        pytest.fail("\"crm_stats_ipv4_neighbor_available\" counter was not decremented")

    # Remove neighbor
    asichost.shell(neighbor_del_cmd)

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
    new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

    # Verify "crm_stats_ipv4_neighbor_used" counter was decremented
    pytest_assert(new_crm_stats_neighbor_used - crm_stats_neighbor_used >= 0, \
        "\"crm_stats_ipv4_neighbor_used\" counter was not decremented")
    # Verify "crm_stats_ipv4_neighbor_available" counter was incremented
    pytest_assert(new_crm_stats_neighbor_available - crm_stats_neighbor_available == 0, \
        "\"crm_stats_ipv4_neighbor_available\" counter was not incremented")

    used_percent = get_used_percent(new_crm_stats_neighbor_used, new_crm_stats_neighbor_available)
    if used_percent < 1:
        neighbours_num = get_entries_num(new_crm_stats_neighbor_used, new_crm_stats_neighbor_available)
        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        configure_neighbors(amount=neighbours_num, interface=crm_interface[0], ip_ver=ip_ver, asichost=asichost,
            test_name="test_crm_neighbor")

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
        new_crm_stats_neighbor_used, new_crm_stats_neighbor_available = get_crm_stats(get_neighbor_stats, duthost)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "IPv[4/6] neighbor" CRM resource
    verify_thresholds(duthost, asichost,  crm_cli_res="ipv{ip_ver} neighbor".format(ip_ver=ip_ver), crm_used=new_crm_stats_neighbor_used,
        crm_avail=new_crm_stats_neighbor_available)


@pytest.mark.parametrize("group_member,network", [(False, "2.2.2.0/24"), (True, "2.2.2.0/24")])
def test_crm_nexthop_group(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, crm_interface, group_member, network):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)

    nhg_del_template="""
        %s
        ip -4 {{ns_prefix}} route del 3.3.3.0/24 dev {{iface}}
        ip -4 {{ns_prefix}} route del 4.4.4.0/24 dev {{iface2}}   
        ip {{ns_prefix}} neigh del 3.3.3.1 lladdr 11:22:33:44:55:66 dev {{iface}}
        ip {{ns_prefix}} neigh del 4.4.4.1 lladdr 77:22:33:44:55:66 dev {{iface2}}
        ip -4 {{ns_prefix}} route del {{prefix}} nexthop via 3.3.3.1 nexthop via 4.4.4.1""" %(NS_PREFIX_TEMPLATE)

    nhg_add_template="""
        %s
        ip -4 {{ns_prefix}} route add 3.3.3.0/24 dev {{iface}}
        ip -4 {{ns_prefix}} route add 4.4.4.0/24 dev {{iface2}}
        ip {{ns_prefix}} neigh replace 3.3.3.1 lladdr 11:22:33:44:55:66 dev {{iface}}
        ip {{ns_prefix}} neigh replace 4.4.4.1 lladdr 77:22:33:44:55:66 dev {{iface2}}
        ip -4 {{ns_prefix}} route add {{prefix}} nexthop via 3.3.3.1 nexthop via 4.4.4.1""" %(NS_PREFIX_TEMPLATE)

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

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_nexthop_group_[member]" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    if group_member:
        template_resource = 2
    else:
        template_resource = 1
    # Verify "crm_stats_nexthop_group_[member]_used" counter was incremented
    if not (new_nexthop_group_used - nexthop_group_used == template_resource):
        RESTORE_CMDS["test_crm_nexthop_group"].append(del_template.render(\
            iface=crm_interface[0], iface2=crm_interface[1], prefix=network, namespace=asichost.namespace))
        pytest.fail("\"crm_stats_nexthop_group_{}used\" counter was not incremented".format("member_" if group_member else ""))

    # Verify "crm_stats_nexthop_group_[member]_available" counter was decremented
    if not (nexthop_group_available - new_nexthop_group_available >= template_resource):
        RESTORE_CMDS["test_crm_nexthop_group"].append(del_template.render(\
            iface=crm_interface[0], iface2=crm_interface[1], prefix=network, namespace=asichost.namespace))
        pytest.fail("\"crm_stats_nexthop_group_{}available\" counter was not decremented".format("member_" if group_member else ""))

    # Remove nexthop group members
    logger.info("Removing nexthop groups")
    duthost.shell(del_template.render(iface=crm_interface[0], iface2=crm_interface[1], prefix=network, namespace=asichost.namespace))

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_nexthop_group_[member]" used and available counter value
    new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

    # Verify "crm_stats_nexthop_group_[member]_used" counter was decremented
    pytest_assert(new_nexthop_group_used - nexthop_group_used == 0, \
        "\"crm_stats_nexthop_group_{}used\" counter was not decremented".format("member_" if group_member else ""))

    # Verify "crm_stats_nexthop_group_[member]_available" counter was incremented
    pytest_assert(new_nexthop_group_available - nexthop_group_available == 0, \
        "\"crm_stats_nexthop_group_{}available\" counter was not incremented".format("member_" if group_member else ""))

    #Preconfiguration needed for used percentage verification
    used_percent = get_used_percent(new_nexthop_group_used, new_nexthop_group_available)
    if used_percent < 1:
        nexthop_group_num = get_entries_num(new_nexthop_group_used, new_nexthop_group_available)
        _, nexthop_available_resource_num = get_crm_stats(get_nexthop_group_another_stats, duthost)
        nexthop_group_num = min(nexthop_group_num, nexthop_available_resource_num)
        # Increase default Linux configuration for ARP cache
        increase_arp_cache(duthost, nexthop_group_num, 4, "test_crm_nexthop_group")

        # Add new neighbor entries to correctly calculate used CRM resources in percentage
        configure_nexthop_groups(amount=nexthop_group_num, interface=crm_interface[0],
            asichost=asichost, test_name="test_crm_nexthop_group")

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        # Get new "crm_stats_ipv[4/6]_neighbor" used and available counter value
        new_nexthop_group_used, new_nexthop_group_available = get_crm_stats(get_nexthop_group_stats, duthost)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    verify_thresholds(duthost, asichost, crm_cli_res=redis_threshold, crm_used=new_nexthop_group_used,
        crm_avail=new_nexthop_group_available)


def test_acl_entry(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, collector):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_collector = collector[asichost.asic_index]
    
    apply_acl_config(duthost, asichost, "test_acl_entry", asic_collector)
    acl_tbl_key = asic_collector["acl_tbl_key"]
    get_acl_entry_stats = "{db_cli} COUNTERS_DB HMGET {acl_tbl_key} \
                            crm_stats_acl_entry_used \
                            crm_stats_acl_entry_available"\
                                .format(db_cli=asichost.sonic_db_cli,
                                        acl_tbl_key=acl_tbl_key)

    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, "templates")
    acl_rules_template = "acl.json"
    dut_tmp_dir = "/tmp"

    RESTORE_CMDS["crm_threshold_name"] = "acl_entry"

    crm_stats_acl_entry_used = 0
    crm_stats_acl_entry_available = 0

    # Get new "crm_stats_acl_entry" used and available counter value
    new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available = get_crm_stats(get_acl_entry_stats, duthost)

    # Verify "crm_stats_acl_entry_used" counter was incremented
    pytest_assert(new_crm_stats_acl_entry_used - crm_stats_acl_entry_used == 2, \
        "\"crm_stats_acl_entry_used\" counter was not incremented")

    crm_stats_acl_entry_available = new_crm_stats_acl_entry_available + new_crm_stats_acl_entry_used

    used_percent = get_used_percent(new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available)
    if used_percent < 1:
        # Preconfiguration needed for used percentage verification
        nexthop_group_num = get_entries_num(new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available)

        apply_acl_config(duthost, asichost, "test_acl_entry", asic_collector, nexthop_group_num)

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available = get_crm_stats(get_acl_entry_stats, duthost)

    # Verify thresholds for "ACL entry" CRM resource
    verify_thresholds(duthost,asichost, crm_cli_res="acl group entry", crm_used=new_crm_stats_acl_entry_used,
        crm_avail=new_crm_stats_acl_entry_available)

    # Remove ACL
    duthost.command("acl-loader delete")

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_acl_entry" used and available counter value
    new_crm_stats_acl_entry_used, new_crm_stats_acl_entry_available = get_crm_stats(get_acl_entry_stats, duthost)

    # Verify "crm_stats_acl_entry_used" counter was decremented
    pytest_assert(new_crm_stats_acl_entry_used - crm_stats_acl_entry_used == 0, \
        "\"crm_stats_acl_entry_used\" counter was not decremented")

    # Verify "crm_stats_acl_entry_available" counter was incremented
    pytest_assert(new_crm_stats_acl_entry_available - crm_stats_acl_entry_available == 0, \
        "\"crm_stats_acl_entry_available\" counter was not incremented")


def test_acl_counter(duthosts, enum_rand_one_per_hwsku_frontend_hostname,enum_frontend_asic_index, collector):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    asic_collector = collector[asichost.asic_index]

    if not "acl_tbl_key" in asic_collector:
        pytest.skip("acl_tbl_key is not retrieved")
    acl_tbl_key = asic_collector["acl_tbl_key"]

    RESTORE_CMDS["crm_threshold_name"] = "acl_counter"

    crm_stats_acl_counter_used = 0
    crm_stats_acl_counter_available = 0

    # Get original "crm_stats_acl_counter_available" counter value
    cmd = "{db_cli} COUNTERS_DB HGET {acl_tbl_key} crm_stats_acl_counter_available"
    std_out = int(duthost.command(\
                    cmd.format(db_cli=asichost.sonic_db_cli,
                                acl_tbl_key=acl_tbl_key))
                    ["stdout"])
    original_crm_stats_acl_counter_available = std_out

    apply_acl_config(duthost, asichost, "test_acl_counter", asic_collector)

    # Get new "crm_stats_acl_counter" used and available counter value
    get_acl_counter_stats = "{db_cli} COUNTERS_DB HMGET \
                                {acl_tbl_key} crm_stats_acl_counter_used \
                                crm_stats_acl_counter_available"\
                                    .format(db_cli=asichost.sonic_db_cli,
                                            acl_tbl_key=acl_tbl_key)
    new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available = get_crm_stats(get_acl_counter_stats, duthost)

    # Verify "crm_stats_acl_counter_used" counter was incremented
    pytest_assert(new_crm_stats_acl_counter_used - crm_stats_acl_counter_used == 2, \
        "\"crm_stats_acl_counter_used\" counter was not incremented")

    used_percent = get_used_percent(new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available)
    if used_percent < 1:
        # Preconfiguration needed for used percentage verification
        needed_acl_counter_num = get_entries_num(new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available)

        get_acl_entry_stats = "{db_cli} COUNTERS_DB HMGET {acl_tbl_key} crm_stats_acl_entry_used \
        crm_stats_acl_entry_available".format(db_cli=asichost.sonic_db_cli, acl_tbl_key=acl_tbl_key)
        _, available_acl_entry_num = get_crm_stats(get_acl_entry_stats, duthost)
        # The number we can applied is limited to available_acl_entry_num
        apply_acl_config(duthost, asichost, "test_acl_counter", asic_collector, min(needed_acl_counter_num, available_acl_entry_num))

        logger.info("Waiting {} seconds for SONiC to update resources...".format(SONIC_RES_UPDATE_TIME))
        # Make sure SONIC configure expected entries
        time.sleep(SONIC_RES_UPDATE_TIME)

        new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available = get_crm_stats(get_acl_counter_stats, duthost)

    crm_stats_acl_counter_available = new_crm_stats_acl_counter_available + new_crm_stats_acl_counter_used

    # Verify thresholds for "ACL entry" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="acl group counter", crm_used=new_crm_stats_acl_counter_used,
        crm_avail=new_crm_stats_acl_counter_available)

    # Remove ACL
    duthost.command("acl-loader delete")

    # Make sure CRM counters updated
    time.sleep(CRM_UPDATE_TIME)

    # Get new "crm_stats_acl_counter" used and available counter value
    new_crm_stats_acl_counter_used, new_crm_stats_acl_counter_available = get_crm_stats(get_acl_counter_stats, duthost)

    # Verify "crm_stats_acl_counter_used" counter was decremented
    pytest_assert(new_crm_stats_acl_counter_used - crm_stats_acl_counter_used == 0, \
        "\"crm_stats_acl_counter_used\" counter was not decremented")

    # Verify "crm_stats_acl_counter_available" counter was incremented
    pytest_assert(new_crm_stats_acl_counter_available - crm_stats_acl_counter_available >= 0, \
        "\"crm_stats_acl_counter_available\" counter was not incremented")

    # Verify "crm_stats_acl_counter_available" counter was equal to original value
    pytest_assert(original_crm_stats_acl_counter_available - new_crm_stats_acl_counter_available == 0, \
        "\"crm_stats_acl_counter_available\" counter is not equal to original value")

@pytest.mark.usefixtures('disable_fdb_aging')
def test_crm_fdb_entry(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    if "t0" not in tbinfo["topo"]["name"].lower():
        pytest.skip("Unsupported topology, expected to run only on 'T0*' topology")
    get_fdb_stats = "redis-cli --raw -n 2 HMGET CRM:STATS crm_stats_fdb_entry_used crm_stats_fdb_entry_available"
    topology = tbinfo["topo"]["properties"]["topology"]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    port_dict = dict(zip(cfg_facts['port_index_map'].values(), cfg_facts['port_index_map'].keys()))
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

    # Get "crm_stats_fdb_entry" used and available counter value
    crm_stats_fdb_entry_used, crm_stats_fdb_entry_available = get_crm_stats(get_fdb_stats, duthost)
    # Generate FDB json file with one entry and apply it on DUT
    apply_fdb_config(duthost, "test_crm_fdb_entry", vlan_id, iface, 1)

    # Get new "crm_stats_fdb_entry" used and available counter value
    new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available = get_crm_stats(get_fdb_stats, duthost)

    # Verify "crm_stats_fdb_entry_used" counter was incremented
    pytest_assert(new_crm_stats_fdb_entry_used - crm_stats_fdb_entry_used == 1, \
        "Counter 'crm_stats_fdb_entry_used' was not incremented")

    # Verify "crm_stats_fdb_entry_available" counter was decremented
    pytest_assert(crm_stats_fdb_entry_available - new_crm_stats_fdb_entry_available == 1, \
        "Counter 'crm_stats_fdb_entry_available' was not incremented")

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
        # Get new "crm_stats_fdb_entry" used and available counter value
        new_crm_stats_fdb_entry_used, new_crm_stats_fdb_entry_available = get_crm_stats(get_fdb_stats, duthost)

        RESTORE_CMDS["wait"] = SONIC_RES_UPDATE_TIME

    # Verify thresholds for "FDB entry" CRM resource
    verify_thresholds(duthost, asichost, crm_cli_res="fdb", crm_used=new_crm_stats_fdb_entry_used,
        crm_avail=new_crm_stats_fdb_entry_available)

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
    pytest_assert(new_crm_stats_fdb_entry_available - crm_stats_fdb_entry_available >= 0, \
        "Counter 'crm_stats_fdb_entry_available' was not incremented")
