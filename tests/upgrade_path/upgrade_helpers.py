import pytest
import logging
import time
import tempfile
import random
import re
from six.moves.urllib.parse import urlparse
import ipaddress
from tests.common.helpers.assertions import pytest_assert
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_WARM, REBOOT_TYPE_COLD
from tests.common.utilities import wait_until, setup_ferret
from tests.platform_tests.verify_dut_health import check_neighbors

# internal only import - used by ferret functions
import json
import os

SYSTEM_STABILIZE_MAX_TIME = 300
logger = logging.getLogger(__name__)

TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'
TMP_PEER_INFO_FILE = "/tmp/peer_dev_info.json"
TMP_PEER_PORT_INFO_FILE = "/tmp/neigh_port_info.json"


def pytest_runtest_setup(item):
    from_list = item.config.getoption('base_image_list')
    to_list = item.config.getoption('target_image_list')
    if not from_list or not to_list:
        pytest.skip("base_image_list or target_image_list is empty")


@pytest.fixture(scope="module")
def restore_image(localhost, duthosts, rand_one_dut_hostname, upgrade_path_lists, tbinfo):
    _, _, _, restore_to_image, _ = upgrade_path_lists
    yield
    duthost = duthosts[rand_one_dut_hostname]
    if restore_to_image:
        logger.info("Preparing to cleanup and restore to {}".format(restore_to_image))
        # restore orignial image
        install_sonic(duthost, restore_to_image, tbinfo)
        # Perform a cold reboot
        reboot(duthost, localhost)


def get_reboot_command(duthost, upgrade_type):
    reboot_command = reboot_ctrl_dict.get(upgrade_type).get("command")
    return reboot_command


def check_sonic_version(duthost, target_version):
    current_version = duthost.image_facts()['ansible_facts']['ansible_image_facts']['current']
    assert current_version == target_version, \
        "Upgrade sonic failed: target={} current={}".format(target_version, current_version)


def install_sonic(duthost, image_url, tbinfo):
    new_route_added = False
    if urlparse(image_url).scheme in ('http', 'https',):
        mg_gwaddr = duthost.get_extended_minigraph_facts(tbinfo).get("minigraph_mgmt_interface", {}).get("gwaddr")
        mg_gwaddr = ipaddress.IPv4Address(mg_gwaddr)
        rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))
        for nexthop in rtinfo_v4['nexthops']:
            if mg_gwaddr == nexthop[0]:
                break
        else:
            # Temporarily change the default route to mgmt-gateway address. This is done so that
            # DUT can download an image from a remote host over the mgmt network.
            logger.info("Add default mgmt-gateway-route to the device via {}".format(mg_gwaddr))
            duthost.shell("ip route replace default via {}".format(mg_gwaddr), module_ignore_errors=True)
            new_route_added = True
        res = duthost.reduce_and_add_sonic_images(new_image_url=image_url)
    else:
        out = duthost.command("df -BM --output=avail /host", module_ignore_errors=True)["stdout"]
        avail = int(out.split('\n')[1][:-1])
        if avail >= 2000:
            # There is enough space to install directly
            save_as = "/host/downloaded-sonic-image"
        else:
            save_as = "/tmp/tmpfs/downloaded-sonic-image"
            # Create a tmpfs partition to download image to install
            duthost.shell("mkdir -p /tmp/tmpfs", module_ignore_errors=True)
            duthost.shell("umount /tmp/tmpfs", module_ignore_errors=True)
            duthost.shell("mount -t tmpfs -o size=1300M tmpfs /tmp/tmpfs", module_ignore_errors=True)
        logger.info("Image exists locally. Copying the image {} into the device path {}".format(image_url, save_as))
        duthost.copy(src=image_url, dest=save_as)
        res = duthost.reduce_and_add_sonic_images(save_as=save_as)

    # if the new default mgmt-gateway route was added, remove it. This is done so that
    # default route src address matches Loopback0 address
    if new_route_added:
        logger.info("Remove default mgmt-gateway-route earlier added")
        duthost.shell("ip route del default via {}".format(mg_gwaddr), module_ignore_errors=True)
    return res['ansible_facts']['downloaded_image_version']


def check_services(duthost):
    """
    Perform a health check of services
    """
    logging.info("Wait until DUT uptime reaches {}s".format(300))
    while duthost.get_uptime().total_seconds() < 300:
        time.sleep(1)
    logging.info("Wait until all critical services are fully started")
    logging.info("Check critical service status")
    pytest_assert(duthost.critical_services_fully_started(), "dut.critical_services_fully_started is False")

    for service in duthost.critical_services:
        status = duthost.get_service_props(service)
        pytest_assert(status["ActiveState"] == "active", "ActiveState of {} is {}, expected: active"
                      .format(service, status["ActiveState"]))
        pytest_assert(status["SubState"] == "running", "SubState of {} is {}, expected: running"
                      .format(service, status["SubState"]))


def check_reboot_cause(duthost, expected_cause):
    reboot_cause = get_reboot_cause(duthost)
    logging.info("Checking cause from dut {} to expected {}".format(reboot_cause, expected_cause))
    return reboot_cause == expected_cause


@pytest.fixture
def create_hole_in_tcam(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    ROUTER_MAC_ADDRESS = duthost.shell(
        "sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'")["stdout_lines"][0].decode("utf-8")
    DOWNSTREAM_VLAN_LIST = duthost.shell(
        "sonic-cfggen -d -v 'VLAN|list' | tr -d '[],'")['stdout']
    VLAN = duthost.shell(
        "echo {} | sed -e 's/'u/'/'".format(DOWNSTREAM_VLAN_LIST))['stdout']
    APP_DB_FDB_ROUTER_MAC = ROUTER_MAC_ADDRESS.upper().replace(':', '-')
    STATE_DB_FDB_ROUTER_MAC = duthost.shell("echo {}".format(ROUTER_MAC_ADDRESS))['stdout']
    BRCM_STATION_ROUTER_MAC = ROUTER_MAC_ADDRESS.upper().replace(':', '')

    def apply_fdb_config(duthost, vlan_id, iface, appdb_router_mac):
        """ Creates FDB config and applies it on DUT """
        dut_fdb_config = os.path.join("/tmp", "fdb.json")
        fdb_entry_json = [{ "FDB_TABLE:{}:{}".format(vlan_id, appdb_router_mac):
            { "port": iface, "type": "dynamic" }, "OP": "SET" }]
        with tempfile.NamedTemporaryFile(suffix=".json", prefix="fdb_config") as fp:
            logger.info("Generating FDB config")
            json.dump(fdb_entry_json, fp)
            fp.flush()
            # Copy FDB JSON config to switch
            duthost.template(src=fp.name, dest=dut_fdb_config, force=True)
        # Copy FDB JSON config to SWSS container
        cmd = "docker cp {} swss:/".format(dut_fdb_config)
        duthost.command(cmd)
        # Add FDB entry
        cmd = "docker exec -i swss swssconfig /fdb.json"
        duthost.command(cmd)

    def create_hole(duthost, localhost, metadata_process):
        PORT = random.choice(duthost.get_vlan_intfs())
        # Add router MAC to state-db
        duthost.shell(
            "redis-cli -n 6 hset 'FDB_TABLE|'Vlan1000:'{}'  'type' 'dynamic'".format(STATE_DB_FDB_ROUTER_MAC))
        duthost.shell(
            "redis-cli -n 6 hset 'FDB_TABLE|'Vlan1000:'{}'  'port' {}".format(STATE_DB_FDB_ROUTER_MAC, PORT))

        # Add router MAC to app-db
        apply_fdb_config(duthost, VLAN, PORT, APP_DB_FDB_ROUTER_MAC)
        # Check if the router mac exists in the DBs
        exists_in_statedb = duthost.shell(
            "redis-cli -n 6 EXISTS 'FDB_TABLE|'{}':'{}".format(VLAN, STATE_DB_FDB_ROUTER_MAC))['stdout']
        exists_in_appdb = duthost.shell(
            "redis-cli -n 0 EXISTS 'FDB_TABLE:'{}':'{}".format(VLAN, APP_DB_FDB_ROUTER_MAC))['stdout']
        if exists_in_statedb != '1' or exists_in_appdb != '1':
            logger.error("Failed to add router MAC address to db. Statedb - {}; APPLdb - {}".format(
                exists_in_statedb, exists_in_appdb))

        # Warm reboot to create a hole in my_station_tcam
        reboot(duthost, localhost, reboot_type=REBOOT_TYPE_WARM)

        # Verify that the tcam hole is now created
        STATION_TCAM_SIZE = duthost.shell(
            "bcmcmd -n 0 'listmem my_station_tcam' | grep 'Entries:' | awk '{print $2}'")['stdout']
        STATION_TCAM_LAST_INDEX_EXIST= duthost.shell(
            "bcmcmd -n 0 'dump chg my_station_tcam' | grep -c '\[{}\]'".format(
                int(STATION_TCAM_SIZE) - 1))['stdout']
        if STATION_TCAM_LAST_INDEX_EXIST == '1':
            logger.info("Hole in TCAM found")
        else:
            logger.error("Hole in TCAM not found when expected.")

        # If Metadata script is used, the below steps will be performed by the replaced script on the device
        if not metadata_process:
            logger.info("Set up Station TCAM Entry 1 Vlan Mask as 0 for mitigation on Broadcom")
            duthost.shell("bcmcmd 'l2 station add id=1 mac=0x{} macm=0xffffffffffff ".format(BRCM_STATION_ROUTER_MAC) +
            "vlanid=0 vlanidm=0 ipv4=1 ipv6=1 arprarp=1 replace=1'")
            # Remove app db entry before warmboot to image with a fix
            duthost.shell("redis-cli -n 0 del 'FDB_TABLE:'{}':'{}".format(VLAN, APP_DB_FDB_ROUTER_MAC))

    yield create_hole

    # clean up
    duthost.shell("redis-cli -n 6 del 'FDB_TABLE|'{}':'{}".format(VLAN, STATE_DB_FDB_ROUTER_MAC), module_ignore_errors=True)
    duthost.shell("redis-cli -n 0 del 'FDB_TABLE:'{}':'{}".format(VLAN, APP_DB_FDB_ROUTER_MAC), module_ignore_errors=True)
    duthost.shell("docker exec -i swss rm /fdb.json*", module_ignore_errors=True)


def check_copp_config(duthost):
    logging.info("Comparing CoPP configuration from copp_cfg.json to COPP_TABLE")
    copp_tables = json.loads(duthost.shell("sonic-db-dump -n APPL_DB -k COPP_TABLE* -y")["stdout"])
    copp_cfg = json.loads(duthost.shell("cat /etc/sonic/copp_cfg.json")["stdout"])
    feature_status = duthost.shell("show feature status")["stdout"]
    copp_tables_formatted = get_copp_table_formatted_dict(copp_tables)
    copp_cfg_formatted = get_copp_cfg_formatted_dict(copp_cfg, feature_status)
    pytest_assert(copp_tables_formatted == copp_cfg_formatted,
                  "There is a difference between CoPP config and CoPP tables. CoPP config: {}\nCoPP tables:"
                  " {}".format(copp_tables_formatted, copp_cfg_formatted))


def get_copp_table_formatted_dict(copp_tables):
    """
    Format the copp tables output to "copp_group":{"values"} only
    """
    formatted_dict = {}
    for queue_group, queue_group_value in copp_tables.items():
        new_queue_group = queue_group.replace("COPP_TABLE:", "")
        formatted_dict.update({new_queue_group: queue_group_value["value"]})
    logging.debug("Formatted copp tables dictionary: {}".format(formatted_dict))
    return formatted_dict


def get_copp_cfg_formatted_dict(copp_cfg, feature_status):
    """
    Format the copp_cfg.json output to compare with copp tables
    """
    formatted_dict = {}
    for trap_name, trap_value in copp_cfg["COPP_TRAP"].items():
        pattern = r"{}\s+enabled".format(trap_name)
        trap_enabled = re.search(pattern, feature_status)
        if trap_value.get("always_enabled", "") or trap_enabled:
            trap_group = trap_value["trap_group"]
            if trap_group in formatted_dict:
                exist_trap_ids = formatted_dict[trap_group]["trap_ids"].split(",")
                additional_trap_ids = trap_value["trap_ids"].split(",")
                trap_ids = exist_trap_ids + additional_trap_ids
                trap_ids.sort()
                formatted_dict[trap_group].update({"trap_ids": ",".join(trap_ids)})
            else:
                formatted_dict.update({trap_group: copp_cfg["COPP_GROUP"][trap_group]})
                formatted_dict[trap_group].update({"trap_ids": trap_value["trap_ids"]})
    formatted_dict.update({"default": copp_cfg["COPP_GROUP"]["default"]})
    logging.debug("Formatted copp_cfg.json dictionary: {}".format(formatted_dict))
    return formatted_dict


def upgrade_test_helper(duthost, localhost, ptfhost, from_image, to_image,
                        tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer, modify_reboot_script=None, allow_fail=False,
                        sad_preboot_list=None, sad_inboot_list=None, reboot_count=1,
                        enable_cpa=False, preboot_setup=None, postboot_setup=None):

    reboot_type = get_reboot_command(duthost, upgrade_type)
    if enable_cpa and "warm-reboot" in reboot_type:
        # always do warm-reboot with CPA enabled
        setup_ferret(duthost, ptfhost, tbinfo)
        ptf_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        reboot_type = reboot_type + " -c {}".format(ptf_ip)

    advancedReboot = None

    if upgrade_type == REBOOT_TYPE_COLD:
        # advance-reboot test (on ptf) does not support cold reboot yet
        if preboot_setup:
            preboot_setup()
    else:
        advancedReboot = get_advanced_reboot(rebootType=reboot_type,
                                             advanceboot_loganalyzer=advanceboot_loganalyzer,
                                             allow_fail=allow_fail)

    for i in range(reboot_count):
        if upgrade_type == REBOOT_TYPE_COLD:
            reboot(duthost, localhost)
            if postboot_setup:
                postboot_setup()
        else:
            advancedReboot.runRebootTestcase(prebootList=sad_preboot_list, inbootList=sad_inboot_list,
                                             preboot_setup=preboot_setup if i == 0 else None,
                                             postboot_setup=postboot_setup)

        if not allow_fail:
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            networking_uptime = duthost.get_networking_uptime().seconds
            timeout = max((SYSTEM_STABILIZE_MAX_TIME - networking_uptime), 1)
            if "6100" not in duthost.facts["hwsku"]:
                pytest_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
                              "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost),
                                                                                      upgrade_type))
            check_services(duthost)
            check_neighbors(duthost, tbinfo)
            check_copp_config(duthost)

    if enable_cpa and "warm-reboot" in reboot_type:
        ptfhost.shell('supervisorctl stop ferret')
