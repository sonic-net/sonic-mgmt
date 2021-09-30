import pytest
import os
import tempfile
import json
import random
import logging
from datetime import datetime
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.ssh_utils import prepare_testbed_ssh_keys
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_COLD, REBOOT_TYPE_WARM
from tests.upgrade_path.upgrade_helpers import check_services, install_sonic, check_sonic_version, get_reboot_command
from tests.upgrade_path.upgrade_helpers import ptf_params, setup  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)


# upgrade_path pytest arguments
def pytest_addoption(parser):
    options_group = parser.getgroup("Upgrade_path test suite options")

    options_group.addoption(
        "--upgrade_type",
        default="warm",
        help="Specify the type (warm/fast/cold) of upgrade that is needed from source to target image",
    )

    options_group.addoption(
        "--base_image_list",
        default="",
        help="Specify the base image(s) for upgrade (comma seperated list is allowed)",
    )

    options_group.addoption(
        "--target_image_list",
        default="",
        help="Specify the target image(s) for upgrade (comma seperated list is allowed)",
    )

    options_group.addoption(
        "--restore_to_image",
        default="",
        help="Specify the target image to restore to, or stay in target image if empty",
    )

@pytest.fixture(scope="module")
def upgrade_path_lists(request):
    upgrade_type = request.config.getoption('upgrade_type')
    from_list = request.config.getoption('base_image_list')
    to_list = request.config.getoption('target_image_list')
    restore_to_image = request.config.getoption('restore_to_image')
    return upgrade_type, from_list, to_list, restore_to_image


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

    def create_hole(duthost, localhost):
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

        # Set up Station TCAM Entry 1 Vlan Mask as 0 for mitigation on Broadcom
        duthost.shell("bcmcmd 'l2 station add id=1 mac=0x{} macm=0xffffffffffff ".format(BRCM_STATION_ROUTER_MAC) +
        "vlanid=0 vlanidm=0 ipv4=1 ipv6=1 arprarp=1 replace=1'")
        # Remove app db entry before warmboot to image with a fix
        duthost.shell("redis-cli -n 0 del 'FDB_TABLE:'{}':'{}".format(VLAN, APP_DB_FDB_ROUTER_MAC))

    yield create_hole

    # clean up
    duthost.shell("redis-cli -n 6 del 'FDB_TABLE|'{}':'{}".format(VLAN, STATE_DB_FDB_ROUTER_MAC), module_ignore_errors=True)
    duthost.shell("redis-cli -n 0 del 'FDB_TABLE:'{}':'{}".format(VLAN, APP_DB_FDB_ROUTER_MAC), module_ignore_errors=True)
    duthost.shell("docker exec -i swss rm /fdb.json*", module_ignore_errors=True)


@pytest.mark.device_type('vs')
def test_upgrade_path(request, localhost, duthosts, rand_one_dut_hostname, ptfhost,
    upgrade_path_lists, ptf_params, setup, tbinfo, create_hole_in_tcam):
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_list_images, to_list_images, _ = upgrade_path_lists
    from_list = from_list_images.split(',')
    to_list = to_list_images.split(',')
    assert (from_list and to_list)
    for from_image in from_list:
        for to_image in to_list:
            logger.info("Test upgrade path from {} to {}".format(from_image, to_image))
            # Install base image
            logger.info("Installing {}".format(from_image))
            target_version = install_sonic(duthost, from_image, tbinfo)
            # Perform a cold reboot
            logger.info("Cold reboot the DUT to make the base image as current")
            reboot(duthost, localhost)
            check_sonic_version(duthost, target_version)

            # Create a hole in tcam
            create_hole = request.config.getoption('tcam_hole')
            if create_hole:
                create_hole_in_tcam(duthost, localhost)

            # Install target image
            logger.info("Upgrading to {}".format(to_image))
            target_version = install_sonic(duthost, to_image, tbinfo)
            test_params = ptf_params
            test_params['target_version'] = target_version
            test_params['reboot_type'] = get_reboot_command(duthost, upgrade_type)
            if create_hole:
                ptf_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
                test_params['reboot_type'] = "warm-reboot -c {}".format(ptf_ip)
            prepare_testbed_ssh_keys(duthost, ptfhost, test_params['dut_username'])
            log_file = "/tmp/advanced-reboot.ReloadTest.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
            if test_params['reboot_type'] == reboot_ctrl_dict.get(REBOOT_TYPE_COLD).get("command"):
                # advance-reboot test (on ptf) does not support cold reboot yet
                reboot(duthost, localhost)
            else:
                ptf_runner(ptfhost,
                        "ptftests",
                        "advanced-reboot.ReloadTest",
                        platform_dir="ptftests",
                        params=test_params,
                        platform="remote",
                        qlen=10000,
                        log_file=log_file)
            reboot_cause = get_reboot_cause(duthost)
            logger.info("Check reboot cause. Expected cause {}".format(upgrade_type))
            pytest_assert(reboot_cause == upgrade_type, "Reboot cause {} did not match the trigger - {}".format(reboot_cause, upgrade_type))
            check_services(duthost)
