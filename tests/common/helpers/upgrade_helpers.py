import pytest
import logging
import ipaddress
import json
import re
from dataclasses import dataclass
from six.moves.urllib.parse import urlparse
import tests.common.fixtures.grpc_fixtures  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common import reboot
from tests.common.reboot import get_reboot_cause, reboot_ctrl_dict
from tests.common.reboot import REBOOT_TYPE_WARM, REBOOT_TYPE_COLD
from tests.common.reboot import reboot_and_check
from tests.common.utilities import wait_until, setup_ferret
from tests.common.platform.device_utils import check_neighbors
from typing import Dict, Optional

SYSTEM_STABILIZE_MAX_TIME = 300
logger = logging.getLogger(__name__)

TMP_VLAN_PORTCHANNEL_FILE = '/tmp/portchannel_interfaces.json'
TMP_VLAN_FILE = '/tmp/vlan_interfaces.json'
TMP_PORTS_FILE = '/tmp/ports.json'
TMP_PEER_INFO_FILE = "/tmp/peer_dev_info.json"
TMP_PEER_PORT_INFO_FILE = "/tmp/neigh_port_info.json"


@dataclass(frozen=True)
class GnoiUpgradeConfig:
    to_image: str
    dut_image_path: str
    upgrade_type: str
    protocol: str = "HTTP"
    allow_fail: bool = False
    to_version: Optional[str] = None  # Optional expected Version string to validate after upgrade


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
    if upgrade_type == REBOOT_TYPE_WARM:
        next_os_version = duthost.shell('sonic_installer list | grep Next | cut -f2 -d " "')['stdout']
        current_os_version = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']
        # warm-reboot has to be forced for an upgrade from 201811 to 201811+ to bypass ASIC config changed error
        if 'SONiC-OS-201811' in current_os_version and 'SONiC-OS-201811' not in next_os_version:
            reboot_command = "warm-reboot -f"
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
        rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network('0.0.0.0/0'))
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


def check_services(duthost, tbinfo):
    """
    Perform a health check of services
    """
    dut_min_uptime = 900 if 't2' in tbinfo['topo']['name'] else 300
    logging.info("Wait until all critical services are fully started")
    pytest_assert(wait_until(dut_min_uptime, 30, 30, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    critical_services = [re.sub(r'(\d+)$', r'@\1', service) for service in duthost.critical_services]
    for service in critical_services:
        status = duthost.get_service_props(service)
        pytest_assert(status["ActiveState"] == "active", "ActiveState of {} is {}, expected: active"
                      .format(service, status["ActiveState"]))
        pytest_assert(status["SubState"] == "running", "SubState of {} is {}, expected: running"
                      .format(service, status["SubState"]))


def check_reboot_cause(duthost, expected_cause):
    reboot_cause = get_reboot_cause(duthost)
    logging.info("Checking cause from dut {} to expected {}".format(reboot_cause, expected_cause))
    return reboot_cause == expected_cause


def check_copp_config(duthost):
    logging.info("Comparing CoPP configuration from copp_cfg.json to COPP_TABLE")

    if duthost.is_supervisor_node() and duthost.facts['switch_type'] == "fabric":
        logging.info("Skipping CoPP config check for fabric (VoQ) supervisor card as it "
                     "doesn't program CoPP tables into APPL_DB")
        return

    for asichost in duthost.asics:
        copp_tables = json.loads(asichost.command("sonic-db-dump -n APPL_DB -k COPP_TABLE* -y")["stdout"])
        copp_cfg = json.loads(duthost.shell("cat /etc/sonic/copp_cfg.json")["stdout"])
        feature_status = duthost.shell("show feature status")["stdout"]
        copp_tables_formatted = get_copp_table_formatted_dict(copp_tables)
        copp_cfg_formatted = get_copp_cfg_formatted_dict(copp_cfg, feature_status)
        pytest_assert(copp_tables_formatted == copp_cfg_formatted,
                      "There is a difference between CoPP config and CoPP tables. CoPP config: {}\nCoPP tables: {}"
                      .format(copp_tables_formatted, copp_cfg_formatted))


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
                        enable_cpa=False, preboot_setup=None, postboot_setup=None,
                        consistency_checker_provider=None):

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
                                             consistency_checker_provider=consistency_checker_provider,
                                             allow_fail=allow_fail)

    for i in range(reboot_count):
        if upgrade_type == REBOOT_TYPE_COLD:
            reboot(duthost, localhost, safe_reboot=True)
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
            pytest_assert(wait_until(timeout, 5, 0, check_reboot_cause, duthost, upgrade_type),
                          "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost),
                                                                                  upgrade_type))
            check_services(duthost, tbinfo)
            check_neighbors(duthost, tbinfo)
            check_copp_config(duthost)

    if enable_cpa and "warm-reboot" in reboot_type:
        ptfhost.shell('supervisorctl stop ferret')


def multi_hop_warm_upgrade_test_helper(duthost, localhost, ptfhost, tbinfo, get_advanced_reboot, upgrade_type,
                                       upgrade_path_urls, base_image_setup=None, pre_hop_setup=None,
                                       post_hop_teardown=None, consistency_checker_provider=None,
                                       multihop_advanceboot_loganalyzer_factory=None, sad_preboot_list=None,
                                       sad_inboot_list=None, enable_cpa=False):

    reboot_type = get_reboot_command(duthost, upgrade_type)
    if enable_cpa and "warm-reboot" in reboot_type:
        # always do warm-reboot with CPA enabled
        setup_ferret(duthost, ptfhost, tbinfo)
        ptf_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        reboot_type = reboot_type + " -c {}".format(ptf_ip)

    advancedReboot = get_advanced_reboot(rebootType=reboot_type,
                                         consistency_checker_provider=consistency_checker_provider)
    advancedReboot.runMultiHopRebootTestcase(
        upgrade_path_urls, base_image_setup=base_image_setup, pre_hop_setup=pre_hop_setup,
        post_hop_teardown=post_hop_teardown,
        multihop_advanceboot_loganalyzer_factory=multihop_advanceboot_loganalyzer_factory,
        prebootList=sad_preboot_list, inbootList=sad_inboot_list)

    if enable_cpa and "warm-reboot" in reboot_type:
        ptfhost.shell('supervisorctl stop ferret')


def _get_images_from_sonic_installer_list(duthost) -> Dict[str, Optional[str]]:
    """
    Run `sonic-installer list` and parse 'Current:' and 'Next:'.

    Returns:
        {"current": <str or None>, "next": <str or None>}
    """
    res = duthost.shell("sonic-installer list", module_ignore_errors=True)
    out = (res.get("stdout") or "").strip()
    if res.get("rc", 1) != 0 or not out:
        return {"current": None, "next": None}

    current = None
    next = None

    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^Current:\s*(.+?)\s*$", line)
        if m:
            current = m.group(1).strip()
            continue
        m = re.match(r"^Next:\s*(.+?)\s*$", line)
        if m:
            next = m.group(1).strip()
            continue

    return {"current": current, "next": next}


def perform_gnoi_upgrade(
    ptf_gnoi,
    duthost,
    tbinfo,
    cfg: GnoiUpgradeConfig,
    cold_reboot_setup=None,
    localhost=None,
    conn_graph_facts=None,
    xcvr_skip_list=None,
    duthosts=None,
):
    """
    gNOI-based upgrade helper using PtfGnoi high-level APIs (no raw call_unary in tests).

    Flow:
      1) preboot_setup (if provided)
      2) File.TransferToRemote: download cfg.to_image -> cfg.dut_image_path on DUT
      3) System.SetPackage: set package to cfg.dut_image_path
      4) System.Reboot: trigger reboot (non-blocking; disconnect may occur)
      5) Mimic upgrade_test_helper reboot verification:
           networking_uptime -> timeout -> wait_until(check_reboot_cause)
      6) Standard post-reboot checks:
           check_services / check_neighbors / check_copp_config
      7) Version validation:
           assert expected_to_version appears in 'show version'
    """
    logger.info(
        "gNOI upgrade: to_image=%s dut_image_path=%s upgrade_type=%s protocol=%s",
        cfg.to_image, cfg.dut_image_path, cfg.upgrade_type, cfg.protocol
    )

    # ---- Input sanity ----
    pytest_assert(ptf_gnoi is not None, "ptf_gnoi must be provided")
    pytest_assert(duthost is not None, "duthost must be provided")
    pytest_assert(tbinfo is not None, "tbinfo must be provided")
    pytest_assert(cfg.to_image, "to_image must be provided")
    pytest_assert(cfg.dut_image_path, "dut_image_path must be provided")
    pytest_assert(cfg.upgrade_type, "upgrade_type must be provided")
    gNOI_REBOOT_CAUSE_TIMEOUT = 5 * 60
    # Map upgrade_type ("warm"/"cold") to gNOI enum token ("WARM"/"COLD")
    # reboot_method = "WARM" if str(cfg.upgrade_type).lower() == "warm" else "COLD"
    # ---- 1) reboot to base image ----
    if cfg.upgrade_type == REBOOT_TYPE_COLD:
        # advance-reboot test (on ptf) does not support cold reboot yet
        if cold_reboot_setup:
            cold_reboot_setup()
        # Re-apply TLS so server cert has DUT IP in SAN after reboot.
        from tests.common.fixtures.grpc_fixtures import ensure_gnoi_tls_server
        ptfhost = ptf_gnoi.grpc_client.ptfhost
        ensure_gnoi_tls_server(duthost, ptfhost)
    # ---- 2) TransferToRemote (via wrapper) ----
    transfer_resp = ptf_gnoi.file_transfer_to_remote(
        url=cfg.to_image,
        local_path=cfg.dut_image_path,
        protocol=cfg.protocol,
    )
    logger.info("TransferToRemote response: %s", transfer_resp)
    pytest_assert(isinstance(transfer_resp, dict), "TransferToRemote did not return a JSON object")

    # DUT-side validation: file exists and non-empty
    res = duthost.shell(f"test -s {cfg.dut_image_path}", module_ignore_errors=True)
    pytest_assert(res.get("rc", 1) == 0, f"Downloaded file not found or empty on DUT: {cfg.dut_image_path}")

    # ---- 3) SetPackage (via wrapper) ----
    setpkg_resp = ptf_gnoi.system_set_package(
        local_path=cfg.dut_image_path,
        version=cfg.to_version,
        activate=True,
    )
    logger.info("SetPackage response: %s", setpkg_resp)
    pytest_assert(isinstance(setpkg_resp, dict), "SetPackage did not return a JSON object")

    pytest_assert(cfg.to_version, "cfg.to_version must be provided for validation")
    # ---- 4) Reboot (via reboot_and_check) ----
    pytest_assert(localhost is not None, "localhost must be provided for reboot_and_check")
    pytest_assert(conn_graph_facts is not None, "conn_graph_facts must be provided for reboot_and_check")
    pytest_assert(xcvr_skip_list is not None, "xcvr_skip_list must be provided for reboot_and_check")

    interfaces = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})
    reboot_and_check(
        localhost,
        duthost,
        interfaces,
        xcvr_skip_list,
        reboot_type=cfg.upgrade_type,
        duthosts=duthosts,
        invocation_type="gnoi_based",
        ptf_gnoi=ptf_gnoi,
    )

    if cfg.allow_fail:
        logger.warning("allow_fail=True: skipping reboot-cause/health/version validations")
        return {"transfer_resp": transfer_resp, "setpkg_resp": setpkg_resp}

    # ---- 5) Reuse EXACT reboot-cause waiting pattern from upgrade_test_helper ----
    logger.info("Check reboot cause. Expected cause %s", cfg.upgrade_type)

    pytest_assert(
        wait_until(gNOI_REBOOT_CAUSE_TIMEOUT, 10, 0, check_reboot_cause, duthost, cfg.upgrade_type),
        "Reboot cause {} did not match the trigger - {}".format(get_reboot_cause(duthost), cfg.upgrade_type)
    )

    # ---- 6) Standard post-reboot validations ----
    check_services(duthost, tbinfo)
    check_neighbors(duthost, tbinfo)
    check_copp_config(duthost)

    # ---- 7) Version validation) ----
    images = _get_images_from_sonic_installer_list(duthost)
    logger.info("sonic-installer list parsed: %s", images)
    pytest_assert(
        images.get("current") == cfg.to_version,
        f"Current image mismatch after reboot. current={images.get('current')} expected={cfg.to_version}. full={images}"
    )

    return {"transfer_resp": transfer_resp, "setpkg_resp": setpkg_resp}
