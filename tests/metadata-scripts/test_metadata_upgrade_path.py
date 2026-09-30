import hashlib
import json
import logging
import random
import shlex
import uuid

import pytest
from utilities import (
    boot_into_base_image,
    boot_into_base_image_t2,
    cleanup_prev_images,
    sonic_update_firmware,
    stage_metadata_scripts
)
from postupgrade_helper import run_postupgrade_actions, run_bgp_neighbor
from firmware_report_helper import find_metadata_actions_dir, verify_unmapped_update_firmware_failure_report
from upgrade_strategies import run_preload_firmware_script
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import patch_rsyslog
from tests.common.reboot import REBOOT_TYPE_COLD
from tests.common.helpers.upgrade_helpers import install_sonic, upgrade_test_helper, add_pfc_storm_table
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.fixtures.advanced_reboot import get_advanced_reboot                                   # noqa F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db                            # noqa F401
from tests.common.fixtures.consistency_checker.consistency_checker import consistency_checker_provider  # noqa F401
from tests.common.platform.device_utils import advanceboot_loganalyzer, advanceboot_neighbor_restore, \
    verify_dut_health, verify_testbed_health                                                            # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory                                 # noqa F401
from tests.common.platform.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.platform_tests.verify_dut_health import add_fail_step_to_reboot  # lgtm[py/unused-import]    # noqa F401

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


@pytest.fixture
def preload_ehf_payload_server(localhost, ptfhost, request):
    """Serve an EHF test payload from the PTF management interface."""
    if not request.config.getoption('metadata_process'):
        pytest.skip("This test requires --metadata_process")
    if request.config.getoption('upgrade_strategy') != 'script':
        pytest.skip("This test validates the script-based preload strategy")

    server_token = str(uuid.uuid4())
    server_root = "/tmp/preload-firmware-ehf-{}".format(server_token)
    payload_name = "preload-firmware-ehf-payload"
    payload_path = "{}/{}".format(server_root, payload_name)
    server_log = "{}.log".format(server_root)
    payload_content = "SONiC preload_firmware EHF checksum failure payload\n"
    server_pid = ""

    port_result = ptfhost.shell(
        "python3 -c \"import socket; s=socket.socket(); s.bind(('', 0)); "
        "print(s.getsockname()[1]); s.close()\""
    )
    server_port = int(port_result["stdout"].strip())

    try:
        ptfhost.file(path=server_root, state="directory")
        ptfhost.copy(content=payload_content, dest=payload_path)
        payload_md5 = hashlib.md5(
            payload_content.encode("utf-8")
        ).hexdigest()
        http_server_command = (
            "cd {root} && exec python3 -m http.server {port} --bind 0.0.0.0"
        ).format(
            root=shlex.quote(server_root),
            port=server_port
        )
        server_result = ptfhost.shell(
            "nohup sh -c {command} > {log} 2>&1 & echo $!".format(
                command=shlex.quote(http_server_command),
                log=shlex.quote(server_log)
            )
        )
        server_pid = server_result["stdout"].strip().splitlines()[-1]
        pytest_assert(
            server_pid.isdigit(),
            "Failed to start EHF payload server: {}".format(server_result)
        )
        localhost.wait_for(
            host=ptfhost.mgmt_ip,
            port=server_port,
            state="started",
            timeout=30
        )

        yield {
            "filename": payload_name,
            "md5": payload_md5,
            "url": "http://{}:{}/{}".format(
                ptfhost.mgmt_ip,
                server_port,
                payload_name
            )
        }
    finally:
        if server_pid.isdigit():
            ptfhost.shell(
                "kill {}".format(server_pid),
                module_ignore_errors=True
            )
        ptfhost.file(path=server_root, state="absent")
        ptfhost.file(path=server_log, state="absent")


@pytest.fixture(scope="module")
def upgrade_path_lists(request, upgrade_type_params, base_image, target_image):
    restore_to_image = request.config.getoption('restore_to_image')
    enable_cpa = request.config.getoption('enable_cpa')
    if not base_image or not target_image:
        pytest.skip("base_image_list or target_image_list is empty")
    return upgrade_type_params, base_image, target_image, restore_to_image, enable_cpa


@pytest.fixture
def skip_cancelled_case(request, upgrade_type_params):
    if "test_cancelled_upgrade_path" in request.node.name and \
            upgrade_type_params not in ["warm", "fast"]:
        pytest.skip("Cancelled upgrade path test supported only for fast and warm reboot types.")


def pytest_generate_tests(metafunc):
    if metafunc.config.getoption("multi_hop_upgrade_path"):
        # This pytest execution is for multi-hop upgrade path - don't parametrize for A->B upgrade
        return
    if "upgrade_path_lists" not in metafunc.fixturenames:
        return

    # Parametrize for A->B upgrade
    base_image_list = metafunc.config.getoption("base_image_list")
    base_image_list = base_image_list.split(',')
    target_image_list = metafunc.config.getoption("target_image_list")
    target_image_list = target_image_list.split(',')
    base_branch_names = list()
    target_branch_names = list()
    for base_image in base_image_list:
        url_parts = base_image.split("/")
        for part in url_parts:
            if "internal-" in part:
                branch = part.split("internal-")[-1]
                base_branch_names.append(branch + "-to")
            if "public" in part:
                target_branch_names.append("master")
    for target_image in target_image_list:
        url_parts = target_image.split("/")
        for part in url_parts:
            if "internal-" in part:
                branch = part.split("internal-")[-1]
                target_branch_names.append(branch)
            if "public" in part:
                target_branch_names.append("master")
    metafunc.parametrize("base_image", base_image_list, scope="module", ids=base_branch_names)
    metafunc.parametrize("target_image", target_image_list, scope="module", ids=target_branch_names)

    upgrade_types = metafunc.config.getoption("upgrade_type")
    upgrade_types = upgrade_types.split(",")
    input_sad_cases = metafunc.config.getoption("sad_case_list")
    input_sad_list = list()
    for input_case in input_sad_cases.split(","):
        input_case = input_case.strip()
        if input_case.lower() not in SAD_CASE_LIST:
            logging.warn("Unknown SAD case ({}) - skipping it.".format(input_case))
            continue
        input_sad_list.append(input_case.lower())
    if "upgrade_type_params" in metafunc.fixturenames:
        if "sad_case_type" not in metafunc.fixturenames:
            params = upgrade_types
            metafunc.parametrize("upgrade_type_params", params, scope="module")
        else:
            metafunc.parametrize("upgrade_type_params", ["warm"], scope="module")
            metafunc.parametrize("sad_case_type", input_sad_list, scope="module")


def setup_upgrade_test(duthost, localhost, from_image, to_image,
                       tbinfo, metadata_process, upgrade_type,
                       modify_reboot_script=None, allow_fail=False, upgrade_strategy=None):
    """Sets up the test environment for an A->B upgrade test."""
    logger.info("Test upgrade path from {} to {} on {}".format(from_image, to_image, duthost.hostname))

    # Install and reboot into base image
    if tbinfo['topo']['type'] != 't2':  # We do this all at once seperately for T2
        cleanup_prev_images(duthost)
        boot_into_base_image(duthost, localhost, from_image, tbinfo)

    # Install target image
    logger.info("Upgrading {} to {}".format(duthost.hostname, to_image))
    if metadata_process:
        if upgrade_strategy is None:
            raise ValueError("upgrade_strategy is required when metadata_process=True")
        sonic_update_firmware(duthost, localhost, to_image, upgrade_type, upgrade_strategy)
    else:
        install_sonic(duthost, to_image, tbinfo)

    logger.info("Add pfc storm table to {}.".format(duthost.hostname))
    add_pfc_storm_table(duthost)

    if allow_fail and modify_reboot_script:
        # add fail step to reboot script
        modify_reboot_script(upgrade_type)


def test_preload_firmware_ehf_checksum_failure(
        localhost, duthosts, rand_one_dut_hostname,
        preload_ehf_payload_server):
    """Test checksum failure leaves a non-retriable EHF report."""
    duthost = duthosts[rand_one_dut_hostname]
    event_guid = str(uuid.uuid4())
    payload_name = preload_ehf_payload_server["filename"]
    payload_url = preload_ehf_payload_server["url"]
    payload_path = "/tmp/{}".format(payload_name)
    report_path = (
        "/host/sonic-upgrade-reports/preload_firmware.{}.json".format(
            event_guid
        )
    )
    incorrect_md5 = "0" * 32
    cleanup_command = "sudo rm -f {payload} {report} {report_tmp}".format(
        payload=shlex.quote(payload_path),
        report=shlex.quote(report_path),
        report_tmp=shlex.quote(report_path + ".tmp")
    )

    try:
        duthost.shell(cleanup_command, module_ignore_errors=True)
        stage_metadata_scripts(duthost, localhost)
        result = run_preload_firmware_script(
            duthost,
            payload_url,
            payload_name,
            incorrect_md5,
            event_guid=event_guid,
            module_ignore_errors=True
        )
        pytest_assert(
            result["rc"] == 3,
            (
                "Expected preload_firmware checksum failure rc=3, got "
                "rc={}: stdout={!r}, stderr={!r}"
            ).format(
                result["rc"],
                result.get("stdout", ""),
                result.get("stderr", "")
            )
        )

        payload_stat = duthost.stat(path=payload_path)["stat"]
        pytest_assert(payload_stat["exists"] and payload_stat["size"] > 0,
                      "preload_firmware did not download the EHF test payload")
        downloaded_md5_result = duthost.command(
            "md5sum {}".format(shlex.quote(payload_path))
        )
        downloaded_md5 = downloaded_md5_result["stdout"].split()[0]
        pytest_assert(
            downloaded_md5 == preload_ehf_payload_server["md5"],
            "Downloaded EHF test payload does not match the PTF source"
        )

        report_result = duthost.command(
            "sudo cat {}".format(shlex.quote(report_path))
        )
        report = json.loads(report_result["stdout"])
        summary = report.get("sonic_upgrade_summary", {})
        actions = report.get("sonic_upgrade_actions", {})
        logger.info("Validated preload_firmware EHF report: %s",
                    json.dumps(report, sort_keys=True))

        pytest_assert(
            summary.get("script_name") == "preload_firmware",
            "EHF report has the wrong script_name: {}".format(summary)
        )
        pytest_assert(
            summary.get("guid") == event_guid,
            "EHF report GUID does not match: {}".format(summary)
        )
        pytest_assert(
            summary.get("fault_code") == "3",
            "EHF report has the wrong fault_code: {}".format(summary)
        )
        pytest_assert(
            actions.get("retriable") is False,
            "EHF checksum failure must be non-retriable: {}".format(actions)
        )
    finally:
        duthost.shell(cleanup_command, module_ignore_errors=True)


def test_cancelled_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                                upgrade_path_lists, skip_cancelled_case, tbinfo, request,
                                get_advanced_reboot, advanceboot_loganalyzer,  # noqa: F811
                                add_fail_step_to_reboot, verify_dut_health,    # noqa: F811
                                consistency_checker_provider, upgrade_strategy_fixture):  # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, _ = upgrade_path_lists
    modify_reboot_script = add_fail_step_to_reboot
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, modify_reboot_script=modify_reboot_script,
                           allow_fail=True, upgrade_strategy=upgrade_strategy_fixture)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        allow_fail=True)


def test_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                      upgrade_path_lists, tbinfo, request, get_advanced_reboot,  # noqa: F811
                      advanceboot_loganalyzer, verify_dut_health,                # noqa: F811
                      consistency_checker_provider, upgrade_strategy_fixture):   # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, upgrade_strategy=upgrade_strategy_fixture)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        enable_cpa=enable_cpa)

    if metadata_process and request.config.getoption('upgrade_strategy') == 'script':
        # Include reporting coverage in the existing A->B case after a successful upgrade.
        verify_unmapped_update_firmware_failure_report(duthost, find_metadata_actions_dir())


def test_upgrade_path_t2(localhost, duthosts, ptfhost, upgrade_path_lists,
                         tbinfo, request, verify_testbed_health,             # noqa: F811
                         upgrade_strategy_fixture):
    _, from_image, to_image, _, _ = upgrade_path_lists
    # Only cold reboot is supported for T2
    upgrade_type = REBOOT_TYPE_COLD
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')
    skip_bgp_neighbor = request.config.getoption('skip_bgp_neighbor')

    # Boot whole chassis into base image first
    for duthost in duthosts:
        cleanup_prev_images(duthost)
    boot_into_base_image_t2(duthosts, localhost, from_image, tbinfo)

    def upgrade_path_preboot_setup(dut):
        setup_upgrade_test(dut, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, upgrade_strategy=upgrade_strategy_fixture)

    def upgrade_path_postboot_setup(dut):
        run_postupgrade_actions(dut, localhost, tbinfo, metadata_process, skip_postupgrade_actions)
        run_bgp_neighbor(dut, localhost, tbinfo, metadata_process, skip_bgp_neighbor)
        patch_rsyslog(dut)

    suphost = duthosts.supervisor_nodes[0]
    upgrade_test_helper(suphost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type,
                        get_advanced_reboot=None,               # Not needed as only cold reboot supported to T2
                        advanceboot_loganalyzer=None,           # Not needed as only cold reboot supported to T2
                        preboot_setup=lambda: upgrade_path_preboot_setup(suphost),
                        postboot_setup=lambda: upgrade_path_postboot_setup(suphost),
                        consistency_checker_provider=None,
                        enable_cpa=False)

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for dut in duthosts.frontend_nodes:
            executor.submit(upgrade_test_helper, dut, localhost, ptfhost, from_image,
                            to_image, tbinfo, upgrade_type,
                            get_advanced_reboot=None,           # Not needed as only cold reboot supported to T2
                            advanceboot_loganalyzer=None,       # Not needed as only cold reboot supported to T2
                            preboot_setup=lambda dut=dut: upgrade_path_preboot_setup(dut),
                            postboot_setup=lambda dut=dut: upgrade_path_postboot_setup(dut),
                            consistency_checker_provider=None,  # Not needed as only cold reboot supported to T2
                            enable_cpa=False)


def test_upgrade_path_t2_delayed(localhost, duthosts, ptfhost, upgrade_path_lists,
                                 tbinfo, request, verify_testbed_health,                      # noqa: F811
                                 upgrade_strategy_fixture):
    """
    This test is similar to test_upgrade_path_t2 but delays relegates one linecard to be upgraded late,
    after all other devices have been upgraded.
    """

    if len(duthosts.frontend_nodes) < 2:
        pytest.skip("This test requires at least 2 frontend nodes")

    _, from_image, to_image, _, _ = upgrade_path_lists
    # Only cold reboot is supported for T2
    upgrade_type = REBOOT_TYPE_COLD
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')
    skip_bgp_neighbor = request.config.getoption('skip_bgp_neighbor')

    for duthost in duthosts:
        cleanup_prev_images(duthost)
    boot_into_base_image_t2(duthosts, localhost, from_image, tbinfo)

    def upgrade_path_preboot_setup(dut):
        setup_upgrade_test(dut, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, upgrade_strategy=upgrade_strategy_fixture)

    def upgrade_path_postboot_setup(dut):
        run_postupgrade_actions(dut, localhost, tbinfo, metadata_process, skip_postupgrade_actions)
        run_bgp_neighbor(dut, localhost, tbinfo, metadata_process, skip_bgp_neighbor)
        patch_rsyslog(dut)

    duthosts_frontend_nodes = list(duthosts.frontend_nodes)
    delayed_dut = random.choice(duthosts_frontend_nodes)
    duthosts_frontend_nodes.remove(delayed_dut)
    logger.info("Delaying upgrade for {}".format(delayed_dut.hostname))

    suphost = duthosts.supervisor_nodes[0]
    logger.info("Starting upgrade for {}".format(suphost))
    upgrade_test_helper(suphost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type,
                        get_advanced_reboot=None,               # Not needed as only cold reboot supported to T2
                        advanceboot_loganalyzer=None,           # Not needed as only cold reboot supported to T2
                        preboot_setup=lambda: upgrade_path_preboot_setup(suphost),
                        postboot_setup=lambda: upgrade_path_postboot_setup(suphost),
                        consistency_checker_provider=None,      # Not needed as only cold reboot supported to T2
                        enable_cpa=False)

    logger.info("Starting upgrade for {}".format(duthosts_frontend_nodes))
    # Upgrade all frontend nodes but delayed_dut in parallel
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for dut in duthosts_frontend_nodes:
            executor.submit(upgrade_test_helper, dut, localhost, ptfhost, from_image,
                            to_image, tbinfo, upgrade_type,
                            get_advanced_reboot=None,           # Not needed as only cold reboot supported to T2
                            advanceboot_loganalyzer=None,       # Not needed as only cold reboot supported to T2
                            preboot_setup=lambda dut=dut: upgrade_path_preboot_setup(dut),
                            postboot_setup=lambda dut=dut: upgrade_path_postboot_setup(dut),
                            consistency_checker_provider=None,  # Not needed as only cold reboot supported to T2
                            enable_cpa=False)

    logger.info("Starting upgrade (delayed) for {}".format(delayed_dut))
    upgrade_test_helper(delayed_dut, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type,
                        get_advanced_reboot=None,               # Not needed as only cold reboot supported to T2
                        advanceboot_loganalyzer=None,           # Not needed as only cold reboot supported to T2
                        preboot_setup=lambda: upgrade_path_preboot_setup(delayed_dut),
                        postboot_setup=lambda: upgrade_path_postboot_setup(delayed_dut),
                        consistency_checker_provider=None,      # Not needed as only cold reboot supported to T2
                        enable_cpa=False)


def test_double_upgrade_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                             upgrade_path_lists, tbinfo, request, get_advanced_reboot,  # noqa: F811
                             advanceboot_loganalyzer, verify_dut_health,                # noqa: F811
                             consistency_checker_provider, upgrade_strategy_fixture):   # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, upgrade_strategy=upgrade_strategy_fixture)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        reboot_count=2, enable_cpa=enable_cpa)


def test_warm_upgrade_sad_path(localhost, duthosts, rand_one_dut_hostname, ptfhost,
                               upgrade_path_lists, tbinfo, request, get_advanced_reboot,                   # noqa: F811
                               advanceboot_loganalyzer, verify_dut_health, nbrhosts, fanouthosts, vmhost,  # noqa: F811
                               backup_and_restore_config_db, consistency_checker_provider,                 # noqa: F811
                               advanceboot_neighbor_restore, sad_case_type, upgrade_strategy_fixture):     # noqa: F811
    duthost = duthosts[rand_one_dut_hostname]
    upgrade_type, from_image, to_image, _, enable_cpa = upgrade_path_lists
    metadata_process = request.config.getoption('metadata_process')
    skip_postupgrade_actions = request.config.getoption('skip_postupgrade_actions')
    sad_preboot_list, sad_inboot_list = get_sad_case_list(duthost, nbrhosts,
                                                          fanouthosts, vmhost, tbinfo, sad_case_type)

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           metadata_process, upgrade_type, upgrade_strategy=upgrade_strategy_fixture)

    def upgrade_path_postboot_setup():
        run_postupgrade_actions(duthost, localhost, tbinfo, metadata_process, skip_postupgrade_actions,
                                check_failed=False)
        patch_rsyslog(duthost)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, upgrade_type, get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        postboot_setup=upgrade_path_postboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        sad_preboot_list=sad_preboot_list,
                        sad_inboot_list=sad_inboot_list, enable_cpa=enable_cpa)
