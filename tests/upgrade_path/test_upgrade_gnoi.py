import logging
import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.upgrade_path.test_upgrade_path import setup_upgrade_test
from tests.common.helpers.upgrade_helpers import perform_gnoi_upgrade, GnoiUpgradeConfig
from tests.common.helpers.upgrade_helpers import upgrade_test_helper
from tests.common.platform.warmboot_sad_cases import get_sad_case_list, SAD_CASE_LIST
from tests.common.fixtures.advanced_reboot import get_advanced_reboot   # noqa: F401
from tests.common.fixtures.consistency_checker.consistency_checker import consistency_checker_provider  # noqa: F401
from tests.common.platform.device_utils import verify_dut_health    # noqa: F401
from tests.common.platform.device_utils import advanceboot_loganalyzer, advanceboot_neighbor_restore  # noqa: F401
from tests.common.fixtures.duthost_utils import backup_and_restore_config_db    # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
]


def pytest_generate_tests(metafunc):
    if "sad_case_type" in metafunc.fixturenames:
        sad_cases = list(SAD_CASE_LIST)
        if "multi_sad" in sad_cases and "sad_bgp" in sad_cases and "sad_lag" in sad_cases:
            sad_cases.remove("multi_sad")
        metafunc.parametrize("sad_case_type", sad_cases, scope="module")


@pytest.fixture(scope="module")
def gnoi_upgrade_path_lists(request):
    upgrade_type = request.config.getoption("upgrade_type")          # "warm" / "cold"
    from_image = request.config.getoption("base_image_list")
    to_image = request.config.getoption("target_image_list")
    to_version = request.config.getoption("target_version")

    dut_image_path = "/var/tmp/sonic_image"

    return (upgrade_type, from_image, to_image, to_version, dut_image_path)


@pytest.mark.device_type("vs")
def test_upgrade_via_gnoi(
    localhost, duthosts, ptfhost, rand_one_dut_hostname,
    nbrhosts, fanouthosts, tbinfo, request,
    gnoi_upgrade_path_lists, ptf_gnoi,  # noqa: F811
    conn_graph_facts, xcvr_skip_list
):
    duthost = duthosts[rand_one_dut_hostname]

    (upgrade_type, from_image, to_image, to_version, dut_image_path) = gnoi_upgrade_path_lists

    logger.info("Test gNOI upgrade path from %s to %s", from_image, to_image)

    cur = duthost.shell("show version", module_ignore_errors=False)["stdout"]
    logger.info("Pre-upgrade show version:\n%s", cur)

    duthost.shell(f"rm -f {dut_image_path}", module_ignore_errors=True)

    assert to_image, "target_image_list must be set (used as to_image for gNOI TransferToRemote)"

    cfg = GnoiUpgradeConfig(
        to_image=to_image,
        dut_image_path=dut_image_path,
        upgrade_type=upgrade_type,
        protocol="HTTP",
        allow_fail=False,
        to_version=to_version,
    )

    def upgrade_path_preboot_setup():
        # Save TLS config to disk before the reboot so it persists through it.
        # setup_upgrade_test reboots the DUT which restores CONFIG_DB from disk,
        # and without this save the gnmi_tls fixture's config would be wiped.
        duthost.shell("sudo config save -y")
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           upgrade_type)

    perform_gnoi_upgrade(
        ptf_gnoi=gnmi_tls.gnoi,
        duthost=duthost,
        tbinfo=tbinfo,
        cfg=cfg,
        cold_reboot_setup=upgrade_path_preboot_setup,
        localhost=localhost,
        conn_graph_facts=conn_graph_facts,
        xcvr_skip_list=xcvr_skip_list,
        duthosts=duthosts,
    )


@pytest.mark.device_type("vs")
def test_warm_upgrade_sad_path_via_gnoi(
    localhost, duthosts, ptfhost, rand_one_dut_hostname,
    nbrhosts, fanouthosts, vmhost, tbinfo, request,
    gnoi_upgrade_path_lists, gnmi_tls,  # noqa: F811
    get_advanced_reboot, verify_dut_health, advanceboot_loganalyzer,  # noqa: F811
    backup_and_restore_config_db,  # noqa: F811
    advanceboot_neighbor_restore, consistency_checker_provider,  # noqa: F811
    sad_case_type,
):
    duthost = duthosts[rand_one_dut_hostname]

    (_, from_image, to_image, to_version, dut_image_path) = gnoi_upgrade_path_lists

    logger.info("Test gNOI warm upgrade sad path from %s to %s (sad_case_type=%s)",
                from_image, to_image, sad_case_type)

    def upgrade_path_preboot_setup():
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           "warm")

    sad_preboot_list, sad_inboot_list = get_sad_case_list(
        duthost, nbrhosts, fanouthosts, vmhost, tbinfo, sad_case_type)

    upgrade_test_helper(duthost, localhost, ptfhost, from_image,
                        to_image, tbinfo, "warm", get_advanced_reboot,
                        advanceboot_loganalyzer=advanceboot_loganalyzer,
                        preboot_setup=upgrade_path_preboot_setup,
                        consistency_checker_provider=consistency_checker_provider,
                        sad_preboot_list=sad_preboot_list,
                        sad_inboot_list=sad_inboot_list)
