import logging
import pytest

from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    setup_gnoi_tls_server, ptf_gnoi, ptf_grpc
)
from tests.upgrade_path.test_upgrade_path import setup_upgrade_test
from tests.common.helpers.upgrade_helpers import perform_gnoi_upgrade, GnoiUpgradeConfig

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


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
        setup_upgrade_test(duthost, localhost, from_image, to_image, tbinfo,
                           upgrade_type)

    perform_gnoi_upgrade(
        ptf_gnoi=ptf_gnoi,
        duthost=duthost,
        tbinfo=tbinfo,
        cfg=cfg,
        cold_reboot_setup=upgrade_path_preboot_setup,
        localhost=localhost,
        conn_graph_facts=conn_graph_facts,
        xcvr_skip_list=xcvr_skip_list,
        duthosts=duthosts,
    )
