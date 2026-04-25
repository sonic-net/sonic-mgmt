"""
Vendor utility docker tests load a single JSON that defines docker_run, health, and validation.
Default: files/cisco_utility_docker.json (Cisco 8000). Other vendors
should add files/<name>.json and select it with --utility-docker-config; commands on the DUT
are assembled in utility_docker_helpers from that JSON only.
"""

import logging
import os

import pytest

from tests.vendor_utility_docker import utility_docker_helpers as udh

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption(
        "--utility-docker-config",
        action="store",
        default=udh.DEFAULT_CONFIG,
        help="Path to vendor utility docker JSON (default: files/cisco_utility_docker.json for Cisco 8000)",
    )
    parser.addoption(
        "--utility-docker-tarball",
        action="store",
        default=None,
        help="Full path to the .gz image on the test runner (default: <vendor_utility_docker>/tarball_filename from JSON)",
    )


@pytest.fixture(scope="module")
def utility_docker_vendor_cfg(request):
    path = request.config.getoption("--utility-docker-config")
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        pytest.skip("Vendor utility docker config not found: {}".format(path))
    return udh.load_vendor_config(path)


@pytest.fixture(scope="module")
def utility_docker_local_tarball_optional(request, utility_docker_vendor_cfg):
    """
    Path to .gz on the test runner if that file exists; otherwise None.
    Resolution on the DUT (image already loaded vs ~/ vs copy) is done in
    utility_docker_install_source — same idea as swap_syncd using local docker images.
    """
    override = request.config.getoption("--utility-docker-tarball")
    local_path = udh.resolve_local_tarball_path(utility_docker_vendor_cfg, udh.MODULE_DIR, override)
    if os.path.isfile(local_path):
        logger.info("Utility docker tarball on test runner: %s", local_path)
        return local_path
    logger.info(
        "No utility tarball on test runner at %s — will use image or tarball on DUT if present",
        local_path,
    )
    return None


@pytest.fixture(scope="module")
def utility_docker_install_source(
    request,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    utility_docker_vendor_cfg,
    utility_docker_local_tarball_optional,
):
    """
    Decide install source (priority; registry first when configured, same Ansible creds as swap_syncd):
    1) registry pull on DUT (docker pull + tag); use --public_docker_registry like swap_syncd for public host
    2) tarball under admin home on DUT (~/tarball_filename)
    3) tarball on test runner (copy to /tmp on DUT)
    4) image already on DUT (docker image inspect)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    public_reg = request.config.getoption("--public_docker_registry")
    res = udh.resolve_utility_install_source(
        duthost,
        utility_docker_vendor_cfg,
        utility_docker_local_tarball_optional,
        public_docker_registry=public_reg,
    )
    if res.kind == "none":
        pytest.skip(
            "Utility docker not available: no matching image on DUT, no tarball at {}, "
            "and no tarball on the test runner. Pre-load the image (`docker load`), copy "
            "{1} to the DUT home dir, place {1} under tests/vendor_utility_docker/ on the test "
            "runner, pass --utility-docker-tarball, or ensure docker_registry_host in Ansible creds "
            "for registry pull (or omit docker_registry_host so registry is skipped and use a tarball / local image)."
            .format(udh.dut_home_tarball_path(utility_docker_vendor_cfg), utility_docker_vendor_cfg["tarball_filename"])
        )
    if res.kind == "runner_tarball":
        duthost.copy(src=utility_docker_local_tarball_optional, dest=res.remote_tarball_path)
    logger.info("utility_docker_install_source: kind=%s", res.kind)
    yield duthost, res
