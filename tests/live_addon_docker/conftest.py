"""
Vendor utility docker tests load a single JSON that defines docker_run, health, and validation.

Default path: ``files/<asic_type>_utility_docker.json`` (``asic_type`` from the enum DUT), for
example ``files/cisco-8000_utility_docker.json``. Missing file is a hard failure. Override with
``--utility-docker-config``. Commands on the DUT are assembled in utility_docker_helpers from
that JSON only.
"""

import logging
import os

import pytest

from tests.live_addon_docker import utility_docker_helpers as udh

logger = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption(
        "--utility-docker-config",
        action="store",
        default=None,
        help=(
            "Path to vendor utility docker JSON (default: files/<asic_type>_utility_docker.json "
            "from DUT facts, e.g. files/cisco-8000_utility_docker.json; fails if missing)"
        ),
    )
    parser.addoption(
        "--utility-docker-tarball",
        action="store",
        default=None,
        help="Full path to the .gz image on the DUT (default: <live_addon_docker>/tarball_filename from JSON)",
    )
    parser.addoption(
        "--live_addon_docker_registry",
        action="store",
        default=None,
        help=(
            "Override the docker registry host used for the live-addon image pull path. "
            "When set, this replaces Ansible creds docker_registry_host for the registry pull. "
            "Use --public_docker_registry to force no-login behavior (same as swap_syncd)."
        ),
    )


@pytest.fixture(scope="module")
def utility_docker_vendor_cfg(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    opt = request.config.getoption("--utility-docker-config")
    if opt:
        path = os.path.abspath(opt)
    else:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic_type = (duthost.facts.get("asic_type") or "").strip()
        if not asic_type:
            pytest.fail("DUT asic_type is empty; cannot resolve vendor utility docker JSON path")
        path = udh.default_vendor_config_path(asic_type)
        logger.info(
            "utility_docker_vendor_cfg: using default from asic_type=%s -> %s",
            asic_type,
            path,
        )
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
    registry_override = request.config.getoption("--live_addon_docker_registry")
    res = udh.resolve_utility_install_source(
        duthost,
        utility_docker_vendor_cfg,
        utility_docker_local_tarball_optional,
        public_docker_registry=public_reg,
        docker_registry_host_override=registry_override,
    )
    if res.kind == "none":
        pytest.skip(
            "Utility docker not available: no matching image on DUT, no tarball at {0}, "
            "and no tarball on the test runner. Pre-load the image (`docker load`), copy "
            "{1} to the DUT home dir, place {1} under tests/live_addon_docker/ on the test "
            "runner, pass --utility-docker-tarball, or ensure docker_registry_host in Ansible creds "
            "for registry pull (or omit docker_registry_host so registry is skipped and use a tarball / local image)."
            .format(udh.dut_home_tarball_path(utility_docker_vendor_cfg), utility_docker_vendor_cfg["tarball_filename"])
        )
    if res.kind == "runner_tarball":
        duthost.copy(src=utility_docker_local_tarball_optional, dest=res.remote_tarball_path)
    logger.info("utility_docker_install_source: kind=%s", res.kind)
    yield duthost, res
