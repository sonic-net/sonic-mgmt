"""
Live-addon docker tests load a single JSON that defines docker_run, health, and validation.

Default path: ``files/<asic_type>_live_addon_docker.json`` (``asic_type`` from the enum DUT).
Override with ``--live-addon-docker-config``.
Commands on the DUT are assembled in live_addon_docker_helpers from that JSON only.

Registry and tag at test time: ``--live_addon_docker_registry``, ``--live_addon_docker_image_tag``.
"""

import logging
import os

import pytest

from tests.live_addon_docker import live_addon_docker_helpers as lad

logger = logging.getLogger(__name__)


def _cli_image_tag(request):
    val = request.config.getoption("--live_addon_docker_image_tag", default=None)
    if val and str(val).strip():
        return str(val).strip()
    return None


def pytest_addoption(parser):
    parser.addoption(
        "--live-addon-docker-config",
        action="store",
        default=None,
        help=(
            "Path to live-addon docker JSON (default: files/<asic_type>_live_addon_docker.json "
            "from DUT facts; fails if missing)"
        ),
    )
    parser.addoption(
        "--live-addon-docker-tarball",
        action="store",
        default=None,
        help="Full path to the .gz image on the test runner (default: tarball_filename from JSON)",
    )
    parser.addoption(
        "--live_addon_docker_registry",
        action="store",
        default=None,
        help=(
            "Docker registry host for live-addon image pull (e.g. myacr.azurecr.io). "
            "Overrides Ansible creds docker_registry_host for this test module only. "
            "Use --public_docker_registry for no-login public host (same as swap_syncd)."
        ),
    )
    parser.addoption(
        "--live_addon_docker_image_tag",
        action="store",
        default=None,
        help=(
            "Docker image tag for registry pull and docker_run.image_ref (overrides JSON tag and "
            "dut os_version for pull). For CI builds, e.g. kube-20260527-202505-amd64."
        ),
    )


@pytest.fixture(scope="module")
def live_addon_docker_vendor_cfg(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    opt = request.config.getoption("--live-addon-docker-config")
    if opt:
        path = os.path.abspath(opt)
    else:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        asic_type = (duthost.facts.get("asic_type") or "").strip()
        if not asic_type:
            pytest.fail("DUT asic_type is empty; cannot resolve live-addon docker JSON path")
        path = lad.default_live_addon_config_path(asic_type)
        logger.info(
            "live_addon_docker_vendor_cfg: using default from asic_type=%s -> %s",
            asic_type,
            path,
        )
    if not os.path.isfile(path):
        pytest.skip("Live-addon docker config not found: {}".format(path))
    cfg = lad.load_live_addon_config(path)
    tag = _cli_image_tag(request)
    if tag:
        cfg = lad.apply_image_tag_to_config(cfg, tag)
        logger.info(
            "live_addon_docker_vendor_cfg: image tag overridden by CLI -> %s",
            cfg["docker_run"]["image_ref"],
        )
    return cfg


@pytest.fixture(scope="module")
def live_addon_docker_local_tarball_optional(request, live_addon_docker_vendor_cfg):
    """
    Path to .gz on the test runner if that file exists; otherwise None.
    Resolution on the DUT (image already loaded vs ~/ vs copy) is done in
    live_addon_docker_install_source — same idea as swap_syncd using local docker images.
    """
    override = request.config.getoption("--live-addon-docker-tarball")
    local_path = lad.resolve_local_tarball_path(live_addon_docker_vendor_cfg, lad.MODULE_DIR, override)
    if os.path.isfile(local_path):
        logger.info("Live-addon docker tarball on test runner: %s", local_path)
        return local_path
    logger.info(
        "No live-addon tarball on test runner at %s — will use image or tarball on DUT if present",
        local_path,
    )
    return None


@pytest.fixture(scope="module")
def live_addon_docker_install_source(
    request,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    live_addon_docker_vendor_cfg,
    live_addon_docker_local_tarball_optional,
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
    res = lad.resolve_live_addon_install_source(
        duthost,
        live_addon_docker_vendor_cfg,
        live_addon_docker_local_tarball_optional,
        public_docker_registry=public_reg,
        docker_registry_host_override=registry_override,
        registry_image_tag=_cli_image_tag(request),
    )
    if res.kind == "none":
        pytest.skip(
            "Live-addon docker not available: no matching image on DUT, no tarball at {0}, "
            "and no tarball on the test runner. Pre-load the image (`docker load`), copy "
            "{1} to the DUT home dir, place {1} under tests/live_addon_docker/ on the test "
            "runner, pass --live-addon-docker-tarball, or ensure docker_registry_host in Ansible creds "
            "for registry pull (or omit docker_registry_host so registry is skipped and use a tarball / local image)."
            .format(
                lad.dut_home_tarball_path(live_addon_docker_vendor_cfg),
                live_addon_docker_vendor_cfg["tarball_filename"],
            )
        )
    if res.kind == "runner_tarball":
        duthost.copy(src=live_addon_docker_local_tarball_optional, dest=res.remote_tarball_path)
    logger.info("live_addon_docker_install_source: kind=%s", res.kind)
    yield duthost, res
