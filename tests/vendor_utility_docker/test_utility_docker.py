"""
Install and validate a vendor utility docker via ``docker run`` (no sonic-package-manager).

Image resolution (registry first by default, then fallbacks; same ``docker_registry_*`` Ansible
creds as ``swap_syncd`` / ``tests.common.system_utils.docker``):

1. **Registry** — ``docker pull`` then ``docker tag`` to ``docker_run.image_ref`` (same Ansible
   ``docker_registry_*`` as syncd-rpc; use ``--public_docker_registry`` for public host, same as swap_syncd).
2. **Tarball on DUT** — ``/home/admin/<tarball_filename>`` — ``sudo docker load -i`` then ``docker run``.
3. **Tarball on test runner** — copy to ``/tmp/`` on DUT, then ``docker load -i`` and ``docker run``.
4. **Image already on DUT** — ``docker image inspect`` on ``docker_run.image_ref`` / ``candidate_image_refs``.

Before install: any existing utility container is stopped and removed; if a tarball will be loaded,
configured utility images are removed so ``docker load`` starts clean.

If none of the above apply, tests skip.
"""

import copy
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.vendor_utility_docker import utility_docker_helpers as udh

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]


@pytest.fixture(scope="module")
def utility_docker_setup_teardown(utility_docker_install_source, utility_docker_vendor_cfg):
    duthost, src = utility_docker_install_source
    cfg0 = utility_docker_vendor_cfg
    pre_cores = udh.get_core_filenames(duthost)
    cfg = None

    try:
        udh.prepare_utility_docker_install(duthost, cfg0, src)
        if src.kind == "image_present":
            ref = src.image_ref
            cfg = copy.deepcopy(cfg0)
            cfg["docker_run"]["image_ref"] = ref
        else:
            remote_tarball = src.remote_tarball_path
            load_out = udh.docker_load(duthost, remote_tarball)
            ref = udh.parse_image_from_docker_load(load_out)
            cfg = copy.deepcopy(cfg0)
            if ref:
                cfg["docker_run"]["image_ref"] = ref

        udh.log_version_matrix_compatibility(duthost, cfg0, cfg["docker_run"]["image_ref"])
        udh.docker_run_manual(duthost, cfg)
        cname = (cfg.get("docker_run") or {}).get("container_name")
        if cname:
            udh.verify_utility_container_startup_logs(duthost, cname)
            udh.verify_utility_container_processes(duthost, cname)

        yield duthost, cfg

    finally:
        try:
            if cfg is not None:
                udh.docker_manual_teardown(duthost, cfg["docker_run"])
        except Exception as exc:
            logger.warning("Teardown command failed (cleanup checks still run): %s", exc)
        udh.verify_post_teardown(duthost, cfg if cfg is not None else cfg0, pre_cores)


def test_utility_docker_image_and_container(utility_docker_setup_teardown):
    duthost, cfg = utility_docker_setup_teardown
    val = cfg.get("validation", {})
    cname = val.get("docker_container_name", cfg.get("docker_run", {}).get("container_name"))
    if cname:
        pytest_assert(
            is_container_running(duthost, cname),
            "Container {!r} is not running (expected it running). Check docker logs on the DUT.".format(cname),
        )


def test_utility_docker_health_http(utility_docker_setup_teardown):
    duthost, cfg = utility_docker_setup_teardown
    health = cfg["health"]
    ok, code, body = udh.wait_for_health_ready(duthost, health)
    pytest_assert(ok, "Health check failed: http_code={} body={}".format(code, body))


def test_utility_docker_health_after_config_reload_cycle(
    utility_docker_setup_teardown, loganalyzer
):
    """
    Config reload, wait (see ``CONFIG_RELOAD_UTILITY_CYCLE_WAIT_SECONDS``), start utility via
    ``docker run``, config reload again, then validate HTTP health.
    """
    duthost, cfg = utility_docker_setup_teardown
    ok, code, body = udh.run_config_reload_utility_start_reload_health(
        duthost, cfg, loganalyzer=loganalyzer
    )
    pytest_assert(
        ok,
        "Health check after config-reload cycle failed: http_code={} body={}".format(code, body),
    )


def _cli_image_tag(request):
    for opt in ("--live_addon_docker_image_tag", "--utility-docker-image-tag"):
        val = request.config.getoption(opt, default=None)
        if val and str(val).strip():
            return str(val).strip()
    return None


def _cli_registry_host(request):
    for opt in ("--live_addon_docker_registry", "--utility-docker-registry"):
        val = request.config.getoption(opt, default=None)
        if val and str(val).strip():
            return str(val).strip()
    return None


def test_utility_docker_image_upgrade(
    request,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    utility_docker_vendor_cfg_raw,
):
    """
    Pull baseline image (DUT ``os_version`` tag), start container, then upgrade to
    ``--live_addon_docker_image_tag`` via registry pull and verify health/processes/logs.

    Requires registry access (Ansible ``docker_registry_host`` or ``--live_addon_docker_registry``).
    """
    target_tag = _cli_image_tag(request)
    if not target_tag:
        pytest.skip(
            "Pass --live_addon_docker_image_tag (or --utility-docker-image-tag) to run upgrade test"
        )

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cfg_base = utility_docker_vendor_cfg_raw
    pre_cores = udh.get_core_filenames(duthost)
    public_reg = request.config.getoption("--public_docker_registry")
    registry_host = _cli_registry_host(request)
    baseline_cfg = None
    target_cfg = None

    try:
        baseline_cfg = udh.apply_image_tag_to_config(cfg_base, duthost.os_version)
        udh.prepare_utility_docker_install(
            duthost, baseline_cfg, udh.InstallSource("image_present", None, None)
        )
        baseline_cfg, _ = udh.upgrade_utility_docker_image(
            duthost,
            baseline_cfg,
            public_docker_registry=public_reg,
            registry_host_override=registry_host,
        )
        logger.info("Baseline utility image installed at %s", baseline_cfg["docker_run"]["image_ref"])

        target_cfg = udh.apply_image_tag_to_config(cfg_base, target_tag)
        if target_cfg["docker_run"]["image_ref"] == baseline_cfg["docker_run"]["image_ref"]:
            pytest.skip(
                "Upgrade target tag {!r} matches baseline os_version tag; pick a different "
                "--live_addon_docker_image_tag".format(target_tag)
            )

        target_cfg, (ok, code, body) = udh.upgrade_utility_docker_image(
            duthost,
            target_cfg,
            public_docker_registry=public_reg,
            registry_host_override=registry_host,
        )
        pytest_assert(
            ok,
            "Health check after image upgrade failed: http_code={} body={}".format(code, body),
        )
    finally:
        try:
            dr = (target_cfg or baseline_cfg or cfg_base).get("docker_run") or {}
            if dr.get("container_name"):
                udh.docker_manual_teardown(duthost, dr)
        except Exception as exc:
            logger.warning("Upgrade test teardown command failed: %s", exc)
        udh.verify_post_teardown(duthost, cfg_base, pre_cores)
