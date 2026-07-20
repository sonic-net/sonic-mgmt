"""
Install and validate a live-addon docker via ``docker run`` (no sonic-package-manager).

Image resolution (registry first by default, then fallbacks):

1. **Registry** — ``docker pull`` from ``--live_addon_docker_registry`` or Ansible ``docker_registry_*``
2. **Tarball on DUT** — ``/home/admin/<tarball_filename>``
3. **Tarball on test runner** — copy to ``/tmp/`` on DUT
4. **Image already on DUT** — ``docker image inspect``

Pass ``--live_addon_docker_image_tag`` for baseline/module tests;
``--live_addon_docker_image_upgrade_tag`` for the image upgrade test.

Post-start validation runs in the module fixture and on every ``docker run`` inside helpers.
The image-upgrade test is standalone (does not use the module fixture).
"""

import copy
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.live_addon_docker import live_addon_docker_helpers as lad

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]


def _cli_image_tag(request):
    val = request.config.getoption("--live_addon_docker_image_tag", default=None)
    if val and str(val).strip():
        return str(val).strip()
    return None


def _cli_registry_host(request):
    val = request.config.getoption("--live_addon_docker_registry", default=None)
    if val and str(val).strip():
        return str(val).strip()
    return None


def _cli_image_upgrade_tag(request):
    val = request.config.getoption("--live_addon_docker_image_upgrade_tag", default=None)
    if val and str(val).strip():
        return str(val).strip()
    return None


@pytest.fixture(scope="module")
def live_addon_docker_setup_teardown(live_addon_docker_install_source, live_addon_docker_vendor_cfg):
    duthost, src = live_addon_docker_install_source
    cfg0 = live_addon_docker_vendor_cfg
    pre_cores = lad.get_core_filenames(duthost)
    cfg = None

    try:
        lad.prepare_live_addon_docker_install(duthost, cfg0, src)
        if src.kind == "image_present":
            ref = src.image_ref
            cfg = copy.deepcopy(cfg0)
            cfg["docker_run"]["image_ref"] = ref
        else:
            remote_tarball = src.remote_tarball_path
            load_out = lad.docker_load(duthost, remote_tarball)
            ref = lad.parse_image_from_docker_load(load_out)
            cfg = copy.deepcopy(cfg0)
            if ref:
                cfg["docker_run"]["image_ref"] = ref

        lad.require_version_matrix_or_skip(duthost, cfg0, cfg["docker_run"]["image_ref"])
        lad.docker_run_manual(duthost, cfg)
        lad.verify_live_addon_post_start(duthost, cfg)

        yield duthost, cfg

    finally:
        try:
            if cfg is not None:
                lad.docker_manual_teardown(duthost, cfg["docker_run"])
        except Exception as exc:
            logger.warning("Teardown command failed (cleanup checks still run): %s", exc)
        lad.verify_post_teardown(duthost, cfg if cfg is not None else cfg0, pre_cores)


def test_live_addon_docker_health_http(live_addon_docker_setup_teardown):
    duthost, cfg = live_addon_docker_setup_teardown
    ok, code, body = lad.wait_for_health_ready(duthost, cfg["health"])
    pytest_assert(ok, "Health check failed: http_code={} body={}".format(code, body))


def test_live_addon_docker_health_after_config_reload_cycle(
    live_addon_docker_setup_teardown, loganalyzer
):
    """
    Config reload, start live-addon via ``docker run``, config reload again,
    teardown + ``docker run`` again, then validate HTTP health.
    """
    duthost, cfg = live_addon_docker_setup_teardown
    ok, code, body = lad.run_config_reload_live_addon_start_reload_health(
        duthost, cfg, loganalyzer=loganalyzer
    )
    pytest_assert(
        ok,
        "Health check after config-reload cycle failed: http_code={} body={}".format(code, body),
    )


def test_live_addon_docker_image_upgrade(
    request,
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    live_addon_docker_vendor_cfg_raw,
):
    """
    Pull baseline image (``--live_addon_docker_image_tag``), start container, then upgrade to
    ``--live_addon_docker_image_upgrade_tag`` via registry pull and verify post-start + HTTP health.

    Requires registry access (Ansible ``docker_registry_host`` or ``--live_addon_docker_registry``).
    """
    baseline_tag = _cli_image_tag(request)
    upgrade_tag = _cli_image_upgrade_tag(request)
    if not baseline_tag:
        pytest.skip("Pass --live_addon_docker_image_tag for baseline live-addon image")
    if not upgrade_tag:
        pytest.skip("Pass --live_addon_docker_image_upgrade_tag for upgrade live-addon image")

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    cfg_base = live_addon_docker_vendor_cfg_raw
    pre_cores = lad.get_core_filenames(duthost)
    public_reg = request.config.getoption("--public_docker_registry")
    registry_host = _cli_registry_host(request)
    baseline_cfg = lad.apply_image_tag_to_config(cfg_base, baseline_tag)
    target_cfg = lad.apply_image_tag_to_config(cfg_base, upgrade_tag)
    if target_cfg["docker_run"]["image_ref"] == baseline_cfg["docker_run"]["image_ref"]:
        pytest.skip(
            "Upgrade tag {!r} matches baseline tag {!r}; use different "
            "--live_addon_docker_image_upgrade_tag".format(upgrade_tag, baseline_tag)
        )

    started_cfg = {"cfg": None}
    try:
        baseline_cfg, (ok, code, body) = lad.upgrade_live_addon_docker_image(
            duthost,
            baseline_cfg,
            public_docker_registry=public_reg,
            docker_registry_host_override=registry_host,
            started_cfg=started_cfg,
        )
        pytest_assert(
            ok,
            "Baseline health check failed before image upgrade: http_code={} body={}".format(
                code, body
            ),
        )
        logger.info(
            "Baseline live-addon image installed at %s",
            baseline_cfg["docker_run"]["image_ref"],
        )

        _, (ok, code, body) = lad.upgrade_live_addon_docker_image(
            duthost,
            target_cfg,
            public_docker_registry=public_reg,
            docker_registry_host_override=registry_host,
            started_cfg=started_cfg,
        )
        pytest_assert(
            ok,
            "Health check after image upgrade failed: http_code={} body={}".format(code, body),
        )
    finally:
        if started_cfg["cfg"] is not None:
            try:
                dr = started_cfg["cfg"].get("docker_run") or {}
                if dr.get("container_name"):
                    lad.docker_manual_teardown(duthost, dr)
            except Exception as exc:
                logger.warning("Upgrade test teardown command failed: %s", exc)
            lad.verify_post_teardown(duthost, cfg_base, pre_cores)
