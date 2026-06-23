"""
Install and validate a live-addon docker via ``docker run`` (no sonic-package-manager).

Image resolution (registry first by default, then fallbacks):

1. **Registry** — ``docker pull`` from ``--live_addon_docker_registry`` or Ansible ``docker_registry_*``
2. **Tarball on DUT** — ``/home/admin/<tarball_filename>``
3. **Tarball on test runner** — copy to ``/tmp/`` on DUT
4. **Image already on DUT** — ``docker image inspect``

Pass ``--live_addon_docker_image_tag`` for CI build tags; ``--live_addon_docker_registry`` per-vendor CR.

Post-start validation (single instance, startup logs or supervisord poll) runs in the module fixture
and on every ``docker run`` inside helpers — not duplicated in individual tests below.
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
