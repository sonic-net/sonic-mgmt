"""Shared helpers for managing `mux.service` on DualToR DUTs.

`mux.service` has a strict systemd start rate-limit
(``StartLimitBurst=3`` / ``StartLimitIntervalSec=1200``). When several test
cases start or restart the service in sequence within the same window, the
budget can be exhausted and systemd rejects the command with
"start of the service was attempted too often", leaving mux down and causing
cascading failures in subsequent tests. This module centralizes the proven
recovery (originally added for the ``shutdown_tor_heartbeat`` teardown in
sonic-mgmt PR #26956) so every shared restart path can reuse it.
"""
import logging

logger = logging.getLogger(__name__)

# Known systemd messages emitted when a unit hits its start rate-limit. Keep
# this list narrow so that only genuine start-limit errors trigger the
# reset-failed recovery and unrelated mux failures still propagate.
START_LIMIT_ERROR_SIGNATURES = (
    "start of the service was attempted too often",
    "Start request repeated too quickly",
    "start-limit-hit",
)


def recover_mux_service_from_start_limit(duthost, action="restart"):
    """Run ``systemctl <action> mux`` and recover from the start rate-limit.

    Detect the systemd start rate-limit error, clear the burst counter with
    ``systemctl reset-failed mux`` and retry the command once. Any other error
    is re-raised unchanged so genuine failures still propagate.

    Args:
        duthost: The DUT host to run the command on.
        action: The systemctl action, either ``"start"`` or ``"restart"``.
    """
    if action not in ("start", "restart"):
        raise ValueError("Unsupported mux.service action: {}".format(action))

    try:
        duthost.shell("systemctl {} mux".format(action))
    except Exception as e:
        if any(sig in str(e) for sig in START_LIMIT_ERROR_SIGNATURES):
            logger.warning(
                "mux.service hit systemd start rate-limit on %s; running "
                "'systemctl reset-failed mux' and retrying '%s'",
                duthost.hostname, action,
            )
            duthost.shell("systemctl reset-failed mux")
            duthost.shell("systemctl {} mux".format(action))
        else:
            raise
