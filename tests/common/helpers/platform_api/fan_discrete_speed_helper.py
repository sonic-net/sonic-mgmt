"""
Shared helpers for chassis / fan-drawer fan tests on platforms with discrete PWM steps
from `chassis.fans.supported_speeds` in platform.json (via `duthost.facts`).
"""

import logging
import random

from tests.common.helpers.platform_api import fan, fan_drawer_fan

logger = logging.getLogger(__name__)

# Fan - for these SKUs; use `chassis.fans.supported_speeds` in platform.json
FAN_SPEED_DISCRETE_PLATFORMS = (
    "x86_64-nokia_ixr7220_h6_128-r0",
    "x86_64-nokia_ixr7220_h6_64-r0",
)


def fan_speed_uses_platform_discrete_list(duthost):
    return duthost.facts.get("platform") in FAN_SPEED_DISCRETE_PLATFORMS


def parse_supported_speeds_csv(raw, log_ctx):
    """Parse comma-separated integer speeds from platform.json."""
    if raw is None:
        return None
    text = raw if isinstance(raw, str) else str(raw)
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except ValueError:
            logger.warning(
                "Ignoring non-integer supported_speeds token %r (%s)",
                part,
                log_ctx,
            )
    return out or None


def get_chassis_fans_supported_speeds(duthost):
    """
    Read the common discrete fan table from `chassis.fans.supported_speeds` in platform.json (via duthost.facts).
    """
    chassis = duthost.facts.get("chassis") or {}
    fans = chassis.get("fans")
    if not fans or not isinstance(fans, list):
        return None
    for entry in fans:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("supported_speeds")
        if raw is not None:
            return parse_supported_speeds_csv(raw, "chassis.fans supported_speeds")
    return None


def pick_initial_discrete_target_speed(num_fans, chassis_speeds, is_controllable, get_smin, get_smax):
    """
    Pick one discrete speed using the first controllable fan index for min/max bounds.
    """
    if not chassis_speeds:
        return None
    for probe in range(num_fans):
        if not is_controllable(probe):
            continue
        smin = get_smin(probe)
        smax = get_smax(probe)
        in_range = [s for s in chassis_speeds if smin <= s <= smax]
        pick_from = in_range if in_range else chassis_speeds
        return random.choice(pick_from)
    return None


def fan_drawer_speed_within_tolerance(platform_api_conn, j, i):
    """True when fan-drawer fan speed is within platform API under/over tolerance for target."""
    under = fan_drawer_fan.is_under_speed(platform_api_conn, j, i)
    over = fan_drawer_fan.is_over_speed(platform_api_conn, j, i)
    return not under and not over


def chassis_fan_speed_within_tolerance(platform_api_conn, i):
    """True when chassis fan speed is within platform API under/over tolerance for target."""
    under = fan.is_under_speed(platform_api_conn, i)
    over = fan.is_over_speed(platform_api_conn, i)
    return not under and not over
