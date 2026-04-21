from __future__ import annotations

from typing import Literal

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_native


# pylint: disable=unused-argument
def load_balancer_status(load_balancer: dict, *args, **kwargs) -> Literal["unknown", "unhealthy", "healthy"]:
    """
    Return the status of a Load Balancer based on its targets.
    """

    def targets_status(targets: list) -> Literal["unknown", "unhealthy", "healthy"]:
        result = "healthy"

        for target in targets:
            # Label selector targets have child targets that must be checked
            if target["type"] == "label_selector":
                status = targets_status(target["targets"])
                if status == "unhealthy":
                    return "unhealthy"

                if status in (None, "unknown"):
                    result = "unknown"

                continue

            # Report missing health status as unknown
            if not target.get("health_status"):
                return "unknown"

            for health_status in target.get("health_status"):
                status = health_status.get("status")
                if status == "unhealthy":
                    return "unhealthy"

                if status in (None, "unknown"):
                    result = "unknown"

        return result

    try:
        return targets_status(load_balancer["targets"])
    except Exception as exc:
        raise AnsibleFilterError(f"load_balancer_status - {to_native(exc)}", orig_exc=exc) from exc


class FilterModule:
    """
    Hetzner Cloud filters.
    """

    def filters(self):
        return {
            "load_balancer_status": load_balancer_status,
        }
