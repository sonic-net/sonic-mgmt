from tests.common.helpers.assertions import pytest_assert


def check_monit_expected_container_logging(duthost):
    """Checks whether alerting message appears as syslog if
    there is unexpected container not running.
    Args:
        duthost: An AnsibleHost object of DuT.
    Returns:
        None.
    """
    syslog_output = duthost.command("sudo grep 'ERR monit' /var/log/syslog")["stdout"]
    pytest_assert("Expected containers not running" not in syslog_output,
                  f"Expected containers not running found in syslog. Output was:\n{syslog_output}")
    return True


def is_route_checker_healthy(duthost):
    """Require live route consistency and Monit's recovered routeCheck status."""
    result = duthost.command("sudo route_check.py", module_ignore_errors=True)
    if result["rc"] != 0:
        return False
    # Monit can retain a churn-time failure until its next scheduled check.
    status = duthost.get_monit_services_status()["routeCheck"]["service_status"]
    return status.lower() in ("status ok", "ok")
