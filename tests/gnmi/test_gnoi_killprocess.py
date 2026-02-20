import logging
from functools import wraps

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.platform.processes_utils import wait_critical_processes

pytest_plugins = ["tests.common.fixtures.grpc_fixtures"]  # noqa: F401


logger = logging.getLogger(__name__)

SIGNAL_TERM = "SIGNAL_TERM"

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


def _apply_shell_wrapper() -> None:
    jinja_literal = "{{.Names}}"
    safe_replacement = "{% raw %}{{.Names}}{% endraw %}"

    def _wrap_class_shell(cls) -> None:
        if not cls or getattr(cls, "_gnxi_shell_wrapped", False):
            return

        orig_shell = getattr(cls, "shell", None)
        if not callable(orig_shell):
            return

        @wraps(orig_shell)
        def wrapped_shell(self, cmd, *args, **kwargs):
            try:
                if isinstance(cmd, str) and jinja_literal in cmd:
                    cmd = cmd.replace(jinja_literal, safe_replacement)
            except Exception:
                pass
            return orig_shell(self, cmd, *args, **kwargs)

        setattr(cls, "shell", wrapped_shell)
        setattr(cls, "_gnxi_shell_wrapped", True)

    for path in [
        "tests.common.devices.sonic.MultiAsicSonicHost",
        "tests.common.devices.sonic.SonicHost",
        "pytest_ansible.host.Host",
    ]:
        try:
            mod_path, cls_name = path.rsplit(".", 1)
            mod = __import__(mod_path, fromlist=[cls_name])
            cls = getattr(mod, cls_name, None)
            _wrap_class_shell(cls)
        except Exception:
            continue


_apply_shell_wrapper()


def _kill_process(ptf_gnoi, name: str, restart: bool = False, signal=SIGNAL_TERM):
    logger.info(
        "gNOI KillProcess request: name=%r restart=%r signal=%r",
        name,
        restart,
        signal,
    )
    try:
        resp = ptf_gnoi.kill_process(name=name, restart=restart, signal=signal)
        logger.info("gNOI KillProcess response: %s", resp)
        return 0, str(resp) if resp is not None else ""
    except Exception as exc:
        logger.error("gNOI KillProcess error: %s", exc)
        return 1, str(exc)


@pytest.mark.parametrize(
    "process,is_valid,expected_msg",
    [
        ("gnmi", False, "Dbus does not support gnmi service management"),
        ("nonexistent", False, "Dbus does not support nonexistent service management"),
        ("", False, "Dbus stop_service called with no service specified"),
        ("snmp", True, ""),
        ("dhcp_relay", True, ""),
        ("radv", True, ""),
        ("restapi", True, ""),
        ("lldp", True, ""),
        ("sshd", True, ""),
        ("pmon", True, ""),
        ("rsyslog", True, ""),
        ("telemetry", True, ""),
    ],
)
def test_gnoi_killprocess_then_restart(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    process,
    is_valid,
    expected_msg,
):
    duthost = duthosts[rand_one_dut_hostname]

    if is_valid and process and not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    ret, msg = _kill_process(ptf_gnoi, name=process, restart=False)

    if is_valid:
        pytest_assert(
            ret == 0,
            f"KillProcess API unexpectedly reported failure: {msg}",
        )
        pytest_assert(
            not is_container_running(duthost, process),
            f"{process} found running after KillProcess reported success",
        )

        ret, msg = _kill_process(ptf_gnoi, name=process, restart=True)
        pytest_assert(
            ret == 0,
            (
                "KillProcess API unexpectedly reported failure when "
                f"attempting to restart {process}: {msg}"
            ),
        )
        pytest_assert(
            duthost.is_host_service_running(process),
            f"{process} not running after KillProcess reported successful restart",
        )
    else:
        pytest_assert(
            ret != 0,
            "KillProcess API unexpectedly succeeded with invalid request parameters",
        )
        pytest_assert(expected_msg in msg, f"Unexpected error message: {msg}")

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )


@pytest.mark.parametrize(
    "restart_value,should_be_running_after",
    [
        (True, True),
        (False, False),
    ],
)
def test_gnoi_killprocess_restart(
    duthosts,
    rand_one_dut_hostname,
    ptf_gnoi,
    restart_value,
    should_be_running_after,
):
    """
    Verify the restart parameter behavior in KillProcess API.

    Tests that restart=True brings the service back up, and restart=False
    leaves it down.
    """
    duthost = duthosts[rand_one_dut_hostname]
    process = "snmp"

    if not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    ret, msg = _kill_process(ptf_gnoi, name=process, restart=restart_value)
    pytest_assert(
        ret == 0,
        f"KillProcess API unexpectedly reported failure: {msg}",
    )

    # Check if service state matches expectations based on restart parameter
    is_running = is_container_running(duthost, process)
    pytest_assert(
        is_running == should_be_running_after,
        f"After KillProcess with restart={restart_value}: "
        f"expected running={should_be_running_after}, got running={is_running}",
    )

    # If service was stopped, restart it for cleanup
    if not should_be_running_after:
        ret, msg = _kill_process(ptf_gnoi, name=process, restart=True)
        pytest_assert(
            ret == 0,
            f"Failed to restart {process} for cleanup: {msg}",
        )

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )


def test_invalid_signal(duthosts, rand_one_dut_hostname, ptf_gnoi):
    duthost = duthosts[rand_one_dut_hostname]

    ret, msg = _kill_process(
        ptf_gnoi,
        name="snmp",
        restart=True,
        signal="SIGNAL_KILL",
    )
    pytest_assert(
        ret != 0,
        "KillProcess API unexpectedly succeeded with invalid request parameters",
    )
    pytest_assert(
        "KillProcess only supports SIGNAL_TERM (option 1)" in msg,
        f"Unexpected error message in response to invalid gNOI request: {msg}",
    )

    wait_critical_processes(duthost)
    pytest_assert(
        duthost.critical_services_fully_started,
        "System unhealthy after gNOI API request",
    )
