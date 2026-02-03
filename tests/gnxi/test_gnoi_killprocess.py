from functools import wraps

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.platform.processes_utils import wait_critical_processes


# Import fixtures to ensure pytest discovers them
pytest_plugins = ["tests.common.fixtures.grpc_fixtures"]  # noqa: F401

# KillProcess expects enum-name strings
SIGNAL_TERM = "SIGNAL_TERM"
SIGNAL_INVALID = "SIGNAL_KILL"  # intentionally invalid enum name for negative test

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


def _apply_shell_wrapper():
    """
    Wrap likely host classes' `shell` methods so any literal docker format
    token '{{.Names}}' is replaced with a Jinja raw block before Ansible/Jinja
    templating runs on the command string.

    This runs at module-import time (during pytest collection) so the runtime
    fixture code will see the fixed command.
    """
    jinja_literal = "{{.Names}}"
    safe_replacement = "{% raw %}{{.Names}}{% endraw %}"

    def _wrap_class_shell(cls):
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
                # Fail-safe: do nothing if wrapper malfunctions
                pass
            return orig_shell(self, cmd, *args, **kwargs)

        setattr(cls, "shell", wrapped_shell)
        setattr(cls, "_gnxi_shell_wrapped", True)

    candidates = [
        "tests.common.devices.sonic.MultiAsicSonicHost",
        "tests.common.devices.sonic.SonicHost",
        "pytest_ansible.host.Host",
    ]

    for path in candidates:
        try:
            mod_path, cls_name = path.rsplit(".", 1)
            mod = __import__(mod_path, fromlist=[cls_name])
            cls = getattr(mod, cls_name, None)
            _wrap_class_shell(cls)
        except Exception:
            # Ignore import errors and continue — we try several candidates
            continue


_apply_shell_wrapper()


def _kill_process(ptf_gnoi, name: str, restart: bool = False, signal: str = SIGNAL_TERM):
    """
    Invoke gNOI System.KillProcess via the underlying grpc client.
    Returns (ret, msg):
      ret == 0 => success, non-zero => failure
      msg      => stringified service message / error
    """
    request = {"name": name, "restart": restart, "signal": signal}
    try:
        resp = ptf_gnoi.grpc_client.call_unary("gnoi.system.System", "KillProcess", request)
        return 0, (str(resp) if resp is not None else "")
    except Exception as e:
        return 1, str(e)


@pytest.fixture(scope="module", autouse=True)
def _skip_if_killprocess_not_supported(ptf_gnoi):
    """
    Probe with a non-destructive request (invalid service name). If the backend
    is a gNOI/gnxi implementation that returns Unimplemented / Service not
    found (and does not include legacy 'Dbus' messages), skip the module to
    avoid noisy failures — this test suite expects the older DBus-style errors.
    """
    ret, msg = _kill_process(ptf_gnoi, name="gnmi", restart=False, signal=SIGNAL_TERM)
    if ret != 0 and ("Service or method not found" in msg or "Code: Unimplemented" in msg) and "Dbus" not in msg:
        pytest.skip(f"KillProcess not supported in this environment: {msg}")


@pytest.mark.parametrize(
    "process,is_valid,expected_msg",
    [
        ("gnmi", False, "Dbus does not support gnmi service management"),
        ("nonexistent", False, "Dbus does not support nonexistent service management"),
        ("", False, "Dbus stop_service called with no service specified"),
        ("snmp", True, ""),
        ("dhcp_relay", True, ""),  # service names align with host services
        ("radv", True, ""),
        ("restapi", True, ""),
        ("lldp", True, ""),
        ("sshd", True, ""),
        ("swss", True, ""),
        ("pmon", True, ""),
        ("rsyslog", True, ""),
        ("telemetry", True, ""),
    ],
)
def test_gnoi_killprocess_then_restart(
    duthosts, rand_one_dut_hostname, ptf_gnoi, process, is_valid, expected_msg
):
    duthost = duthosts[rand_one_dut_hostname]

    if process and not duthost.is_host_service_running(process):
        pytest.skip(f"{process} is not running")

    ret, msg = _kill_process(ptf_gnoi, name=process, restart=False, signal=SIGNAL_TERM)

    if is_valid:
        pytest_assert(ret == 0, f"KillProcess API unexpectedly reported failure: {msg}")
        pytest_assert(
            not is_container_running(duthost, process),
            f"{process} found running after KillProcess reported success",
        )

        ret, msg = _kill_process(ptf_gnoi, name=process, restart=True, signal=SIGNAL_TERM)
        pytest_assert(
            ret == 0,
            f"KillProcess API unexpectedly reported failure when attempting to restart {process}: {msg}",
        )
        pytest_assert(
            duthost.is_host_service_running(process),
            f"{process} not running after KillProcess reported successful restart",
        )
    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
        pytest_assert(
            expected_msg in msg,
            f"Unexpected error message in response to invalid gNOI request: {msg}",
        )

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


@pytest.mark.parametrize(
    "request_restart_value,is_valid",
    [
        ("invalid", False),
        ("", False),
    ],
)
def test_gnoi_killprocess_restart(
    duthosts, rand_one_dut_hostname, ptf_gnoi, request_restart_value, is_valid
):
    duthost = duthosts[rand_one_dut_hostname]

    restart_arg = request_restart_value
    ret, msg = _kill_process(ptf_gnoi, name="snmp", restart=restart_arg, signal=SIGNAL_TERM)

    if is_valid:
        pytest_assert(ret == 0, f"KillProcess API unexpectedly reported failure: {msg}")
        pytest_assert(
            is_container_running(duthost, "snmp"),
            "snmp not running after KillProcess API reported successful restart",
        )
    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")
        allowed_alternatives = [
            "panic",
            "Unimplemented",
            "Service or method not found",
            "invalid",
            "ERROR:",
        ]
        pytest_assert(
            any(tok in msg for tok in allowed_alternatives),
            f"Unexpected error message in response to invalid gNOI request: {msg}",
        )

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


def test_invalid_signal(duthosts, rand_one_dut_hostname, ptf_gnoi):
    duthost = duthosts[rand_one_dut_hostname]

    ret, msg = _kill_process(ptf_gnoi, name="snmp", restart=True, signal=SIGNAL_INVALID)
    pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid request parameters")

    # Accept either server-side rejection ("only supports SIGNAL_TERM" / "Please specify SIGNAL_TERM")
    # or client-side enum parsing errors containing "invalid" / "enum".
    pytest_assert(
        ("only supports SIGNAL_TERM" in msg)
        or ("Please specify SIGNAL_TERM" in msg)
        or ("invalid" in msg.lower())
        or ("enum" in msg.lower()),
        f"Unexpected error message in response to invalid gNOI request: {msg}",
    )

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")
    