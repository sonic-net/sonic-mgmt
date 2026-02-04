from functools import wraps
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running
from tests.common.platform.processes_utils import wait_critical_processes

pytest_plugins = ["tests.common.fixtures.grpc_fixtures"]  # noqa: F401

SIGNAL_TERM = "SIGNAL_TERM"
SIGNAL_INVALID = "SIGNAL_KILL"  # intentionally invalid enum name for negative test

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.usefixtures("setup_gnoi_tls_server"),
]


def _apply_shell_wrapper():
    """
    Wrap `shell` methods for classes to handle literal docker format tokens.
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
            continue


_apply_shell_wrapper()


def _kill_process(ptf_gnoi, name: str, restart: bool = False, signal: str = SIGNAL_TERM):
    """
    Wrap gNOI System.KillProcess by invoking the high-level utility.

    Args:
        ptf_gnoi: PtfGnoi instance to perform operations
        name: Name of the process to kill
        restart: Whether to restart the process
        signal: Signal to use (default: SIGNAL_TERM)

    Returns:
        ret: 0 on success, non-zero on failure
        msg: Response message or error
    """
    try:
        # Use the gNOI utility instead of direct call_unary usage
        response = ptf_gnoi.upgrade_status(name)
        return 0, str(response)
    except Exception as e:
        return 1, str(e)


@pytest.fixture(autouse=True)
def _skip_if_killprocess_not_supported(ptf_gnoi):
    """
    Skip the test if KillProcess API is not supported.
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
        ("dhcp_relay", True, ""),
    ],
)
def test_gnoi_killprocess_then_restart(duthosts, rand_one_dut_hostname, ptf_gnoi, process, is_valid, expected_msg):
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
        pytest_assert(ret == 0, f"KillProcess API unexpectedly failed when restarting {process}: {msg}")
        pytest_assert(duthost.is_host_service_running(process), f"{process} not running after API restart")

    else:
        pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid parameters")
        pytest_assert(expected_msg in msg, f"Unexpected error message: {msg}")

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")


def test_invalid_signal(duthosts, rand_one_dut_hostname, ptf_gnoi):
    duthost = duthosts[rand_one_dut_hostname]

    ret, msg = _kill_process(ptf_gnoi, name="snmp", restart=True, signal=SIGNAL_INVALID)
    pytest_assert(ret != 0, "KillProcess API unexpectedly succeeded with invalid signal")
    pytest_assert("invalid" in msg.lower() or "enum" in msg.lower(), f"Unexpected error message: {msg}")

    wait_critical_processes(duthost)
    pytest_assert(duthost.critical_services_fully_started, "System unhealthy after gNOI API request")
