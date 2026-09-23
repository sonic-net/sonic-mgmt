import os
import sys
from unittest import mock


_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(_TEST_DIR)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.connections.ssh_console_conn import (  # noqa: E402
    SSHConsoleConn,
)


def test_switch_to_host_console_selects_host_and_logs_in():
    conn = SSHConsoleConn.__new__(SSHConsoleConn)
    conn.RETURN = "\r"
    conn.logger = mock.MagicMock()
    conn.sonic_username = "admin"
    conn.sonic_password = ["password"]
    conn._bootloader_deferred = False
    conn.select_delay_factor = mock.MagicMock(return_value=1)
    conn.read_channel = mock.MagicMock(return_value="BMC console selector\n")
    conn.write_channel = mock.MagicMock()
    conn.login_stage_2 = mock.MagicMock(return_value="admin@dut:~$ ")
    conn.session_preparation_finalise = mock.MagicMock()

    with mock.patch("tests.common.connections.ssh_console_conn.time.sleep"):
        output = SSHConsoleConn.switch_to_host_console(conn)

    assert output == "admin@dut:~$ "
    assert [call.args[0] for call in conn.write_channel.call_args_list] == [
        "\x15",
        "2\r",
    ]
    conn.login_stage_2.assert_called_once_with(
        username="admin",
        password="password",
        defer_on_bootloader=True,
    )
    conn.session_preparation_finalise.assert_called_once_with()
