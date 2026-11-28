from unittest.mock import MagicMock, patch

import pytest

from tests.common.devices.base import AnsibleHostBase
from tests.common.devices.eos import EosHost


def make_host():
    ansible_adhoc = MagicMock()
    with patch.object(AnsibleHostBase, "__init__", return_value=None):
        host = EosHost(ansible_adhoc, "eos-neighbor", "admin", "password")
    return host


@pytest.mark.parametrize("model,expected,agent", [
    ("multi-agent", True, "Bgp"),
    ("single-agent", False, "Rib"),
])
def test_bgp_agent_selection_without_shell_credentials(model, expected, agent):
    host = make_host()
    assert host.shell_user is None
    assert host.shell_passwd is None
    with patch.object(host, "eos_command", return_value={
        "stdout": [{"protoModelStatus": {"operatingProtoModel": model}}]
    }) as command, patch.object(host, "eos_config") as config:
        assert host.is_multiagent() is expected
        host.kill_bgpd()
        host.start_bgpd()

    command.assert_called_once_with(commands=["show ip route summary | json"])
    assert [call.kwargs["lines"] for call in config.call_args_list] == [
        ["agent {} shutdown".format(agent)],
        ["no agent {} shutdown".format(agent)],
    ]


def test_failed_probe_is_retried():
    host = make_host()
    with patch.object(host, "eos_command", side_effect=[
        RuntimeError("probe failed"),
        {
            "stdout": [
                {"protoModelStatus": {"operatingProtoModel": "multi-agent"}}
            ]
        },
    ]) as command:
        with pytest.raises(RuntimeError, match="probe failed"):
            host.is_multiagent()
        assert host.is_multiagent() is True
    assert command.call_count == 2
