"""Check that DhcpClient.exchange only accepts replies that reach the requesting client's port.

Run inside the sonic-mgmt container with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_dhcp_server_match_client.py -v
"""

import ast
import logging
from collections import namedtuple
from pathlib import Path
from unittest.mock import Mock

import pytest

scapy = pytest.importorskip("scapy.all")

MODULE_PATH = Path(__file__).resolve().parents[2] / "dhcp_server" / "dhcp_server_match_common.py"
CLIENT_MAC = "02:dc:00:00:00:01"
XID = 0x1234
CLIENT_PORT, OTHER_PORT = 1, 2

Port = namedtuple("Port", ["name", "ptf_index"])
PollResult = namedtuple("PollResult", ["port", "packet"])


class FakeDataplane(object):
    """Per-port receive queues with the poll() semantics of ptf.dataplane.DataPlane."""

    def __init__(self, received):
        self.queues = {port: list(packets) for port, packets in received.items()}

    def flush(self):
        pass

    def poll(self, device_number=0, port_number=None, timeout=None, filters=()):
        ports = [port_number] if port_number is not None else sorted(self.queues)
        for port in ports:
            queue = self.queues.get(port, [])
            while queue:
                packet = queue.pop(0)
                if all(check(packet) for check in filters):
                    return PollResult(port, packet)
        return PollResult(None, None)


def _assert(condition, message="assertion failed"):
    assert condition, message


@pytest.fixture
def client_class():
    tree = ast.parse(MODULE_PATH.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "DhcpClient")
    namespace = {
        "binascii": __import__("binascii"),
        "scapy": scapy,
        "testutils": Mock(),
        "pytest_assert": _assert,
        "logger": logging.getLogger(__name__),
        "new_client_mac": Mock(return_value=CLIENT_MAC),
        "REPLY_TIMEOUT": 1,
        "NO_REPLY_TIMEOUT": 1,
        "STRAY_REPLY_TIMEOUT": 0,
        "MATCH_LEASE_TIME": 600,
    }
    exec(compile(ast.Module(body=[cls], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["DhcpClient"]


def _reply(xid=XID, mac=CLIENT_MAC):
    return bytes(scapy.Ether(dst=mac) / scapy.IP() / scapy.UDP(sport=67, dport=68) /
                 scapy.BOOTP(op=2, xid=xid, chaddr=bytes.fromhex(mac.replace(":", "")), yiaddr="192.0.2.10"))


def _client(client_class, received):
    adapter = Mock()
    adapter.dataplane = FakeDataplane(received)
    client_port = Port("Ethernet4", CLIENT_PORT)
    env = Mock(vlan="Vlan1000", members=[client_port, Port("Ethernet8", OTHER_PORT)])
    return client_class(env, adapter, client_port, mac=CLIENT_MAC)


def test_reply_only_on_other_vlan_port_is_rejected(client_class):
    client = _client(client_class, {OTHER_PORT: [_reply()]})
    with pytest.raises(AssertionError, match="arrived on PTF port 2 but not on the client port 1"):
        client.exchange(Mock(), XID)


def test_reply_on_client_port_is_accepted_despite_earlier_flooded_copy(client_class):
    client = _client(client_class, {OTHER_PORT: [_reply()], CLIENT_PORT: [_reply(xid=XID + 1), _reply()]})
    reply = client.exchange(Mock(), XID)
    assert reply is not None and reply[scapy.BOOTP].xid == XID


def test_no_reply_anywhere_returns_none(client_class):
    client = _client(client_class, {OTHER_PORT: [_reply(xid=XID + 1)]})
    assert client.exchange(Mock(), XID) is None


def test_expect_no_offer_still_fails_on_reply_to_other_port(client_class):
    """Negative checks must stay strict: a reply anywhere is a failure."""
    client = _client(client_class, {OTHER_PORT: [_reply()]})
    client.discover = lambda opt60=Ellipsis, timeout=None: client.exchange(Mock(), XID, timeout)
    with pytest.raises(AssertionError):
        client.expect_no_offer()
