import asyncio
import contextlib
import importlib.util
import json
import socket
import struct
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from scapy.all import Ether, ICMP, IP, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, Raw, UDP
from scapy.utils import checksum


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "icmp_responder.py"
SPEC = importlib.util.spec_from_file_location("icmp_responder", SCRIPT)
responder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(responder)


def make_request(ipv6, payload):
    """Build a probe with explicit Ethernet addresses and recognizable echo fields."""
    ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    if ipv6:
        return ethernet / IPv6(src="2001:db8:1::1", dst="2001:db8:2::2") / ICMPv6EchoRequest(
            id=123, seq=65535, data=payload)
    return ethernet / IP(src="10.1.0.36", dst="192.0.2.2") / ICMP(id=123, seq=65535) / Raw(payload)


@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("dst_mac", [None, "02:00:00:00:00:03"])
@pytest.mark.parametrize("payload", [b"", bytes(range(255))], ids=["empty", "binary"])
def test_echo_reply(ipv6, dst_mac, payload):
    """Preserve probe identity and payload while generating a valid echo reply."""
    request = make_request(ipv6, payload)
    protocol = responder.ICMPResponderProtocol(Mock(), asyncio.Event(), dst_mac)
    reply = Ether(protocol.icmp_reply(bytes(request)))
    assert reply.src == request.dst
    assert reply.dst == (dst_mac or request.src)
    network = IPv6 if ipv6 else IP
    assert reply[network].src == request[network].dst
    assert reply[network].dst == request[network].src
    echo = reply[ICMPv6EchoReply] if ipv6 else reply[ICMP]
    assert echo.type == (129 if ipv6 else 0)
    assert echo.code == 0
    assert echo.id == 123
    assert echo.seq == 65535
    assert (echo.data if ipv6 else bytes(echo.payload)) == payload
    if ipv6:
        pseudo_header = socket.inet_pton(socket.AF_INET6, reply[IPv6].src)
        pseudo_header += socket.inet_pton(socket.AF_INET6, reply[IPv6].dst)
        pseudo_header += struct.pack("!I3xB", len(bytes(echo)), socket.IPPROTO_ICMPV6)
        assert checksum(pseudo_header + bytes(echo)) == 0
    else:
        assert checksum(bytes(reply[IP])[:reply[IP].ihl * 4]) == 0
        assert checksum(bytes(echo)) == 0


@pytest.mark.parametrize("ipv6", [False, True])
def test_pause_resume(ipv6):
    """Pause drops requests and resume restores responses for both families."""
    pause_event = asyncio.Event()
    protocol = responder.ICMPResponderProtocol(Mock(), pause_event)
    transport = Mock()
    protocol.connection_made(transport)
    request = bytes(make_request(ipv6, b"probe"))
    pause_event.set()
    protocol.data_received(request)
    transport.write.assert_not_called()
    pause_event.clear()
    protocol.data_received(request)
    transport.write.assert_called_once_with(protocol.icmp_reply(request))


@pytest.mark.parametrize("ipv6_enabled,ipv6,source,request_type,accepted", [
    (False, False, "10.1.0.36", 8, True),
    (False, True, "2001:db8:1::1", 128, False),
    (True, False, "10.1.0.36", 8, True),
    (True, False, "10.1.0.37", 8, False),
    (True, False, "10.1.0.36", 0, False),
    (True, True, "2001:db8:1::1", 128, True),
    (True, True, "2001:db8:3::1", 128, True),
    (True, True, "2001:db8:4::1", 128, False),
    (True, True, "2001:db8:1::2", 128, False),
    (True, True, "2001:db8:1::1", 129, False),
    (True, True, "2001:db8:1::1", 135, False),
    (True, True, "2001:db8:1::1", None, False),
])
def test_kernel_filter(ipv6_enabled, ipv6, source, request_type, accepted):
    """Exercise the actual attached BPF with accepted and rejected frames."""
    sources = ["2001:db8:1::1", "2001:db8:3::1"] if ipv6_enabled else []
    try:
        receiver = responder.create_socket("lo", sources)
    except PermissionError:
        pytest.skip("Kernel filter validation requires CAP_NET_RAW")
    with receiver, socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sender:
        sender.bind(("lo", 0))
        receiver.settimeout(0.1)
        request = make_request(ipv6, b"kernel-filter-probe")
        network = request[IPv6 if ipv6 else IP]
        network.src = source
        if request_type is None:
            network.remove_payload()
            network.add_payload(UDP(sport=12345, dport=12346) / Raw(b"unrelated"))
        else:
            request[ICMPv6EchoRequest if ipv6 else ICMP].type = request_type
        sender.send(bytes(request))
        if accepted:
            assert receiver.recv(2048) == bytes(request)
        else:
            with pytest.raises(socket.timeout):
                receiver.recv(2048)


@pytest.mark.parametrize("mux,enabled", [
    ({}, False),
    ({"cable_type": "active-active", "soc_ipv4": "192.0.2.2/32"}, False),
    ({"cable_type": "active-active", "soc_ipv4": "192.0.2.2/32", "soc_ipv6": "2001:db8:2::2/128"}, False),
    ({"cable_type": "active-active", "soc_ipv6": "2001:db8:2::2/128", "server_ipv4": "192.0.2.3/32"}, True),
    ({"cable_type": "active-active", "soc_ipv4": "192.0.2.2/32", "server_ipv6": "2001:db8:2::3/128"}, False),
    ({"server_ipv6": "2001:db8:2::2/128"}, True),
    ({"server_ipv4": "192.0.2.2/32", "server_ipv6": "2001:db8:2::2/128"}, False),
])
def test_fixture_family_selection(mux, enabled):
    """Fixtures use the selected endpoint family and deduplicate ToR source addresses."""
    from tests.common.fixtures.ptfhost_utils import get_icmp_responder_ipv6_args
    dut = Mock()
    dut.get_running_config_facts.return_value = {
        "MUX_CABLE": {"Ethernet8": mux},
        "LOOPBACK_INTERFACE": {"Loopback2": {"10.1.0.36/32": {}, "2001:db8:1::1/128": {}}},
    }
    expected = " --src_ipv6 2001:db8:1::1" if enabled else ""
    assert get_icmp_responder_ipv6_args([dut, dut]) == expected


@pytest.mark.parametrize("loopbacks", [
    {}, {"Loopback2": {"::/128": {}}}, {"Loopback2": {"10.1.0.36/32": {}}},
])
def test_fixture_requires_ipv6_source(loopbacks):
    """Fail setup rather than silently start an IPv4-only responder for an IPv6 port."""
    from tests.common.fixtures.ptfhost_utils import get_icmp_responder_ipv6_args
    dut = Mock(hostname="tor")
    dut.get_running_config_facts.return_value = {
        "MUX_CABLE": {"Ethernet8": {"cable_type": "active-active", "soc_ipv6": "2001:db8:2::2/128"}},
        "LOOPBACK_INTERFACE": loopbacks,
    }
    with pytest.raises(pytest.fail.Exception, match="IPv6 Loopback2"):
        get_icmp_responder_ipv6_args([dut])


@pytest.mark.parametrize("session", [False, True])
@pytest.mark.parametrize("missing_source", [False, True])
def test_fixture_launch_arguments(monkeypatch, session, missing_source):
    """Both fixture scopes validate sources before setup and render them on success."""
    from tests.common.fixtures import ptfhost_utils
    monkeypatch.setattr(ptfhost_utils, "icmp_responder_session_started", False)
    monkeypatch.setattr(ptfhost_utils, "update_linkmgrd_probe_interval", Mock())
    monkeypatch.setattr(ptfhost_utils, "TEMPLATES_DIR", str(SCRIPT.parent.parent / "templates"))
    dut = Mock(hostname="tor")
    dut.get_running_config_facts.return_value = {
        "MUX_CABLE": {"Ethernet8": {"cable_type": "active-active", "soc_ipv6": "2001:db8:2::2/128"}},
        "LOOPBACK_INTERFACE": {"Loopback2": {"2001:db8:1::1/128": {}}},
        "VLAN": {"Vlan1000": {}},
    }
    if missing_source:
        dut.get_running_config_facts.return_value["LOOPBACK_INTERFACE"] = {}
    dut.get_extended_minigraph_facts.return_value = {"minigraph_ptf_indices": {"Ethernet8": 1}}
    dut.get_vlan_intfs.return_value = ["Ethernet8"]
    dut.get_dut_iface_mac.return_value = "02:00:00:00:00:03"
    duthosts = MagicMock()
    duthosts.__iter__.side_effect = lambda: iter([dut])
    duthosts.__getitem__.return_value = dut
    ptfhost = Mock()
    tbinfo = {"topo": {"name": "dualtor-aa", "type": "t0"}}
    if session:
        fixture = ptfhost_utils.run_icmp_responder_session.__wrapped__(duthosts, dut, ptfhost, tbinfo, Mock())
    else:
        fixture = ptfhost_utils.run_icmp_responder.__wrapped__(duthosts, "tor", ptfhost, tbinfo, Mock())
    try:
        if missing_source:
            with pytest.raises(pytest.fail.Exception, match="IPv6 Loopback2"):
                next(fixture)
            ptfhost.copy.assert_not_called()
            duthosts.shell.assert_not_called()
            ptfhost_utils.update_linkmgrd_probe_interval.assert_not_called()
            return
        next(fixture)
        rendered = [call.kwargs["content"] for call in ptfhost.copy.call_args_list if "content" in call.kwargs]
        assert len(rendered) == 1
        assert "-i eth1 -m 02:00:00:00:00:03 --src_ipv6 2001:db8:1::1" in rendered[0]
    finally:
        fixture.close()


@pytest.mark.parametrize("ipv6", [False, True])
def test_running_service_pause_recovery(monkeypatch, tmp_path, ipv6):
    """Run actual asynchronous socket I/O and pause/resume through the JSON FIFO."""
    try:
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(responder.ETH_P_ALL))
    except PermissionError:
        pytest.skip("Service validation requires CAP_NET_RAW")
    monkeypatch.setattr(responder, "ICMP_RESPONDER_PIPE", str(tmp_path / "control.pipe"))
    original_create_socket = responder.create_socket
    original_control = responder.responder_control

    async def exercise():
        loop = asyncio.get_running_loop()
        ready = asyncio.Event()
        resumed = asyncio.Event()
        events = {}

        def capture_socket(*args, **kwargs):
            receiver = original_create_socket(*args, **kwargs)
            loop.call_soon(ready.set)
            return receiver

        async def capture_control(reader_fd, pause_events):
            events.update(pause_events)
            original_clear = events["lo"].clear

            def clear_and_notify():
                original_clear()
                resumed.set()

            monkeypatch.setattr(events["lo"], "clear", clear_and_notify)
            await original_control(reader_fd, pause_events)

        monkeypatch.setattr(responder, "create_socket", capture_socket)
        monkeypatch.setattr(responder, "responder_control", capture_control)
        service = asyncio.create_task(responder.start_icmp_responder(
            ["lo"], dst_mac="02:00:00:00:00:03", ipv6_sources=["2001:db8:1::1"]))

        async def receive_reply(sequence):
            while True:
                packet = Ether(await loop.sock_recv(sender, 2048))
                echo_type = ICMPv6EchoReply if ipv6 else ICMP
                if echo_type in packet:
                    echo = packet[echo_type]
                    if echo.type == (129 if ipv6 else 0) and echo.id == 123 and echo.seq == sequence:
                        return bytes(packet)

        try:
            await asyncio.wait_for(ready.wait(), 2)
            sender.bind(("lo", 0))
            sender.setblocking(False)
            protocol = responder.ICMPResponderProtocol(Mock(), asyncio.Event(), "02:00:00:00:00:03")
            with open(responder.ICMP_RESPONDER_PIPE, "w") as control:
                for sequence, paused in [(1, False), (2, True), (3, False)]:
                    control.write(json.dumps({"lo": paused}) + "\n")
                    control.flush()
                    await asyncio.wait_for(events["lo"].wait() if paused else resumed.wait(), 2)
                    resumed.clear()
                    request = make_request(ipv6, bytes(range(255)))
                    request[ICMPv6EchoRequest if ipv6 else ICMP].seq = sequence
                    await loop.sock_sendall(sender, bytes(request))
                    if paused:
                        with pytest.raises(asyncio.TimeoutError):
                            await asyncio.wait_for(receive_reply(sequence), 0.1)
                    else:
                        reply = await asyncio.wait_for(receive_reply(sequence), 2)
                        assert reply == protocol.icmp_reply(bytes(request))
        finally:
            service.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await service

    with sender:
        asyncio.run(exercise())


def test_cli_ipv6_sources(monkeypatch):
    """The CLI passes repeated IPv6 source arguments and existing options to the service."""
    start = AsyncMock()
    monkeypatch.setattr(responder, "start_icmp_responder", start)
    monkeypatch.setattr(sys, "argv", [
        "icmp_responder", "-i", "lo", "-m", "02:00:00:00:00:03",
        "--src_ipv6", "2001:db8:1::1", "--src_ipv6", "2001:db8:3::1",
    ])
    responder.main()
    start.assert_awaited_once()
    assert start.await_args.kwargs["interfaces"] == ["lo"]
    assert start.await_args.kwargs["dst_mac"] == "02:00:00:00:00:03"
    assert [str(source) for source in start.await_args.kwargs["ipv6_sources"]] == [
        "2001:db8:1::1", "2001:db8:3::1"]
