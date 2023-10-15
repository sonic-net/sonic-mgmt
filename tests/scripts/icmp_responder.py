import argparse
import asyncio
import ctypes
import functools
import json
import os
import signal
import socket
import struct

from collections.abc import Mapping
from scapy.all import Ether, ICMP, IP


# As defined in asm/socket.h
SO_ATTACH_FILTER = 26

# BPF filter "icmp[icmptype]==8 and src host 10.1.0.36"
icmp_bpf_filter = [
    [0x28, 0, 0, 0x0000000c],
    [0x15, 0, 10, 0x00000800],
    [0x30, 0, 0, 0x00000017],
    [0x15, 0, 8, 0x00000001],
    [0x28, 0, 0, 0x00000014],
    [0x45, 6, 0, 0x00001fff],
    [0xb1, 0, 0, 0x0000000e],
    [0x50, 0, 0, 0x0000000e],
    [0x15, 0, 3, 0x00000008],
    [0x20, 0, 0, 0x0000001a],
    [0x15, 0, 1, 0x0a010024],
    [0x6, 0, 0, 0x00040000],
    [0x6, 0, 0, 0x00000000]
]


def bpf_stmt(code, jt, jf, k):
    """Format struct `sock_filter`."""
    return struct.pack("HBBI", code, jt, jf, k)


def build_bpfilter(filter):
    """Build BPF filter buffer."""
    return ctypes.create_string_buffer(b"".join(bpf_stmt(*_) for _ in filter))


class ICMPResponderProtocol(asyncio.Protocol):
    """ICMP responder protocol class to define read/write callbacks."""

    def __init__(self, on_con_lost, pause_event, dst_mac=None):
        self.transport = None
        self.on_con_lost = on_con_lost
        self.dst_mac = dst_mac
        self.pause_event = pause_event

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        if self.pause_event.is_set():
            return
        reply = self.icmp_reply(data)
        self.transport.write(reply)

    def eof_received(self):
        return True

    def connection_lost(self, exc):
        if not self.on_con_lost.cancelled():
            self.on_con_lost.set_result(True)

    @functools.lru_cache(maxsize=None)
    def icmp_reply(self, icmp_request):
        reply = Ether(icmp_request)
        reply[ICMP].type = 0
        # Force re-generation of the checksum
        reply[ICMP].chksum = None
        reply[IP].src, reply[IP].dst = reply[IP].dst, reply[IP].src
        reply[IP].chksum = None
        reply[Ether].src, reply[Ether].dst = reply[Ether].dst, reply[Ether].src
        if self.dst_mac is not None:
            reply[Ether].dst = self.dst_mac
        return bytes(reply)


def create_socket(interface):
    """Create a packet socket binding to a specified interface."""

    sock = socket.socket(family=socket.AF_PACKET,
                         type=socket.SOCK_RAW, proto=0)

    sock.setblocking(False)
    bpf_filter = build_bpfilter(icmp_bpf_filter)
    fprog = struct.pack("HL", len(icmp_bpf_filter),
                        ctypes.addressof(bpf_filter))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)

    sock.bind((interface, socket.SOCK_RAW))

    return sock


async def icmp_responder(interface, pause_event, dst_mac=None):
    """Start responding to ICMP requests received from specified interface."""
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()

    sock = create_socket(interface)
    transport, protocol = await loop._create_connection_transport(
        sock, lambda: ICMPResponderProtocol(on_con_lost, pause_event, dst_mac), ssl=None, server_hostname=None)

    try:
        await protocol.on_con_lost
    finally:
        transport.close()
        sock.close()


async def responder_control(reader_fd, pause_events):
    loop = asyncio.get_running_loop()

    reader = asyncio.StreamReader()
    read_protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: read_protocol, reader_fd)

    while True:
        raw_data = await reader.readline()
        raw_data = raw_data.strip()
        if raw_data:
            try:
                data = json.loads(raw_data.strip())
            except json.decoder.JSONDecodeError:
                continue
            if isinstance(data, Mapping):
                for interface, is_pause in list(data.items()):
                    if interface in pause_events:
                        pause_event = pause_events[interface]
                        if is_pause:
                            pause_event.set()
                        else:
                            pause_event.clear()


def stop_tasks(loop):
    """Stop all tasks in current event loop."""
    for task in asyncio.all_tasks(loop=loop):
        task.cancel()


ICMP_RESPONDER_PIPE = "/tmp/icmp_responder.pipe"


def create_control_pipe():
    if os.path.exists(ICMP_RESPONDER_PIPE):
        os.unlink(ICMP_RESPONDER_PIPE)
    os.mkfifo(ICMP_RESPONDER_PIPE)


async def start_icmp_responder(interfaces, dst_mac=None):
    """Start responding to ICMP requests received from the interfaces."""
    pause_events = {interface: asyncio.Event() for interface in interfaces}

    create_control_pipe()
    # NOTE: the read fd is open with O_NONBLOCK as no writer is not available
    # and the dummy write fd is used to keep the read fd open
    reader_fd = os.fdopen(
        os.open(ICMP_RESPONDER_PIPE, os.O_RDONLY | os.O_NONBLOCK))
    _ = open(ICMP_RESPONDER_PIPE, "w")

    tasks = [icmp_responder(interface, event, dst_mac=dst_mac)
             for interface, event in list(pause_events.items())]
    tasks.append(responder_control(reader_fd, pause_events))

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, functools.partial(stop_tasks, loop))
    loop.add_signal_handler(
        signal.SIGTERM, functools.partial(stop_tasks, loop))

    await asyncio.gather(*tasks, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description="ICMP responder")
    parser.add_argument("--intf", "-i", dest="ifaces", required=True,
                        action="append", help="interface to listen for ICMP request")
    parser.add_argument("--dst_mac", "-m", dest="dst_mac", required=False,
                        action="store", help="The destination MAC to use for ICMP echo replies")
    args = parser.parse_args()
    interfaces = args.ifaces
    dst_mac = args.dst_mac

    try:
        asyncio.run(start_icmp_responder(
            interfaces=interfaces, dst_mac=dst_mac))
    except asyncio.CancelledError:
        print("Exiting...")
        return


if __name__ == "__main__":
    main()
