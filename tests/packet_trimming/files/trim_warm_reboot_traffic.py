#!/usr/bin/env python3
"""
Sequence numbered traffic generator and trimmed packet loss analyzer.

This script runs on the PTF host and is used by the packet trimming warm reboot test:
    send <iface> <router_mac> <dst_ip> <dscp> <pps> <duration> <packet_size>
        Send UDP packets carrying an incrementing "COUNT:<9 digits>|" marker. The marker is placed
        at the beginning of the payload, so that it is still present after the packet is trimmed.
    analyze
        Read a pcap stream from stdin and report the trimmed packet loss as JSON on stdout.
"""
import json
import signal
import struct
import sys
import time

COUNTER_PREFIX = "COUNT:"
COUNTER_DIGITS = 9
# Source addresses of the generated packets, they only have to be unused addresses
SRC_MAC = "00:11:22:33:44:55"
SRC_IP = "8.8.8.8"
SRC_IPV6 = "2000::1"
SRC_PORT = 4321
DST_PORT = 1234
# TTL of the generated packets, the DUT decrements it, so the captured copies have TTL - 1
TTL = 64
# ECN Capable Transport(0), ECT(0)
ECN = 2
# Packets bigger than this size were forwarded by the DUT without being trimmed
UNTRIMMED_SIZE_THRESHOLD = 1000
# Reporting the first entries is enough to tell when and where the disruption happened
MAX_REPORTED_ENTRIES = 20
# Byte order of a pcap stream, the second magic of each byte order is the nanosecond variant
PCAP_MAGIC_BYTE_ORDER = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
                         b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}
# The magic numbers of the pcap variants that store the timestamp fraction in nanoseconds
PCAP_NANOSECOND_MAGIC = (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


def send_traffic(iface, router_mac, dst_ip, dscp, pps, duration, packet_size):
    """
    Send a paced stream of sequence numbered UDP packets until the duration expires.

    Args:
        iface (str): Interface to send the packets from
        router_mac (str): Router MAC address of the DUT
        dst_ip (str): Destination IP address
        dscp (int): DSCP value, it decides which egress queue the packets land on
        pps (int): Packets per second
        duration (int): How long to keep sending the traffic, in seconds
        packet_size (int): Payload size in bytes
    """
    # Imported here because only the traffic generator needs scapy, the analyzer does not
    from scapy.all import Ether, IP, IPv6, UDP, Raw, conf, raw

    padding = "F" * (packet_size - len(COUNTER_PREFIX) - COUNTER_DIGITS - 1)
    payload = f"{COUNTER_PREFIX}{'0' * COUNTER_DIGITS}|{padding}"
    # The DSCP and ECN bits sit in the same place in the IPv4 ToS and the IPv6 Traffic Class
    if ":" in dst_ip:
        ip_layer = IPv6(src=SRC_IPV6, dst=dst_ip, tc=(dscp << 2) | ECN, hlim=TTL)
    else:
        ip_layer = IP(src=SRC_IP, dst=dst_ip, tos=(dscp << 2) | ECN, ttl=TTL)
    packet = (Ether(src=SRC_MAC, dst=router_mac) /
              ip_layer /
              UDP(sport=SRC_PORT, dport=DST_PORT, chksum=0) /
              Raw(load=payload))

    packet_bytes = bytearray(raw(packet))
    counter_offset = packet_bytes.find(b"0" * COUNTER_DIGITS)
    socket = conf.L2socket(iface=iface)
    interval = 1.0 / pps
    end_time = time.time() + duration
    next_send_time = time.time()
    counter = 0

    def report_sent_count(signum, frame):
        """
        Report the sent count when the test stops the traffic before the duration expires,
        otherwise the count is lost and the achieved rate cannot be told from the log.
        """
        print(f"SENT={counter}")
        sys.stdout.flush()
        sys.exit(0)

    signal.signal(signal.SIGTERM, report_sent_count)

    try:
        while time.time() < end_time:
            counter += 1
            # Update the counter in place, so that the packet size stays constant
            packet_bytes[counter_offset:counter_offset + COUNTER_DIGITS] = b"%09d" % counter
            socket.ins.send(packet_bytes)
            # Pace against a deadline, so that a slow iteration does not slow down the whole stream
            next_send_time += interval
            sleep_time = next_send_time - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)
    finally:
        socket.close()

    print(f"SENT={counter}")


def analyze_capture():
    """
    Read a pcap stream from stdin and report the trimmed packet loss as JSON on stdout.

    The packets are received in the order they were sent, so the loss is detected by comparing each
    counter with the previous one. This keeps the memory usage constant no matter how many packets
    are captured.

    The rate of the received trimmed packets is reported as well, because it decides how many
    packets a short disruption can drop, and therefore whether the measurement can detect one.
    """
    report = {"trimmed": 0, "untrimmed": 0, "untrimmed_counters": [], "total_loss": 0,
              "max_contiguous_loss": 0, "gaps": [], "duration": 0, "rate": 0}
    stream = sys.stdin.buffer
    magic = stream.read(24)[:4]
    if magic not in PCAP_MAGIC_BYTE_ORDER:
        # Report instead of failing, so that the caller always gets a valid report to log
        report["error"] = f"unexpected capture format, magic is {magic.hex()}"
        print(json.dumps(report))
        return

    endian = PCAP_MAGIC_BYTE_ORDER[magic]
    fraction_divisor = 1e9 if magic in PCAP_NANOSECOND_MAGIC else 1e6
    marker = COUNTER_PREFIX.encode()
    previous_counter = None
    first_timestamp = None
    last_timestamp = None

    while True:
        record_header = stream.read(16)
        if len(record_header) < 16:
            break
        timestamp_sec, timestamp_fraction, capture_len, packet_len = struct.unpack(endian + "IIII", record_header)
        timestamp = timestamp_sec + timestamp_fraction / fraction_divisor
        packet_bytes = stream.read(capture_len)

        marker_offset = packet_bytes.find(marker)
        if marker_offset < 0:
            continue
        counter_offset = marker_offset + len(marker)
        counter = int(packet_bytes[counter_offset:counter_offset + COUNTER_DIGITS])

        if packet_len > UNTRIMMED_SIZE_THRESHOLD:
            report["untrimmed"] += 1
            if len(report["untrimmed_counters"]) < MAX_REPORTED_ENTRIES:
                report["untrimmed_counters"].append(counter)
            continue

        report["trimmed"] += 1
        if first_timestamp is None:
            first_timestamp = timestamp
        last_timestamp = timestamp

        if previous_counter is not None and counter > previous_counter + 1:
            loss = counter - previous_counter - 1
            report["total_loss"] += loss
            report["max_contiguous_loss"] = max(report["max_contiguous_loss"], loss)
            if len(report["gaps"]) < MAX_REPORTED_ENTRIES:
                report["gaps"].append({"loss": loss, "after_counter": previous_counter,
                                       "timestamp": f"{timestamp:.6f}"})
        previous_counter = counter

    if first_timestamp is not None and last_timestamp > first_timestamp:
        # Divide by the exact duration, the reported one is rounded and can be zero for a very
        # short capture
        duration = last_timestamp - first_timestamp
        report["duration"] = round(duration, 3)
        report["rate"] = int(report["trimmed"] / duration)

    print(json.dumps(report))


if __name__ == "__main__":
    if sys.argv[1] == "send":
        send_traffic(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]),
                     int(sys.argv[7]), int(sys.argv[8]))
    else:
        analyze_capture()
