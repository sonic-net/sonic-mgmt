"""DHCP DISCOVER flood generator, run on the PTF host by test_dhcp_server_match_stress.py.

Usage: python3 dhcp_server_match_flood.py <config.json>

The configuration lists the clients (interface, MAC, Option 60, expected addresses), the send rate,
the duration, the reply deadline and the drain time. Every DISCOVER has a unique transaction ID, and
replies are correlated by transaction ID and client hardware address. A JSON summary is printed.
"""
import json
import random
import sys
import time

from scapy.all import AsyncSniffer, BOOTP, DHCP, Ether, IP, UDP, conf, mac2str


def build_discover(mac, xid, opt60):
    options = [("message-type", "discover")]
    if opt60:
        options.append(("vendor_class_id", opt60.encode("utf-8")))
    options.append("end")
    return bytes(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                 IP(src="0.0.0.0", dst="255.255.255.255") /
                 UDP(sport=68, dport=67) /
                 BOOTP(op=1, chaddr=mac2str(mac), xid=xid, flags=0x8000) /
                 DHCP(options=options))


def message_type(pkt):
    for option in pkt[DHCP].options:
        if isinstance(option, tuple) and option[0] == "message-type":
            return option[1]
    return None


def main(config_path):
    with open(config_path) as config_file:
        config = json.load(config_file)
    clients = config["clients"]
    rate, duration = config["rate"], config["duration"]
    deadline, drain = config["deadline"], config["drain"]
    ifaces = sorted(set(client["iface"] for client in clients))
    sockets = {iface: conf.L2socket(iface=iface) for iface in ifaces}
    replies = {}

    def on_packet(pkt):
        if BOOTP not in pkt or pkt[BOOTP].op != 2 or DHCP not in pkt:
            return
        key = (pkt[BOOTP].xid, bytes(pkt[BOOTP].chaddr)[:6])
        if key not in replies:
            replies[key] = (time.time(), pkt[BOOTP].yiaddr, message_type(pkt))

    sniffer = AsyncSniffer(iface=ifaces, filter="udp and (port 67 or port 68)", prn=on_packet, store=False)
    sniffer.start()
    time.sleep(2)

    sent = []
    xid_base = random.randint(1, 0x7fffffff)
    total = int(rate * duration)
    started = time.time()
    for index in range(total):
        target = started + float(index) / rate
        delay = target - time.time()
        if delay > 0:
            time.sleep(delay)
        client = clients[index % len(clients)]
        xid = (xid_base + index) & 0xffffffff
        sockets[client["iface"]].send(build_discover(client["mac"], xid, client.get("opt60")))
        sent.append((xid, client, time.time()))
    send_elapsed = time.time() - started
    time.sleep(deadline + drain)
    sniffer.stop()
    for sock in sockets.values():
        sock.close()

    result = {"sent": len(sent), "send_seconds": round(send_elapsed, 2), "offers": 0, "missing": 0, "late": 0,
              "wrong_pool": 0, "unexpected": 0, "latencies": [], "errors": []}
    for xid, client, sent_at in sent:
        reply = replies.get((xid, bytes(mac2str(client["mac"]))))
        expected = client.get("expect")
        if not expected:
            if reply is not None:
                result["unexpected"] += 1
                result["errors"].append("unmatched {} got {}".format(client["mac"], reply[1]))
            continue
        if reply is None:
            result["missing"] += 1
            continue
        reply_at, yiaddr, msg_type = reply
        result["offers"] += 1
        latency = reply_at - sent_at
        result["latencies"].append(round(latency, 4))
        if msg_type != 2 or yiaddr not in expected:
            result["wrong_pool"] += 1
            result["errors"].append("{} with {} got type {} address {}".format(
                client["mac"], client.get("opt60"), msg_type, yiaddr))
        elif latency > deadline:
            result["late"] += 1
    result["errors"] = result["errors"][:20]
    print(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1])
