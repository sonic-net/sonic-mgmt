#!/usr/bin/env python3
"""Install cSONiC virtual-wire flows using live OVS port discovery."""

import argparse
import subprocess


LACP_DESTINATION = "01:80:c2:00:00:02"
FLOW_COOKIE = "0xc50c1c"


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bridge", required=True)
    parser.add_argument("--neighbor-port", required=True)
    args = parser.parse_args()

    ports = run("ovs-vsctl", "list-ports", args.bridge).splitlines()
    if args.neighbor_port not in ports:
        raise SystemExit("{} is not attached to {}".format(
            args.neighbor_port, args.bridge))

    peer_ports = [port for port in ports
                  if port != args.neighbor_port
                  and not port.startswith("inje-")]
    if len(peer_ports) != 1:
        raise SystemExit("expected one DUT peer on {}, found: {}".format(
            args.bridge, ", ".join(peer_ports) or "none"))
    dut_port = peer_ports[0]

    ofports = {}
    for port in (args.neighbor_port, dut_port):
        value = run("ovs-vsctl", "get", "Interface", port, "ofport")
        if not value.isdigit() or int(value) <= 0:
            raise SystemExit("invalid OpenFlow port for {}: {}".format(
                port, value))
        ofports[port] = value

    desired = [
        "cookie={},table=0,priority=20,in_port={},dl_dst={},actions=output:{}".format(
            FLOW_COOKIE, ofports[dut_port], LACP_DESTINATION,
            ofports[args.neighbor_port]),
        "cookie={},table=0,priority=20,in_port={},dl_dst={},actions=output:{}".format(
            FLOW_COOKIE, ofports[args.neighbor_port], LACP_DESTINATION,
            ofports[dut_port]),
    ]

    subprocess.check_call([
        "ovs-ofctl", "del-flows", args.bridge,
        "cookie={}/-1".format(FLOW_COOKIE),
    ])
    subprocess.check_call([
        "ovs-ofctl", "add-flow", args.bridge,
        "cookie={},table=0,priority=0,actions=NORMAL".format(FLOW_COOKIE),
    ])
    for flow in desired:
        subprocess.check_call(["ovs-ofctl", "add-flow", args.bridge, flow])

    print("changed=true bridge={} neighbor={} dut={}".format(
        args.bridge, args.neighbor_port, dut_port))


if __name__ == "__main__":
    main()
