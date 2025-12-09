import argparse
import ipaddress
import syslog

from time import sleep
from swsscommon import swsscommon

"""
Tests orchagent response to alternating neighbor/route updates for matching ip.

In dualtor scenarios, tunnel routes for mux neighbors are programmed separately from traditional route updates.

Tests a corner case where neighbor entry is learned on mux but routes
are also advertised on up/downstream with same prefix

    1. Neighbor learned on standby mux
    2. Neighbor learned on active mux
    3. Route advertised on Vlan
    4. Route advertised on PortChannel
"""

DATABASE = swsscommon.DBConnector("APPL_DB", 0)

NEIGH_TABLE = swsscommon.ProducerStateTable(DATABASE, "NEIGH_TABLE")
ROUTE_TABLE = swsscommon.ProducerStateTable(DATABASE, "ROUTE_TABLE")


def to_fvs(fvs):
    return swsscommon.FieldValuePairs([(k, v) for k, v in fvs.items()])


def log_msg(message):
    syslog.syslog(syslog.LOG_NOTICE, message)


def set_neighbor(interface, ip, mac):
    key = f"{interface}:{ip}"
    ip_version = ipaddress.ip_address(ip).version
    fvs = {"neigh": mac, "family": f"IPv{ip_version}"}
    NEIGH_TABLE.set(key, to_fvs(fvs))


def set_route(ip, nexthops, ifnames):
    ip_version = ipaddress.ip_address(ip).version
    if ip_version == 4:
        prefix = f"{ip}/32"
    elif ip_version == 6:
        prefix = f"{ip}/128"
    else:
        print("unexpected ip version, exiting...")
        exit(1)

    key = f"{prefix}"

    nexthop_list = ",".join(nexthops)
    ifname_list = ",".join(ifnames)

    fvs = {"nexthop": f"{nexthop_list}", "ifname": f"{ifname_list}"}
    ROUTE_TABLE.set(key, to_fvs(fvs))


def main(vlan_if, portchannel_if, standby_mac, active_mac, ip, vlan_nexthops, portchannel_nexthops, iterations):
    for i in range(int(iterations)):
        log_msg(f"================ Begin Test {i} ====================")
        set_neighbor(vlan_if, ip, standby_mac)
        sleep(1)
        set_neighbor(vlan_if, ip, active_mac)
        sleep(.05)
        set_route(ip, vlan_nexthops, [vlan_if])
        sleep(3)
        set_route(ip, portchannel_nexthops, portchannel_if)
        sleep(1)
        log_msg(f"================ End Test {i} ====================")


if __name__ == '__main__':
    parser = argparse.ArgumentParser('Test alternating neighbor/route updates')
    parser.add_argument('--vlan-if')
    parser.add_argument('--portchannel-if', type=lambda s: s.split(','))
    parser.add_argument('--standby-mac')
    parser.add_argument('--active-mac')
    parser.add_argument('--ip')
    parser.add_argument('--vlan-nexthops', type=lambda s: s.split(','))
    parser.add_argument('--portchannel-nexthops', type=lambda s: s.split(','))
    parser.add_argument('--iterations')

    args = parser.parse_args()
    main(args.vlan_if, args.portchannel_if, args.standby_mac, args.active_mac,
         args.ip, args.vlan_nexthops, args.portchannel_nexthops, args.iterations)
