import base64
import datetime
import json
import logging

import random
import re
import string
import time
from collections import defaultdict
import pytest
import requests
import ptf.packet as scapy
import ptf.testutils as testutils

from ptf.mask import Mask
from ptf.testutils import simple_ipv6_sr_packet, verify_no_packet_any
from scapy.all import Raw
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.l2 import Ether
from tests.common.helpers.dut_utils import get_available_tech_support_files, get_new_techsupport_files_list, \
    extract_techsupport_tarball_file
from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat
from tests.common.utilities import wait_until
from tests.common.helpers.srv6_helper import SRv6

logger = logging.getLogger(__name__)
LOCATOR_NUM = 128
ROUTE_BASE = '2001'

# CRM refreshes its resource counters on this interval, in seconds
CRM_DEFAULT_POLL_INTERVAL = 300
CRM_FAST_POLL_INTERVAL = 10

#
# uN configuration used by the SRv6 data plane and warm reboot tests
#
UN_LOCATOR_NAME = 'loc1'
UN_LOCATOR_PREFIX = 'fcbb:bbbb:1::'
UN_SID_PREFIX = 'fcbb:bbbb:1::/48'
UN_SID_APPL_DB_KEY = 'SRV6_MY_SID_TABLE:32:16:0:0:fcbb:bbbb:1::'
# Destination address of the injected packets, it matches the uN SID above
UN_SID_TRAFFIC_DST = 'fcbb:bbbb:1:2::'
# Destination address of the packets once the uN behavior has been applied
UN_EGRESS_DST = 'fcbb:bbbb:2::'
UN_EGRESS_ROUTE = 'fcbb:bbbb:2::/48'
SRV6_BLACKHOLE_ROUTE = 'fcbb:bbbb::/32'


class MyLocators():
    # Generate 128 locators with incrementing IPv6 addresses
    my_locator_list = [
        [f'locator_{i + 1}', f'{ROUTE_BASE}:1001:{1 + i}::', f'{1 + i}'] for i in range(LOCATOR_NUM)
    ]


class MySIDs(MyLocators):
    TUNNEL_MODE = [SRv6.pipe_mode]
    # Generate 128 SIDs based on the locator list
    MY_SID_LIST = [
        [locator_name, sid, SRv6.uN, 'default']
        for locator_name, sid, _ in MyLocators.my_locator_list
    ]


def validate_sai_sdk_dump_files(duthost, techsupport_folder, feature_list=[]):
    """
    Validated that expected SAI dump file available inside in techsupport dump file
    """
    logger.info('Validate SAI dump file is included in the tech-support dump')
    saidump_files_inside_techsupport = \
        duthost.shell(f'ls {techsupport_folder}/sai_sdk_dump')['stdout_lines']
    assert saidump_files_inside_techsupport, 'Expected SAI SDK dump file(folder) not available in techsupport dump'
    for feature in feature_list:
        for sai_sdk_dump in saidump_files_inside_techsupport:
            res = duthost.shell(f'zgrep {feature} {techsupport_folder}/sai_sdk_dump/{sai_sdk_dump}',
                                module_ignore_errors=True)['stdout_lines']
            if res and feature in ''.join(res):
                logger.info(f'Feature {feature} parameter exist in {techsupport_folder}/sai_sdk_dump/{sai_sdk_dump}'
                            f'\n{res}')
                break
        else:
            raise Exception(f'Feature "{feature}" parameter does not exist in sai sdk dump files')


def validate_techsupport_generation(duthost, feature_list=[]):
    """
    Validate sai sdk dump file exist
    """
    available_tech_support_files = get_available_tech_support_files(duthost)
    logger.info('Execute show techsupport command')
    duthost.shell('show techsupport')
    new_techsupport_files_list = get_new_techsupport_files_list(duthost, available_tech_support_files)
    tech_support_file_path = new_techsupport_files_list[0]
    logger.info(f'New tech support file: {new_techsupport_files_list}')
    tech_support_name = tech_support_file_path.split('.')[0].lstrip('/var/dump/')

    try:
        logger.info(f'Doing validation for techsupport : {tech_support_name}')
        techsupport_folder_path = extract_techsupport_tarball_file(duthost, tech_support_file_path)
        logger.info('Checking that expected SAI SDK dump file available in techsupport file')
        validate_sai_sdk_dump_files(duthost, techsupport_folder_path, feature_list)
    finally:
        logger.info(f'Delete {tech_support_file_path}')
        duthost.shell(f'sudo rm -rf {tech_support_file_path}')


#
# log directory inside each vsonic. vsonic starts with admin as user.
#
test_log_dir = "/home/admin/testlogs/"


#
# Helper func for print a set of lines
#
def print_lines(outlines):
    for line in outlines:
        logger.debug(line)


#
# Util functions for announce / withdraw routes from ptf docker.
#
def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)


def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)


def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" % (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


#
# Skip some BGP neighbor check
#
def skip_bgp_neighbor_check(neighbor):
    skip_addresses = []
    for addr in skip_addresses:
        if neighbor == addr:
            return True

    return False


#
# Helper func to check if a list of BGP neighbors are up
#
def check_bgp_neighbors_func(nbrhost, neighbors, vrf=""):
    cmd = "vtysh -c 'show bgp summary'"
    if vrf != "":
        cmd = "vtysh -c 'show bgp vrf {} summary'".format(vrf)
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for neighbor in neighbors:
        if skip_bgp_neighbor_check(neighbor):
            logger.debug("Skip {} check".format(neighbor))
            found = found + 1
            continue

        for line in res:
            if neighbor in line:
                arr = line.split()
                pfxrcd = arr[9]
                try:
                    int(pfxrcd)
                    found = found + 1
                    logger.debug("{} ==> BGP neighbor is up and gets pfxrcd {}".format(line, pfxrcd))
                except ValueError:
                    logger.debug("{} ==> BGP neighbor state {}, not up".format(line, pfxrcd))
    return len(neighbors) == found


#
# Checke BGP neighbors
#
def check_bgp_neighbors(nbrhost, neighbors, vrf=""):
    pytest_assert(check_bgp_neighbors_func(nbrhost, neighbors, vrf))


#
# Helper function to count number of Ethernet interfaces
#
def find_node_interfaces(nbrhost):
    cmd = "show version"
    res = nbrhost.command(cmd)["stdout_lines"]
    hwsku = ""
    for line in res:
        if "HwSKU:" in line:
            logger.debug("{}".format(line))
            sarr = line.split()
            hwsku = sarr[1]
            break

    cmd = "show interface status"
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for line in res:
        logger.debug("{}".format(line))
        if "Ethernet" in line:
            found = found + 1

    return found, hwsku


#
# Send receive packets
#
def runSendReceive(pkt, src_port, exp_pkt, dst_ports, pkt_expected, ptfadapter):
    """
    @summary Send packet and verify it is received/not received on the expected ports
    @param pkt: The packet that will be injected into src_port
    @param src_ports: The port into which the pkt will be injected
    @param exp_pkt: The packet that will be received on one of the dst_ports
    @param dst_ports: The ports on which the exp_pkt may be received
    @param pkt_expected: Indicated whether it is expected to receive the exp_pkt on one of the dst_ports
    @param ptfadapter: The ptfadapter fixture
    """
    ptfadapter.dataplane.flush()
    ptfadapter.dataplane.set_qlen(1000000)
    # Send the packet and poll on destination ports
    testutils.send(ptfadapter, ptfadapter.dataplane.port_to_tuple(src_port), pkt, 1)
    logger.debug("Sent packet: " + pkt.summary())

    time.sleep(1)
    expected_ports = [ptfadapter.dataplane.port_to_tuple(port) for port in dst_ports]
    devices = sorted({device for device, port in expected_ports})
    pytest_assert(devices, "No destination PTF ports were supplied")
    deadline = time.monotonic() + 60
    while True:
        for device in devices:
            remaining = max(0, deadline - time.monotonic())
            timeout = min(1, remaining) if len(devices) > 1 else remaining
            result = testutils.dp_poll(ptfadapter, device_number=device, exp_pkt=exp_pkt, timeout=timeout)
            if isinstance(result, ptfadapter.dataplane.PollSuccess):
                break
        if isinstance(result, ptfadapter.dataplane.PollSuccess) or time.monotonic() >= deadline:
            break
    if not isinstance(result, ptfadapter.dataplane.PollSuccess):
        pytest_assert(False, "Did not receive the expected packet on {}:\n{}".format(dst_ports, result.format()))
    pytest_assert((result.device, result.port) in expected_ports,
                  "Received packet on {}, expected one of {}".format((result.device, result.port), expected_ports))
    for device in devices:
        testutils.verify_no_other_packets(ptfadapter, device_number=device)
    index, rcv_pkt = expected_ports.index((result.device, result.port)), result.packet
    received = False
    if rcv_pkt:
        received = True
    pytest_assert(received == pkt_expected)
    logger.debug('index=%s, received=%s' % (str(index), str(received)))
    if received:
        logger.debug("Received packet: " + scapy.Ether(rcv_pkt).summary())
    if pkt_expected:
        logger.debug('Expected packet on dst_ports')
        passed = True if received else False
        logger.debug('Received: ' + str(received))
    else:
        logger.debug('No packet expected on dst_ports')
        passed = False if received else True
        logger.debug('Received: ' + str(received))
    logger.debug('Passed: ' + str(passed))
    return passed


#
# Helper func to check if a list of IPs go via a given set of next hop
#
def check_routes_func(nbrhost, ips, nexthops, vrf="", is_v6=False):
    # Check remote learnt dual homing routes
    vrf_str = ""
    if vrf != "":
        vrf_str = "vrf {}".format(vrf)
    ip_str = "ip"
    if is_v6:
        ip_str = "ipv6"
    for ip in ips:
        cmd = "show {} route {} {} nexthop-group".format(ip_str, vrf_str, ip)
        res = nbrhost.command(cmd)["stdout_lines"]
        print_lines(res)
        found = 0
        for nexthop in nexthops:
            for line in res:
                if nexthop in line:
                    found = found + 1
        if len(nexthops) != found:
            return False
    return True


#
# check if a list of IPs go via a given set of next hop
#
def check_routes(nbrhost, ips, nexthops, vrf="", is_v6=False):
    # Add retry for debugging purpose
    count = 0
    ret = False

    #
    # Sleep 10 sec before retrying
    #
    sleep_duration_for_retry = 10

    # retry 3 times before claiming failure
    while count < 3 and not ret:
        ret = check_routes_func(nbrhost, ips, nexthops, vrf, is_v6)
        if not ret:
            count = count + 1
            # sleep make sure all forwarding structures are settled down.
            time.sleep(sleep_duration_for_retry)
            logger.info("Sleep {} seconds to retry round {}".format(sleep_duration_for_retry, count))

    pytest_assert(ret)


#
# Verify global IPv6 route NHG correlation:
#
#   1. vtysh "show ipv6 route <prefix> nexthop-group" gives the zebra
#      "Nexthop Group ID" (resolved) for the route.
#   2. APPL_STATE_DB key "NHG_FULL_STATE_TABLE:<zebra_nhg_id>" must exist
#      with status == "OK"; it carries the sonic_nhg_id.
#   3. APPL_DB key "ROUTE_TABLE:<prefix>" must carry nexthop_group equal
#      to that sonic_nhg_id.
#
# The whole correlation is performed by a small Python script that is
# uploaded to the DUT and run there once, so that we issue a single SSH
# command instead of one round-trip per redis/vtysh call.
#
# Returns a dict with at least:
#   {"ok": True|False, "msg": "<diagnostic>",
#    "zebra_nhg_id": int, "sonic_nhg_id": int}
#
def check_v6_route_nhg_chain_func(duthost, prefix):
    script = r'''
import json, re, subprocess, sys

PREFIX = sys.argv[1]

def run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

result = {"ok": False, "prefix": PREFIX, "msg": "",
          "zebra_nhg_id": None, "dplane_nhg_id": None,
          "rib_nhg_id_used": None, "sonic_nhg_id": None,
          "route_nexthop_group": None, "nhg_state_status": None}

# (1) zebra: resolved Nexthop Group ID
rc, out, err = run('vtysh -c "show ipv6 route %s nexthop-group"' % PREFIX)
if rc != 0:
    result["msg"] = "vtysh failed: %s" % err.strip()
    print(json.dumps(result)); sys.exit(0)
m = re.search(r"Routing entry for\s+(\S+)", out)
canonical = m.group(1) if m else PREFIX
result["canonical_prefix"] = canonical
m = re.search(r"Nexthop Group ID:\s*(\d+)", out)
if not m:
    result["msg"] = "no Nexthop Group ID in vtysh output"
    print(json.dumps(result)); sys.exit(0)
zebra_nhg_id = int(m.group(1))
result["zebra_nhg_id"] = zebra_nhg_id
m = re.search(r"Received Nexthop Group ID:\s*(\d+)", out)
received_nhg_id = int(m.group(1)) if m else None
result["received_nhg_id"] = received_nhg_id

# (2) zebra NHG id -> plugin dplane NHG id.
# The state table is keyed by the plugin-allocated id; by-rib-id is the
# reverse index from the zebra NHG id to the derived dplane object.
def lookup_dplane_id(rib_id):
    if rib_id is None:
        return None
    rc, out, err = run('vtysh -c "show fpm nhg-fib by-rib-id %d json"'
                       % rib_id)
    if rc != 0 or not out.strip():
        return None
    try:
        objs = json.loads(out)
    except ValueError:
        return None
    if not objs:
        return None
    dplane_id = objs[0].get("dplaneId")
    return dplane_id if isinstance(dplane_id, int) else None

dplane_nhg_id = None
for rib_id in (zebra_nhg_id, received_nhg_id):
    dplane_nhg_id = lookup_dplane_id(rib_id)
    if dplane_nhg_id is not None:
        result["rib_nhg_id_used"] = rib_id
        break
if dplane_nhg_id is None:
    result["msg"] = ("show fpm nhg-fib by-rib-id found no dplane NHG for "
                     "zebra=%d received=%s"
                     % (zebra_nhg_id, received_nhg_id))
    print(json.dumps(result)); sys.exit(0)
result["dplane_nhg_id"] = dplane_nhg_id

# (3) APPL_STATE_DB:NHG_FULL_STATE_TABLE:<dplane_nhg_id>
key = "NHG_FULL_STATE_TABLE:%d" % dplane_nhg_id
rc, out, err = run('redis-cli -n 14 --raw hgetall "%s"' % key)
if rc != 0 or not out.strip():
    result["msg"] = ("NHG_FULL_STATE_TABLE entry %s missing (rc=%d stderr=%r)"
                     % (key, rc, err.strip()))
    print(json.dumps(result)); sys.exit(0)
# Output alternates field/value lines
lines = out.splitlines()
nhg_state = dict(zip(lines[0::2], lines[1::2]))
result["nhg_state_status"] = nhg_state.get("status")
if nhg_state.get("status") != "OK":
    result["msg"] = "NHG state status is %r, expected OK" % nhg_state.get("status")
    print(json.dumps(result)); sys.exit(0)
sonic_nhg_id_str = nhg_state.get("sonic_nhg_id", "")
if not sonic_nhg_id_str.isdigit():
    result["msg"] = "sonic_nhg_id missing or non-numeric: %r" % sonic_nhg_id_str
    print(json.dumps(result)); sys.exit(0)
sonic_nhg_id = int(sonic_nhg_id_str)
result["sonic_nhg_id"] = sonic_nhg_id

# (4) APPL_DB:ROUTE_TABLE:<canonical_prefix>
# Use the canonical prefix from vtysh; fpmsyncd stores host routes without
# the /128 suffix but uses the full /<len> form for everything else.
route_prefix = canonical[:-4] if canonical.endswith("/128") else canonical
rc, out, err = run('redis-cli -n 0 --raw hgetall "ROUTE_TABLE:%s"' % route_prefix)
if rc != 0 or not out.strip():
    result["msg"] = "ROUTE_TABLE entry missing for ROUTE_TABLE:%s" % route_prefix
    print(json.dumps(result)); sys.exit(0)
lines = out.splitlines()
route_row = dict(zip(lines[0::2], lines[1::2]))
route_nhg = route_row.get("nexthop_group", "")
result["route_nexthop_group"] = route_nhg
if not route_nhg.isdigit() or int(route_nhg) != sonic_nhg_id:
    result["msg"] = ("ROUTE_TABLE nexthop_group=%r does not match "
                     "NHG_FULL_STATE_TABLE sonic_nhg_id=%d"
                     % (route_nhg, sonic_nhg_id))
    print(json.dumps(result)); sys.exit(0)

result["ok"] = True
result["msg"] = "OK"
print(json.dumps(result))
'''
    # Single SSH round-trip: pipe the script in via stdin and execute it.
    cmd = "python3 - {} <<'PYEOF'\n{}PYEOF".format(prefix, script)
    res = duthost.shell(cmd, module_ignore_errors=True)
    stdout = (res.get("stdout") or "").strip()
    try:
        data = json.loads(stdout)
    except Exception:
        return {"ok": False,
                "msg": "Failed to parse DUT script output: %r (stderr=%r)" %
                       (stdout, res.get("stderr")),
                "zebra_nhg_id": None,
                "sonic_nhg_id": None}
    return data


#
# Pytest-asserting wrapper around check_v6_route_nhg_chain_func with retry.
#
def check_v6_route_nhg_chain(duthost, prefix, retries=3, retry_wait=10):
    last = None
    for attempt in range(retries):
        last = check_v6_route_nhg_chain_func(duthost, prefix)
        if last.get("ok"):
            logger.info("v6 route NHG chain OK for %s: zebra_nhg_id=%s "
                        "dplane_nhg_id=%s sonic_nhg_id=%s",
                        prefix, last.get("zebra_nhg_id"),
                        last.get("dplane_nhg_id"),
                        last.get("sonic_nhg_id"))
            return last
        logger.info("v6 route NHG chain check attempt %d/%d failed for %s: %s",
                    attempt + 1, retries, prefix, last.get("msg"))
        if attempt + 1 < retries:
            time.sleep(retry_wait)
    pytest_assert(False,
                  "v6 route NHG chain verification failed for {}: {}"
                  .format(prefix, last.get("msg") if last else "no result"))


#
# Verify VRF (IPv4 or IPv6) route NHG correlation:
#
#   1. vtysh "show {ip|ipv6} route vrf <vrf> <prefix> nexthop-group" gives
#      both:
#        - "Nexthop Group ID"          (the resolved NHE id)
#        - "Received Nexthop Group ID" (the protocol-original NHE id)
#      For recursive SRv6 VPN routes these two ids are typically different.
#   2. APPL_STATE_DB key "NHG_FULL_STATE_TABLE:<received_nhg_id>" must
#      exist with status == "OK"; it carries sonic_nhg_id and
#      (for SRv6 VPN routes) pic_context_id.
#   3. APPL_DB key "ROUTE_TABLE:<vrf>:<prefix>" must carry:
#        - nexthop_group  == NHG_FULL_STATE_TABLE.sonic_nhg_id
#        - pic_context_id == NHG_FULL_STATE_TABLE.pic_context_id
#          (only compared if the state table reports a pic_context_id)
#
# Single SSH round-trip — the entire correlation runs as a Python script
# on the DUT.
#
# Returns a dict with at least:
#   {"ok": True|False, "msg": "<diagnostic>",
#    "zebra_nhg_id": int, "received_nhg_id": int,
#    "sonic_nhg_id": int, "pic_context_id": str|None,
#    "route_nexthop_group": str, "route_pic_context_id": str|None}
#
def check_vrf_route_nhg_chain_func(duthost, vrf, prefix, is_v6=False):
    ip_str = "ipv6" if is_v6 else "ip"
    script = r'''
import json, re, subprocess, sys

IP_STR = sys.argv[1]
VRF = sys.argv[2]
PREFIX = sys.argv[3]

def run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

result = {"ok": False, "vrf": VRF, "prefix": PREFIX, "is_v6": IP_STR == "ipv6",
          "msg": "",
          "zebra_nhg_id": None, "received_nhg_id": None,
          "dplane_nhg_id": None, "rib_nhg_id_used": None,
          "sonic_nhg_id": None, "pic_context_id": None,
          "route_nexthop_group": None, "route_pic_context_id": None,
          "nhg_state_status": None}

# (1) vtysh: resolved + received Nexthop Group ID
rc, out, err = run('vtysh -c "show %s route vrf %s %s nexthop-group"'
                   % (IP_STR, VRF, PREFIX))
if rc != 0:
    result["msg"] = "vtysh failed: %s" % err.strip()
    print(json.dumps(result)); sys.exit(0)
m = re.search(r"Routing entry for\s+(\S+)", out)
canonical = m.group(1) if m else PREFIX
result["canonical_prefix"] = canonical
m = re.search(r"Nexthop Group ID:\s*(\d+)", out)
if not m:
    result["msg"] = "no Nexthop Group ID in vtysh output"
    print(json.dumps(result)); sys.exit(0)
result["zebra_nhg_id"] = int(m.group(1))
m = re.search(r"Received Nexthop Group ID:\s*(\d+)", out)
if not m:
    result["msg"] = "no Received Nexthop Group ID in vtysh output"
    print(json.dumps(result)); sys.exit(0)
received_nhg_id = int(m.group(1))
result["received_nhg_id"] = received_nhg_id

# (2) zebra NHG id -> plugin dplane NHG id.
# The plugin allocates its own ids; by-rib-id is the reverse index from the
# zebra NHG id the route carries to the derived dplane object.
def lookup_dplane_id(rib_id):
    rc, out, err = run('vtysh -c "show fpm nhg-fib by-rib-id %d json"'
                       % rib_id)
    if rc != 0 or not out.strip():
        return None
    try:
        objs = json.loads(out)
    except ValueError:
        return None
    if not objs:
        return None
    dplane_id = objs[0].get("dplaneId")
    return dplane_id if isinstance(dplane_id, int) else None

dplane_nhg_id = None
for rib_id in (received_nhg_id, result["zebra_nhg_id"]):
    dplane_nhg_id = lookup_dplane_id(rib_id)
    if dplane_nhg_id is not None:
        result["rib_nhg_id_used"] = rib_id
        break
if dplane_nhg_id is None:
    result["msg"] = ("show fpm nhg-fib by-rib-id found no dplane NHG for "
                     "received=%d zebra=%d"
                     % (received_nhg_id, result["zebra_nhg_id"]))
    print(json.dumps(result)); sys.exit(0)
result["dplane_nhg_id"] = dplane_nhg_id

# (3) APPL_STATE_DB:NHG_FULL_STATE_TABLE:<dplane_nhg_id>
key = "NHG_FULL_STATE_TABLE:%d" % dplane_nhg_id
rc, out, err = run('redis-cli -n 14 --raw hgetall "%s"' % key)
if rc != 0 or not out.strip():
    result["msg"] = ("NHG_FULL_STATE_TABLE entry %s missing (rc=%d stderr=%r)"
                     % (key, rc, err.strip()))
    print(json.dumps(result)); sys.exit(0)
lines = out.splitlines()
nhg_state = dict(zip(lines[0::2], lines[1::2]))
result["nhg_state_status"] = nhg_state.get("status")
if nhg_state.get("status") != "OK":
    result["msg"] = "NHG state status is %r, expected OK" % nhg_state.get("status")
    print(json.dumps(result)); sys.exit(0)
sonic_nhg_id_str = nhg_state.get("sonic_nhg_id", "")
if not sonic_nhg_id_str.isdigit():
    result["msg"] = "sonic_nhg_id missing or non-numeric: %r" % sonic_nhg_id_str
    print(json.dumps(result)); sys.exit(0)
result["sonic_nhg_id"] = int(sonic_nhg_id_str)
# pic_context_id is optional (only present for SRv6 VPN routes)
state_pic = nhg_state.get("pic_context_id")
if state_pic is not None and state_pic != "N/A":
    result["pic_context_id"] = state_pic

# (4) APPL_DB:ROUTE_TABLE:<vrf>:<canonical_prefix>
# Use the canonical prefix from vtysh; fpmsyncd stores host routes
# without the /32 (IPv4) or /128 (IPv6) suffix.
route_prefix = canonical
if IP_STR == "ipv6" and route_prefix.endswith("/128"):
    route_prefix = route_prefix[:-4]
elif IP_STR == "ip" and route_prefix.endswith("/32"):
    route_prefix = route_prefix[:-3]
route_key = "ROUTE_TABLE:%s:%s" % (VRF, route_prefix)
rc, out, err = run('redis-cli -n 0 --raw hgetall "%s"' % route_key)
if rc != 0 or not out.strip():
    result["msg"] = "ROUTE_TABLE entry missing for %s" % route_key
    print(json.dumps(result)); sys.exit(0)
lines = out.splitlines()
route_row = dict(zip(lines[0::2], lines[1::2]))
route_nhg = route_row.get("nexthop_group", "")
result["route_nexthop_group"] = route_nhg
if not route_nhg.isdigit() or int(route_nhg) != result["sonic_nhg_id"]:
    result["msg"] = ("ROUTE_TABLE nexthop_group=%r does not match "
                     "NHG_FULL_STATE_TABLE sonic_nhg_id=%d"
                     % (route_nhg, result["sonic_nhg_id"]))
    print(json.dumps(result)); sys.exit(0)

# pic_context_id correlation (only when state table reports one)
if result["pic_context_id"] is not None:
    route_pic = route_row.get("pic_context_id", "")
    result["route_pic_context_id"] = route_pic
    if route_pic != result["pic_context_id"]:
        result["msg"] = ("ROUTE_TABLE pic_context_id=%r does not match "
                         "NHG_FULL_STATE_TABLE pic_context_id=%r"
                         % (route_pic, result["pic_context_id"]))
        print(json.dumps(result)); sys.exit(0)

result["ok"] = True
result["msg"] = "OK"
print(json.dumps(result))
'''
    cmd = "python3 - {} {} {} <<'PYEOF'\n{}PYEOF".format(ip_str, vrf, prefix, script)
    res = duthost.shell(cmd, module_ignore_errors=True)
    stdout = (res.get("stdout") or "").strip()
    try:
        data = json.loads(stdout)
    except Exception:
        return {"ok": False,
                "msg": "Failed to parse DUT script output: %r (stderr=%r)" %
                       (stdout, res.get("stderr")),
                "zebra_nhg_id": None,
                "received_nhg_id": None,
                "sonic_nhg_id": None,
                "pic_context_id": None}
    return data


#
# Pytest-asserting wrapper around check_vrf_route_nhg_chain_func with retry.
#
def check_vrf_route_nhg_chain(duthost, vrf, prefix, is_v6=False,
                              retries=3, retry_wait=10):
    last = None
    for attempt in range(retries):
        last = check_vrf_route_nhg_chain_func(duthost, vrf, prefix, is_v6=is_v6)
        if last.get("ok"):
            logger.info("vrf route NHG chain OK for vrf=%s prefix=%s: "
                        "zebra_nhg_id=%s received_nhg_id=%s "
                        "dplane_nhg_id=%s sonic_nhg_id=%s pic_context_id=%s",
                        vrf, prefix,
                        last.get("zebra_nhg_id"),
                        last.get("received_nhg_id"),
                        last.get("dplane_nhg_id"),
                        last.get("sonic_nhg_id"),
                        last.get("pic_context_id"))
            return last
        logger.info("vrf route NHG chain check attempt %d/%d failed for "
                    "vrf=%s prefix=%s: %s",
                    attempt + 1, retries, vrf, prefix, last.get("msg"))
        if attempt + 1 < retries:
            time.sleep(retry_wait)
    pytest_assert(False,
                  "vrf route NHG chain verification failed for vrf={} "
                  "prefix={}: {}".format(vrf, prefix,
                                         last.get("msg") if last else "no result"))


#
# Record fwding chain to a file
#
def recording_fwding_chain(nbrhost, fname, comments):

    filename = "{}{}".format(test_log_dir, fname)

    cmd = "mkdir -p {}".format(test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "sudo touch /etc/sonic/frr/vtysh.conf"
    nbrhost.shell(cmd, module_ignore_errors=True)

    cmd = "date >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "echo ' {}' >> {} ".format(comments, filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show bgp summary' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ip route vrf Vrf1 192.100.1.0 nexthop-group' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ipv6 route fd00:201:201:fff1:11:: nexthop-group' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "vtysh -c 'show ipv6 route fd00:202:202:fff2:22:: nexthop-group' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)

    cmd = "echo '' >> {} ".format(filename)
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Debug commands for FRR zebra
#
debug_cmds = [
    'debug zebra events',
    'debug zebra rib',
    'debug zebra rib detailed',
    'debug zebra nht',
    'debug zebra nht detailed',
    'debug zebra dplane',
    'debug zebra nexthop',
    'debug zebra nexthop detail',
    'debug zebra packet',
    'debug zebra packet detail'
]


#
# Turn on/off FRR debug to a file
#
def turn_on_off_frr_debug(duthosts, rand_one_dut_hostname, nbrhosts, filename, vm, is_on=True,
                          debug_cmds_list=None):
    nbrhost = nbrhosts[vm]['host']
    # save frr log to a file
    pfxstr = " "
    if not is_on:
        pfxstr = " no "

    cmds = debug_cmds_list if debug_cmds_list is not None else debug_cmds

    cmd = "vtysh -c 'configure terminal' -c '{} log file {}'".format(pfxstr, filename)
    nbrhost.command(cmd)

    #
    # Change frr debug flags
    #
    for dcmd in cmds:
        cmd = "vtysh -c '" + pfxstr + dcmd + "'"
        nbrhost.command(cmd)

    #
    # Check debug flags
    #
    cmd = "vtysh -c 'show debug'"
    nbrhost.shell(cmd, module_ignore_errors=True)
    #
    # Check log file
    #
    cmd = "vtysh -c 'show run' | grep log"
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Collect file from bgp docker
#
def collect_frr_debugfile(duthosts, rand_one_dut_hostname, nbrhosts, filename, vm):
    nbrhost = nbrhosts[vm]['host']
    cmd = "mkdir -p {}".format(test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)
    cmd = "docker cp bgp:{} {}".format(filename, test_log_dir)
    nbrhost.shell(cmd, module_ignore_errors=True)


#
# Verify that the SID entry is programmed in APPL_DB
#
def verify_appl_db_sid_entry_exist(duthost, sonic_db_cli, key, exist):
    appl_db_my_sids = duthost.command(sonic_db_cli + " APPL_DB keys SRV6_MY_SID_TABLE*")["stdout"]
    return key in appl_db_my_sids if exist else key not in appl_db_my_sids


def enable_srv6_counterpoll(duthost):
    """
    Enable SRv6 counterpoll on the DUT.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cmd = 'sudo counterpoll srv6 enable'
        duthost.shell(cmd)
        logger.info("Successfully enabled SRv6 counterpoll")
        return True
    except Exception as e:
        raise Exception(f"Failed to enable SRv6 counterpoll: {str(e)}")


def disable_srv6_counterpoll(duthost):
    """
    Disable SRv6 counterpoll on the DUT.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cmd = 'sudo counterpoll srv6 disable'
        duthost.shell(cmd)
        logger.info("Successfully disabled SRv6 counterpoll")
        return True
    except Exception as e:
        raise Exception(f"Failed to disable SRv6 counterpoll: {str(e)}")


def set_srv6_counterpoll_interval(duthost, interval_ms, wait_for_new_interval=True):
    """
    Set the polling interval for SRv6 counterpoll.

    Args:
        duthost (SonicHost): DUT host object
        interval_ms (int): Polling interval in milliseconds
        wait_for_new_interval (bool): Whether to wait for the new interval to take effect

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get current interval
        current_status = duthost.get_counter_poll_status()
        if 'SRV6_STAT' not in current_status:
            logger.error("SRv6 counterpoll is not available")
            return False

        current_interval = current_status['SRV6_STAT']['interval']

        # Set new interval
        cmd = f'sudo counterpoll srv6 interval {interval_ms}'
        duthost.shell(cmd)

        # Wait for the new interval to take effect if requested
        if wait_for_new_interval:
            wait_time = current_interval / 1000 + 1  # Convert to seconds and add 1 second buffer
            logger.info(f"Waiting {wait_time} seconds for new interval to take effect")
            time.sleep(wait_time)

        logger.info(f"Successfully set SRv6 counterpoll interval to {interval_ms} ms")
        return True
    except Exception as e:
        raise Exception(f"Failed to set SRv6 counterpoll interval: {str(e)}")


def get_srv6_counterpoll_status(duthost):
    """
    Get the current status of SRv6 counterpoll.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        dict: Dictionary containing status information or None if failed
    """
    try:
        status = duthost.get_counter_poll_status()
        if 'SRV6_STAT' in status:
            return status['SRV6_STAT']
        return None
    except Exception as e:
        raise Exception(f"Failed to get SRv6 counterpoll status: {str(e)}")


def verify_srv6_counterpoll_status(duthost, expected_status, expected_interval=None):
    """
    Verify the status of SRv6 counterpoll.

    Args:
        duthost (SonicHost): DUT host object
        expected_status (str): Expected status ('enable' or 'disable')
        expected_interval (str): Expected interval in milliseconds
    Returns:
        bool: True if status matches expected, False otherwise
    """
    try:
        status = get_srv6_counterpoll_status(duthost)
        if status is None:
            return False

        actual_status = status['status'].lower()
        expected_status = expected_status.lower()
        actual_interval = status['interval']

        if expected_interval:
            if actual_interval != expected_interval:
                logger.error(f"SRv6 counterpoll interval mismatch. Expected: {expected_interval}, "
                             f"Actual: {actual_interval}")
                return False

        if actual_status == expected_status:
            logger.info(f"SRv6 counterpoll status verified as {expected_status}")
            return True
        else:
            logger.error(f"SRv6 counterpoll status mismatch. Expected: {expected_status}, Actual: {actual_status}")
            return False
    except Exception as e:
        raise Exception(f"Failed to verify SRv6 counterpoll status: {str(e)}")


def validate_srv6_counters(duthost, srv6_pkt_list, mysid_list, pkt_num):
    """
    Validate SRv6 counters based on the list of SRv6 packets.

    Args:
        duthost (SonicHost): DUT host object
        srv6_pkt_list (list): List of SRv6 packets
        mysid_list (list): List of MySID to validate
        pkt_num (int): Number of packets to validate

    Returns:
        bool: True if counters match expected values, False otherwise
    """
    if duthost.facts["asic_type"] == "vpp":
        return True
    try:
        stats_list = duthost.show_and_parse('show srv6 stats')
        stats_dict = {item['mysid']: item for item in stats_list}

        for srv6_pkt, mysid in zip(srv6_pkt_list, mysid_list):
            # Wireshark and PTF do not include FCS field when calculating frame length, but the switch does,
            # so add 4 bytes when validating SRv6 counters at switch
            single_pkt_len = len(srv6_pkt) + 4
            mysid_with_prefix = mysid[1] + '/' + str(SRv6.prefix_len)

            if mysid_with_prefix not in stats_dict:
                logger.error(f"MySID {mysid_with_prefix} not found in SRv6 statistics")
                return False

            current_stats = stats_dict[mysid_with_prefix]
            current_packets = int(current_stats['packets'])
            current_bytes = int(current_stats['bytes'])

            if current_packets != pkt_num or current_bytes != pkt_num * single_pkt_len:
                logger.error(f"SRv6 statistics mismatch for MySID {mysid_with_prefix}: "
                             f"Expected Packets={pkt_num}, Bytes={pkt_num * single_pkt_len}, "
                             f"Actual Packets={current_packets}, Bytes={current_bytes}")
                return False

            logger.info(f"SRv6 statistics match expected values for MySID {mysid_with_prefix}: "
                        f"Packets={current_packets}, Bytes={current_bytes}")

        return True
    except Exception as e:
        raise Exception(f"Failed to validate SRv6 counters: {str(e)}")


def get_crm_polling_interval(duthost):
    """
    Return the CRM polling interval, in seconds, configured on the DUT.

    Falls back to the SONiC default when the value cannot be parsed, so that the
    caller always has something to restore.
    """
    output = duthost.command("crm show summary", module_ignore_errors=True)["stdout"]
    match = re.search(r'Polling Interval:\s*(\d+)\s*second', output)
    if match:
        return int(match.group(1))
    logger.warning("Could not parse the CRM polling interval from {!r}, assuming the default {}s"
                   .format(output, CRM_DEFAULT_POLL_INTERVAL))
    return CRM_DEFAULT_POLL_INTERVAL


def set_crm_polling_interval(duthost, interval):
    """Set the CRM polling interval, in seconds, on the DUT."""
    logger.info("Setting the CRM polling interval to {}s".format(interval))
    duthost.command("crm config polling interval {}".format(interval))


def get_srv6_mysid_entry_usage(duthost):
    """
    Get the usage information of SRv6 MySID Entry resources.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        dict: Dictionary containing usage information with keys:
            - 'used_count': Number of used entries
            - 'available_count': Number of available entries
            - 'total_count': Total number of entries
        Returns None if failed to get the information
    """
    try:
        # Get SRv6 MySID Entry usage information using show_and_parse
        usage_list = duthost.show_and_parse('crm show resources srv6-my-sid-entry')

        # Find the entry for srv6_my_sid_entry
        for entry in usage_list:
            if entry['resource name'] == 'srv6_my_sid_entry':
                used_count = int(entry['used count'])
                available_count = int(entry['available count'])
                total_count = used_count + available_count

                result = {
                    'used_count': used_count,
                    'available_count': available_count,
                    'total_count': total_count
                }

                logger.info(f"SRv6 MySID Entry usage: Used={used_count}, Available={available_count}, "
                            f"Total={total_count}")
                return result

        logger.error("SRv6 MySID Entry resource not found in CRM output")
        return None

    except Exception as e:
        raise Exception(f"Failed to get SRv6 MySID Entry usage: {str(e)}")


def clear_srv6_counters(duthost):
    """
    Clear all SRv6 counters using sonic-clear command.

    Args:
        duthost (SonicHost): DUT host object

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        cmd = 'sudo sonic-clear srv6counters'
        duthost.shell(cmd)
        logger.info("Successfully cleared SRv6 counters")
        return True
    except Exception as e:
        raise Exception(f"Failed to clear SRv6 counters: {str(e)}")


def verify_srv6_crm_status(duthost, expected_used_count, expected_available_count):
    '''
    Verify the CRM status of SRv6 SID.

    Args:
        duthost (SonicHost): DUT host object
        expected_used_count (int): Expected number of used entries
        expected_available_count (int): Expected number of available entries
    '''
    mysid_crm_status = get_srv6_mysid_entry_usage(duthost)
    if not mysid_crm_status:
        logger.info("Failed to get SRv6 MySID Entry usage")
        return False
    if mysid_crm_status['used_count'] != expected_used_count:
        logger.info(f"Expected {expected_used_count} used SRv6 MySID Entries, but got {mysid_crm_status['used_count']}")
        return False
    if mysid_crm_status['available_count'] != expected_available_count:
        logger.info(f"Expected {expected_available_count} available SRv6 MySID Entries, "
                    f"but got {mysid_crm_status['available_count']}")
        return False

    logger.info("SRv6 MySID Entry usage verified successfully")
    return True


#
# Get the mac address of a neighbor
#
def get_neighbor_mac(dut, neighbor_ip):
    """Get the MAC address of the neighbor via the ip neighbor table"""
    return dut.command("ip neigh show {}".format(neighbor_ip))['stdout'].split()[4]


def verify_asic_db_sid_entry_exist(duthost, sonic_db_cli):
    """
    Verify that ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries exist in the ASIC DB.
    Args:
        duthost: The DUT host object
        sonic_db_cli: The sonic-db-cli command with namespace options
    Returns:
        bool: True if entries exist, False otherwise
    """
    asic_db_my_sids = duthost.command(sonic_db_cli +
                                      " ASIC_DB keys *ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY*")["stdout"]
    return len(asic_db_my_sids.strip()) > 0



def get_ptf_src_port_and_dut_port_and_neighbor(dut, tbinfo):
    """Get the PTF port mapping for the duthost or an asic of the duthost"""
    dut_mg_facts = dut.get_extended_minigraph_facts(tbinfo)
    ports_map = dut_mg_facts["minigraph_ptf_indices"]
    if len(ports_map) == 0:
        pytest.skip("No PTF ports found for {}".format(dut))

    lldp_table = dut.command("show lldp table")['stdout'].split("\n")[3:]
    neighbor_table = [line.split() for line in lldp_table]
    for entry in neighbor_table:
        intf = entry[0]
        if intf in ports_map:
            # Check if this interface is part of a portchannel
            ptf_ports = [ports_map[intf]]

            # Check if the interface is a member of any portchannel
            if 'minigraph_portchannels' in dut_mg_facts:
                for pc_name, pc_info in dut_mg_facts['minigraph_portchannels'].items():
                    if intf in pc_info.get('members', []):
                        # Found a portchannel - get PTF ports for all members
                        logger.info("Interface {} is a member of portchannel {}".format(intf, pc_name))
                        ptf_ports = []
                        for member in pc_info['members']:
                            if member in ports_map:
                                ptf_ports.append(ports_map[member])
                                logger.info("Added portchannel member {} with PTF port {}".format(
                                    member, ports_map[member]))
                        break

            return intf, ptf_ports, entry[1]  # local intf, ptf_src_ports (list), neighbor hostname

    pytest.skip("No active LLDP neighbor found for {}".format(dut))
    return None


def run_srv6_traffic_test(duthost, dut_mac, ptf_src_ports, neighbor_ip, ptfadapter, ptfhost, with_srh):
    # Convert single port to list for uniform handling
    if isinstance(ptf_src_ports, int):
        ptf_src_ports_list = [ptf_src_ports]
    else:
        ptf_src_ports_list = ptf_src_ports

    # Use the first port for sending packets
    ptf_src_port = ptf_src_ports_list[0]
    device, port = ptfadapter.dataplane.port_to_tuple(ptf_src_port)
    ptfhost = ptfadapter.ptfhosts[device]
    src_mac = ptfadapter.dataplane.get_mac(device, port).decode()

    for i in range(0, 10):
        # generate a random payload
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        if with_srh:
            injected_pkt = simple_ipv6_sr_packet(
                eth_dst=dut_mac,
                eth_src=src_mac,
                ipv6_src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1",
                ipv6_dst="fcbb:bbbb:1:2::",
                srh_seg_left=1,
                srh_nh=41,
                inner_frame=IPv6() / UDP(dport=4791) / Raw(load=payload)
            )
        else:
            injected_pkt = Ether(dst=dut_mac, src=src_mac) \
                           / IPv6(src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1", dst="fcbb:bbbb:1:2::") \
                           / IPv6() / UDP(dport=4791) / Raw(load=payload)

        expected_pkt = injected_pkt.copy()
        expected_pkt['Ether'].dst = get_neighbor_mac(duthost, neighbor_ip)
        expected_pkt['Ether'].src = dut_mac
        expected_pkt['IPv6'].dst = "fcbb:bbbb:2::"
        expected_pkt['IPv6'].hlim -= 1
        logger.debug("Expected packet #{}: {}".format(i, expected_pkt.summary()))
        runSendReceive(injected_pkt, ptf_src_port, expected_pkt, ptf_src_ports_list, True, ptfadapter)


def _normalize_asic_db_mysid_key(key):
    """
    Build a comparable identity for an ASIC_DB MY_SID entry key.

    The key embeds the entry definition as a json document, e.g.
    ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY:{"switch_id":"oid:0x21...","sid":"fcbb:bbbb:1::",...}
    The SAI object ids are dropped so that the comparison only covers the entry
    itself: both the switch id and the virtual router id are allocated by syncd
    and are legitimately reassigned across a warm reboot, while the SID and its
    locator, function and argument lengths identify the entry.
    """
    _, _, entry = key.partition('SAI_OBJECT_TYPE_MY_SID_ENTRY:')
    if not entry:
        return key
    try:
        decoded = json.loads(entry)
    except ValueError:
        return entry
    if isinstance(decoded, dict):
        decoded.pop('switch_id', None)
        decoded.pop('vr_id', None)
        return json.dumps(decoded, sort_keys=True)
    return entry


def get_asic_db_mysid_entries(duthost, sonic_db_cli="sonic-db-cli"):
    """
    Collect the SRv6 MY_SID entries programmed in the ASIC DB.

    Returns:
        dict: {normalized entry key: {attribute: value}}
    """
    entries = {}
    keys = duthost.command(
        sonic_db_cli + ' ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY*"')["stdout"]
    for key in keys.splitlines():
        key = key.strip()
        if not key:
            continue
        attributes = duthost.command(
            "{} ASIC_DB HGETALL '{}'".format(sonic_db_cli, key), module_ignore_errors=True)["stdout"]
        entries[_normalize_asic_db_mysid_key(key)] = attributes
    return entries


def verify_static_route_installed(duthost, prefix, nexthop=None, ifname=None, blackhole=False,
                                  sonic_db_cli="sonic-db-cli", cli_options=""):
    """
    Verify that a static route is installed all the way down to the ASIC.

    The static routes used for SRv6 forwarding are configured in CONFIG_DB and
    are never redistributed into BGP, so they cannot be verified from a BGP
    neighbor. They are instead checked on the box, stage by stage, so that a
    failure tells which component did not program the route:
    FRR RIB -> kernel -> APPL_DB -> ASIC_DB.

    Args:
        duthost: DUT host object
        prefix: the route prefix, e.g. fcbb:bbbb:2::/48
        nexthop: expected next hop address, checked when given
        ifname: expected egress interface, checked when given
        blackhole: True when the route is expected to be a blackhole route
        sonic_db_cli: sonic-db-cli command, including the namespace options
        cli_options: namespace options for vtysh

    Returns:
        bool: True when the route is installed everywhere it is expected to be
    """
    # 1. FRR RIB
    frr_route = duthost.command(
        'vtysh{} -c "show ipv6 route {} json"'.format(cli_options, prefix),
        module_ignore_errors=True)["stdout"]
    try:
        frr_routes = json.loads(frr_route) if frr_route.strip() else {}
    except ValueError:
        logger.error("Unable to parse the FRR route entry for {}: {}".format(prefix, frr_route))
        return False

    frr_entries = []
    for route_entries in frr_routes.values():
        frr_entries.extend(route_entries)
    static_entries = [entry for entry in frr_entries if entry.get('protocol') == 'static']
    if not static_entries:
        logger.error("Static route {} is missing from the FRR RIB".format(prefix))
        return False
    if not any(entry.get('selected') or entry.get('installed') for entry in static_entries):
        logger.error("Static route {} is in the FRR RIB but is not selected nor installed".format(prefix))
        return False

    # 2. Linux kernel
    kernel_route = duthost.command(
        "ip -6 route show {}".format(prefix), module_ignore_errors=True)["stdout"]
    if prefix.split('/')[0] not in kernel_route:
        logger.error("Static route {} is missing from the kernel routing table".format(prefix))
        return False
    if blackhole and "blackhole" not in kernel_route:
        logger.error("Route {} is not a blackhole route in the kernel: {}".format(prefix, kernel_route))
        return False
    if nexthop and nexthop not in kernel_route:
        logger.error("Static route {} does not use next hop {} in the kernel: {}".format(
            prefix, nexthop, kernel_route))
        return False
    if ifname and ifname not in kernel_route:
        logger.error("Static route {} does not use interface {} in the kernel: {}".format(
            prefix, ifname, kernel_route))
        return False

    # 3. APPL_DB
    appl_db_route = duthost.command(
        "{} APPL_DB HGETALL 'ROUTE_TABLE:{}'".format(sonic_db_cli, prefix),
        module_ignore_errors=True)["stdout"]
    if not appl_db_route.strip():
        logger.error("Static route {} is missing from APPL_DB".format(prefix))
        return False
    if blackhole and "true" not in appl_db_route.lower():
        logger.error("Route {} is not marked as blackhole in APPL_DB: {}".format(prefix, appl_db_route))
        return False
    if nexthop and nexthop not in appl_db_route:
        logger.error("Static route {} does not use next hop {} in APPL_DB: {}".format(
            prefix, nexthop, appl_db_route))
        return False

    # 4. ASIC_DB
    asic_db_route = duthost.command(
        '{} ASIC_DB KEYS "*SAI_OBJECT_TYPE_ROUTE_ENTRY*{}*"'.format(sonic_db_cli, prefix),
        module_ignore_errors=True)["stdout"]
    if not asic_db_route.strip():
        logger.error("Static route {} is missing from ASIC_DB".format(prefix))
        return False

    logger.info("Static route {} is installed in the FRR RIB, the kernel, APPL_DB and ASIC_DB".format(prefix))
    return True


def verify_reboot_cause_warm(duthost):
    """
    Verify that the last reboot was a warm reboot.

    A warm reboot which silently degraded into a cold one would make any hitless
    expectation meaningless, so this is checked explicitly.
    """
    reboot_cause = duthost.command("show reboot-cause")["stdout"]
    logger.info("Reboot cause: {}".format(reboot_cause))
    return "warm-reboot" in reboot_cause


def collect_warmboot_diagnostics(duthost, sonic_db_cli="sonic-db-cli"):
    """Collect the warm restart state, to be called when a warm boot test fails."""
    commands = [
        "show reboot-cause",
        "show warm_restart state",
        "show warm_restart config",
        '{} STATE_DB KEYS "WARM_RESTART_TABLE|*"'.format(sonic_db_cli),
        '{} STATE_DB KEYS "WARM_RESTART_ENABLE_TABLE|*"'.format(sonic_db_cli),
    ]
    for command in commands:
        output = duthost.command(command, module_ignore_errors=True)["stdout"]
        logger.info("=== {} ===\n{}".format(command, output))


def run_srv6_no_sid_blackhole_test(setup_uN, ptfadapter, ptfhost, with_srh):
    """
    Verify that packets sent to a SID which is not programmed are dropped.

    The drop relies on the fcbb:bbbb::/32 blackhole static route, so this also
    covers the persistence of that route across a disruption.
    """
    duthost = setup_uN['duthost']
    dut_mac = setup_uN['dut_mac']
    dut_port = setup_uN['dut_port']
    ptf_src_ports = setup_uN['ptf_src_ports']
    neighbor_ip = setup_uN['neighbor_ip']
    ptf_port_ids = setup_uN['ptf_port_ids']

    # Use the first port to send traffic
    first_ptf_port = ptf_src_ports[0] if isinstance(ptf_src_ports, list) else ptf_src_ports
    device, port = ptfadapter.dataplane.port_to_tuple(first_ptf_port)
    ptfhost = ptfadapter.ptfhosts[device]
    src_mac = ptfadapter.dataplane.get_mac(device, port).decode()
    ports_by_device = defaultdict(list)
    for ptf_port in ptf_port_ids:
        port_device, port_id = ptfadapter.dataplane.port_to_tuple(ptf_port)
        ports_by_device[port_device].append(port_id)

    # Verify that the ASIC DB has the SRv6 SID entries
    sonic_db_cli = "sonic-db-cli" + setup_uN['cli_options']
    assert wait_until(20, 5, 0, verify_asic_db_sid_entry_exist, duthost, sonic_db_cli), \
        "ASIC_STATE:SAI_OBJECT_TYPE_MY_SID_ENTRY entries are missing in ASIC_DB before blackhole test"

    # get the drop counter before traffic test
    if duthost.facts["asic_type"] == "broadcom":
        portstat = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])
        before_count = int(portstat[dut_port]['rx_drp'])
    elif duthost.facts["asic_type"] == "mellanox":
        before_count = int(duthost.command(f"show interfaces counters rif {dut_port}")['stdout_lines'][6].split()[0])
    else:
        pytest.skip("Blackhole drop counter check is not supported for asic_type {}".format(
            duthost.facts["asic_type"]))

    # inject a number of packets with random payload
    pkt_count = 100
    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    if with_srh:
        injected_pkt = simple_ipv6_sr_packet(
            eth_dst=dut_mac,
            eth_src=src_mac,
            ipv6_src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1",
            ipv6_dst="fcbb:bbbb:3:2::",
            srh_seg_left=1,
            srh_nh=41,
            inner_frame=IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1") / UDP(
                dport=4791) / Raw(load=payload)
        )
    else:
        injected_pkt = Ether(dst=dut_mac, src=src_mac) \
                       / IPv6(src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1", dst="fcbb:bbbb:3:2::") \
                       / IPv6(dst=neighbor_ip, src=ptfhost.mgmt_ipv6 if ptfhost.mgmt_ipv6 else "1000::1") \
                       / UDP(dport=4791) / Raw(load=payload)

    expected_pkt = injected_pkt.copy()
    expected_pkt['IPv6'].dst = "fcbb:bbbb:3:2::"
    expected_pkt['IPv6'].hlim -= 1
    logger.debug("Expected packet: {}".format(expected_pkt.summary()))

    expected_pkt = Mask(expected_pkt)
    expected_pkt.set_do_not_care_packet(Ether, "dst")
    expected_pkt.set_do_not_care_packet(Ether, "src")
    testutils.send(ptfadapter, (device, port), injected_pkt, count=pkt_count)
    for port_device, ports in ports_by_device.items():
        verify_no_packet_any(ptfadapter, expected_pkt, ports, device_number=port_device, timeout=1)

    # verify that the RX_DROP counter is incremented
    if duthost.facts["asic_type"] == "broadcom":
        portstat = parse_portstat(duthost.command(f'portstat -i {dut_port}')['stdout_lines'])
        after_count = int(portstat[dut_port]['rx_drp'])
        assert after_count >= (before_count + pkt_count), "RX_DRP counter is not incremented as expected"
    elif duthost.facts["asic_type"] == "mellanox":
        after_count = int(duthost.command(f"show interfaces counters rif {dut_port}")['stdout_lines'][6].split()[0])
        assert after_count >= (before_count + pkt_count), "RIF RX_ERR counter is not incremented as expected"



# --- PIC Convergence Test Helpers ---

def apply_config_cmmds_to_vtysh(nbrhost, cmd_list):
    """Apply a list of vtysh configuration-mode commands to a device in one RPC.

    Builds a single vtysh invocation with 'configure terminal' followed by
    each command as a -c argument, so all commands are applied in one SSH
    round-trip instead of N separate calls.

    Args:
        nbrhost: The device node (duthost or nbrhost) to apply commands on
        cmd_list: List of strings, each a vtysh config-mode command
    """
    if not cmd_list:
        return
    args = "-c 'configure terminal'"
    for input_cmd in cmd_list:
        args += " -c '{}'".format(input_cmd)
    nbrhost.command("vtysh {}".format(args))


def collect_db_entries(duthost, testcase_name, db_name, collecting_prefix):
    # 1. Determine Redis credentials
    if db_name == "appdb":
        db_num, port = 0, 6379
    elif db_name == "appstatedb":
        db_num, port = 14, 6379
    else:
        logger.error(f"Invalid db_name {db_name}")
        return

    # 2. Prepare script content — uses a single python3 invocation to dump
    #    all matching Redis hash keys to JSON, avoiding per-field jq subprocesses.
    script_content = r"""#!/bin/bash
DB_NUM="$1"; PORT="$2"; PREFIX="$3"; OUTFILE="$4"
python3 -c "
import redis, json, sys
r = redis.Redis(host='127.0.0.1', port=int(sys.argv[2]), db=int(sys.argv[1]), decode_responses=True)
keys = sorted(r.keys(sys.argv[3] + ':*'))
out = {}
for k in keys:
    out[k] = r.hgetall(k)
with open(sys.argv[4], 'w') as f:
    json.dump(out, f, indent=2)
" "$DB_NUM" "$PORT" "$PREFIX" "$OUTFILE"
"""

    # 3. Encode script as base64 to bypass Jinja2 templating entirely
    script_b64 = base64.b64encode(script_content.encode('utf-8')).decode('ascii')

    script_path = "/tmp/collect_redis.sh"
    out_path = f"{test_log_dir}/{testcase_name}_{collecting_prefix}.json"

    # Write script using base64 (bypasses Jinja2)
    duthost.shell(f"echo '{script_b64}' | base64 -d > {script_path}")
    duthost.command(f"chmod +x {script_path}")

    # Run with extended timeout in case of large datasets
    duthost.command(f"{script_path} {db_num} {port} '{collecting_prefix}' {out_path}")


def collect_vtysh_route_snapshot(duthost, snapshot_name):
    """Run vtysh route/nexthop show commands and save output to a file in one RPC.

    Each command's output is preceded by a header line showing the command,
    making the output file easy to read. All commands run in a single shell
    invocation to minimize SSH round-trips.

    Args:
        duthost: DUT host object
        snapshot_name: name prefix for the output file
    """
    outfile = "{}/{}_snapshot.txt".format(test_log_dir, snapshot_name)
    vtysh_cmds = [
        "show bgp sum",
        "show ip route vrf Vrf1 192.100.0.1 nexthop",
        "show ipv6 route nexthop",
        "show ip route vrf Vrf1 nexthop",
        "show next rib",
    ]
    script_lines = []
    for i, vcmd in enumerate(vtysh_cmds):
        redir = ">" if i == 0 else ">>"
        script_lines.append("echo '=== {} ===' {} {}".format(vcmd, redir, outfile))
        script_lines.append("vtysh -c '{}' >> {}".format(vcmd, outfile))
    cmd = " && ".join(script_lines)
    duthost.shell(cmd, module_ignore_errors=True)


def start_record_collection(duthost, testcase_name):
    """Capture a 'before' snapshot, then start tailing swss.rec/fpmsync.rec/syslog on DUT.

    Snapshot DB/route state is collected first so the subsequent tail processes
    only capture events triggered by the test action itself, not by the
    snapshot collection commands.
    """
    duthost.command("mkdir -p {}".format(test_log_dir))

    # 1. Collect "before" snapshot first (DB entries + vtysh route dumps).
    before_name = testcase_name + "_before"
    collect_db_entries(duthost, before_name, "appdb", "NEXTHOP_GROUP_TABLE")
    collect_db_entries(duthost, before_name, "appstatedb", "NHG_FULL_STATE_TABLE")
    collect_vtysh_route_snapshot(duthost, before_name)

    # 2. Now start the background tails so only post-trigger events are captured.
    for rec in ["swss.rec", "fpmsync.rec"]:
        prefix = rec.replace(".rec", "")
        outfile = "{}/{}_{}.rec".format(test_log_dir, prefix, testcase_name)
        duthost.command(
            "setsid sh -c 'tail -f /var/log/swss/{} > {} 2>&1 &' </dev/null >/dev/null 2>&1".format(rec, outfile)
        )

    for rec in ["syslog"]:
        outfile = "{}/{}_{}".format(test_log_dir, rec, testcase_name)
        duthost.command(
            "setsid sh -c 'tail -f /var/log/{} > {} 2>&1 &' </dev/null >/dev/null 2>&1".format(rec, outfile)
        )


def stop_record_collection(duthost, testcase_name):
    """Stop record collection and copy files to test_log_dir .

    Kills tail processes and archives captured records.
    """
    duthost.command("pkill -f 'tail -f /var/log/swss'", module_ignore_errors=True)
    duthost.command("pkill -f 'tail -f /var/log/'", module_ignore_errors=True)
    testcase_name = testcase_name + "_after"
    collect_db_entries(duthost, testcase_name, "appdb", "NEXTHOP_GROUP_TABLE")
    collect_db_entries(duthost, testcase_name, "appstatedb", "NHG_FULL_STATE_TABLE")
    collect_vtysh_route_snapshot(duthost, testcase_name)

def assert_appdb_nexthop_removed(duthost, nexthop, timeout=10, poll_interval=1):
    """Poll APP_DB until nexthop is absent from all forwarding entries.

    Both NHG objects and routes can carry a nexthop directly (a route with a
    single surviving path does not get an NHG object), so both tables are
    checked. NHGs that are skipped:
    1. Gateway NHGs for the given nexthop (gate field matches), or
    2. SRv6 NHGs (any recursive depends has non-null nh_srv6).

    Runs a single python3 script on DUT per poll iteration (one RPC call).
    """
    # Self-contained python3 script that runs locally on the DUT.
    # Takes nexthop as argument.
    # Prints "found:<key>" if nexthop is still present in a non-skipped NHG,
    # or "not_found" if nexthop is absent from all relevant NHGs.
    check_script = r"""#!/usr/bin/env python3
import redis, json, sys

def get_nhg_json(r_state, rib_id):
    raw = r_state.hget('NHG_FULL_STATE_TABLE:{}'.format(rib_id), 'json')
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, KeyError):
        return None

def find_rib_id_by_sonic_nhg_id(r_state, sonic_nhg_id):
    keys = r_state.keys('NHG_FULL_STATE_TABLE:*')
    for key in keys:
        if isinstance(key, bytes):
            key = key.decode()
        entry_sonic_id = r_state.hget(key, 'sonic_nhg_id')
        if entry_sonic_id:
            if isinstance(entry_sonic_id, bytes):
                entry_sonic_id = entry_sonic_id.decode()
            if entry_sonic_id.strip() == sonic_nhg_id:
                return key.replace('NHG_FULL_STATE_TABLE:', '')
    return None

def any_nh_srv6_present(r_state, rib_id, visited=None):
    if visited is None:
        visited = set()
    if rib_id in visited:
        return False
    visited.add(rib_id)
    nhg_data = get_nhg_json(r_state, rib_id)
    if nhg_data is None:
        return False
    if nhg_data.get('nh_srv6') is not None:
        return True
    depends_raw = r_state.hget('NHG_FULL_STATE_TABLE:{}'.format(rib_id), 'depends')
    if depends_raw:
        if isinstance(depends_raw, bytes):
            depends_raw = depends_raw.decode()
        try:
            depends = json.loads(depends_raw)
        except (ValueError, KeyError):
            depends = []
        for dep_id in depends:
            if any_nh_srv6_present(r_state, str(dep_id), visited):
                return True
    return False

def should_skip(r_state, sonic_nhg_id, nexthop):
    rib_id = find_rib_id_by_sonic_nhg_id(r_state, sonic_nhg_id)
    if rib_id is None:
        return False
    nhg_data = get_nhg_json(r_state, rib_id)
    if nhg_data is None:
        return False
    # Case 1: Gateway NHG
    gate = nhg_data.get('gate', '')
    if gate == nexthop:
        return True
    # Case 2: SRv6 NHG
    if any_nh_srv6_present(r_state, rib_id):
        return True
    return False

def uses_nexthop(value, nexthop):
    return any(part.strip() == nexthop for part in value.split(','))

def main():
    nexthop = sys.argv[1]
    r_app = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True)
    r_state = redis.Redis(host='127.0.0.1', port=6379, db=14, decode_responses=False)

    keys = r_app.keys('NEXTHOP_GROUP_TABLE:*')
    for key in keys:
        nh_value = r_app.hget(key, 'nexthop') or ''
        if uses_nexthop(nh_value, nexthop):
            sonic_nhg_id = key.replace('NEXTHOP_GROUP_TABLE:', '')
            if should_skip(r_state, sonic_nhg_id, nexthop):
                continue
            print('found:{}'.format(key))
            return

    # A route with a single path carries the nexthop directly.
    keys = r_app.keys('ROUTE_TABLE:*')
    for key in keys:
        nh_value = r_app.hget(key, 'nexthop') or ''
        if uses_nexthop(nh_value, nexthop):
            print('found:{}'.format(key))
            return
    print('not_found')

if __name__ == '__main__':
    main()
"""

    # Push script to DUT once
    script_b64 = base64.b64encode(check_script.encode('utf-8')).decode('ascii')
    script_path = "/tmp/check_nhg_removed.py"
    duthost.shell("echo '{}' | base64 -d > {}".format(script_b64, script_path))
    duthost.command("chmod +x {}".format(script_path))

    deadline = time.time() + timeout
    last_found_key = ""
    while time.time() < deadline:
        # Single RPC call per poll iteration
        check_result = duthost.command(
            "python3 {} '{}'".format(script_path, nexthop),
            module_ignore_errors=True)
        output = check_result.get('stdout', '').strip()
        if output == 'not_found':
            return  # success
        # Still found — extract key for error reporting
        if output.startswith('found:'):
            last_found_key = output[len('found:'):]
        time.sleep(poll_interval)

    logger.error("Fail in assert_appdb_nexthop_removed, nexthop '{}' still in {}".format(
        nexthop, last_found_key))
    pytest_assert(False, "Nexthop '{}' still present in APPDB after {}s".format(nexthop, timeout))


def assert_appdb_nexthop_present(duthost, nexthop):
    """Assert nexthop is used by at least one APP_DB forwarding entry.

    A nexthop can be carried by an NHG object (multi-path) or directly by a
    route (single surviving path), so both tables are checked.
    """
    check_script = r"""#!/usr/bin/env python3
import redis, sys

def uses_nexthop(value, nexthop):
    return any(part.strip() == nexthop for part in value.split(','))

def main():
    nexthop = sys.argv[1]
    r_app = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True)
    for pattern in ('NEXTHOP_GROUP_TABLE:*', 'ROUTE_TABLE:*'):
        keys = r_app.keys(pattern)
        for key in keys:
            nh_value = r_app.hget(key, 'nexthop') or ''
            if uses_nexthop(nh_value, nexthop):
                print('found:{}'.format(key))
                return
    print('not_found')

if __name__ == '__main__':
    main()
"""
    script_b64 = base64.b64encode(check_script.encode('utf-8')).decode('ascii')
    script_path = "/tmp/check_nhg_present.py"
    duthost.shell("echo '{}' | base64 -d > {}".format(script_b64, script_path))

    result = duthost.command(
        "python3 {} '{}'".format(script_path, nexthop),
        module_ignore_errors=True)
    output = result.get('stdout', '').strip()
    if output.startswith('found:'):
        return  # success
    pytest_assert(False, "Nexthop '{}' not found in any APPDB NHG entry".format(nexthop))


def _extract_sonic_nhg_id_from_rec_line(line):
    """Extract sonic NHG ID from a rec file line like '...|NEXTHOP_GROUP_TABLE:5|SET|...'"""
    match = re.search(r'NEXTHOP_GROUP_TABLE:(\d+)', line)
    if match:
        return match.group(1)
    return None


def _is_skipable_nhg(duthost, sonic_nhg_id):
    """Check if a sonic NHG ID should be skipped in ordering violation checks.

    Returns True if the NHG's RIB entry has SRv6 info in its depends (zebra
    convergence update) or if the RIB ID is pending deletion. Both are
    legitimate and should not be flagged as PIC ordering violations.
    """
    check_script = """\
import redis, json, sys, subprocess

def get_nhg_json(r_state, rib_id):
    raw = r_state.hget('NHG_FULL_STATE_TABLE:{}'.format(rib_id), 'json')
    if not raw:
        return None
    try:
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)
    except (ValueError, KeyError):
        return None

def find_rib_id_by_sonic_nhg_id(r_state, sonic_nhg_id):
    keys = r_state.keys('NHG_FULL_STATE_TABLE:*')
    for key in keys:
        if isinstance(key, bytes):
            key = key.decode()
        entry_sonic_id = r_state.hget(key, 'sonic_nhg_id')
        if entry_sonic_id:
            if isinstance(entry_sonic_id, bytes):
                entry_sonic_id = entry_sonic_id.decode()
            if entry_sonic_id.strip() == sonic_nhg_id:
                return key.replace('NHG_FULL_STATE_TABLE:', '')
    return None

def any_nh_srv6_present(r_state, rib_id, visited=None):
    if visited is None:
        visited = set()
    if rib_id in visited:
        return False
    visited.add(rib_id)
    nhg_data = get_nhg_json(r_state, rib_id)
    if nhg_data is None:
        return False
    if nhg_data.get('nh_srv6') is not None:
        return True
    depends_raw = r_state.hget('NHG_FULL_STATE_TABLE:{}'.format(rib_id), 'depends')
    if depends_raw:
        if isinstance(depends_raw, bytes):
            depends_raw = depends_raw.decode()
        try:
            depends = json.loads(depends_raw)
        except (ValueError, KeyError):
            depends = []
        for dep_id in depends:
            if any_nh_srv6_present(r_state, str(dep_id), visited):
                return True
    return False

def has_time_to_deletion(rib_id):
    try:
        out = subprocess.check_output(
            ['vtysh', '-c', 'show nexthop rib {}'.format(rib_id)],
            stderr=subprocess.STDOUT)
        if isinstance(out, bytes):
            out = out.decode()
        return 'Time to Deletion' in out
    except subprocess.CalledProcessError:
        return False

sonic_nhg_id = sys.argv[1]
r_state = redis.Redis(host='127.0.0.1', port=6379, db=14, decode_responses=False)
rib_id = find_rib_id_by_sonic_nhg_id(r_state, sonic_nhg_id)
if rib_id is None:
    print('no_rib_id')
    sys.exit(0)
if any_nh_srv6_present(r_state, rib_id):
    print('skip')
elif has_time_to_deletion(rib_id):
    print('skip')
else:
    print('not_skip')
"""
    script_path = "/tmp/check_srv6_nhg.py"
    script_b64 = base64.b64encode(check_script.encode('utf-8')).decode('ascii')
    duthost.shell("echo '{}' | base64 -d > {}".format(script_b64, script_path))

    result = duthost.command(
        "python3 {} '{}'".format(script_path, sonic_nhg_id),
        module_ignore_errors=True)
    output = result.get('stdout', '').strip()
    return output == 'skip'


def verify_nhg_before_routes(duthost, testcase_name, trigger_nexthop, trigger_ts=None):
    """Assert all NEXTHOP_GROUP_TABLE updates happen before ROUTE_TABLE after trigger.

    After the NEIGH_TABLE DEL line for trigger_nexthop, verifies that no
    ROUTE_TABLE entry appears before all NEXTHOP_GROUP_TABLE entries have
    been written. This confirms PIC fast-path pushes NHG updates before
    RIB reconvergence route updates.

    NEXTHOP_GROUP_TABLE updates caused by zebra convergence (where the NHG's
    RIB ID has SRv6 info in its depends) are excluded from violation checks.

    ROUTE_TABLE entries with "protocol:kernel" (e.g. loopback routes) are
    skipped since they are not part of the BGP/zebra reconvergence ordering.

    When trigger_ts is provided, only lines within a 5-second window
    [trigger_ts, trigger_ts + 5s] are checked. Lines outside this window
    are not part of the PIC fast-path convergence event.

    Args:
        duthost: DUT host object
        testcase_name: test case name (matches swss_{name}.rec)
        trigger_nexthop: the nexthop address whose NEIGH_TABLE DEL is the trigger
        trigger_ts: datetime of the exceptional trigger; only lines within
                    [trigger_ts, trigger_ts + 5s] are checked. Capture with
                    get_dut_timestamp() immediately before firing the trigger.
                    Optional — if None, all lines are checked.
    """
    rec_file = "{}/swss_{}.rec".format(test_log_dir, testcase_name)
    content = duthost.command("cat {}".format(rec_file), module_ignore_errors=True)
    lines = content.get('stdout', '').split('\n')

    # Filter to only the [trigger_ts, trigger_ts + 5s] window
    if trigger_ts is not None:
        window_end = trigger_ts + datetime.timedelta(seconds=5)
        filtered = []
        for line in lines:
            line_ts = _parse_rec_timestamp(line)
            if line_ts is None:
                continue
            if line_ts >= trigger_ts and line_ts <= window_end:
                filtered.append(line)
        lines = filtered

    # Find the trigger line: NEIGH_TABLE:*:<nexthop>|DEL
    trigger_pattern = "NEIGH_TABLE:"
    trigger_suffix = ":{}|DEL".format(trigger_nexthop)
    trigger_idx = None
    for i, line in enumerate(lines):
        if trigger_pattern in line and trigger_suffix in line:
            trigger_idx = i
            break

    pytest_assert(trigger_idx is not None,
                  "Trigger line NEIGH_TABLE DEL for {} not found in {}".format(
                      trigger_nexthop, rec_file))

    # After trigger, check ordering: all NHG updates must come before any ROUTE_TABLE
    saw_route = False
    first_route_line = ""
    violating_nhg_line = ""
    nhg_ids_seen_before_route = set()

    for line in lines[trigger_idx + 1:]:
        if not line.strip():
            continue
        if "ROUTE_TABLE:" in line:
            # Skip kernel-protocol routes (e.g. loopback) — not part of
            # BGP/zebra reconvergence ordering
            if "protocol:kernel" in line:
                continue
            if not saw_route:
                saw_route = True
                first_route_line = line
        elif "NEXTHOP_GROUP_TABLE:" in line:
            if "|SET|" not in line:
                continue
            sonic_nhg_id = _extract_sonic_nhg_id_from_rec_line(line)
            if not saw_route:
                if sonic_nhg_id:
                    nhg_ids_seen_before_route.add(sonic_nhg_id)
            else:
                # Skip NHG updates that don't reference the failed nexthop.
                if trigger_nexthop not in line:
                    continue
                # Skip NHGs already updated in the initial PIC fast-path block.
                # Their later update is zebra convergence catching up.
                if sonic_nhg_id and sonic_nhg_id in nhg_ids_seen_before_route:
                    continue
                # Check if this NHG update is due to zebra convergence (SRv6 depends)
                if sonic_nhg_id and _is_skipable_nhg(duthost, sonic_nhg_id):
                    continue
                violating_nhg_line = line
                break

    pytest_assert(not violating_nhg_line,
                  "NEXTHOP_GROUP_TABLE update found after ROUTE_TABLE update. "
                  "First ROUTE_TABLE: '{}' | Violating NHG: '{}'".format(
                      first_route_line, violating_nhg_line))


def get_dut_timestamp(duthost):
    """Return the current DUT time as a datetime object (one RPC call).

    Uses the same microsecond precision as swss rec file timestamps so the
    returned value can be compared directly against parsed rec line timestamps.
    """
    result = duthost.command("date +%Y-%m-%d.%H:%M:%S.%6N", module_ignore_errors=True)
    ts_str = result.get('stdout', '').strip()
    try:
        return datetime.datetime.strptime(ts_str, "%Y-%m-%d.%H:%M:%S.%f")
    except ValueError:
        return None


def _parse_rec_timestamp(line):
    """Extract the timestamp from a swss rec line as a datetime object.

    Rec line format: YYYY-MM-DD.HH:MM:SS.ffffff|<rest>
    Returns None if the line doesn't start with a recognizable timestamp.
    """
    match = re.match(r'^(\d{4}-\d{2}-\d{2}\.\d{2}:\d{2}:\d{2}\.\d+)', line)
    if not match:
        return None
    try:
        return datetime.datetime.strptime(match.group(1), "%Y-%m-%d.%H:%M:%S.%f")
    except ValueError:
        return None


def verify_no_nhg_update(duthost, testcase_name, trigger_ts=None):
    """Assert no unexpected NEXTHOP_GROUP_TABLE SET operation in the swss record file.

    Used in BGP remote failure tests where route withdrawal should result in
    only ROUTE_TABLE updates (2 paths to 1 path), with no NHG changes pushed
    to hardware.

    A NEXTHOP_GROUP_TABLE entry is NOT flagged as a violation when:
      - its timestamp is outside the [trigger_ts, trigger_ts + 5s] window
        (not caused by the test action)
      - it is a DEL (deletion) rather than a SET
      - the NHG's RIB entry has SRv6 info in its depends (legitimate zebra
        convergence update), or its RIB ID is pending deletion. This is the
        same skip logic used by _is_skipable_nhg().

    When trigger_ts is provided, only lines within a 5-second window
    [trigger_ts, trigger_ts + 5s] are checked. Lines outside this window
    are not part of the test-triggered convergence event.

    Args:
        duthost: DUT host object
        testcase_name: test case name (matches swss_{name}.rec)
        trigger_ts: datetime of the exceptional trigger; only lines within
                    [trigger_ts, trigger_ts + 5s] are checked. Capture with
                    get_dut_timestamp() immediately before firing the trigger.
                    Optional — if None, all lines are checked.
    """
    rec_file = "{}/swss_{}.rec".format(test_log_dir, testcase_name)
    content = duthost.command("cat {}".format(rec_file), module_ignore_errors=True)
    lines = content.get('stdout', '').split('\n')

    for line in lines:
        if "NEXTHOP_GROUP_TABLE:" not in line:
            continue
        # Skip lines outside the [trigger_ts, trigger_ts + 5s] window
        if trigger_ts is not None:
            line_ts = _parse_rec_timestamp(line)
            if line_ts is not None:
                window_end = trigger_ts + datetime.timedelta(seconds=5)
                if line_ts < trigger_ts or line_ts > window_end:
                    continue
        # Skip deletions — only SETs push NHG changes to hardware
        if "|SET|" not in line:
            continue
        # Skip SRv6-depends NHGs and NHGs whose RIB entry is pending deletion
        sonic_nhg_id = _extract_sonic_nhg_id_from_rec_line(line)
        if sonic_nhg_id and _is_skipable_nhg(duthost, sonic_nhg_id):
            continue
        pytest_assert(False,
                      "Unexpected NEXTHOP_GROUP_TABLE SET found in {}: {}".format(
                          rec_file, line))


def verify_pic_nhg_switch(duthost, testcase_name, backup_nexthop, trigger_ts=None):
    """Verify PIC NHG switch: backup NHG has single nexthop and VRF routes are updated.

    Checks:
      1. A NEXTHOP_GROUP_TABLE SET exists with exactly one nexthop matching
         backup_nexthop.
      2. VRF route updates (ROUTE_TABLE:Vrf*) exist in the record.

    Args:
        duthost: DUT host object
        testcase_name: test case name (matches swss_{name}.rec)
        backup_nexthop: the remaining nexthop IP (e.g. "2064:200::1e")
        trigger_ts: optional datetime; only lines within [trigger_ts, trigger_ts + 5s]
                    are checked.
    """
    rec_file = "{}/swss_{}.rec".format(test_log_dir, testcase_name)
    content = duthost.command("cat {}".format(rec_file), module_ignore_errors=True)
    lines = content.get('stdout', '').split('\n')

    if trigger_ts is not None:
        window_end = trigger_ts + datetime.timedelta(seconds=5)
        filtered = []
        for line in lines:
            line_ts = _parse_rec_timestamp(line)
            if line_ts is None:
                continue
            if line_ts >= trigger_ts and line_ts <= window_end:
                filtered.append(line)
        lines = filtered

    # Step 1: Find NEXTHOP_GROUP_TABLE SET with single nexthop matching backup_nexthop
    found_backup_nhg = False
    for line in lines:
        if "NEXTHOP_GROUP_TABLE:" not in line or "|SET|" not in line:
            continue
        nh_match = re.search(r'\|nexthop:([^|]+)', line)
        if not nh_match:
            continue
        nexthops = nh_match.group(1).split(',')
        if len(nexthops) == 1 and nexthops[0].strip() == backup_nexthop:
            found_backup_nhg = True
            break

    pytest_assert(found_backup_nhg,
                  "No NEXTHOP_GROUP_TABLE SET with single nexthop '{}' found in {}".format(
                      backup_nexthop, rec_file))

    # Step 2: VRF route updates must exist in the record
    vrf_route_count = 0
    for line in lines:
        if not line.strip():
            continue
        if "ROUTE_TABLE:Vrf" not in line or "|SET|" not in line:
            continue
        vrf_route_count += 1

    pytest_assert(vrf_route_count > 0,
                  "No VRF route updates found in {}".format(rec_file))


def wait_for_vrf_route_recursive_paths(duthost, vrf, prefix, expected_nexthops,
                                       poll_interval=10, timeout=100,
                                       rekick_after=30, rekick_interval=60,
                                       max_rekicks=3,
                                       remote_host=None,
                                       remote_clear_target=None,
                                       remote_asn=64600,
                                       local_loopback=None):
    """Poll 'show ip route vrf <vrf> <prefix>' until all expected recursive nexthops appear.

    Args:
        duthost: host running vtysh
        vrf: VRF name (e.g. "Vrf1")
        prefix: route prefix (e.g. "192.100.0.1")
        expected_nexthops: list of recursive nexthop IPs that must all be present
        poll_interval: seconds between retries (switches to 30s after rekick phase starts)
        timeout: total seconds to wait before failing
        rekick_after: if a nexthop is still missing after this many seconds,
            issue `clear bgp <nh>` for that neighbor to reseed its FSM.
            Set to None to disable.
        rekick_interval: seconds between successive rekick attempts for the
            same neighbor.
        max_rekicks: maximum number of clear bgp attempts per nexthop.
            Once exhausted, stop retrying that nexthop (avoids endless loops
            when the remote BGP session is truly stuck).
        remote_host: optional remote peer host. When set, each rekick also
            issues `clear bgp <remote_clear_target>` on this host. Required
            for eBGP-multihop VPN sessions where the remote outgoing TCP
            socket can wedge in Connect/Active and a local-side clear alone
            cannot unstick it.
        remote_clear_target: BGP neighbor IP to clear on remote_host (e.g.
            the local DUT's loopback as seen by the remote peer). Ignored
            unless remote_host is also provided.
        remote_asn: ASN of the BGP instance on remote_host that owns the
            session toward remote_clear_target. Required because FRR rejects
            `router bgp` without an ASN when multiple BGP instances exist
            (e.g. default + VRF). Default 64600 matches PE1 in the SRv6
            sanity topology.
        local_loopback: local DUT IPv6 address as seen by remote_host (TCP
            destination for the wedged BGP session). When supplied, the
            third-tier escalation issues `ss -K dst <local_loopback>` on
            remote_host to forcibly close any half-open TCP socket that
            shutdown/no-shutdown could not clear.
    """
    cmd = "vtysh -c 'show ip route vrf {} {}'".format(vrf, prefix)
    start = time.time()
    deadline = start + timeout
    last_rekick_time = {}
    rekick_count = {}
    last_output = ""
    in_rekick_phase = False
    while True:
        result = duthost.command(cmd, module_ignore_errors=True)
        last_output = result.get('stdout', '')
        missing = [nh for nh in expected_nexthops if nh not in last_output]
        if not missing:
            return
        if (rekick_after is not None and
                time.time() - start >= rekick_after):
            in_rekick_phase = True
            now = time.time()
            for nh in missing:
                last_kick = last_rekick_time.get(nh, 0)
                if now - last_kick < rekick_interval:
                    continue
                if rekick_count.get(nh, 0) >= max_rekicks:
                    if remote_host is not None and remote_clear_target:
                        hard_reset_count = rekick_count.get(nh + '_hard', 0)
                        if hard_reset_count < 2:
                            rekick_count[nh + '_hard'] = hard_reset_count + 1
                            logging.info("wait_for_vrf_route_recursive_paths: "
                                         "max rekicks exhausted for %s; "
                                         "hard-resetting remote peer %s "
                                         "(shutdown/no shutdown asn=%s, attempt %d/2)",
                                         nh, remote_clear_target,
                                         remote_asn, hard_reset_count + 1)
                            shut = remote_host.command(
                                "vtysh -c 'configure terminal' "
                                "-c 'router bgp {}' "
                                "-c 'neighbor {} shutdown'".format(
                                    remote_asn, remote_clear_target),
                                module_ignore_errors=True)
                            if shut.get('rc', 0) != 0:
                                logging.warning(
                                    "wait_for_vrf_route_recursive_paths: "
                                    "remote shutdown failed rc=%s stdout=%r stderr=%r",
                                    shut.get('rc'), shut.get('stdout'),
                                    shut.get('stderr'))
                            time.sleep(3)
                            unshut = remote_host.command(
                                "vtysh -c 'configure terminal' "
                                "-c 'router bgp {}' "
                                "-c 'no neighbor {} shutdown'".format(
                                    remote_asn, remote_clear_target),
                                module_ignore_errors=True)
                            if unshut.get('rc', 0) != 0:
                                logging.warning(
                                    "wait_for_vrf_route_recursive_paths: "
                                    "remote no-shutdown failed rc=%s stdout=%r stderr=%r",
                                    unshut.get('rc'), unshut.get('stdout'),
                                    unshut.get('stderr'))
                            last_rekick_time[nh] = now
                        elif local_loopback and \
                                rekick_count.get(nh + '_tcp_kill', 0) < 1:
                            rekick_count[nh + '_tcp_kill'] = 1
                            logging.info("wait_for_vrf_route_recursive_paths: "
                                         "hard-resets exhausted for %s; "
                                         "force-closing wedged TCP socket on "
                                         "remote (ss -K dst %s)",
                                         nh, local_loopback)
                            remote_host.command(
                                "sudo ss -K dst {}".format(local_loopback),
                                module_ignore_errors=True)
                            last_rekick_time[nh] = now
                    continue
                underlay = duthost.command(
                    "vtysh -c 'show ipv6 route {}'".format(nh),
                    module_ignore_errors=True)
                underlay_out = underlay.get('stdout', '')
                if 'Known via' not in underlay_out:
                    logging.info("wait_for_vrf_route_recursive_paths: nexthop %s "
                                 "not yet reachable in underlay, skipping rekick",
                                 nh)
                    continue
                rekick_count[nh] = rekick_count.get(nh, 0) + 1
                logging.info("wait_for_vrf_route_recursive_paths: nexthop %s "
                             "reachable but VRF route still missing after %ds; "
                             "re-kicking peer with 'clear bgp %s' (attempt %d/%d)",
                             nh, int(now - start), nh, rekick_count[nh], max_rekicks)
                duthost.command("vtysh -c 'clear bgp {}'".format(nh),
                                module_ignore_errors=True)
                if remote_host is not None and remote_clear_target:
                    logging.info("wait_for_vrf_route_recursive_paths: also "
                                 "re-kicking remote peer with 'clear bgp %s'",
                                 remote_clear_target)
                    remote_host.command(
                        "vtysh -c 'clear bgp {}'".format(remote_clear_target),
                        module_ignore_errors=True)
                last_rekick_time[nh] = now
        if time.time() >= deadline:
            local_summary = duthost.command(
                "vtysh -c 'show bgp ipv6 unicast summary'",
                module_ignore_errors=True).get('stdout', '')
            remote_summary = ''
            if remote_host is not None:
                remote_summary = remote_host.command(
                    "vtysh -c 'show bgp ipv6 unicast summary'",
                    module_ignore_errors=True).get('stdout', '')
            pytest_assert(False,
                          "VRF {} route {} missing recursive nexthops {} after {}s. "
                          "Last route:\n{}\n--- local BGP summary ---\n{}\n"
                          "--- remote BGP summary ---\n{}".format(
                              vrf, prefix, missing, timeout,
                              last_output, local_summary, remote_summary))
        time.sleep(30 if in_rekick_phase else poll_interval)
