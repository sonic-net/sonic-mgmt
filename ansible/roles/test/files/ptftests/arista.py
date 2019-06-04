import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from ptf.dataplane import match_exp_pkt
import datetime
import _strptime  # workaround python bug ref: https://stackoverflow.com/a/22476843/2514803
import time
import subprocess
from ptf.mask import Mask
import socket
import ptf.packet as scapy
import thread
import threading
from multiprocessing.pool import ThreadPool, TimeoutError
import os
import signal
import random
import struct
import socket
from pprint import pprint
from fcntl import ioctl
import sys
import json
import re
from collections import defaultdict
import json
import paramiko
import Queue
import pickle
from operator import itemgetter
import scapy.all as scapyall
import enum

class Arista(object):
    DEBUG = False
    def __init__(self, ip, queue, test_params, login='admin', password='123456'):
        self.ip = ip
        self.queue = queue
        self.login = login
        self.password = password
        self.conn = None
        self.arista_prompt = None
        self.v4_routes = [test_params['vlan_ip_range'], test_params['lo_prefix']]
        self.v6_routes = [test_params['lo_v6_prefix']]
        self.fails = set()
        self.info = set()
        self.min_bgp_gr_timeout = int(test_params['min_bgp_gr_timeout'])

    def __del__(self):
        self.disconnect()

    def connect(self):
        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.conn.connect(self.ip, username=self.login, password=self.password, allow_agent=False, look_for_keys=False)
        self.shell = self.conn.invoke_shell()

        first_prompt = self.do_cmd(None, prompt = '>')
        self.arista_prompt = self.get_arista_prompt(first_prompt)

        self.do_cmd('enable')
        self.do_cmd('terminal length 0')

        return self.shell

    def get_arista_prompt(self, first_prompt):
        lines = first_prompt.split('\n')
        prompt = lines[-1]
        # match all modes - A#, A(config)#, A(config-if)#
        return prompt.strip().replace('>', '.*#')

    def do_cmd(self, cmd, prompt = None):
        if prompt == None:
            prompt = self.arista_prompt

        if cmd is not None:
            self.shell.send(cmd + '\n')

        input_buffer = ''
        while re.search(prompt, input_buffer) is None:
            input_buffer += self.shell.recv(16384)

        return input_buffer

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

        return

    def run(self):
        data = {}
        debug_data = {}
        run_once = False
        log_first_line = None
        quit_enabled = False
        v4_routing_ok = False
        v6_routing_ok = False
        routing_works = True
        self.connect()

        cur_time = time.time()
        sample = {}
        samples = {}
        portchannel_output = self.do_cmd("show interfaces po1 | json")
        portchannel_output = "\n".join(portchannel_output.split("\r\n")[1:-1])
        sample["po_changetime"] = json.loads(portchannel_output, strict=False)['interfaces']['Port-Channel1']['lastStatusChangeTimestamp']
        samples[cur_time] = sample

        while not (quit_enabled and v4_routing_ok and v6_routing_ok):
            cmd = self.queue.get()
            if cmd == 'quit':
                quit_enabled = True
                continue
            cur_time = time.time()
            info = {}
            debug_info = {}
            lacp_output = self.do_cmd('show lacp neighbor')
            info['lacp'] = self.parse_lacp(lacp_output)
            bgp_neig_output = self.do_cmd('show ip bgp neighbors')
            info['bgp_neig'] = self.parse_bgp_neighbor(bgp_neig_output)

            bgp_route_v4_output = self.do_cmd('show ip route bgp | json')
            v4_routing_ok = self.parse_bgp_route(bgp_route_v4_output, self.v4_routes)
            info['bgp_route_v4'] = v4_routing_ok

            bgp_route_v6_output = self.do_cmd("show ipv6 route bgp | json")
            v6_routing_ok = self.parse_bgp_route(bgp_route_v6_output, self.v6_routes)
            info["bgp_route_v6"] = v6_routing_ok

            portchannel_output = self.do_cmd("show interfaces po1 | json")
            portchannel_output = "\n".join(portchannel_output.split("\r\n")[1:-1])
            sample["po_changetime"] = json.loads(portchannel_output, strict=False)['interfaces']['Port-Channel1']['lastStatusChangeTimestamp']

            if not run_once:
                self.ipv4_gr_enabled, self.ipv6_gr_enabled, self.gr_timeout = self.parse_bgp_neighbor_once(bgp_neig_output)
                if self.gr_timeout is not None:
                    log_first_line = "session_begins_%f" % cur_time
                    self.do_cmd("send log message %s" % log_first_line)
                    run_once = True

            data[cur_time] = info
            samples[cur_time] = sample
            if self.DEBUG:
                debug_data[cur_time] = {
                    'show lacp neighbor' : lacp_output,
                    'show ip bgp neighbors' : bgp_neig_output,
                    'show ip route bgp' : bgp_route_v4_output,
                    'show ipv6 route bgp' : bgp_route_v6_output,
                }

        attempts = 60
        for _ in range(attempts):
            log_output = self.do_cmd("show log | begin %s" % log_first_line)
            log_lines = log_output.split("\r\n")[1:-1]
            log_data = self.parse_logs(log_lines)
            if len(log_data) != 0:
                break
            time.sleep(1) # wait until logs are populated

        if len(log_data) == 0:
            log_data['error'] = 'Incomplete output'

        self.disconnect()

        # save data for troubleshooting
        with open("/tmp/%s.data.pickle" % self.ip, "w") as fp:
            pickle.dump(data, fp)

        # save debug data for troubleshooting
        if self.DEBUG:
            with open("/tmp/%s.raw.pickle" % self.ip, "w") as fp:
                pickle.dump(debug_data, fp)
            with open("/tmp/%s.logging" % self.ip, "w") as fp:
                fp.write("\n".join(log_lines))

        self.check_gr_peer_status(data)
        cli_data = {}
        cli_data['lacp']   = self.check_series_status(data, "lacp",         "LACP session")
        cli_data['bgp_v4'] = self.check_series_status(data, "bgp_route_v4", "BGP v4 routes")
        cli_data['bgp_v6'] = self.check_series_status(data, "bgp_route_v6", "BGP v6 routes")
        cli_data['po']     = self.check_change_time(samples, "po_changetime", "PortChannel interface")

        route_timeout             = log_data['route_timeout']
        cli_data['route_timeout'] = route_timeout

        # {'10.0.0.38': [(0, '4200065100)')], 'fc00::2d': [(0, '4200065100)')]}
        for nei in route_timeout.keys():
            asn = route_timeout[nei][0][-1]
            msg = 'BGP route GR timeout: neighbor %s (ASN %s' % (nei, asn)
            self.fails.add(msg)

        return self.fails, self.info, cli_data, log_data

    def extract_from_logs(self, regexp, data):
        raw_data = []
        result = defaultdict(list)
        initial_time = -1
        re_compiled = re.compile(regexp)
        for line in data:
            m = re_compiled.match(line)
            if not m:
                continue
            raw_data.append((datetime.datetime.strptime(m.group(1), "%b %d %X"), m.group(2), m.group(3)))

        if len(raw_data) > 0:
            initial_time = raw_data[0][0]
            for when, what, status in raw_data:
                offset = (when - initial_time if when > initial_time else initial_time - when).seconds
                result[what].append((offset, status))

        return result, initial_time

    def parse_logs(self, data):
        result = {}
        bgp_r = r'^(\S+\s+\d+\s+\S+) \S+ Rib: %BGP-5-ADJCHANGE: peer (\S+) .+ (\S+)$'
        result_bgp, initial_time_bgp = self.extract_from_logs(bgp_r, data)
        if_r = r'^(\S+\s+\d+\s+\S+) \S+ Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface (\S+), changed state to (\S+)$'
        result_if, initial_time_if = self.extract_from_logs(if_r, data)

        route_r = r'^(\S+\s+\d+\s+\S+) \S+ Rib: %BGP-5-BGP_GRACEFUL_RESTART_TIMEOUT: Deleting stale routes from peer (\S+) .+ (\S+)$'
        result_rt, initial_time_rt = self.extract_from_logs(route_r, data)

        result['route_timeout'] = result_rt

        if initial_time_bgp == -1 or initial_time_if == -1:
            return result

        for events in result_bgp.values():
            if events[-1][1] != 'Established':
                return result

        # first state is Idle, last state is Established
        for events in result_bgp.values():
            if len(events) > 1:
                assert(events[0][1] != 'Established')

            assert(events[-1][1] == 'Established')

        # first state is down, last state is up
        for events in result_if.values():
            assert(events[0][1] == 'down')
            assert(events[-1][1] == 'up')

        po_name = [ifname for ifname in result_if.keys() if 'Port-Channel' in ifname][0]
        neigh_ipv4 = [neig_ip for neig_ip in result_bgp.keys() if '.' in neig_ip][0]

        result['PortChannel was down (seconds)'] = result_if[po_name][-1][0] - result_if[po_name][0][0]
        for if_name in sorted(result_if.keys()):
            result['Interface %s was down (times)' % if_name] = map(itemgetter(1), result_if[if_name]).count("down")

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was down (seconds)" if ':' in neig_ip else "BGP IPv4 was down (seconds)"
            result[key] = result_bgp[neig_ip][-1][0] - result_bgp[neig_ip][0][0]

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was down (times)" if ':' in neig_ip else "BGP IPv4 was down (times)"
            result[key] = map(itemgetter(1), result_bgp[neig_ip]).count("Idle")

        bgp_po_offset = (initial_time_if - initial_time_bgp if initial_time_if > initial_time_bgp else initial_time_bgp - initial_time_if).seconds
        result['PortChannel went down after bgp session was down (seconds)'] = bgp_po_offset + result_if[po_name][0][0]

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was gotten up after Po was up (seconds)" if ':' in neig_ip else "BGP IPv4 was gotten up after Po was up (seconds)"
            result[key] = result_bgp[neig_ip][-1][0] - bgp_po_offset - result_if[po_name][-1][0]

        return result

    def parse_lacp(self, output):
        return output.find('Bundled') != -1

    def parse_bgp_neighbor_once(self, output):
        is_gr_ipv4_enabled = False
        is_gr_ipv6_enabled = False
        restart_time = None
        for line in output.split('\n'):
            if '     Restart-time is' in line:
                restart_time = int(line.replace('       Restart-time is ', ''))
                continue

            if 'is enabled, Forwarding State is' in line:
                if 'IPv6' in line:
                    is_gr_ipv6_enabled = True
                elif 'IPv4' in line:
                    is_gr_ipv4_enabled = True

        return is_gr_ipv4_enabled, is_gr_ipv6_enabled, restart_time

    def parse_bgp_info(self, output):
        neigh_bgp = None
        dut_bgp = None
        asn = None
        for line in output.split('\n'):
            if 'BGP neighbor is' in line:
                dut_bgp = re.findall('BGP neighbor is (.*?),', line)[0]
            elif 'Local AS is' in line:
                asn = re.findall('Local AS is (\d+?),', line)[0]
            elif 'Local TCP address is' in line:
                neigh_bgp = re.findall('Local TCP address is (.*?),', line)[0]
                break

        return neigh_bgp, dut_bgp, asn

    def parse_bgp_neighbor(self, output):
        gr_active = None
        gr_timer = None
        for line in output.split('\n'):
            if 'Restart timer is' in line:
                gr_active = 'is active' in line
                gr_timer = str(line[-9:-1])

        return gr_active, gr_timer

    def parse_bgp_route(self, output, expects):
        prefixes = set()
        data = "\n".join(output.split("\r\n")[1:-1])
        obj = json.loads(data)

        if "vrfs" in obj and "default" in obj["vrfs"]:
            obj = obj["vrfs"]["default"]
        for prefix, attrs in obj["routes"].items():
            if "routeAction" not in attrs or attrs["routeAction"] != "forward":
                continue
            if all("Port-Channel" in via["interface"] for via in attrs["vias"]):
                prefixes.add(prefix)

        return set(expects) == prefixes

    def get_bgp_info(self):
        # Retreive BGP info (peer addr, AS) for the dut and neighbor
        neigh_bgp = {}
        dut_bgp = {}
        for cmd, ver in [('show ip bgp neighbors', 'v4'), ('show ipv6 bgp neighbors', 'v6')]:
            output = self.do_cmd(cmd)
            if ver == 'v6':
                neigh_bgp[ver], dut_bgp[ver], neigh_bgp['asn'] = self.parse_bgp_info(output)
            else:
                neigh_bgp[ver], dut_bgp[ver], neigh_bgp['asn'] = self.parse_bgp_info(output)

        return neigh_bgp, dut_bgp

    def change_bgp_neigh_state(self, asn, is_up=True):
        state = ['shut', 'no shut']
        self.do_cmd('configure')
        self.do_cmd('router bgp %s' % asn)
        self.do_cmd('%s' % state[is_up])
        self.do_cmd('exit')
        self.do_cmd('exit')

    def verify_bgp_neigh_state(self, dut=None, state="Active"):
        bgp_state = {}
        bgp_state['v4'] = bgp_state['v6'] = False
        for cmd, ver in [('show ip bgp summary | json', 'v4'), ('show ipv6 bgp summary | json', 'v6')]:
            output = self.do_cmd(cmd)
            data = '\n'.join(output.split('\r\n')[1:-1])
            obj = json.loads(data)

            if state != 'Active':
                if 'vrfs' in obj:
                    # return True when obj['vrfs'] is empty which is the case when the bgp state is 'down'
                    bgp_state[ver] = not obj['vrfs']
                else:
                    self.fails.add('Verify BGP %s neighbor: Object missing in output' % ver)
            else:
                if 'vrfs' in obj and 'default' in obj['vrfs']:
                    obj = obj['vrfs']['default']
                    if 'peers' in obj:
                        bgp_state[ver] = (obj['peers'][dut[ver]]['peerState'] == state)
                    else:
                        self.fails.add('Verify BGP %S neighbor: Peer attribute missing in output' % ver)
                else:
                    self.fails.add('Verify BGP %s neighbor: Object missing in output' % ver)
        return self.fails, bgp_state

    def check_gr_peer_status(self, output):
        # [0] True 'ipv4_gr_enabled', [1] doesn't matter 'ipv6_enabled', [2] should be >= 120
        if not self.ipv4_gr_enabled:
            self.fails.add("bgp ipv4 graceful restart is not enabled")
        if not self.ipv6_gr_enabled:
            pass # ToDo:
        if self.gr_timeout < 120: # bgp graceful restart timeout less then 120 seconds
            self.fails.add("bgp graceful restart timeout is less then 120 seconds")

        for when, other in sorted(output.items(), key = lambda x : x[0]):
            gr_active, timer = other['bgp_neig']
            # wnen it's False, it's ok, wnen it's True, check that inactivity timer not less then self.min_bgp_gr_timeout seconds
            if gr_active and datetime.datetime.strptime(timer, '%H:%M:%S') < datetime.datetime(1900, 1, 1, second = self.min_bgp_gr_timeout):
                self.fails.add("graceful restart timer is almost finished. Less then %d seconds left" % self.min_bgp_gr_timeout)

    def check_series_status(self, output, entity, what):
        # find how long anything was down
        # Input parameter is a dictionary when:status
        # constraints:
        # entity must be down just once
        # entity must be up when the test starts
        # entity must be up when the test stops

        sorted_keys = sorted(output.keys())
        if not output[sorted_keys[0]][entity]:
            self.fails.add("%s must be up when the test starts" % what)
            return 0, 0
        if not output[sorted_keys[-1]][entity]:
            self.fails.add("%s must be up when the test stops" % what)
            return 0, 0

        start = sorted_keys[0]
        cur_state = True
        res = defaultdict(list)
        for when in sorted_keys[1:]:
            if cur_state != output[when][entity]:
                res[cur_state].append(when - start)
                start = when
                cur_state = output[when][entity]
        res[cur_state].append(when - start)

        is_down_count = len(res[False])

        if is_down_count > 1:
            self.info.add("%s must be down just for once" % what)

        return is_down_count, sum(res[False]) # summary_downtime

    def check_change_time(self, output, entity, what):
        # find last changing time updated, if no update, the entity is never changed
        # Input parameter is a dictionary when:last_changing_time
        # constraints:
        # the dictionary `output` cannot be empty
        sorted_keys = sorted(output.keys())
        if not output:
            self.fails.add("%s cannot be empty" % what)
            return 0, 0

        start = sorted_keys[0]
        prev_time = output[start]
        change_count = 0
        for when in sorted_keys[1:]:
            if prev_time != output[when][entity]:
                prev_time = output[when][entity]
                change_count += 1

        if change_count > 0:
            self.info.add("%s state changed %d times" % (what, change_count))

        # Note: the first item is a placeholder
        return 0, change_count

