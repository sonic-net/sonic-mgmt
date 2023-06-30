import datetime
import time
import threading
import json
import re
from collections import defaultdict
import paramiko
import pickle
from operator import itemgetter
import scapy.all as scapyall
import ast
import socket

import host_device


class Sonic(host_device.HostDevice):
    DEBUG = False
    # unit: second
    SSH_CMD_TIMEOUT = 10

    def __init__(self, ip, queue, test_params, log_cb=None, login='admin', password='password'):
        self.ip = ip
        self.queue = queue
        self.log_cb = log_cb
        self.login = login
        self.password = password
        self.conn = None
        self.v4_routes = list(ast.literal_eval(test_params['vlan_ip_range']).values())
        self.v4_routes.append(test_params['lo_prefix'])
        self.v6_routes = [test_params['lo_v6_prefix']]
        self.fails = set()
        self.info = set()
        self.min_bgp_gr_timeout = int(test_params['min_bgp_gr_timeout'])
        self.reboot_type = test_params['reboot_type']
        self.bgp_v4_v6_time_diff = test_params['bgp_v4_v6_time_diff']
        self.port_channel_intf_idx = test_params['port_channel_intf_idx']
        self.port_channel_last_lacp_pdu_time = None
        self.port_channel_last_lacp_pdu_time_lock = threading.Lock()
        self.lacp_pdu_timings = list()

    def log(self, msg):
        if self.log_cb is not None:
            self.log_cb('SSH thread VM={}: {}'.format(self.ip, msg))

    def connect(self):
        if self.conn is None:
            self.conn = paramiko.SSHClient()
            self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.conn.connect(self.ip, username=self.login, password=self.password,
                              allow_agent=False, look_for_keys=False)

        self.show_lacp_command = self.parse_supported_show_lacp_command()
        self.show_ip_bgp_command = self.parse_supported_bgp_neighbor_command()
        self.show_ipv6_bgp_command = self.parse_supported_bgp_neighbor_command(v4=False)
        return self.conn

    def do_cmd(self, cmd):
        attempts = 0
        while attempts < 5:
            attempts += 1
            try:
                stdin, stdout, stderr = self.conn.exec_command(cmd, timeout=Sonic.SSH_CMD_TIMEOUT)
                return stdout.read()
            except socket.timeout:
                self.log("Timeout when running command: {}".format(cmd))
                return ""
            except paramiko.SSHException:
                # Possibly caused by https://github.com/paramiko/paramiko/issues/822
                # Disconnect and reconnect as a possible workaround?
                self.disconnect()
                self.connect()
        self.log("Unable to get the output of '{}' after {} attempts".format(cmd, attempts))
        return ""

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def lacp_packet_callback(self, pkt):
        with self.port_channel_last_lacp_pdu_time_lock:
            self.port_channel_last_lacp_pdu_time = time.time()

    def monitor_lacp_packets(self, intf_idx):
        scapyall.sniff(prn=self.lacp_packet_callback, iface="eth{}".format(intf_idx),
                       filter="ether proto 0x8809", store=0)

    def run(self):
        data = {}
        debug_data = {}
        quit_enabled = False
        v4_routing_ok = False
        v6_routing_ok = False
        self.connect()

        cur_time = time.time()
        start_time = time.time()
        self.collect_lacppdu_time = True

        for intf_idx in self.port_channel_intf_idx:
            lacp_thread = threading.Thread(target=self.monitor_lacp_packets, args=[intf_idx, ])
            lacp_thread.setDaemon(True)
            lacp_thread.start()

        # TODO: Disabling v6_routing_ok check due to IPv6 FRR issue. Re-add v6_routing_ok once either:
        # * https://github.com/FRRouting/frr/issues/13587 is fixed and the fix gets merged into SONiC, or
        # * https://github.com/sonic-net/sonic-buildimage/pull/12853 is reverted
        while not (quit_enabled and v4_routing_ok):
            cmd = None
            # quit command was received, we don't process next commands
            # but wait for v4_routing_ok and v6_routing_ok
            if not quit_enabled:
                cmd = self.queue.get()
                if cmd == 'quit':
                    quit_enabled = True
                    continue
                elif cmd == 'cpu_down' or cmd == 'cpu_going_up' or cmd == 'cpu_up':
                    last_lacppdu_time_before_reboot = None
                    with self.port_channel_last_lacp_pdu_time_lock:
                        last_lacppdu_time_before_reboot = self.port_channel_last_lacp_pdu_time
                    if last_lacppdu_time_before_reboot is not None:
                        self.lacp_pdu_timings.append(last_lacppdu_time_before_reboot)

            cur_time = time.time()
            info = {}
            lacp_output = self.do_cmd(self.show_lacp_command)
            info['lacp'] = self.parse_lacp(lacp_output)
            bgp_neig_output = self.do_cmd('vtysh -c "show bgp neighbor json"')
            info['bgp_neig'] = self.parse_bgp_neighbor(bgp_neig_output)

            v4_routing, bgp_route_v4_output = self.check_bgp_route(self.v4_routes)
            if v4_routing != v4_routing_ok:
                v4_routing_ok = v4_routing
                self.log('BGP routing for ipv4 OK: %s' % (v4_routing_ok))
            info['bgp_route_v4'] = v4_routing_ok

            v6_routing, bgp_route_v6_output = self.check_bgp_route(self.v6_routes, ipv6=True)
            if v6_routing != v6_routing_ok:
                v6_routing_ok = v6_routing
                self.log('BGP routing for ipv6 OK: %s' % (v6_routing_ok))
            info["bgp_route_v6"] = v6_routing_ok

            self.ipv4_gr_enabled, self.ipv6_gr_enabled, self.gr_timeout = \
                self.parse_bgp_neighbor_once(bgp_neig_output)

            data[cur_time] = info
            if self.DEBUG:
                debug_data[cur_time] = {
                    'show lacp neighbor': lacp_output,
                    'show ip bgp neighbors': bgp_neig_output,
                    'show ip route bgp': bgp_route_v4_output,
                    'show ipv6 route bgp': bgp_route_v6_output,
                }
            time.sleep(1)

        log_data = {}

        self.log('Collecting logs')
        log_lines = self.do_cmd("sudo cat "
                                "/var/log/syslog{,.1} "
                                "/var/log/teamd.log{,.1} "
                                "/var/log/frr/bgpd.log "
                                "/var/log/frr/zebra.log").split('\n')
        syslog_regex_r = r'^(\S+\s+\d+\s+\d+:\d+:\d+)\.\d+ \S+ [A-Z]+ ([a-z\-]+#[/a-zA-Z0-9_]+)' \
            r'(?:\s+\d+-\d+-\d+\s+\d+:\d+:\d+,\d+\s+[A-Z]+\s+\w+)?(?:\[\d+\])?: (.+)$'
        parsed_logs = self.extract_from_logs(syslog_regex_r, log_lines, min_timestamp=start_time)
        self.log('Log output "{}"'.format('\n'.join(["{} {} {}".format(k[0], j, k[1])
                                                    for j in parsed_logs for k in parsed_logs[j]])))
        log_data = self.parse_logs(parsed_logs)
        if not (self.reboot_type == 'fast-reboot' and
                'bgp#bgpd' in parsed_logs and 'PortChannel' in parsed_logs) \
                and not (self.reboot_type == 'warm-reboot' and 'bgp#bgpd' in parsed_logs) \
                and not (self.reboot_type == 'service-warm-restart' and 'bgp#bgpd' in parsed_logs):
            log_data['error'] = 'Incomplete logs'

        self.log('Disconnecting from VM')
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

        self.log('Checking BGP GR peer status on VM')
        self.check_gr_peer_status(data)
        cli_data = {}
        # cli_data['lacp']   = self.check_series_status(data, "lacp",         "LACP session")
        cli_data['lacp'] = (0, 0)
        cli_data['bgp_v4'] = self.check_series_status(data, "bgp_route_v4", "BGP v4 routes")
        # TODO: same as above for v6_routing_ok
        cli_data['bgp_v6'] = (1, 0)
        cli_data['po'] = self.check_lag_flaps("PortChannel1", log_lines, start_time)

        if 'route_timeout' in log_data:
            route_timeout = log_data['route_timeout']
            cli_data['route_timeout'] = route_timeout

            # {'10.0.0.38': [(0, '4200065100)')], 'fc00::2d': [(0, '4200065100)')]}
            for nei in route_timeout.keys():
                asn = route_timeout[nei][0][-1]
                msg = 'BGP route GR timeout: neighbor %s (ASN %s' % (nei, asn)
                self.fails.add(msg)

        if cli_data['po'][1] > 0:
            self.fails.add('Port channel flap occurred!')

        self.log('Finishing run()')
        return self.fails, self.info, cli_data, log_data, {
            "lacp_all": list(set(self.lacp_pdu_timings))
            }

    def extract_from_logs(self, regexp, data, min_timestamp=None):
        raw_data = []
        result = defaultdict(list)
        re_compiled = re.compile(regexp)
        for line in data:
            m = re_compiled.match(line)
            if not m:
                continue
            log_time = datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + m.group(1), "%Y %b %d %X")
            # Python 3 version (Python 2 doesn't have timestamp():
            # raw_data.append((log_time.timestamp(), m.group(2), m.group(3)))
            raw_data.append((time.mktime(log_time.timetuple()), m.group(2), m.group(3)))

        if len(raw_data) > 0:
            for when, what, status in raw_data:
                if min_timestamp and when >= min_timestamp:
                    result[what].append((when, status))

        return result

    def parse_logs(self, data):
        result = {}
        # bgp_r = r'^(\S+\s+\d+\s+\S+) \S+ Rib: %BGP-5-ADJCHANGE: peer (\S+) .+ (\S+)$'
        result_bgp, initial_time_bgp = {}, 0
        # if_r = r'^(\S+\s+\d+\s+\S+) \S+ Ebra: %LINEPROTO-5-UPDOWN: ' \
        #         r'Line protocol on Interface (\S+), changed state to (\S+)$'
        result_if, initial_time_if = {}, 0

        # route_r = r'^(\S+\s+\d+\s+\S+) \S+ Rib: %BGP-5-BGP_GRACEFUL_RESTART_TIMEOUT: ' \
        #     r'Deleting stale routes from peer (\S+) .+ (\S+)$'
        result_rt = {}

        result['route_timeout'] = result_rt

        # for fast-reboot, we expect to have both the bgp and portchannel events in the logs. for warm-reboot,
        # portchannel events might not be present in the logs all the time.
        if self.reboot_type == 'fast-reboot' and (initial_time_bgp == -1 or initial_time_if == -1):
            return result
        elif self.reboot_type == 'warm-reboot' and initial_time_bgp == -1:
            return result
        elif self.reboot_type == 'service-warm-restart' and initial_time_bgp == -1:
            return result

        # verify BGP establishment time between v4 and v6 peer is not more than self.bgp_v4_v6_time_diff
        if self.reboot_type == 'warm-reboot':
            estab_time = 0
            for ip in result_bgp:
                if estab_time > 0:
                    diff = abs(result_bgp[ip][-1][0] - estab_time)
                    assert diff <= self.bgp_v4_v6_time_diff, \
                        'BGP establishement time between v4 and v6 peer is longer than {} sec, it was {}'.format(
                                self.bgp_v4_v6_time_diff, diff)
                    break
                estab_time = result_bgp[ip][-1][0]

        po_carrier_data = [k for k in data["teamd#teamd_PortChannel1"] if "carrier changed to" in k[1]]

        if len(po_carrier_data) > 0:
            # first state is down, last state is up
            first_state = po_carrier_data[0][1].replace("carrier changed to ", "")
            last_state = po_carrier_data[-1][1].replace("carrier changed to ", "")
            assert first_state == 'DOWN', 'First PO state should be down, it was {}'.format(first_state)
            assert last_state == 'UP', 'Last PO state should be up, it was {}'.format(last_state)

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was down (seconds)" if ':' in neig_ip else "BGP IPv4 was down (seconds)"
            result[key] = result_bgp[neig_ip][-1][0] - result_bgp[neig_ip][0][0]

        for neig_ip in result_bgp.keys():
            key = "BGP IPv6 was down (times)" if ':' in neig_ip else "BGP IPv4 was down (times)"
            result[key] = map(itemgetter(1), result_bgp[neig_ip]).count("Idle")

        result['PortChannel was down (seconds)'] = po_carrier_data[-1][0] - po_carrier_data[0][0] \
            if po_carrier_data else 0
        for if_name in sorted(result_if.keys()):
            result['Interface %s was down (times)' % if_name] = map(itemgetter(1), result_if[if_name]).count("down")

        bgp_po_offset = abs(initial_time_if - initial_time_bgp)
        result['BGP went down after portchannel went down (seconds)'] = bgp_po_offset

        for neig_ip in result_bgp.keys():
            key = "BGP {} was gotten up after Po was up (seconds)".format("IPv6" if ':' in neig_ip else "IPv4")
            result[key] = result_bgp[neig_ip][-1][0] - bgp_po_offset

        return result

    def check_lag_flaps(self, interface, log_lines, start_time):
        lag_flap_r = r'^(\S+\s+\d+\s+\S+)\.\d+ \S+ \w+ teamd#teamd_(\S+)\[\d+\]: carrier changed to (\w+)$'
        result_lag_flaps = self.extract_from_logs(lag_flap_r, log_lines, min_timestamp=start_time)
        if interface not in result_lag_flaps:
            # no logs related to this LAG recorded, return assuming no LAG flaps
            return 0, 0

        num_lag_flaps = len([x for x in result_lag_flaps[interface] if x[1] == "DOWN"])
        return 0, num_lag_flaps

    def parse_lacp(self, output):
        return output.find('Bundled') != -1

    def parse_bgp_neighbor_once(self, output):
        is_gr_ipv4_enabled = False
        is_gr_ipv6_enabled = False
        restart_time = None
        obj = json.loads(output)
        for prefix, attrs in obj.items():
            if "exabgp" in attrs["nbrDesc"]:
                continue
            if attrs["gracefulRestartInfo"]["remoteGrMode"] == "Disable":
                if ":" in prefix:
                    is_gr_ipv6_enabled = False
                else:
                    is_gr_ipv4_enabled = False
                continue
            if attrs["gracefulRestartInfo"]["timers"]["receivedRestartTimer"] > 0:
                if ":" in prefix:
                    is_gr_ipv6_enabled = True
                else:
                    is_gr_ipv4_enabled = True
                restart_time = attrs["gracefulRestartInfo"]["timers"]["receivedRestartTimer"]

        return is_gr_ipv4_enabled, is_gr_ipv6_enabled, restart_time

    def parse_bgp_info(self, output):
        obj = json.loads(output)
        neigh_bgp = None
        dut_bgp = None
        asn = None
        for neighbor, attrs in obj.items():
            dut_bgp = neighbor
            asn = attrs["localAs"]
            neigh_bgp = attrs["hostLocal"]

        return neigh_bgp, dut_bgp, asn

    def parse_bgp_neighbor(self, output):
        gr_active = False
        gr_timer = None
        obj = json.loads(output)
        for prefix, attrs in obj.items():
            if "exabgp" in attrs["nbrDesc"]:
                continue
            if "gracefulRestartInfo" not in attrs:
                continue
            if "restartTimerRemaining" not in attrs["gracefulRestartInfo"]:
                continue
            gr_active = True
            gr_timer = attrs["gracefulRestartInfo"]["restartTimerRemaining"]
            break

        return gr_active, gr_timer

    def parse_bgp_route(self, output, expects):
        prefixes = set()
        obj = json.loads(output)

        for prefix, attrs in obj.items():
            attrs = attrs[0]
            if "nexthops" not in attrs:
                continue
            if all("PortChannel" in via["interfaceName"] for via in attrs["nexthops"]):
                prefixes.add(prefix)

        return set(expects).issubset(prefixes)

    def parse_supported_show_lacp_command(self):
        show_lacp_command = "show lacp neighbor"
        self.log("show lacp command is '{}'".format(show_lacp_command))
        return show_lacp_command

    def parse_supported_bgp_neighbor_command(self, v4=True):
        if v4:
            show_bgp_neighbors_cmd = "show ip bgp neighbors"
            self.log("show ip bgp neighbor command is '{}'".format(show_bgp_neighbors_cmd))
        else:
            show_bgp_neighbors_cmd = "show ipv6 bgp neighbors"
            self.log("show ipv6 bgp neighbor command is '{}'".format(show_bgp_neighbors_cmd))

        return show_bgp_neighbors_cmd

    def check_bgp_route(self, expects, ipv6=False):
        cmd = 'vtysh -c "show ip route json"'
        if ipv6:
            cmd = 'vtysh -c "show ipv6 route json"'

        output = self.do_cmd(cmd)
        ok = self.parse_bgp_route(output, expects)

        return ok, output

    def get_bgp_info(self):
        # Retreive BGP info (peer addr, AS) for the dut and neighbor
        neigh_bgp = {}
        dut_bgp = {}
        for cmd, ver in [(self.show_ip_bgp_command, 'v4'), (self.show_ipv6_bgp_command, 'v6')]:
            output = self.do_cmd(cmd)
            if ver == 'v6':
                neigh_bgp[ver], dut_bgp[ver], neigh_bgp['asn'] = self.parse_bgp_info(output)
            else:
                neigh_bgp[ver], dut_bgp[ver], neigh_bgp['asn'] = self.parse_bgp_info(output)

        return neigh_bgp, dut_bgp

    def change_bgp_route(self, cfg_map):
        self.do_cmd('configure')
        for item in cfg_map:
            self.do_cmd(item)
        self.do_cmd('exit')

    def change_bgp_neigh_state(self, asn, is_up=True):
        # BGP shut/unshut for peer
        raise NotImplementedError

    def verify_bgp_neigh_state(self, dut=None, state="Active"):
        bgp_state = {}
        bgp_state['v4'] = bgp_state['v6'] = False
        for cmd, ver in [('show ip bgp summary | json', 'v4'), ('show ipv6 bgp summary | json', 'v6')]:
            output = self.do_cmd(cmd)
            data = '\n'.join(output.split('\r\n')[1:-1])
            obj = json.loads(data)

            if state == 'down':
                if 'vrfs' in obj:
                    # return True when obj['vrfs'] is empty which is the case when the bgp state is 'down'
                    bgp_state[ver] = not obj['vrfs']
                else:
                    self.fails.add('Verify BGP %s neighbor: Object missing in output' % ver)
            else:
                if 'vrfs' in obj and 'default' in obj['vrfs']:
                    obj = obj['vrfs']['default']
                    if 'peers' in obj:
                        bgp_state[ver] = (obj['peers'][dut[ver]]['peerState'] in state)
                    else:
                        self.fails.add('Verify BGP %s neighbor: Peer attribute missing in output' % ver)
                else:
                    self.fails.add('Verify BGP %s neighbor: Object missing in output' % ver)
        return self.fails, bgp_state

    def change_neigh_lag_state(self, intf, is_up=True):
        # Port-channel interface shut/unshut
        raise NotImplementedError

    def change_neigh_intfs_state(self, intfs, is_up=True):
        for intf in intfs:
            self.change_neigh_lag_state(intf, is_up=is_up)

    def verify_neigh_lag_state(self, lag, state="connected", pre_check=True):
        states = state.split(',')
        lag_state = False
        msg_prefix = ['Postboot', 'Preboot']
        is_match = re.match(r'(Port-Channel|Ethernet)\d+', lag)
        if is_match:
            output = self.do_cmd('show interfaces %s | json' % lag)
            if 'Invalid' not in output:
                data = '\n'.join(output.split('\r\n')[1:-1])
                obj = json.loads(data)

                if 'interfaces' in obj and lag in obj['interfaces']:
                    lag_state = (obj['interfaces'][lag]['interfaceStatus'] in states)
                else:
                    self.fails.add('%s: Verify LAG %s: Object missing in output' % (msg_prefix[pre_check], lag))
                return self.fails, lag_state

        self.fails.add('%s: Invalid interface name' % msg_prefix[pre_check])
        return self.fails, lag_state

    def verify_neigh_lag_no_flap(self):
        # Note: this function may have false-positives (with regards to link flaps). The start time used here is
        # the system's boot time, not the test start time, which means any LAG flaps before the start of the test
        # would get included here.
        log_lines = self.do_cmd("sudo cat /var/log/teamd.log{,.1}").split('\n')
        boot_time = datetime.datetime.strptime(self.do_cmd("uptime -s").strip(), "%Y-%m-%d %H:%M:%S")
        _, flap_cnt = self.check_lag_flaps("PortChannel1", log_lines, time.mktime(boot_time.timetuple()))
        return self.fails, flap_cnt

    def check_gr_peer_status(self, output):
        # [0] True 'ipv4_gr_enabled', [1] doesn't matter 'ipv6_enabled', [2] should be >= 120
        if not self.ipv4_gr_enabled:
            self.fails.add("bgp ipv4 graceful restart is not enabled")
        if not self.ipv6_gr_enabled:
            pass  # TODO:
        if self.gr_timeout < 120:  # bgp graceful restart timeout less then 120 seconds
            self.fails.add("bgp graceful restart timeout ({}) is less then 120 seconds".format(self.gr_timeout))

        for when, other in sorted(output.items(), key=lambda x: x[0]):
            gr_active, timer = other['bgp_neig']
            # wnen it's False, it's ok, wnen it's True, check that inactivity timer not less then
            # self.min_bgp_gr_timeout seconds
            if gr_active and datetime.datetime.strptime(timer, '%H:%M:%S').time() < \
                    datetime.time(second=self.min_bgp_gr_timeout):
                self.fails.add("graceful restart timer is almost finished. Less then %d seconds left"
                               % self.min_bgp_gr_timeout)

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

        if len(sorted_keys) == 1:
            # for service warm restart, the down count could be 0
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

        return is_down_count, sum(res[False])  # summary_downtime
