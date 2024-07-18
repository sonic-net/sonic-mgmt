'''
generate and update qos params for brcm platform
'''

import json
import logging
import re
import sys


# change history
#           [major, minor, patch, date, author, description]
versions = [[1, 1, 0, '7/18/2024', 'Xu Chen', 'add change history'],
            [1, 0, 0, '7/2/2024', 'Xu Chen', 'first sharing revision']]


#
# extract section content from input text to support run this script in dev mode
#
def section(input_text, section_name):
    found_section = False
    extracted_section = ""
    section_name_pattern = re.escape(section_name)  # Escape special characters in section name

    lines = input_text.split('\n')
    for line in lines:
        if line.startswith("========"):
            if found_section:
                break
            found_section = bool(re.search('^======== ' + section_name_pattern + ' ', line))

        if found_section:
            extracted_section += line + '\n'

    return extracted_section

#
# extrace testportIds from input data
#
# since testePortIds schema was changed
# from
#        "testPortIds":
#        [
#            0,
#            2,
#            4,
#            6,
#            116,
#            118
#        ]
# to
#        "testPortIds":
#        {
#            "1":
#            {
#                "0":
#                [
#                    0,
#                    2,
#                    4,
#                    6,
#                    116,
#                    118
#                ]
#            }
#        },
# not sure if it will change later, so use recursive method to extract testPortIds
#
def extract_test_port_ids(data, int_set=None):
    if int_set is None:
        int_set = set()

    if data is None:
        return int_set

    if isinstance(data, int):
        int_set.add(data)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, int):
                int_set.add(item)
            else:
                extract_test_port_ids(item, int_set)
    elif isinstance(data, dict):
        for _, value in data.items():
            extract_test_port_ids(value, int_set)

    return int_set


class QosParamBroadcom(object):

    def __init__(self, arguments):
        self.arguments = arguments

        self.dev_mode = False
        if all(arg is None for arg in self.arguments.values()):
            self.dev_mode = True
            # in dev_mode: run this script without sonic-mgmt environment
            # load arguments from the file as necessary input
            self.load_arguments()

        self.msg('QosParamBroadcom is running in {} mode'.format('dev' if self.dev_mode else 'non-dev'))
        self.msg('Dump input options of QosParamBroadcom: {}'.format(self.arguments))

        self.asic_param_dic = {'td2': {'cell_size': 208, 'xpe_count': 1},
                               'td3': {'cell_size': 256, 'xpe_count': 1},
                               'th':  {'cell_size': 208, 'xpe_count': 4},
                               'th2': {'cell_size': 208, 'xpe_count': 4},
                               'th3': {'cell_size': 208, 'xpe_count': 2}}

        self.asic_type = self.arguments['asic_type']
        self.cell_size = self.asic_param_dic[self.asic_type]['cell_size']
        self.xpe_count = self.asic_param_dic[self.asic_type]['xpe_count']
        self.speed_cable_len = self.arguments['speed_cable_len']
        self.qos_params = self.arguments['qos_params']
        self.ingressLosslessProfile = self.arguments['ingressLosslessProfile']
        self.ingressLossyProfile = self.arguments['ingressLossyProfile']
        self.egressLosslessProfile = self.arguments['egressLosslessProfile']
        self.egressLossyProfile = self.arguments['egressLossyProfile']
        self.dutConfig = self.arguments['dutConfig']
        self.dualTor = self.arguments['dualTor']
        self.dutTopo = self.arguments['dutTopo']
        self.bufferConfig = self.arguments['bufferConfig']
        self.dutHost = self.arguments['dutHost']
        self.testbedTopologyName = self.arguments['testbedTopologyName']
        # extract profile name from input string: BUFFER_PROFILE_TABLE:pg_lossless_100000_300m_profile
        self.selected_profile = self.arguments['selected_profile'].split(':')[-1]
        self.testPortIds = list(extract_test_port_ids(self.dutConfig.get('testPortIds', None)))

    def msg(self, message, level='info'):
        if self.dev_mode:
            sys.stderr.write(message + "\n")
        else:
            log_funcs = {'debug': logging.debug,
                         'info': logging.info,
                         'warning': logging.info,
                         'error': logging.error,
                         'critical': logging.error}
            log_fn = log_funcs.get(level.lower(), logging.info)
            log_fn(message)

    def load_arguments(self, filename='qos_param_generator_arguments.json'):
        try:
            with open(filename, 'r') as file:
                self.arguments = json.load(file)
        except FileNotFoundError:
            pass  # Keep the existing arguments if the file doesn't exist

    def collect_device_info(self, command):
        retcode = True
        message = 'Failed to collect {}'.format(command)
        try:
            if self.dev_mode:
                # in dev_mode: run this script without sonic-mgmt environment
                # load device info from the file as necessary input
                with open('qos_param_generator_asic_info.rec', "r") as fp:
                    input_text = fp.read()  # Read the entire file content
                message = section(input_text, command)
            else:
                message = self.dutHost.shell(command, module_ignore_errors=True)['stdout']
        except:
            retcode = False
        return (retcode, message)

    #
    # input argument is not enough to calculate qos parameters,
    # need to collect additional info, and parse it, to support following calculation
    #
    def parse_device_config(self):
        self.cfg = {}

        # parse output of command "bcmcmd 'g THDI_BUFFER_CELL_LIMIT_SP'",
        # schema of parse result is as below:
        #   'ingress_shared_limit_sp0': 39867,
        rc, out = self.collect_device_info("bcmcmd 'g THDI_BUFFER_CELL_LIMIT_SP'")
        if rc:
            self.msg('Read ASIC THDI_BUFFER_CELL_LIMIT_SP register, output {}'.format(out), level='debug')
            for line in out.splitlines():
                if line:
                    m = re.match('THDI_BUFFER_CELL_LIMIT_SP\(0\).*\]\=([0-9a-fx]+)', line)
                    if m:
                        self.cfg['ingress_shared_limit_sp0'] = int(m.group(1), 0)
                        break

        # parse output of command "bcmcmd 'g MMU_THDM_DB_POOL_SHARED_LIMIT'",
        # schema of parse result is as below:
        #   'egress_shared_limit_sp0': 50901,
        rc, out = self.collect_device_info("bcmcmd 'g MMU_THDM_DB_POOL_SHARED_LIMIT'")
        if rc:
            self.msg('Read ASIC MMU_THDM_DB_POOL_SHARED_LIMIT register, output {}'.format(out), level='debug')
            count = 0
            for line in out.splitlines():
                if line:
                    m = re.match('MMU_THDM_DB_POOL_SHARED_LIMIT\(([01])\).*\]\=([0-9a-fx]+)', line)
                    if m:
                        self.cfg['egress_shared_limit_sp{}'.format(m.group(1))] = int(m.group(2), 0)
                        count += 1
                        if count == 2:
                            break

        # parse output of command "mmuconfig -l" output,
        # schema of parse result is as below:
        # 'mmuconfig': {
        #   'profile': {
        #     'pg_lossless_50000_300m_profile': {
        #       'xon_offset': '2496',
        #       'dynamic_th': '0',
        #       'xon': '1248',
        #       'xoff': '101088',
        #       'pool': 'ingress_lossless_pool',
        #       'size': '1248'
        #     },
        #     ... ...
        #   },
        #   'pool': {
        #     'ingress_lossless_pool': {
        #       'xoff': '7827456',
        #       'type': 'ingress',
        #       'mode': 'dynamic',
        #       'size': '33169344'
        #     },
        #     ... ...
        #   }
        # }
        rc, out = self.collect_device_info("mmuconfig -l")
        if rc:
            self.msg('Read mmuconfig, output {}'.format(out), level='debug')
            key0 = None
            key1 = None
            key2 = None
            val = None
            self.cfg['mmuconfig'] = {}
            for line in out.splitlines():
                line = line.strip()
                if line and line[0].lower().isalpha():
                    mmucfg = line.split()
                    if len(mmucfg) != 2:
                        continue
                    if mmucfg[0].lower() in ('pool:', 'profile:'):
                        key0 = mmucfg[0].lower()[:-1]
                        key1 = mmucfg[1]
                    else:
                        key2 = mmucfg[0]
                        val = mmucfg[1]
                        self.cfg['mmuconfig'].setdefault(key0, {}).setdefault(key1, {})[key2] = val

        # parse input argument "bufferConfig"
        # schema of parse result is as below:
        #  'buffer_pg': {
        #    'Ethernet80': {
        #      0: 'ingress_lossy_profile',
        #      3: 'pg_lossless_50000_300m_profile',
        #      4: 'pg_lossless_50000_300m_profile'
        #    },
        #    'Ethernet8': {
        #      0: 'ingress_lossy_profile',
        #      3: 'pg_lossless_50000_300m_profile',
        #      4: 'pg_lossless_50000_300m_profile'
        #    },
        self.cfg['buffer_pg'] = {}
        for pg_name, pg_profile in self.bufferConfig['BUFFER_PG'].items():
            pg_profile_name = self.extract_profile_name(pg_profile['profile'])
            port_name, pg_range = pg_name.split("|")
            pg_number = pg_range.split('-')
            start_pg = int(pg_number[0])
            end_pg = int(pg_number[1]) if len(pg_number) > 1 else start_pg
            for pg in range(start_pg, end_pg + 1):
                self.cfg['buffer_pg'].setdefault(port_name, {})[pg] = pg_profile_name

        # Change the query index of 'buffer_pg' from "port->pg->profile" to "profile->port->pg"
        # schema is as below:
        #  'buffer_pg_profile': {
        #    'pg_lossless_50000_300m_profile': {
        #      'Ethernet180': set([
        #        3,
        #        4
        #      ]),
        #      ... ...
        #    },
        #    'ingress_lossy_profile': {
        #      'Ethernet180': set([
        #        0
        #      ]),
        self.cfg['buffer_pg_profile'] = {}
        for port_name, pg_profile in self.cfg['buffer_pg'].items():
            for pg, profile_name in pg_profile.items():
                self.cfg['buffer_pg_profile'].setdefault(profile_name, {}).setdefault(port_name, set()).add(pg)

        # parse output of command "bcmcmd 'show pmap'"
        # schema of parse result is as below:
        #  'bcm_port_map': {
        #    'xe29': {
        #      'mmu': 65,
        #      'half-pipe': 0,
        #      'logical': 35,
        #      'pipe': 1,
        #      'ucast_Qbase/Numq': '10/10',
        #      'mcast_Qbase/Numq': '10/10',
        #      'idb': 1,
        #      'physical': 79
        #    },
        self.cfg['bcm_port_map'] = {}
        rc, out = self.collect_device_info("bcmcmd 'show pmap'")
        if rc:
            self.msg('Read broadcom port map, output {}'.format(out), level='debug')
            for line in out.splitlines():
                line = line.strip()
                maps = line.split()
                if len(maps) == 9:
                    self.cfg['bcm_port_map'].setdefault(maps[0], {}).update(
                        {'pipe':             int(maps[1]),
                         'logical':          int(maps[2]),
                         'physical':         int(maps[3]),
                         'idb':              int(maps[4]),
                         'mmu':              int(maps[5]),
                         'ucast_Qbase/Numq': maps[6],
                         'mcast_Qbase/Numq': maps[7],
                         'half-pipe':        int(maps[8])})

        # parse output of command "bcmcmd 'knetctrl netif show'"
        # schema of parse result is as below:
        #  'knet_port_map': {
        #    'xe29': {
        #      'ifid': 38,
        #      'vlan': 0,
        #      'type': 'Port',
        #      'ifname': 'Ethernet2',
        #      'tag': 'keeprxtag'
        #    },
        self.cfg['knet_netif_map'] = {}
        retry_cnt = 0
        retry_max = 20
        # run "knetctrl netif show" multiple times to make sure there is no unknown port in the output
        while retry_cnt < retry_max:
            incomplete = False
            rc, out = self.collect_device_info("bcmcmd 'knetctrl netif show'")
            if rc:
                self.msg('Read knet netif port map, output {}'.format(out), level='debug')
                for line in out.splitlines():
                    line = line.strip()
                    maps = line.split()
                    if len(maps) == 8:
                        ifid = int(maps[2][:-1])
                        ifname = maps[3].split('=')[-1]
                        tp = maps[4].split('=')[-1]
                        vlan = int(maps[5].split('=')[-1])
                        bcmport = maps[6].split('=')[-1]
                        tag = maps[7]
                        if self.cfg['knet_netif_map'].get(ifname, None) is None:
                            self.cfg['knet_netif_map'].setdefault(ifname, {}).update(
                                {'ifid': ifid, 'bcmport': bcmport, 'type': tp, 'vlan': vlan, 'tag': tag})
                        elif 'unknown' not in bcmport:
                            self.cfg['knet_netif_map'][ifname]['bcmport'] = bcmport
                        if 'unknown' in self.cfg['knet_netif_map'][ifname]['bcmport']:
                            incomplete = True
            if not incomplete:
                break
            retry_cnt += 1

        if retry_cnt >= retry_max:
            self.msg('There have unknown port in the output of "knetctrl netif show" after {} times'.format(retry_cnt))
            return False

        self.cfg['knet_port_map'] = {}
        for ifname, entry in self.cfg['knet_netif_map'].items():
            self.cfg['knet_port_map'].setdefault(entry['bcmport'], {}).update(
                {'ifid': entry['ifid'],
                 'ifname': ifname,
                 'type': entry['type'],
                 'vlan': entry['vlan'],
                 'tag': entry['tag']})

        # parse output of command "show int st | grep Eth"
        # schema of parse result is as below:
        #  'sonic_port_map': {
        #    'Ethernet226': {
        #      'testPortId': 105,
        #      'linkstate': 'down'
        #    },
        self.cfg['sonic_port_map'] = {}
        rc, out = self.collect_device_info("show int st | grep Eth")
        if rc:
            self.msg('Read sonic port map, output {}'.format(out), level='debug')
            test_port_id = 0
            for line in out.splitlines():
                line = line.strip()
                m = re.match('^\s*(Ethernet[0-9]{1,3})\s+[0-9]+', line)
                if m:
                    up = re.findall('up\s+up', line)
                    self.cfg['sonic_port_map'].setdefault(m.group(1), {}).update({'testPortId': test_port_id,
                                                                                  'linkstate': 'up' if up else 'down'})
                    test_port_id += 1

        # integrage "bcm_port_map", "knet_port_map" and "sonic_port_map" to "bcm_pipe_ports
        # schema of parse result is as below:
        #  'bcm_pipe_ports': {
        #    0: [
        #      {
        #        'testPortId': 79,
        #        'ifname': 'Ethernet174',
        #        'bcm_port': 'xe23',
        #        'linkstate': 'down'
        #      },
        #      ... ...
        #    1: [
        #      {
        #        'testPortId': 1,
        #        'ifname': 'Ethernet2',
        #        'bcm_port': 'xe29',
        #        'linkstate': 'down'
        #      },
        #      ... ...
        self.cfg['bcm_pipe_ports'] = {}
        for bcm_port, port_info in self.cfg['bcm_port_map'].items():
            # exclude cpu0, lb0, lb1, lb2, just process front panel port
            if port_info['ucast_Qbase/Numq'] != '0/0':
                self.cfg['bcm_pipe_ports'].setdefault(port_info['pipe'], [])
                ifname = self.cfg['knet_port_map'][bcm_port]['ifname']
                testPortId = self.cfg['sonic_port_map'][ifname]['testPortId']
                linkstate = self.cfg['sonic_port_map'][ifname]['linkstate']
                self.cfg['bcm_pipe_ports'][port_info['pipe']].append({'bcm_port': bcm_port,
                                                                      'ifname': ifname,
                                                                      'testPortId': testPortId,
                                                                      'linkstate': linkstate})

        # parse output of command "show run all | jq '.TC_TO_PRIORITY_GROUP_MAP'",
        #  get below two mapping table:
        #  'tc_to_pg_map': {
        #    'AZURE': {
        #      0: 0,
        #      1: 0,
        #      2: 2,
        #      3: 3,
        #      4: 4,
        #      5: 0,
        #      6: 6,
        #      7: 0,
        #      8: 0
        #    },
        #     ... ...
        #  'tc_from_pg_map': {
        #    'AZURE': {
        #      0: set([
        #        0,
        #        1,
        #        5,
        #        8,
        #        7
        #      ]),
        self.cfg['tc_to_pg_map'] = {}
        self.cfg['tc_from_pg_map'] = {}
        rc, out = self.collect_device_info("show run all | jq '.TC_TO_PRIORITY_GROUP_MAP'")
        if rc:
            self.msg('Read TC to PG map, output {}'.format(out), level='debug')
            profile_name = None
            for line in out.splitlines():
                line = line.strip()
                m = re.match('"(\S+)":\s{', line)
                if m:
                    profile_name = m.group(1)
                    self.cfg['tc_to_pg_map'].setdefault(profile_name, {})
                    self.cfg['tc_from_pg_map'].setdefault(profile_name, {})
                    continue
                m = re.match('"([0-9]+)":\s"([0-9]+)"', line)
                if m:
                    tc = int(m.group(1))
                    pg = int(m.group(2))
                    self.cfg['tc_to_pg_map'][profile_name][tc] = pg
                    self.cfg['tc_from_pg_map'][profile_name].setdefault(pg, set()).add(tc)

        # parse output of command "show run all | jq '.DSCP_TO_TC_MAP'",
        #  get below two mapping table:
        #  'dscp_to_tc_map': {
        #    'AZURE': {
        #      0: 1,
        #      1: 1,
        #      2: 1,
        #      3: 3,
        #      4: 4,
        #      5: 1,
        #      6: 1,
        #      7: 1,
        #      8: 0,
        #      9: 1,
        #      10: 1,
        #      ... ...
        #  'dscp_from_tc_map': {
        #    'AZURE': {
        #      0: set([
        #        8
        #      ]),
        self.cfg['dscp_to_tc_map'] = {}
        self.cfg['dscp_from_tc_map'] = {}
        rc, out = self.collect_device_info("show run all | jq '.DSCP_TO_TC_MAP'")
        if rc:
            self.msg('Read DSCP to TC map, output {}'.format(out), level='debug')
            profile_name = None
            for line in out.splitlines():
                line = line.strip()
                m = re.match('"(\S+)":\s{', line)
                if m:
                    profile_name = m.group(1)
                    self.cfg['dscp_to_tc_map'].setdefault(profile_name, {})
                    self.cfg['dscp_from_tc_map'].setdefault(profile_name, {})
                    continue
                m = re.match('"([0-9]+)":\s"([0-9]+)"', line)
                if m:
                    dscp = int(m.group(1))
                    tc = int(m.group(2))
                    self.cfg['dscp_to_tc_map'][profile_name][dscp] = tc
                    self.cfg['dscp_from_tc_map'][profile_name].setdefault(tc, set()).add(dscp)

        self.msg('Parsed device config {}'.format(self.cfg))
        return True

    def run(self):
        if not self.parse_device_config():
            self.msg('Failed to parse device config, use original qos_params')
            return self.qos_params
        self.prepare_default_parameters()
        self.calculate_parameters()
        self.msg('Calculation of qos_params {}'.format(self.qos_params))
        return self.qos_params

    def get_similar_speed_cable_length(self, must_profile=None):
        # Workaround: to continue the QoS SAI test without qos parameter of particular speed and cable length,
        # use the most similar speed cable length for qos sai test
        # until developer share the correct qos parameter for particular speed and cable length
        speed_cable_len = self.speed_cable_len.split('_')
        speed = int(speed_cable_len[0])
        length = int(speed_cable_len[1][:-1])
        speed_length_list = [(speed, length)]
        for speed_len in self.qos_params.keys():
            m = re.match('(\d+)_(\d+)m', speed_len)
            if m:
                if must_profile != None and must_profile not in self.qos_params[speed_len]:
                    continue
                speed_length_list.append((int(m.group(1)), int(m.group(2))))

        if len(speed_length_list) < 2:
            self.msg('qos parameter must has one similar speed_cable_len at least (must_profile={})'.format(
                must_profile))
            return None

        speed_length_list.sort(key=lambda x: (x[0], x[1]))
        this_index = speed_length_list.index((speed, length))
        ref_index = this_index + 1 if this_index + 1 < len(speed_length_list) else this_index - 1
        ref_speed_len = '{}_{}m'.format(speed_length_list[ref_index][0], speed_length_list[ref_index][1])
        return ref_speed_len

    def create_default_speed_cable_length_parameter(self):
        similar_speed_len = self.get_similar_speed_cable_length()
        if similar_speed_len != None:
            self.qos_params[self.speed_cable_len] = self.qos_params[similar_speed_len]
            self.msg('Clone default speed cable length parameters from qos_params[{}] to qos_params[{}]'.format(
                similar_speed_len, self.speed_cable_len))
        else:
            self.msg("qos_params don't support {} parameters".format(self.speed_cable_len))

    def create_default_xon_parameter(self, xon_profile):
        self.qos_params[self.speed_cable_len][xon_profile] = self.qos_params[xon_profile]
        self.msg('Clone default xon parameters from qos_params[{}] to qos_params[{}][{}]'.format(
            xon_profile, self.speed_cable_len, xon_profile))

    def create_default_headroom_pool_size_parameter(self, hdrm_profile):
        if hdrm_profile in self.qos_params:
            self.qos_params[self.speed_cable_len][hdrm_profile] = self.qos_params[hdrm_profile]
            self.msg('Clone default headroom pool size parameters from qos_params[{}] to qos_params[{}][{}]'.format(
                hdrm_profile, self.speed_cable_len, hdrm_profile))
        else:
            self.msg("qos_params don't support headroom pool size parameters")

    def create_default_pg_shared_watermark_parameter(self, pg_profile):
        self.qos_params[self.speed_cable_len][pg_profile] = self.qos_params[pg_profile]
        self.msg('Clone default PG shared watermark parameters from qos_params[{}] to qos_params[{}][{}]'.format(
            pg_profile, self.speed_cable_len, pg_profile))

    def create_default_queue_shared_watermark_parameter(self, que_profile):
        self.qos_params[self.speed_cable_len][que_profile] = self.qos_params[que_profile]
        self.msg('Clone default queue shared watermark parameters from qos_params[{}] to qos_params[{}][{}]'.format(
            que_profile, self.speed_cable_len, que_profile))

    def create_lossy_queue_parameter(self, que_profile):
        if que_profile in self.qos_params:
            # get default value from upper layer
            self.qos_params[self.speed_cable_len][que_profile] = self.qos_params[que_profile]
            self.msg('Clone default lossy queue parameters from qos_params[{}] to qos_params[{}][{}]'.format(
                que_profile, self.speed_cable_len, que_profile))
        else:
            # get default value from similar speed/length
            similar_speed_len = self.get_similar_speed_cable_length(que_profile)
            if similar_speed_len != None:
                self.qos_params[self.speed_cable_len][que_profile] = self.qos_params[similar_speed_len][que_profile]
                self.msg('Clone default lossy queue parameters from qos_params[{}][{}] to qos_params[{}][{}]'.format(
                    similar_speed_len, que_profile, self.speed_cable_len, que_profile))
            else:
                self.msg("qos_params don't support lossy queue parameters")

    def create_pg_headroom_parameter(self, pg_profile):
        if pg_profile in self.qos_params:
            # get default value from upper layer
            self.qos_params[self.speed_cable_len][pg_profile] = self.qos_params[pg_profile]
            self.msg('Clone default PG headroom parameters from qos_params[{}] to qos_params[{}][{}]'.format(
                pg_profile, self.speed_cable_len, pg_profile))
        else:
            # get default value from similar speed/length
            similar_speed_len = self.get_similar_speed_cable_length(pg_profile)
            if similar_speed_len != None:
                self.qos_params[self.speed_cable_len][pg_profile] = self.qos_params[similar_speed_len][pg_profile]
                self.msg('Clone default PG headroom parameters from qos_params[{}][{}] to qos_params[{}][{}]'.format(
                    similar_speed_len, pg_profile, self.speed_cable_len, pg_profile))
            else:
                self.msg("qos_params don't support PG headroom parameters")

    #
    # Ideally, input qos parameters will not miss fields
    # But some corner cases will cause it, for example, newly introduced topology/speed/breakout, etc...
    # So if some fields are missing, default values are generated here, as a workaround to move test forward
    # Eventually, feature developers will complete it.
    #
    def prepare_default_parameters(self):
        if self.speed_cable_len not in self.qos_params:
            self.create_default_speed_cable_length_parameter()

        for xon_profile in ["xon_1", "xon_2"]:
            if xon_profile not in self.qos_params[self.speed_cable_len]:
                self.create_default_xon_parameter(xon_profile)

        for hdrm_profile in ['hdrm_pool_size']:
            if hdrm_profile not in self.qos_params[self.speed_cable_len]:
                self.create_default_headroom_pool_size_parameter(hdrm_profile)

        for pg_profile in ["wm_pg_shared_lossless", "wm_pg_shared_lossy"]:
            if pg_profile not in self.qos_params[self.speed_cable_len]:
                self.create_default_pg_shared_watermark_parameter(pg_profile)

        for que_profile in ['wm_q_shared_lossless', 'wm_q_shared_lossy']:
            if que_profile not in self.qos_params[self.speed_cable_len]:
                self.create_default_queue_shared_watermark_parameter(que_profile)

        for que_profile in ['lossy_queue_1']:
            if que_profile not in self.qos_params[self.speed_cable_len]:
                self.create_lossy_queue_parameter(que_profile)

        for pg_profile in ['wm_pg_headroom']:
            if pg_profile not in self.qos_params[self.speed_cable_len]:
                self.create_pg_headroom_parameter(pg_profile)

        for profile in ["xoff_1", "xoff_2", "xon_1", "xon_2"]:
            default_margin = 4
            if 'pkts_num_margin' not in self.qos_params[self.speed_cable_len][profile] or \
                    self.qos_params[self.speed_cable_len][profile]['pkts_num_margin'] < default_margin:
                self.qos_params[self.speed_cable_len][profile].update({'pkts_num_margin': default_margin})
                self.msg('Add/Increase default margin parameters for qos_params[{}][{}] to value {}'.format(
                    self.speed_cable_len, profile, default_margin))

    def byte_to_cell(self, bytes):
        return int((int(bytes) + self.cell_size - 1) / self.cell_size)

    def extract_profile_name(self, fullname):
        # profile name string pattern in branch internal-202012:
        #     "Ethernet112|2-4":
        #     {
        #         "profile": "[BUFFER_PROFILE|egress_lossless_profile]"
        #     },
        #
        # profile name string pattern in branch internal:
        #     "Ethernet112|2-4":
        #     {
        #         "profile": "egress_lossless_profile"
        #     },
        fn = fullname.split('|')[-1] if fullname else None
        return fn[:-1] if bool(fn) and fn[-1] == ']' else fn

    def calc_available_share_buffer_size(self, total_share_buffer_size, mode, threshold):
        avaiable_share_buffer_size = 0
        if mode == 'dynamic':
            # dynamic threshold:
            #     Memory can be allocated from shared buffer for pgi  for port p if
            #         Alpha * free buffer > Bp,i
            #     Bp,i: Buffer allocated for pgi of ingress port p
            #
            # Considering one port one pg scenario, above formula is simplized as:
            #     alpha * (shared buffer - x) > x
            #     x indicate used share buffer
            #
            # +------------+----------+-------+
            # | dynamic_th | register | alpha |
            # +------------+----------+-------+
            # |     -7     |    0     | 1/128 |
            # |     -6     |    1     | 1/64  |
            # |     -5     |    2     | 1/32  |
            # |     -4     |    3     | 1/16  |
            # |     -3     |    4     | 1/8   |
            # |     -2     |    5     | 1/4   |
            # |     -1     |    6     | 1/2   |
            # |      0     |    7     | 1     |
            # |      1     |    8     | 2     |
            # |      2     |    9     | 4     |
            # |      3     |    10    | 8     |
            # +------------+----------+-------+
            if threshold < 0:
                threshold *= -1
                avaiable_share_buffer_size = int(total_share_buffer_size / (2 ** threshold + 1))
            else:
                avaiable_share_buffer_size = int(total_share_buffer_size * (2 ** threshold) / (2 ** threshold + 1))
        else:
            assert False, 'TODO: so far, not support to calculate avaiable shared buffer for static mode'
        return avaiable_share_buffer_size

    def get_pg_min_size(self, selected_profile):
        if self.asic_type == 'td2':
            # According to test on td2 ASIC, PG min equal half of pg_reset_offset
            # hardcode here now, do more investigation later, and then refact it
            return self.byte_to_cell(self.ingressLosslessProfile['xon_offset']) >> 1
        return self.byte_to_cell(self.cfg['mmuconfig']['profile'][selected_profile]['size'])

    def get_total_share_buffer_size(self):
        # th/th2/th3's shared buffer = ingress_lossless_pool.size / xpe_count
        cells = self.byte_to_cell(self.cfg['mmuconfig']['pool']['ingress_lossless_pool']['size'])
        share_buf_size = int(cells / self.xpe_count)
        debug_message = 'share_buffer = ingress_lossless_pool.size ({} cells // {})'.format(cells, self.xpe_count)
        indent = ' ' * len('share_buffer ')
        if self.asic_type in ['td2', 'td3']:
            # for td2/td3'
            # total share buffer = ingress_lossless_pool.size
            #                    - ingress_lossless_pool.xoff
            #                    - (egress_lossy_profile.size * total egress lossy queue number)
            #                    - (pg_lossless_profile.size * total lossless buffer pg number)
            egress_profiles = {}
            egress_profiles['egress_lossy_profile'] = self.bufferConfig['BUFFER_PROFILE']['egress_lossy_profile']
            pg_lossless_profiles = {}
            for prof_name, prof_value in self.bufferConfig['BUFFER_PROFILE'].items():
                if re.search('pg_lossless_(.*)_profile', prof_name):
                    pg_lossless_profiles[prof_name] = prof_value

            hdrm_pool = self.byte_to_cell(self.cfg['mmuconfig']['pool']['ingress_lossless_pool'].get('xoff', 0))
            share_buf_size -= hdrm_pool
            debug_message += '\n{}- ingress_lossless_pool.xoff ({} cells)'.format(indent, hdrm_pool)

            for que_name, que_profile in self.bufferConfig['BUFFER_QUEUE'].items():
                que_profile_name = self.extract_profile_name(que_profile['profile'])
                m = re.match('Ethernet\d+\|(\d)-(\d)', que_name)
                if m:
                    que_num = int(m.group(2)) - int(m.group(1)) + 1
                    if que_profile_name == 'egress_lossless_profile':
                        continue
                    share_buf_size -= self.byte_to_cell(egress_profiles[que_profile_name]['size']) * que_num
                    debug_message += '\n{}- que_name ({}): egress_profile.size ({} cells * {})'.format(
                        indent, que_name, self.byte_to_cell(egress_profiles[que_profile_name]['size']), que_num)
                    continue
                m = re.match('Ethernet\d+\|\d', que_name)
                if m and que_profile_name in egress_profiles:
                    que_num = 1
                    share_buf_size -= self.byte_to_cell(egress_profiles[que_profile_name]['size']) * que_num
                    debug_message += '\n{}- que_name ({}): egress_profile.size ({} cells * {})'.format(
                        indent, que_name, self.byte_to_cell(egress_profiles[que_profile_name]['size']), que_num)

            for pg_name, pg_profile in self.bufferConfig['BUFFER_PG'].items():
                pg_profile_name = self.extract_profile_name(pg_profile['profile'])
                m = re.match('Ethernet\d+\|(\d)-(\d)', pg_name)
                if m:
                    pg_num = int(m.group(2)) - int(m.group(1)) + 1
                    share_buf_size -= self.byte_to_cell(
                        pg_lossless_profiles[pg_profile_name]['size']) * pg_num
                    debug_message += '\n{}- pg_name ({}): pg_lossless_profile.size ({} cells * {})'.format(
                        indent, pg_name, self.byte_to_cell(pg_lossless_profiles[pg_profile_name]['size']), pg_num)
                else:
                    m = re.match('Ethernet\d+\|\d', pg_name)
                    if m and pg_profile_name in pg_lossless_profiles:
                        pg_num = 1
                        share_buf_size -= self.byte_to_cell(pg_lossless_profiles[pg_profile_name]['size']) * pg_num
                        debug_message += '\n{}- pg_name ({}): pg_lossless_profile.size ({} cells * {})'.format(
                            indent, pg_name, self.byte_to_cell(pg_lossless_profiles[pg_profile_name]['size']), pg_num)
        self.msg('debug message:\n{}'.format(debug_message))

        # workaround for inaccureate ingress shared buffer capacity
        if 'ingress_shared_limit_sp0' in self.cfg and share_buf_size != self.cfg['ingress_shared_limit_sp0']:
            self.msg('Workaround: correct total share buffer size from {} to {}'.format(
                share_buf_size, self.cfg['ingress_shared_limit_sp0']))
            share_buf_size = self.cfg['ingress_shared_limit_sp0']

        return share_buf_size

    def get_total_Headroom_pool_size(self):
        cells = self.byte_to_cell(self.cfg['mmuconfig']['pool']['ingress_lossless_pool'].get('xoff', 0))
        return int(cells / self.xpe_count)

    def get_pg_headroom_size(self, selected_profile):
        return self.byte_to_cell(self.cfg['mmuconfig']['profile'][selected_profile]['xoff'])

    #
    # caclulate qos parameters, and update self.qos_params
    #
    def calculate_parameters(self):
        #
        # first, calculate common paramter for most of tests
        #
        # TODO:
        # Initially, the parameters "bufferConfig", "ingressLosslessProfile" and "egressLosslessProfile" passed by
        # sonic-mgmt were used for calculation. Later, some calculations used additional parameters obtained by
        # parse_device_config(). Will be optimized later.

        # ingress common calculation:
        pg_min = self.get_pg_min_size(self.selected_profile)
        total_share_buf = self.get_total_share_buffer_size()
        buf_mode = self.cfg['mmuconfig']['pool']['ingress_lossless_pool']['mode']
        buf_threshold = int(self.cfg['mmuconfig']['profile'][self.selected_profile]['dynamic_th'])
        avail_share_buf = self.calc_available_share_buffer_size(total_share_buf, buf_mode, buf_threshold)
        pg_hdrm = self.get_pg_headroom_size(self.selected_profile)
        pg_reset_offset = self.byte_to_cell(self.ingressLosslessProfile['xon_offset'])
        self.msg('Ingress calculation: pg_min {}, avail_share_buf {}, total_share_buf {}, pg_hdrm {}, '
                 'pg_reset_offset {}'.format(pg_min, avail_share_buf, total_share_buf, pg_hdrm, pg_reset_offset))

        # egress common calculation:
        eg_lossless_que_min = self.byte_to_cell(self.egressLosslessProfile['size'])
        self.msg('Egress lossless calculation: eg_lossless_que_min {}'.format(eg_lossless_que_min))
        eg_lossy_que_min = self.byte_to_cell(self.egressLossyProfile['size'])
        egress_lossy_pool = self.bufferConfig['BUFFER_POOL']['egress_lossy_pool']
        eg_total_share_buf = self.byte_to_cell(egress_lossy_pool['size']) // self.xpe_count
        eg_avail_share_buf = self.calc_available_share_buffer_size(
            eg_total_share_buf, egress_lossy_pool['mode'], int(self.egressLossyProfile['dynamic_th']))
        self.msg('Egress lossy calculation: eg_lossy_que_min {}, eg_avail_share_buf {}, eg_total_share_buf {}'.format(
            eg_lossy_que_min, eg_avail_share_buf, eg_total_share_buf))
        # workaround for inaccureate egress lossy shared buffer capacity
        # egress lossy pool size is smaller than egress lossless pool
        egress_shared_limit_sp0 = self.cfg.get('egress_shared_limit_sp0', 0)
        egress_shared_limit_sp1 = self.cfg.get('egress_shared_limit_sp1', 0)
        egress_lossy_shared_limit_sp = egress_shared_limit_sp0
        if egress_lossy_shared_limit_sp == 0:
            egress_lossy_shared_limit_sp = egress_shared_limit_sp1
        elif 0 < egress_shared_limit_sp1 < egress_lossy_shared_limit_sp:
            egress_lossy_shared_limit_sp = egress_shared_limit_sp1
        if egress_lossy_shared_limit_sp > 0 and total_share_buf != egress_lossy_shared_limit_sp:
            eg_avail_share_buf = self.calc_available_share_buffer_size(
                egress_lossy_shared_limit_sp, egress_lossy_pool['mode'], int(self.egressLossyProfile['dynamic_th']))
            self.msg('Workaround egress lossy calculation: eg_lossy_que_min {}, eg_avail_share_buf {}, '
                     'eg_total_share_buf {}'.format(eg_lossy_que_min, eg_avail_share_buf, egress_lossy_shared_limit_sp))

        #
        # Second, update self.qos_params based on the calculation results
        # There are also some special cases, such as hdrm_pool_size, which require
        # special parameters to be calculated in his own calculation method.
        #
        self.calc_param_for_xoff(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                 pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                 eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_xon(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_hdrm_pool_size(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                           pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                           eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_wm_pg_shared_lossless(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                                  pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                                  eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_wm_pg_shared_lossy(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                               pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                               eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_wm_q_shared_lossless(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                                 pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                                 eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_wm_q_shared_lossy(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                              pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                              eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_lossy_queue_1(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                          pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                          eg_avail_share_buf, self.selected_profile)
        self.calc_param_for_wm_pg_headroom(pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                           pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                           eg_avail_share_buf, self.selected_profile)
        self.update_param_for_breakout()


    def update_param_for_breakout(self):
        if 'breakout' in self.qos_params[self.speed_cable_len]:
            profile_list = list(self.qos_params[self.speed_cable_len]['breakout'].keys())
            for profile_name in profile_list:
                profile = self.qos_params[self.speed_cable_len].get(profile_name, None)
                if profile is not None:
                    self.msg('Update qos_params[{}]["breakout"][{}] from {} to {}'.format(self.speed_cable_len, profile_name,
                        self.qos_params[self.speed_cable_len]['breakout'][profile_name], profile))
                    self.qos_params[self.speed_cable_len]['breakout'].update({profile_name: profile})


    def calc_param_for_xoff(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf, pg_reset_offset,
                            pg_hdrm, eg_lossless_que_min, eg_lossy_que_min, eg_avail_share_buf, selected_profile):
        for xoff_profile in ["xoff_1", "xoff_2"]:
            profile = self.qos_params[self.speed_cable_len][xoff_profile]
            if profile["pkts_num_trig_pfc"] != pg_min + avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, xoff_profile, profile["pkts_num_trig_pfc"], pg_min + avail_share_buf))
                profile["pkts_num_trig_pfc"] = pg_min + avail_share_buf
            if profile["pkts_num_trig_ingr_drp"] != pg_min + avail_share_buf + pg_hdrm:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_ingr_drp"] from {} to {}'.format(
                    self.speed_cable_len, xoff_profile, profile["pkts_num_trig_ingr_drp"], pg_min + avail_share_buf + pg_hdrm))
                profile["pkts_num_trig_ingr_drp"] = pg_min + avail_share_buf + pg_hdrm

    def calc_param_for_xon(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf, pg_reset_offset,
                           pg_hdrm, eg_lossless_que_min, eg_lossy_que_min, eg_avail_share_buf, selected_profile):
        for xon_profile in ["xon_1", "xon_2"]:
            profile = self.qos_params[self.speed_cable_len][xon_profile]
            if profile["pkts_num_trig_pfc"] != pg_min + avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, xon_profile, profile["pkts_num_trig_pfc"], pg_min + avail_share_buf))
                profile["pkts_num_trig_pfc"] = pg_min + avail_share_buf
            if profile["pkts_num_dismiss_pfc"] != pg_reset_offset:
                self.msg('Update qos_params[{}][{}]["pkts_num_dismiss_pfc"] from {} to {}'.format(
                    self.speed_cable_len, xon_profile, profile["pkts_num_dismiss_pfc"], pg_reset_offset))
                profile["pkts_num_dismiss_pfc"] = pg_reset_offset

    def calc_param_for_wm_pg_shared_lossless(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                             pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                             eg_avail_share_buf, selected_profile):
        for pg_profile in ["wm_pg_shared_lossless"]:
            profile = self.qos_params[self.speed_cable_len][pg_profile]
            if "pkts_num_trig_pfc" not in profile or profile["pkts_num_trig_pfc"] != pg_min + avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_pfc"], pg_min + avail_share_buf))
                profile.update({"pkts_num_trig_pfc": pg_min + avail_share_buf})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != pg_min:
                self.msg('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_fill_min"], pg_min))
                profile.update({"pkts_num_fill_min": pg_min})

    def calc_param_for_wm_pg_shared_lossy(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                          pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                          eg_avail_share_buf, selected_profile):
        for pg_profile in ["wm_pg_shared_lossy"]:
            profile = self.qos_params[self.speed_cable_len][pg_profile]

            default_margin = 4
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                self.msg('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != 0:
                self.msg('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_fill_min"], 0))
                profile.update({"pkts_num_fill_min": 0})

            if "pkts_num_trig_egr_drp" not in profile or \
                    profile["pkts_num_trig_egr_drp"] != eg_lossy_que_min + eg_avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_egr_drp"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_egr_drp"],
                    eg_lossy_que_min + eg_avail_share_buf))
                profile.update({"pkts_num_trig_egr_drp": eg_lossy_que_min + eg_avail_share_buf})

    def calc_param_for_wm_q_shared_lossless(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                            pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                            eg_avail_share_buf, selected_profile):
        # testQosSaiQSharedWatermark[wm_q_shared_lossless]
        #
        # ingress view:        PG min |                              PG shared |           PG HDRM |
        #                             +                                        +                   +
        # buffer space:  -------------*----------------------------------------*-------------------*------------*
        #                                  +                                                       .            +
        # egress view:             Que min |                                                       . Que shared |
        #                                  +                                                       +
        #                                  |           <-- valid Que watermark range -->           |
        # case param:    pkts_num_fill_min |                                pkts_num_trig_ingr_drp |
        for que_profile in ["wm_q_shared_lossless"]:
            profile = self.qos_params[self.speed_cable_len][que_profile]

            default_margin = 8
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                self.msg('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_trig_ingr_drp" not in profile or \
                    profile["pkts_num_trig_ingr_drp"] != pg_min + avail_share_buf + pg_hdrm:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_ingr_drp"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile["pkts_num_trig_ingr_drp"],
                    pg_min + avail_share_buf + pg_hdrm))
                profile.update({"pkts_num_trig_ingr_drp": pg_min + avail_share_buf + pg_hdrm})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != eg_lossless_que_min:
                self.msg('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile["pkts_num_fill_min"], eg_lossless_que_min))
                profile.update({"pkts_num_fill_min": eg_lossless_que_min})

    def calc_param_for_wm_q_shared_lossy(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                         pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                         eg_avail_share_buf, selected_profile):
        # testQosSaiQSharedWatermark[wm_q_shared_lossy]
        #
        # ingress view:        PG min |                              PG shared |           PG HDRM |
        #                             +                                        +                   +
        # buffer space:  -------------*----------------------------------------*--------------*----*------------
        #                                  +                                     .            +
        # egress view:             Que min |                                     . Que shared |
        #                                  +                                                  +
        #                                  |        <-- valid Que watermark range -->         |
        # case param:    pkts_num_fill_min |                            pkts_num_trig_egr_drp |
        for que_profile in ["wm_q_shared_lossy"]:
            profile = self.qos_params[self.speed_cable_len][que_profile]

            default_margin = 8
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                self.msg('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != eg_lossy_que_min:
                self.msg('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile["pkts_num_fill_min"], eg_lossy_que_min))
                profile.update({"pkts_num_fill_min": eg_lossy_que_min})

            if "pkts_num_trig_egr_drp" not in profile or \
                    profile["pkts_num_trig_egr_drp"] != eg_lossy_que_min + eg_avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_egr_drp"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_trig_egr_drp", -1),
                    eg_lossy_que_min + eg_avail_share_buf))
                profile.update({"pkts_num_trig_egr_drp": eg_lossy_que_min + eg_avail_share_buf})

    def calc_param_for_lossy_queue_1(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                     pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                     eg_avail_share_buf, selected_profile):
        for que_profile in ["lossy_queue_1"]:
            profile = self.qos_params[self.speed_cable_len][que_profile]

            default_margin = 4
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                self.msg('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_trig_egr_drp" not in profile or \
                    profile["pkts_num_trig_egr_drp"] != eg_lossy_que_min + eg_avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_egr_drp"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_trig_egr_drp", -1),
                    eg_lossy_que_min + eg_avail_share_buf))
                profile.update({"pkts_num_trig_egr_drp": eg_lossy_que_min + eg_avail_share_buf})

    def calc_param_for_wm_pg_headroom(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                      pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                      eg_avail_share_buf, selected_profile):
        for pg_profile in ["wm_pg_headroom"]:
            profile = self.qos_params[self.speed_cable_len][pg_profile]

            default_margin = 4
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                self.msg('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_trig_pfc" not in profile or profile["pkts_num_trig_pfc"] != pg_min + avail_share_buf:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_pfc"], pg_min + avail_share_buf))
                profile.update({"pkts_num_trig_pfc": pg_min + avail_share_buf})

            if "pkts_num_trig_ingr_drp" not in profile or \
                    profile["pkts_num_trig_ingr_drp"] != pg_min + avail_share_buf + pg_hdrm:
                self.msg('Update qos_params[{}][{}]["pkts_num_trig_ingr_drp"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_ingr_drp"],
                    pg_min + avail_share_buf + pg_hdrm))
                profile.update({"pkts_num_trig_ingr_drp": pg_min + avail_share_buf + pg_hdrm})


    def pick_test_ports(self, pipe):
        test_ports = [entry['testPortId'] for entry in self.cfg['bcm_pipe_ports'][pipe] if entry['linkstate'] == 'up']
        test_ports.sort()
        # important: only use test ports which are in self.testPortIds which is available for test
        return [port for port in test_ports if port in self.testPortIds]


    def calc_param_for_hdrm_pool_size(self, pg_min, total_share_buf, buf_mode, buf_threshold, avail_share_buf,
                                      pg_reset_offset, pg_hdrm, eg_lossless_que_min, eg_lossy_que_min,
                                      eg_avail_share_buf, selected_profile):
        total_hdrm_size = self.get_total_Headroom_pool_size()
        total_pg_numbers = int((total_hdrm_size + pg_hdrm - 1) / pg_hdrm)
        last_pg_hdrm_size = total_hdrm_size - (total_pg_numbers - 1) * pg_hdrm

        pgs = [3, 4] # TODO: need to get accurate PGs from "buffer_pg"
        pg_number_per_port = len(pgs)
        total_test_port_number = int((total_pg_numbers + pg_number_per_port - 1) / pg_number_per_port)

        dscps = [3, 4] # TODO: need to get accurate DSCPs from "tc_to_pg_map" and "dscp_to_tc_map" table

        available_share_buf_size = []
        for _ in range(total_pg_numbers):
            available_share_buf_size.append(self.calc_available_share_buffer_size(
                total_share_buf - sum(available_share_buf_size), buf_mode, buf_threshold))

        # choose test port for sai_qos_tests.HdrmPoolSizeTest
        pipes = list(self.cfg['bcm_pipe_ports'].keys())
        # for "TH" asic, prefer pipe 3, since its ingress port and egress port are in same mmu slice
        # so sort pipe by reverse order, and then pipe 3 will be selected first
        pipes.sort(reverse=True)
        for pipe in pipes:
            test_ports = self.pick_test_ports(pipe)
            if len(test_ports) >= total_test_port_number + 1:
                break
            test_ports = None

        if test_ports is not None:
            dst_port_id = test_ports[0]
            src_port_ids = []
            for idx in range(1, 1 + total_test_port_number):
                src_port_ids.append(test_ports[idx])

        for hdrm_profile in ['hdrm_pool_size']:
            if hdrm_profile not in self.qos_params[self.speed_cable_len]:
                continue
            profile = self.qos_params[self.speed_cable_len][hdrm_profile]
            if test_ports is None:
                self.msg('Clear qos_params[{}][{}]["src_port_ids"], since no enough test ports'.format(
                    self.speed_cable_len, hdrm_profile))
                profile.update({"src_port_ids": []})
                return

            # Don't use "pkts_num_trig_pfc" anymore,
            # since they cannot support degressive share buffer in dynamic mode.
            # Here, introduce "pkts_num_trig_pfc_multi" to replace "pkts_num_trig_pfc".
            # but, to be backward compatible, still assige a fake value to "pkts_num_trig_pfc"
            pfc_thresholds = [x + pg_min for x in available_share_buf_size]
            self.msg('Update qos_params[{}][{}]["pkts_num_trig_pfc_multi"] from {} to {}'.format(
                self.speed_cable_len, hdrm_profile, profile.get("pkts_num_trig_pfc_multi", 'N/A'), pfc_thresholds))
            profile.update({"pkts_num_trig_pfc_multi": pfc_thresholds})
            profile.update({"pkts_num_trig_pfc": pfc_thresholds[0]})

            # update "pkts_num_hdrm_full" if necessary
            if 'pkts_num_hdrm_full' not in profile or profile['pkts_num_hdrm_full'] != pg_hdrm:
                self.msg('Update qos_params[{}][{}]["pkts_num_hdrm_full"] from {} to {}'.format(
                    self.speed_cable_len, hdrm_profile, profile.get("pkts_num_hdrm_full", 'N/A'), pg_hdrm))
                profile.update({"pkts_num_hdrm_full": pg_hdrm})

            # update "pkts_num_hdrm_partial" if necessary
            if 'pkts_num_hdrm_partial' not in profile or profile['pkts_num_hdrm_partial'] != last_pg_hdrm_size:
                self.msg('Update qos_params[{}][{}]["pkts_num_hdrm_partial"] from {} to {}'.format(
                    self.speed_cable_len, hdrm_profile, profile.get("pkts_num_hdrm_partial", 'N/A'),
                    last_pg_hdrm_size))
                profile.update({"pkts_num_hdrm_partial": last_pg_hdrm_size})

            # update "pgs_num" if necessary
            if 'pgs_num' not in profile or profile['pgs_num'] != total_pg_numbers:
                self.msg('Update qos_params[{}][{}]["pgs_num"] from {} to {}'.format(
                    self.speed_cable_len, hdrm_profile, profile.get("pgs_num", 'N/A'), total_pg_numbers))
                profile.update({"pgs_num": total_pg_numbers})

            # update "pgs"
            self.msg('Update qos_params[{}][{}]["pgs"] from {} to {}'.format(
                self.speed_cable_len, hdrm_profile, profile.get("pgs", 'N/A'), pgs))
            profile.update({"pgs": pgs})

            # update "dscps"
            self.msg('Update qos_params[{}][{}]["dscps"] from {} to {}'.format(
                self.speed_cable_len, hdrm_profile, profile.get("dscps", 'N/A'), dscps))
            profile.update({"dscps": dscps})

            # update "dst_port_id" if necessary
            if 'dst_port_id' not in profile or profile['dst_port_id'] != dst_port_id:
                self.msg('Update qos_params[{}][{}]["dst_port_id"] from {} to {}'.format(
                    self.speed_cable_len, hdrm_profile, profile.get("dst_port_id", 'N/A'), dst_port_id))
                profile.update({"dst_port_id": dst_port_id})

            # update "src_port_ids"
            self.msg('Update qos_params[{}][{}]["src_port_ids"] from {} to {}'.format(
                self.speed_cable_len, hdrm_profile, profile.get("src_port_ids", 'N/A'), src_port_ids))
            profile.update({"src_port_ids": src_port_ids})

            # update "margin" if necessary
            headroom_margin = 4
            if 'margin' not in profile or profile['margin'] < headroom_margin:
                self.msg('Update qos_params[{}][{}]["margin"] from {} to {}'.format(
                    self.speed_cable_len, hdrm_profile, profile.get("margin", 'N/A'), headroom_margin))
                profile.update({"margin": headroom_margin})
