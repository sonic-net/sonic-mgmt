'''
generate and update qos params for brcm platform
'''

import logging
import re


logger = logging.getLogger(__name__)


class QosParamBroadcom(object):

    def __init__(self,
                 qos_params,
                 asic_type,
                 speed_cable_len,
                 dutConfig,
                 ingressLosslessProfile,
                 ingressLossyProfile,
                 egressLosslessProfile,
                 egressLossyProfile,
                 sharedHeadroomPoolSize,
                 dualTor,
                 dutTopo,
                 bufferConfig,
                 dutHost,
                 testbedTopologyName,
                 verbose=True):

        if verbose:
            logger.info('Dump input options of QosParamBroadcom')
            logger.info('qos_params {}'.format(qos_params))
            logger.info('asic_type {}'.format(asic_type))
            logger.info('speed_cable_len {}'.format(speed_cable_len))
            logger.info('dutConfig {}'.format(dutConfig))
            logger.info('ingressLosslessProfile {}'.format(ingressLosslessProfile))
            logger.info('ingressLossyProfile {}'.format(ingressLossyProfile))
            logger.info('egressLosslessProfile {}'.format(egressLosslessProfile))
            logger.info('egressLossyProfile {}'.format(egressLossyProfile))
            logger.info('sharedHeadroomPoolSize {}'.format(sharedHeadroomPoolSize))
            logger.info('dualTor {}'.format(dualTor))
            logger.info('dutTopo {}'.format(dutTopo))
            logger.info('bufferConfig: {}'.format(bufferConfig))
            logger.info('testbedTopologyName: {}'.format(testbedTopologyName))

        self.asic_param_dic = {
            'td2': {
                'cell_size': 208,
                'xpe_count': 1
            },
            'td3': {
                'cell_size': 256,
                'xpe_count': 1
            },
            'th': {
                'cell_size': 208,
                'xpe_count': 4
            },
            'th2': {
                'cell_size': 208,
                'xpe_count': 4
            },
            'th3': {
                'cell_size': 208,
                'xpe_count': 2
            }
        }
        self.asic_type = asic_type
        self.cell_size = self.asic_param_dic[asic_type]['cell_size']
        self.xpe_count = self.asic_param_dic[asic_type]['xpe_count']
        self.speed_cable_len = speed_cable_len
        self.qos_params = qos_params
        self.ingressLosslessProfile = ingressLosslessProfile
        self.ingressLossyProfile = ingressLossyProfile
        self.egressLosslessProfile = egressLosslessProfile
        self.egressLossyProfile = egressLossyProfile
        self.dutConfig = dutConfig
        self.dualTor = dualTor
        self.dutTopo = dutTopo
        self.bufferConfig = bufferConfig
        self.dutHost = dutHost
        self.testbedTopologyName = testbedTopologyName
        self.verbose = verbose
        self.asicConfig = None
        if self.dutHost != None:
            self.asicConfig = self.collect_asic_config(self.dutHost)


    def collect_asic_config(self, duthost):
        asicConfig = {}
        try:
            output = duthost.shell('bcmcmd "g THDI_BUFFER_CELL_LIMIT_SP"', module_ignore_errors=True)
            logger.info('Read ASIC THDI_BUFFER_CELL_LIMIT_SP register, output {}'.format(output))
            for line in output['stdout'].replace('\r', '\n').split('\n'):
                if line:
                    m = re.match('THDI_BUFFER_CELL_LIMIT_SP\(0\).*\<LIMIT=(\S+)\>', line)
                    if m:
                        asicConfig['ingress_shared_limit_sp0'] = int(m.group(1), 0)
                        break

            output = duthost.shell('bcmcmd "g MMU_THDM_DB_POOL_SHARED_LIMIT"', module_ignore_errors=True)
            logger.info('Read ASIC MMU_THDM_DB_POOL_SHARED_LIMIT register, output {}'.format(output))
            count = 0
            for line in output['stdout'].replace('\r', '\n').split('\n'):
                if line:
                    m = re.match('MMU_THDM_DB_POOL_SHARED_LIMIT\(([01])\).*\]\=(\S+)', line)
                    if m:
                        asicConfig['egress_shared_limit_sp{}'.format(m.group(1))] = int(m.group(2), 0)
                        count += 1
                        if count == 2:
                            break
        except:
            logger.info('Failed to read and parse ASIC THDI_BUFFER_CELL_LIMIT_SP/MMU_THDM_DB_POOL_SHARED_LIMIT register')
        logger.info('ASIC buffer config {}'.format(asicConfig))
        return asicConfig

    def run(self):
        self.prepare_default_parameters()
        self.calculate_parameters()
        logger.info('Calculation of qos_params {}'.format(self.qos_params))
        return self.qos_params


    def get_similar_speed_cable_length(self, must_profile=None):

        def compare_speed_cable_len(a, b):
            # (speed, len)
            if a[0] < b[0]:
                return -1
            elif a[0] > b[0]:
                return 1
            else:
                if a[1] < b[1]:
                    return -1
                elif a[1] > b[1]:
                    return 1
                else:
                    return 0

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
            logger.info('qos parameter must has one similar speed_cable_len at least (must_profile={})'.format(must_profile))
            return None

        speed_length_list.sort(cmp=compare_speed_cable_len)
        this_index = speed_length_list.index((speed, length))
        ref_index = this_index + 1 if this_index + 1 < len(speed_length_list) else this_index - 1
        ref_speed_len = '{}_{}m'.format(speed_length_list[ref_index][0], speed_length_list[ref_index][1])
        return ref_speed_len


    def create_default_speed_cable_length_parameter(self):
        similar_speed_len = self.get_similar_speed_cable_length()
        if similar_speed_len != None:
            self.qos_params[self.speed_cable_len] = self.qos_params[similar_speed_len]
            logger.info('Clone default speed cable length parameters from qos_params[{}] to qos_params[{}]'.format(similar_speed_len, self.speed_cable_len))
        else:
            logger.info("qos_params don't support {} parameters".format(self.speed_cable_len))


    def create_default_xon_parameter(self, xon_profile):
        self.qos_params[self.speed_cable_len][xon_profile] = self.qos_params[xon_profile]
        logger.info('Clone default xon parameters from qos_params[{}] to qos_params[{}][{}]'.format(xon_profile, self.speed_cable_len, xon_profile))


    def create_default_headroom_pool_size_parameter(self, hdrm_profile):
        if hdrm_profile in self.qos_params:
            self.qos_params[self.speed_cable_len][hdrm_profile] = self.qos_params[hdrm_profile]
            logger.info('Clone default headroom pool size parameters from qos_params[{}] to qos_params[{}][{}]'.format(hdrm_profile, self.speed_cable_len, hdrm_profile))
        else:
            logger.info("qos_params don't support headroom pool size parameters")

    def create_default_pg_shared_watermark_parameter(self, pg_profile):
        self.qos_params[self.speed_cable_len][pg_profile] = self.qos_params[pg_profile]
        logger.info('Clone default PG shared watermark parameters from qos_params[{}] to qos_params[{}][{}]'.format(pg_profile, self.speed_cable_len, pg_profile))


    def create_default_queue_shared_watermark_parameter(self, que_profile):
        self.qos_params[self.speed_cable_len][que_profile] = self.qos_params[que_profile]
        logger.info('Clone default queue shared watermark parameters from qos_params[{}] to qos_params[{}][{}]'.format(que_profile, self.speed_cable_len, que_profile))


    def create_lossy_queue_parameter(self, que_profile):
        if que_profile in self.qos_params:
            # get default value from upper layer
            self.qos_params[self.speed_cable_len][que_profile] = self.qos_params[que_profile]
            logger.info('Clone default lossy queue parameters from qos_params[{}] to qos_params[{}][{}]'.format(que_profile, self.speed_cable_len, que_profile))
        else:
            # get default value from similar speed/length
            similar_speed_len = self.get_similar_speed_cable_length(que_profile)
            if similar_speed_len != None:
                self.qos_params[self.speed_cable_len][que_profile] = self.qos_params[similar_speed_len][que_profile]
                logger.info('Clone default lossy queue parameters from qos_params[{}][{}] to qos_params[{}][{}]'.format(similar_speed_len, que_profile, self.speed_cable_len, que_profile))
            else:
                logger.info("qos_params don't support lossy queue parameters")


    def create_pg_headroom_parameter(self, pg_profile):
        if pg_profile in self.qos_params:
            # get default value from upper layer
            self.qos_params[self.speed_cable_len][pg_profile] = self.qos_params[pg_profile]
            logger.info('Clone default PG headroom parameters from qos_params[{}] to qos_params[{}][{}]'.format(pg_profile, self.speed_cable_len, pg_profile))
        else:
            # get default value from similar speed/length
            similar_speed_len = self.get_similar_speed_cable_length(pg_profile)
            if similar_speed_len != None:
                self.qos_params[self.speed_cable_len][pg_profile] = self.qos_params[similar_speed_len][pg_profile]
                logger.info('Clone default PG headroom parameters from qos_params[{}][{}] to qos_params[{}][{}]'.format(similar_speed_len, pg_profile, self.speed_cable_len, pg_profile))
            else:
                logger.info("qos_params don't support PG headroom parameters")


    def prepare_default_parameters(self):
        if self.speed_cable_len not in self.qos_params:
            self.create_default_speed_cable_length_parameter()

        for xon_profile in ["xon_1", "xon_2"]:
            if xon_profile not in self.qos_params[self.speed_cable_len]:
                self.create_default_xon_parameter(xon_profile)

        # for hdrm_profile in ['hdrm_pool_size']:
        #     if hdrm_profile not in self.qos_params[self.speed_cable_len]:
        #         self.create_default_headroom_pool_size_parameter(hdrm_profile)

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
            if 'pkts_num_margin' not in self.qos_params[self.speed_cable_len][profile] or self.qos_params[self.speed_cable_len][profile]['pkts_num_margin'] < default_margin:
                self.qos_params[self.speed_cable_len][profile].update({'pkts_num_margin': default_margin})
                logger.info('Add/Increase default margin parameters for qos_params[{}][{}] to value {}'.format(self.speed_cable_len, profile, default_margin))


    def calculate_parameters(self):

        def byte_to_cell(bytes):
            return (int(bytes) + self.cell_size - 1) // self.cell_size

        def extract_profile_name(fullname):
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

        def calc_avaiable_shared_buffer(shared_buffer_cells, buffer_pool, buffer_profile):
            avaiable_shared_buffer_cells = 0
            if buffer_pool['mode'] == 'dynamic':
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
                th = int(buffer_profile['dynamic_th'])
                x = 0
                if th < 0:
                    th *= -1
                    x = shared_buffer_cells // (2 ** th + 1)
                else:
                    x = shared_buffer_cells * (2 ** th) // (2 ** th + 1)
                avaiable_shared_buffer_cells = x
            else:
                assert False, 'TODO: so far, not support to calculate avaiable shared buffer for static mode'
            return avaiable_shared_buffer_cells


        # calculate ingress PG min
        ingress_pg_min_cells = byte_to_cell(self.ingressLosslessProfile['size'])

        # calculate ingress shared buffer
        ingress_lossless_pool = self.bufferConfig['BUFFER_POOL']['ingress_lossless_pool']
        # th/th2/th3's shared buffer = ingress_lossless_pool.size / xpe_count
        ingress_shared_buffer_cells = byte_to_cell(ingress_lossless_pool['size']) // self.xpe_count
        debug_message = 'shared_buffer = ingress_lossless_pool.size (bytes {}|cells {} // {})'.format(ingress_lossless_pool['size'], byte_to_cell(ingress_lossless_pool['size']), self.xpe_count)

        if self.asic_type in ['td2', 'td3']:
            # td2/td3's shared buffer = ingress_lossless_pool.size
            #                         - ingress_lossless_pool.xoff
            #                         - (egress_lossless_profile.size * total egress lossless queue number)
            #                         - (egress_lossy_profile.size * total egress lossy queue number)
            #                         - (pg_lossless_profile.size * total lossless buffer pg number)
            egress_profiles = {}
            egress_profiles['egress_lossless_profile'] = self.bufferConfig['BUFFER_PROFILE']['egress_lossless_profile']
            egress_profiles['egress_lossy_profile'] = self.bufferConfig['BUFFER_PROFILE']['egress_lossy_profile']
            pg_lossless_profiles = {}
            for prof_name, prof_value in self.bufferConfig['BUFFER_PROFILE'].items():
                if re.search('pg_lossless_(.*)_profile', prof_name):
                    pg_lossless_profiles[prof_name] = prof_value

            ingress_shared_buffer_cells -= byte_to_cell(ingress_lossless_pool.get('xoff', 0))
            debug_message += '\n              - ingress_lossless_pool.xoff (bytes {}|cells {})'.format(ingress_lossless_pool.get('xoff', 0), byte_to_cell(ingress_lossless_pool.get('xoff', 0)))
            for que_name, que_profile in self.bufferConfig['BUFFER_QUEUE'].items():
                que_profile_name = extract_profile_name(que_profile['profile'])
                m = re.match('Ethernet\d+\|(\d)-(\d)', que_name)
                if m:
                    que_num = int(m.group(2)) - int(m.group(1)) + 1
                    ingress_shared_buffer_cells -= byte_to_cell(egress_profiles[que_profile_name]['size']) * que_num
                    debug_message += '\n              - que_name ({}): egress_profile.size (bytes {}|cells {}) * que_num ({})'.format(que_name, egress_profiles[que_profile_name]['size'], byte_to_cell(egress_profiles[que_profile_name]['size']), que_num)
                else:
                    m = re.match('Ethernet\d+\|\d', que_name)
                    if m and que_profile_name in egress_profiles:
                        que_num = 1
                        ingress_shared_buffer_cells -= byte_to_cell(egress_profiles[que_profile_name]['size']) * que_num
                        debug_message += '\n              - que_name ({}): egress_profile.size (bytes {}|cells {}) * que_num ({})'.format(que_name, egress_profiles[que_profile_name]['size'], byte_to_cell(egress_profiles[que_profile_name]['size']), que_num)

            for pg_name, pg_profile in self.bufferConfig['BUFFER_PG'].items():
                pg_profile_name = extract_profile_name(pg_profile['profile'])
                m = re.match('Ethernet\d+\|(\d)-(\d)', pg_name)
                if m:
                    pg_num = int(m.group(2)) - int(m.group(1)) + 1
                    ingress_shared_buffer_cells -= byte_to_cell(
                        pg_lossless_profiles[pg_profile_name]['size']) * pg_num
                    debug_message += '\n              - pg_name ({}): pg_lossless_profile.size (bytes {}|cells {}) * pg_num ({})'.format(pg_name, pg_lossless_profiles[pg_profile_name]['size'], byte_to_cell(pg_lossless_profiles[pg_profile_name]['size']), pg_num)
                else:
                    m = re.match('Ethernet\d+\|\d', pg_name)
                    if m and pg_profile_name in pg_lossless_profiles:
                        pg_num = 1
                        ingress_shared_buffer_cells -= byte_to_cell(pg_lossless_profiles[pg_profile_name]['size']) * pg_num
                        debug_message += '\n              - pg_name ({}): pg_lossless_profile.size (bytes {}|cells {}) * pg_num ({})'.format(pg_name, pg_lossless_profiles[pg_profile_name]['size'], byte_to_cell(pg_lossless_profiles[pg_profile_name]['size']), pg_num)

        if self.verbose:
            logger.info('debug message:\n{}'.format(debug_message))

        # calculate ingress avaiable shared buffer
        ingress_avaiable_shared_buffer_cells = calc_avaiable_shared_buffer(ingress_shared_buffer_cells, ingress_lossless_pool, self.ingressLosslessProfile)

        headroom_cells = byte_to_cell(self.ingressLosslessProfile['xoff'])
        pg_reset_offset_cells = byte_to_cell(self.ingressLosslessProfile['xon_offset'])
        if self.asic_type == 'td2':
            # According to test on td2 ASIC, PG min equal half of pg_reset_offset
            # hardcode here now, do more investigation later, and then refact it
            ingress_pg_min_cells = pg_reset_offset_cells // 2

        logger.info('Ingress calculation: ingress_pg_min_cells {}, ingress_avaiable_shared_buffer_cells {}, ingress_shared_buffer_cells(calc) {}, headroom_cells {}, pg_reset_offset_cells {}'.format(
            ingress_pg_min_cells, ingress_avaiable_shared_buffer_cells, ingress_shared_buffer_cells, headroom_cells, pg_reset_offset_cells))

        # workaround for inaccureate ingress shared buffer capacity
        if 'ingress_shared_limit_sp0' in self.asicConfig and ingress_shared_buffer_cells != self.asicConfig['ingress_shared_limit_sp0']:
            ingress_avaiable_shared_buffer_cells = calc_avaiable_shared_buffer(self.asicConfig['ingress_shared_limit_sp0'], ingress_lossless_pool, self.ingressLosslessProfile)
            logger.info('Workaround ingress calculation: ingress_pg_min_cells {}, ingress_avaiable_shared_buffer_cells {}, ingress_shared_buffer_cells(reg) {}, headroom_cells {}, pg_reset_offset_cells {}'.format(
                ingress_pg_min_cells, ingress_avaiable_shared_buffer_cells, self.asicConfig['ingress_shared_limit_sp0'], headroom_cells, pg_reset_offset_cells))

        # calculate egress lossless que min
        egress_lossless_que_min_cells = byte_to_cell(self.egressLosslessProfile['size'])
        logger.info('Egress lossless calculation: egress_lossless_que_min_cells {}'.format(egress_lossless_que_min_cells))

        # calculate egress lossy que min
        egress_lossy_que_min_cells = byte_to_cell(self.egressLossyProfile['size'])

        # calculate egress lossy shared buffer
        egress_lossy_pool = self.bufferConfig['BUFFER_POOL']['egress_lossy_pool']
        egress_lossy_shared_buffer_cells = byte_to_cell(egress_lossy_pool['size']) // self.xpe_count

        # calculate egress lossy avaiable shared buffer
        egress_lossy_avaiable_shared_buffer_cells = calc_avaiable_shared_buffer(egress_lossy_shared_buffer_cells, egress_lossy_pool, self.egressLossyProfile)
        logger.info('Egress lossy calculation: egress_lossy_que_min_cells {}, egress_lossy_avaiable_shared_buffer_cells {}, egress_lossy_shared_buffer_cells(calc) {}'.format(
            egress_lossy_que_min_cells, egress_lossy_avaiable_shared_buffer_cells, egress_lossy_shared_buffer_cells))

        # workaround for inaccureate egress lossy shared buffer capacity
        # egress lossy pool size is smaller than egress lossless pool
        egress_shared_limit_sp0 = self.asicConfig.get('egress_shared_limit_sp0', 0)
        egress_shared_limit_sp1 = self.asicConfig.get('egress_shared_limit_sp1', 0)
        egress_lossy_shared_limit_sp = egress_shared_limit_sp0
        if egress_lossy_shared_limit_sp == 0:
            egress_lossy_shared_limit_sp = egress_shared_limit_sp1
        elif 0 < egress_shared_limit_sp1 < egress_lossy_shared_limit_sp:
            egress_lossy_shared_limit_sp = egress_shared_limit_sp1
        if egress_lossy_shared_limit_sp > 0 and ingress_shared_buffer_cells != egress_lossy_shared_limit_sp:
            egress_lossy_avaiable_shared_buffer_cells = calc_avaiable_shared_buffer(egress_lossy_shared_limit_sp, egress_lossy_pool, self.egressLossyProfile)
            logger.info('Workaround egress lossy calculation: egress_lossy_que_min_cells {}, egress_lossy_avaiable_shared_buffer_cells {}, egress_lossy_shared_buffer_cells(reg) {}'.format(
                egress_lossy_que_min_cells, egress_lossy_avaiable_shared_buffer_cells, egress_lossy_shared_limit_sp))

        # todo breakout case
        for xoff_profile in ["xoff_1", "xoff_2"]:
            profile = self.qos_params[self.speed_cable_len][xoff_profile]
            if profile["pkts_num_trig_pfc"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, xoff_profile, profile["pkts_num_trig_pfc"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells))
                profile["pkts_num_trig_pfc"] = ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells
            if profile["pkts_num_trig_ingr_drp"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_ingr_drp"] from {} to {}'.format(
                    self.speed_cable_len, xoff_profile, profile["pkts_num_trig_ingr_drp"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells))
                profile["pkts_num_trig_ingr_drp"] = ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells

        for xon_profile in ["xon_1", "xon_2"]:
            profile = self.qos_params[self.speed_cable_len][xon_profile]
            if profile["pkts_num_trig_pfc"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, xon_profile, profile["pkts_num_trig_pfc"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells))
                profile["pkts_num_trig_pfc"] = ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells
            if profile["pkts_num_dismiss_pfc"] != pg_reset_offset_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_dismiss_pfc"] from {} to {}'.format(
                    self.speed_cable_len, xon_profile, profile["pkts_num_dismiss_pfc"], pg_reset_offset_cells))
                profile["pkts_num_dismiss_pfc"] = pg_reset_offset_cells

        # for hdrm_profile in ['hdrm_pool_size']:
        #     if hdrm_profile not in self.qos_params[self.speed_cable_len]:
        #         continue

        #     profile = self.qos_params[self.speed_cable_len][hdrm_profile]
        #     if 'pkts_num_trig_pfc' not in profile or profile['pkts_num_trig_pfc'] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells:
        #         logger.info('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(self.speed_cable_len, hdrm_profile, profile.get("pkts_num_trig_pfc", -1), ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells))
        #         profile.update({"pkts_num_trig_pfc": ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells})

        #     if 'pkts_num_hdrm_full' not in profile or profile['pkts_num_hdrm_full'] != headroom_cells:
        #         logger.info('Update qos_params[{}][{}]["pkts_num_hdrm_full"] from {} to {}'.format(self.speed_cable_len, hdrm_profile, profile.get("pkts_num_hdrm_full", -1), headroom_cells))
        #         profile.update({"pkts_num_hdrm_full": headroom_cells})

        #     headroom_margin = 4
        #     if 'margin' not in profile or profile['margin'] < headroom_margin:
        #         logger.info('Update qos_params[{}][{}]["margin"] from {} to {}'.format(self.speed_cable_len, hdrm_profile, profile.get("margin", -1), headroom_margin))
        #         profile.update({"margin": headroom_margin})
        #     else:
        #         headroom_margin = profile['margin']

        #     if 'pkts_num_hdrm_partial' not in profile or profile['pkts_num_hdrm_partial'] != headroom_cells - headroom_margin * 2:
        #         logger.info('Update qos_params[{}][{}]["pkts_num_hdrm_partial"] from {} to {}'.format(self.speed_cable_len, hdrm_profile, profile.get("pkts_num_hdrm_partial", -1), headroom_cells - headroom_margin * 2))
        #         profile.update({"pkts_num_hdrm_partial": headroom_cells - headroom_margin * 2})

        #     if ingress_lossless_pool['mode'] == 'dynamic':
        #         logger.info('Update qos_params[{}][{}]["dynamic_threshold"] from {} to {}'.format(self.speed_cable_len, hdrm_profile, profile.get("dynamic_threshold", False), True))
        #         profile.update({"dynamic_threshold": True})


        for pg_profile in ["wm_pg_shared_lossless"]:
            profile = self.qos_params[self.speed_cable_len][pg_profile]
            if "pkts_num_trig_pfc" not in profile or profile["pkts_num_trig_pfc"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_pfc"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells))
                profile.update({"pkts_num_trig_pfc": ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != ingress_pg_min_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_fill_min"], ingress_pg_min_cells))
                profile.update({"pkts_num_fill_min": ingress_pg_min_cells})

        for pg_profile in ["wm_pg_shared_lossy"]:
            profile = self.qos_params[self.speed_cable_len][pg_profile]

            default_margin = 4
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                logger.info('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(self.speed_cable_len, pg_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != 0:
                logger.info('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_fill_min"], 0))
                profile.update({"pkts_num_fill_min": 0})

            if "pkts_num_trig_egr_drp" not in profile or profile["pkts_num_trig_egr_drp"] != egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_egr_drp"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_egr_drp"], egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells))
                profile.update({"pkts_num_trig_egr_drp": egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells})


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
                logger.info('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(self.speed_cable_len, que_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_trig_ingr_drp" not in profile or profile["pkts_num_trig_ingr_drp"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_ingr_drp"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile["pkts_num_trig_ingr_drp"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells))
                profile.update({"pkts_num_trig_ingr_drp": ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != egress_lossless_que_min_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile["pkts_num_fill_min"], egress_lossless_que_min_cells))
                profile.update({"pkts_num_fill_min": egress_lossless_que_min_cells})

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
                logger.info('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(self.speed_cable_len, que_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_fill_min" not in profile or profile["pkts_num_fill_min"] != egress_lossy_que_min_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_fill_min"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile["pkts_num_fill_min"], egress_lossy_que_min_cells))
                profile.update({"pkts_num_fill_min": egress_lossy_que_min_cells})

            if "pkts_num_trig_egr_drp" not in profile or profile["pkts_num_trig_egr_drp"] != egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_egr_drp"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_trig_egr_drp", -1), egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells))
                profile.update({"pkts_num_trig_egr_drp": egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells})


        for que_profile in ["lossy_queue_1"]:
            profile = self.qos_params[self.speed_cable_len][que_profile]

            default_margin = 4
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                logger.info('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(self.speed_cable_len, que_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_trig_egr_drp" not in profile or profile["pkts_num_trig_egr_drp"] != egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_egr_drp"] from {} to {}'.format(
                    self.speed_cable_len, que_profile, profile.get("pkts_num_trig_egr_drp", -1), egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells))
                profile.update({"pkts_num_trig_egr_drp": egress_lossy_que_min_cells + egress_lossy_avaiable_shared_buffer_cells})


        for pg_profile in ["wm_pg_headroom"]:
            profile = self.qos_params[self.speed_cable_len][pg_profile]

            default_margin = 4
            if 'pkts_num_margin' not in profile or profile['pkts_num_margin'] < default_margin:
                logger.info('Update qos_params[{}][{}]["pkts_num_margin"] from {} to {}'.format(self.speed_cable_len, pg_profile, profile.get("pkts_num_margin", -1), default_margin))
                profile.update({"pkts_num_margin": default_margin})

            if "pkts_num_trig_pfc" not in profile or profile["pkts_num_trig_pfc"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_pfc"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_pfc"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells))
                profile.update({"pkts_num_trig_pfc": ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells})

            if "pkts_num_trig_ingr_drp" not in profile or profile["pkts_num_trig_ingr_drp"] != ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells:
                logger.info('Update qos_params[{}][{}]["pkts_num_trig_ingr_drp"] from {} to {}'.format(
                    self.speed_cable_len, pg_profile, profile["pkts_num_trig_ingr_drp"], ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells))
                profile.update({"pkts_num_trig_ingr_drp": ingress_pg_min_cells + ingress_avaiable_shared_buffer_cells + headroom_cells})

