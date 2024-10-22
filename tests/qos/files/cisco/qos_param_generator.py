import logging
from tests.qos.qos_sai_base import QosSaiBase
logger = logging.getLogger(__name__)


class QosParamCisco(object):
    SMALL_SMS_PLATFORMS = ["x86_64-8102_64h_o-r0"]
    DEEP_BUFFER_PLATFORMS = ["x86_64-8111_32eh_o-r0"]
    LOG_PREFIX = "QosParamCisco: "

    def __init__(self, qos_params, duthost, dutAsic, topo, bufferConfig, portSpeedCableLength):
        '''
        Initialize parameters all tests will use
        '''
        self.qos_params = qos_params
        self.dutAsic = dutAsic
        self.bufferConfig = bufferConfig
        self.portSpeedCableLength = portSpeedCableLength
        if self.portSpeedCableLength not in self.qos_params:
            self.qos_params[self.portSpeedCableLength] = {}
        if "pkts_num_leak_out" not in self.qos_params[self.portSpeedCableLength]:
            # Provide a global default of 0 if not specified
            self.qos_params[self.portSpeedCableLength]["pkts_num_leak_out"] = 0
        self.ingress_pool_size = None
        self.ingress_pool_headroom = None
        if "ingress_lossless_pool" in self.bufferConfig["BUFFER_POOL"]:
            self.ingress_pool_size = int(self.bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"])
            self.ingress_pool_headroom = int(self.bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["xoff"])
        self.egress_pool_size = None
        if "egress_lossy_pool" in self.bufferConfig["BUFFER_POOL"]:
            self.egress_pool_size = int(self.bufferConfig["BUFFER_POOL"]["egress_lossy_pool"]["size"])
        # Find SMS size
        self.is_large_sms = duthost.facts['platform'] not in self.SMALL_SMS_PLATFORMS
        self.is_deep_buffer = duthost.facts['platform'] in self.DEEP_BUFFER_PLATFORMS
        # Lossless profile attributes
        lossless_prof_name = "pg_lossless_{}_profile".format(self.portSpeedCableLength)
        lossless_prof = self.bufferConfig["BUFFER_PROFILE"][lossless_prof_name]
        # Init device parameters
        # TODO: topo-t2 support
        # Per-asic variable description:
        # 0: Max queue depth in bytes
        # 1: Flow control configuration on this device, either 'separate' or 'shared'.
        # 2: Number of packets margin for the quantized queue watermark tests.
        asic_params = {"gb": (6144000, "separate", 3072, 384, 1350, 2, 3),
                       "gr": (24576000, "shared", 18000, 384, 1350, 2, 3),
                       "gr2": (None, None, 1, 512, 64, 1, 3)}
        self.supports_autogen = dutAsic in asic_params and topo == "topo-any"
        if self.supports_autogen:
            # Asic dependent parameters
            (max_queue_depth,
             self.flow_config,
             self.q_wmk_margin,
             self.buffer_size,
             self.preferred_packet_size,
             self.lossless_pause_tuning_pkts,
             self.lossless_drop_tuning_pkts) = asic_params[dutAsic]

            # Calculate attempted pause threshold
            if "dynamic_th" in lossless_prof:
                dynamic_th = int(lossless_prof["dynamic_th"])
                alpha = 2 ** dynamic_th
                if dutAsic == "gr2":
                    attempted_pause = int((self.ingress_pool_size - self.ingress_pool_headroom) * alpha / (1. + alpha))
                else:
                    attempted_pause = alpha * self.ingress_pool_size
            elif "static_th" in lossless_prof:
                attempted_pause = int(lossless_prof["static_th"])
            else:
                assert False, "Lossless profile had no dynamic_th or static_th: {}".format(lossless_prof)

            # Calculate real lossless/lossy thresholds while accounting for maxes
            if max_queue_depth is None:
                dynamic_th = int(self.bufferConfig["BUFFER_PROFILE"]["egress_lossy_profile"]["dynamic_th"])
                alpha = 2 ** dynamic_th
                theoretical_drop_thr = int(self.egress_pool_size * alpha / (1. + alpha))
                self.lossy_drop_bytes = (self.gr_get_hw_thr_buffs(theoretical_drop_thr // self.buffer_size) *
                                         self.buffer_size)
                self.log("Lossy queue drop theoretical {} adjusted to {}".format(theoretical_drop_thr,
                                                                                 self.lossy_drop_bytes))
                pre_pad_pause = attempted_pause
            else:
                self.lossy_drop_bytes = max_queue_depth
                max_drop = max_queue_depth * (1 - 0.0748125)
                max_pause = int(max_drop - int(lossless_prof["xoff"]))
                self.log("Max pause thr bytes:       {}".format(max_pause))
                pre_pad_pause = min(attempted_pause, max_pause)

            if dutAsic in ["gr", "gr2"]:
                refined_pause_thr = (self.gr_get_hw_thr_buffs(pre_pad_pause // self.buffer_size) *
                                     self.buffer_size)
                self.log("{} pre-pad pause threshold changed from {} to {}".format(dutAsic, pre_pad_pause,
                                                                                   refined_pause_thr))
                pre_pad_pause = refined_pause_thr

            if dutAsic == "gr2":
                # Has more precise HR accounting based on packet size. Calculate the real
                # number of packets and convert to what later calculations will treat as a
                # 512 buffer size.
                mini_buffer_size = 32
                overhead_mini_buffers = 2
                mini_buffers_per_packet = (self.get_buffer_occupancy(self.preferred_packet_size, mini_buffer_size) +
                                           overhead_mini_buffers)
                self.log("Calculated {} mini buffers per packet of size {}".format(mini_buffers_per_packet,
                                                                                   self.preferred_packet_size))
                mini_buffer_hr = int(int(lossless_prof["xoff"]) // mini_buffer_size)
                packets_hr = int(mini_buffer_hr // mini_buffers_per_packet)
                # Need to parametrize test with HR scaled by full buffer size so the test
                # can divide by buffer size later to get the correct packet count.
                advertised_hr = packets_hr * self.buffer_size
                pre_pad_drop = pre_pad_pause + advertised_hr
            else:
                pre_pad_drop = pre_pad_pause + int(lossless_prof["xoff"])

            # Tune thresholds with padding for precise testing
            buffer_occupancy = self.get_buffer_occupancy(self.preferred_packet_size)
            self.pause_thr = pre_pad_pause + (self.lossless_pause_tuning_pkts * buffer_occupancy * self.buffer_size)
            self.lossless_drop_thr = (pre_pad_drop + (self.lossless_drop_tuning_pkts * buffer_occupancy *
                                                      self.buffer_size))

            # Hysteresis calculations depending on asic
            if dutAsic == "gr2":
                assert "xon_offset" in lossless_prof, "gr2 missing xon_offset from lossless buffer profile"
                xon_offset = int(lossless_prof["xon_offset"])
                self.log("Pre-pad hysteresis bytes: {}".format(xon_offset))
                # Determine difference between pause thr and hysteresis thr.
                # Use raw pause thr for calculation.
                xon_thr = (self.gr_get_hw_thr_buffs((pre_pad_pause - xon_offset) // self.buffer_size) *
                           self.buffer_size)
                # Use padded value for precise packet determination
                self.hysteresis_bytes = self.pause_thr - xon_thr
            else:
                if self.is_deep_buffer:
                    self.reduced_pause_thr = 10 * (1024 ** 2) * (2 ** dynamic_th)
                elif self.is_large_sms:
                    self.reduced_pause_thr = 3 * (1024 ** 2)
                else:
                    self.reduced_pause_thr = 2.25 * (1024 ** 2)
                if dutAsic == "gr":
                    self.reduced_pause_thr = self.gr_get_hw_thr_buffs(self.reduced_pause_thr
                                                                      // self.buffer_size) * self.buffer_size
                self.log("Reduced pause thr bytes:   {}".format(self.reduced_pause_thr))
                self.hysteresis_bytes = int(self.pause_thr - self.reduced_pause_thr -
                                            (2 * self.buffer_size * buffer_occupancy))

            # Logging
            self.log("Attempted pause thr bytes: {}".format(attempted_pause))
            self.log("Pre-pad pause thr bytes:   {}".format(pre_pad_pause))
            self.log("Pause thr bytes:           {}".format(self.pause_thr))
            self.log("Hysteresis bytes: {}".format(self.hysteresis_bytes))
            self.log("Pre-pad drop thr bytes:    {}".format(pre_pad_drop))
            self.log("Drop thr bytes:            {}".format(self.lossless_drop_thr))
            self.config_facts = duthost.asic_instance().config_facts(source="running")["ansible_facts"]
            # DSCP value for lossy
            self.dscp_queue0 = self.get_one_dscp_from_queue(0)
            self.dscp_queue1 = self.get_one_dscp_from_queue(1)
            # DSCP, queue, weight list
            self.dscp_list, self.q_list, self.weight_list = self.get_dscp_q_weight_list()

    def get_one_dscp_from_queue(self, queue):
        '''
        Get one dscp value which is mapped to given queue
        '''
        dscp_to_tc_map = self.config_facts['DSCP_TO_TC_MAP']['AZURE']
        tc_to_queue_map = self.config_facts['TC_TO_QUEUE_MAP']['AZURE']
        queue = str(queue)
        tc = list(tc_to_queue_map.keys())[list(tc_to_queue_map.values()).index(queue)]
        dscp = list(dscp_to_tc_map.keys())[list(dscp_to_tc_map.values()).index(tc)]
        return int(dscp)

    def get_scheduler_cfg(self):
        '''
        Get scheduler configuration
        '''
        return self.config_facts['SCHEDULER']

    def get_queue_cfg(self):
        '''
        Get queue configuration of first interface
        '''
        queue_cfg = self.config_facts['QUEUE']
        interface = list(queue_cfg.keys())[0]
        return queue_cfg[interface]

    def get_queues_from_scheduler(self, scheduler):
        '''
        Get queue list which are mapped to given scheduler
        '''
        queue_list = []
        for q, value in self.get_queue_cfg().items():
            if scheduler == value['scheduler']:
                queue_list.append(int(q))
        return queue_list

    def get_scheduler_from_queue(self, queue):
        '''
        Get scheduler for given queue
        '''
        return self.get_queue_cfg()[str(queue)]["scheduler"]

    def get_queues_on_same_scheduler(self, queue):
        '''
        Get queue list on the same scheduler for given queue
        '''
        scheduler = self.get_scheduler_from_queue(queue)
        return self.get_queues_from_scheduler(scheduler)

    def get_queue_dscp_weight_dict(self):
        q_dscp_weight_dict = {}
        scheduler_cfg = self.get_scheduler_cfg()
        for q, value in self.get_queue_cfg().items():
            queue = int(q)
            scheduler = value['scheduler']
            q_dscp_weight_dict[queue] = {}
            q_dscp_weight_dict[queue]["dscp"] = self.get_one_dscp_from_queue(queue)
            q_dscp_weight_dict[queue]["weight"] = int(scheduler_cfg[scheduler]["weight"])
        return q_dscp_weight_dict

    def get_dscp_q_weight_list(self):
        dscp_list = []
        q_list = []
        weight_list = []
        q_dscp_weight_dict = self.get_queue_dscp_weight_dict()
        for queue, value in q_dscp_weight_dict.items():
            q_list.append(queue)
            weight_list.append(value["weight"])
            dscp_list.append(value["dscp"])
        return dscp_list, q_list, weight_list

    def run(self):
        '''
        Define parameters for each test.

        Each function takes common parameters and outputs to the relevant section of the
        self.qos_params structure.
        '''
        self.__define_shared_reservation_size()
        if not self.supports_autogen:
            return self.qos_params
        self.__define_pfc_xoff_limit()
        self.__define_pfc_xon_limit()
        self.__define_pg_shared_watermark()
        self.__define_buffer_pool_watermark()
        self.__define_q_shared_watermark()
        self.__define_lossy_queue_voq()
        self.__define_lossy_queue()
        self.__define_lossless_voq()
        self.__define_q_watermark_all_ports()
        self.__define_pg_drop()
        self.__define_wm_pg_headroom()
        self.__define_wrr()
        self.__define_wrr_chg()
        return self.qos_params

    def gr_get_mantissa_exp(self, thr):
        assert thr >= 0, "Expected non-negative threshold, not {}".format(thr)
        found = False
        exp = 1
        mantissa = 0
        reduced_thr = int(thr) >> 4
        further_reduced_thr = int(thr) >> 5
        for i in range(32):
            ith_bit = 1 << i
            if further_reduced_thr < ith_bit <= reduced_thr:
                mantissa = int(thr) // ith_bit
                exp = i
                found = True
                break
        if found:
            return mantissa, exp
        return None, None

    def gr2_get_mantissa_exp(self, thr):
        mantissa_len = 5
        exponent = max(thr.bit_length() - mantissa_len, 0)
        mantissa = thr >> exponent
        return mantissa, exponent

    def gr_get_hw_thr_buffs(self, thr):
        ''' thr must be in units of buffers '''
        if self.dutAsic == "gr":
            mantissa, exp = self.gr_get_mantissa_exp(thr)
        elif self.dutAsic == "gr2":
            mantissa, exp = self.gr2_get_mantissa_exp(thr)
        else:
            assert False, "Invalid asic {} for gr_get_hw_thr_buffs".format(self.dutAsic)
        if mantissa is None or exp is None:
            raise Exception("Failed to convert thr {}".format(thr))
        hw_thr = mantissa * (2 ** exp)
        return hw_thr

    def log(self, msg):
        logger.info("{}{}".format(self.LOG_PREFIX, msg))

    def write_params(self, label, params):
        self.log("Label {} autogenerated params {}".format(label, params))
        self.qos_params[self.portSpeedCableLength][label] = params

    def get_buffer_occupancy(self, packet_size, buffer_size=None):
        if buffer_size is None:
            buffer_size = self.buffer_size
        return (packet_size + buffer_size - 1) // buffer_size

    def should_autogen(self, parametrizations):
        '''
        Determines whether to autogenerate parameters on this platform.

        Asserts:
        - 'parametrizations' is a non-empty list of qos yaml param strings.
        - All parameter strings in the list must be either
          all in the qos yaml (top-level or per-port-speed) or not present.

        Returns whether all the below requirements are satisfied:
        - ASIC was provided basic required params at __init__ time (self.supports_autogen).
        - No parameters for these tests are present in the yaml file (yaml takes priority).
        '''
        assert len(parametrizations) > 0, "Invalid should_autogen invocation with empty list"
        param_in_yaml = [(param in self.qos_params or
                          param in self.qos_params[self.portSpeedCableLength])
                         for param in parametrizations]
        assert len(set(param_in_yaml)) == 1, \
            "QOS param generator requires params {} to have same qos.yaml presence".format(parametrizations)
        autogen = self.supports_autogen and not param_in_yaml[0]
        self.log("{} for test labels {}".format(
            "Autogenerating qos" if autogen else "Using qos yaml entries instead of autogen",
            parametrizations))
        return autogen

    def __mark_skip(self, testcase, reason):
        self.qos_params[testcase] = {}
        self.qos_params[testcase]["skip"] = reason

    def __define_shared_reservation_size(self):
        if self.ingress_pool_size is None or self.ingress_pool_headroom is None:
            skip_reason = "ingress_lossless_pool not defined, nothing to test"
            self.__mark_skip("shared_res_size_1", skip_reason)
            self.__mark_skip("shared_res_size_2", skip_reason)
            return
        if self.is_large_sms:
            if self.is_deep_buffer:
                res_1 = {"dscps": [self.dscp_queue0, self.dscp_queue0,
                                   self.dscp_queue1, self.dscp_queue1,
                                   3, 4, 3, 4, 3, 4, 3],
                         "pgs": [0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3],
                         "queues": [0, 0, 1, 1, 3, 4, 3, 4, 3, 4, 3],
                         "src_port_i": [0, 1, 0, 1, 0, 0, 1, 1, 2, 2, 4],
                         "dst_port_i": [5, 6, 7, 8, 5, 5, 6, 6, 7, 7, 8],
                         "pkt_counts": [9728, 9728, 9728, 9728, 3583, 6646, 6646, 1654, 1654, 979, 1],
                         "shared_limit_bytes": 92274816}
                res_2 = {"dscps": [3, 4, 3, 4, 3, 4, 3, 4],
                         "pgs": [3, 4, 3, 4, 3, 4, 3, 4],
                         "queues": [3, 4, 3, 4, 3, 4, 3, 4],
                         "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3],
                         "dst_port_i": [4, 4, 5, 5, 6, 6, 7, 7],
                         "pkt_counts": [11946, 11946, 11946, 11946, 2561, 2561, 1707, 1],
                         "shared_limit_bytes": 83886720}
            else:
                res_1 = {"dscps": [8, 8, 8, 8, 1, 1, 1, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                         "pgs": [0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                         "queues": [0, 0, 0, 0, 1, 1, 1, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                         "src_port_i": [0, 1, 2, 3, 0, 1, 2, 3, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5],
                         "dst_port_i": [6, 7, 8, 9, 6, 7, 8, 9, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11],
                         "pkt_counts": [3822, 3822, 3822, 3822, 3822, 3822, 3822, 3822, 2595, 2595, 2595, 2595,
                                        2038, 2038, 1014, 1014, 1014, 1014, 64, 1],
                         "shared_limit_bytes": 75497472}
                res_2 = {"dscps": [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3],
                         "pgs": [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3],
                         "queues": [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3],
                         "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8],
                         "dst_port_i": [9, 9, 10, 10, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6],
                         "pkt_counts": [3549, 3549, 3549, 3549, 3549, 3549, 3549, 3549, 3549, 3549, 2052, 2052,
                                        1286, 1286, 1286, 238, 1],
                         "shared_limit_bytes": 67109376}
        else:
            res_1 = {"dscps": [8, 8, 8, 8, 8, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                     "pgs": [0, 0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                     "queues": [0, 0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                     "src_port_i": [0, 1, 2, 3, 4, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5],
                     "dst_port_i": [6, 7, 8, 9, 10, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11],
                     "pkt_counts": [3413, 3413, 3413, 3413, 3413, 2389, 2389, 2389, 1526, 1526, 1392, 415,
                                    415, 415, 415, 42, 1],
                     "shared_limit_bytes": 46661760}
            res_2 = {"dscps": [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3],
                     "pgs": [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3],
                     "queues": [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3],
                     "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6],
                     "dst_port_i": [7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13],
                     "pkt_counts": [3527, 3527, 3527, 3527, 3527, 3527, 1798, 1798, 846, 687, 687, 328, 1],
                     "shared_limit_bytes": 41943552}
        try:
            self.qos_params["shared_res_size_1"].update(res_1)
            self.qos_params["shared_res_size_2"].update(res_2)
        except KeyError:
            skip_reason = "Shared Res Size Keys are not found, will be skipping test."
            self.__mark_skip("shared_res_size_1", skip_reason)
            self.__mark_skip("shared_res_size_2", skip_reason)

    def __define_pfc_xoff_limit(self):
        if not self.should_autogen(["xoff_1", "xoff_2"]):
            return
        packet_size = self.preferred_packet_size
        packet_buffs = self.get_buffer_occupancy(packet_size)
        for param_i, dscp_pg in [(1, 3), (2, 4)]:
            params = {"dscp": dscp_pg,
                      "ecn": 1,
                      "pg": dscp_pg,
                      "pkts_num_trig_pfc": self.pause_thr // self.buffer_size // packet_buffs,
                      "pkts_num_trig_ingr_drp": self.lossless_drop_thr // self.buffer_size // packet_buffs,
                      "packet_size": packet_size}
            if dscp_pg == 4:
                # Some control traffic maps to DSCP 4, increase margin.
                params["pkts_num_margin"] = 8
            self.write_params("xoff_{}".format(param_i), params)

    def __define_pfc_xon_limit(self):
        if not self.should_autogen(["xon_1", "xon_2"]):
            return
        packet_size = self.preferred_packet_size
        packet_buffs = self.get_buffer_occupancy(packet_size)
        for param_i, dscp_pg in [(1, 3), (2, 4)]:
            params = {"dscp": dscp_pg,
                      "ecn": 1,
                      "pg": dscp_pg,
                      "pkts_num_trig_pfc": (self.pause_thr // self.buffer_size // packet_buffs) - 1,
                      "pkts_num_hysteresis": self.hysteresis_bytes // self.buffer_size // packet_buffs,
                      "pkts_num_dismiss_pfc": 2,
                      "packet_size": packet_size}
            self.write_params("xon_{}".format(param_i), params)

    def __define_pg_shared_watermark(self):
        common_params = {"ecn": 1,
                         "pkts_num_fill_min": 0,
                         "pkts_num_margin": 4,
                         "packet_size": self.preferred_packet_size,
                         "cell_size": self.buffer_size}
        if self.should_autogen(["wm_pg_shared_lossless"]):
            lossless_params = common_params.copy()
            # In this context, pkts_num_trig_pfc is the maximal watermark value reachable
            # by sending lossless traffic, which includes the headroom. So the drop
            # threshold is used instead of the pause threshold.  The value passed is also
            # in units of buffers, since the final pkt send in the test divides by buffer
            # occupancy first.
            lossless_params.update({"dscp": 3,
                                    "pg": 3,
                                    "pkts_num_trig_pfc": (self.lossless_drop_thr // self.buffer_size)})
            self.write_params("wm_pg_shared_lossless", lossless_params)
        if self.should_autogen(["wm_pg_shared_lossy"]):
            lossy_params = common_params.copy()
            lossy_params.update({"dscp": self.dscp_queue0,
                                 "pg": 0,
                                 "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size})
            self.write_params("wm_pg_shared_lossy", lossy_params)

    def __define_buffer_pool_watermark(self):
        packet_size = self.preferred_packet_size
        packet_buffs = self.get_buffer_occupancy(packet_size)
        if self.should_autogen(["wm_buf_pool_lossless"]):
            lossless_params = {"dscp": 3,
                               "ecn": 1,
                               "pg": 3,
                               "queue": 3,
                               "pkts_num_fill_ingr_min": 0,
                               "pkts_num_trig_pfc": self.lossless_drop_thr // self.buffer_size // packet_buffs,
                               "cell_size": self.buffer_size,
                               "packet_size": packet_size}
            self.write_params("wm_buf_pool_lossless", lossless_params)
        if self.should_autogen(["wm_buf_pool_lossy"]):
            lossy_params = {"dscp": self.dscp_queue0,
                            "ecn": 1,
                            "pg": 0,
                            "queue": 0,
                            "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size // packet_buffs,
                            "pkts_num_fill_egr_min": 0,
                            "cell_size": self.buffer_size,
                            "packet_size": packet_size}
            self.write_params("wm_buf_pool_lossy", lossy_params)

    def __define_q_shared_watermark(self):
        if self.should_autogen(["wm_q_shared_lossless"]):
            lossless_params = {"dscp": 3,
                               "ecn": 1,
                               "queue": 3,
                               "pkts_num_fill_min": 0,
                               "pkts_num_trig_ingr_drp": self.lossless_drop_thr // self.buffer_size,
                               "pkts_num_margin": self.q_wmk_margin,
                               "cell_size": self.buffer_size}
            self.write_params("wm_q_shared_lossless", lossless_params)
        if self.should_autogen(["wm_q_shared_lossy"]):
            lossy_params = {"dscp": self.dscp_queue0,
                            "ecn": 1,
                            "queue": 0,
                            "pkts_num_fill_min": 0,
                            "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size,
                            "pkts_num_margin": self.q_wmk_margin,
                            "cell_size": self.buffer_size}
            self.write_params("wm_q_shared_lossy", lossy_params)

    def __define_lossy_queue_voq(self):
        if self.should_autogen(["lossy_queue_voq_1"]):
            params = {"dscp": self.dscp_queue0,
                      "ecn": 1,
                      "pg": 0,
                      "flow_config": self.flow_config,
                      "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": 64,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_voq_1", params)
        if self.should_autogen(["lossy_queue_voq_2"]):
            params = {"dscp": self.dscp_queue0,
                      "ecn": 1,
                      "pg": 0,
                      "flow_config": "shared",
                      "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": 64,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_voq_2", params)
        if self.should_autogen(["lossy_queue_voq_3"]):
            params = {"dscp": self.dscp_queue0,
                      "ecn": 1,
                      "pg": 0,
                      "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": self.preferred_packet_size,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_voq_3", params)

    def __define_lossy_queue(self):
        if self.should_autogen(["lossy_queue_1"]):
            params = {"dscp": self.dscp_queue0,
                      "ecn": 1,
                      "pg": 0,
                      "pkts_num_trig_egr_drp": self.lossy_drop_bytes // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": self.preferred_packet_size,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_1", params)

    def __define_lossless_voq(self):
        packet_size = self.preferred_packet_size
        packet_buffs = self.get_buffer_occupancy(packet_size)
        common_params = {"ecn": 1,
                         "pkts_num_margin": 4,
                         "packet_size": packet_size,
                         "pkts_num_trig_pfc": self.pause_thr // self.buffer_size // packet_buffs}

        if self.should_autogen(["lossless_voq_1"]):
            params = common_params.copy()
            params.update({"dscp": 3,
                           "pg": 3,
                           "num_of_flows": "multiple"})
            self.write_params("lossless_voq_1", params)

        if self.should_autogen(["lossless_voq_2"]):
            params = common_params.copy()
            params.update({"dscp": 4,
                           "pg": 4,
                           "num_of_flows": "multiple"})
            self.write_params("lossless_voq_2", params)

        if self.should_autogen(["lossless_voq_3"]):
            params = common_params.copy()
            params.update({"dscp": 3,
                           "pg": 3,
                           "num_of_flows": "single"})
            self.write_params("lossless_voq_3", params)

        if self.should_autogen(["lossless_voq_4"]):
            params = common_params.copy()
            params.update({"dscp": 4,
                           "pg": 4,
                           "num_of_flows": "single"})
            self.write_params("lossless_voq_4", params)

    def __define_q_watermark_all_ports(self):
        packet_size = self.preferred_packet_size
        packet_buffs = self.get_buffer_occupancy(packet_size)
        if self.should_autogen(["wm_q_wm_all_ports"]):
            lossy_lossless_action_thr = min(self.lossy_drop_bytes, self.pause_thr)
            pkts_num_leak_out = 0
            if self.dutAsic == "gr2":
                # Send a burst of leakout packets to optimize runtime. Expected leakout is around 950
                pkts_num_leak_out = 800
            self.log("In __define_q_watermark_all_ports, using min lossy-drop/lossless-pause threshold of {}".format(
                lossy_lossless_action_thr))
            params = {"ecn": 1,
                      "pkt_count": lossy_lossless_action_thr // self.buffer_size // packet_buffs,
                      "pkts_num_margin": self.q_wmk_margin,
                      "cell_size": self.buffer_size,
                      "pkts_num_leak_out": pkts_num_leak_out,
                      "packet_size": packet_size}
            self.write_params("wm_q_wm_all_ports", params)

    def __define_pg_drop(self):
        drop_buffers = self.lossless_drop_thr // self.buffer_size
        margin = round(3 * (drop_buffers ** 0.5))
        if self.should_autogen(["pg_drop"]):
            params = {"dscp": 3,
                      "ecn": 1,
                      "pg": 3,
                      "queue": 3,
                      "pkts_num_trig_pfc": self.pause_thr // self.buffer_size,
                      "pkts_num_trig_ingr_drp": drop_buffers,
                      "pkts_num_margin": margin,
                      "iterations": 100}
            self.write_params("pg_drop", params)

    def __define_wm_pg_headroom(self):
        if self.dutAsic != "gr2":
            self.log("Skipping wm_pg_headroom parameters, not supported on this asic.")
            return

        if self.should_autogen(["wm_pg_headroom"]):
            # The cell_size for this test is used in HR watermark calculations. For GR2,
            # this is the packet size plus 64B.
            hr_packet_overhead_bytes = 64
            params = {"dscp": 3,
                      "ecn": 1,
                      "pg": 3,
                      "pkts_num_leak_out": 0,
                      "pkts_num_trig_pfc": self.pause_thr // self.buffer_size,
                      "pkts_num_trig_ingr_drp": (self.lossless_drop_thr // self.buffer_size) + 1,
                      "pkts_num_margin": 2,
                      "packet_size": self.preferred_packet_size,
                      "cell_size": self.preferred_packet_size + hr_packet_overhead_bytes}
            self.write_params("wm_pg_headroom", params)

    def __define_wrr(self):
        q_pkt_cnt = []
        pkt_cnt_multiplier = 470/sum(self.weight_list)
        for weight in self.weight_list:
            q_pkt_cnt.append(int(weight * pkt_cnt_multiplier))
        if self.should_autogen(["wrr"]):
            params = {"ecn": 1,
                      "dscp_list": self.dscp_list,
                      "q_list": self.q_list,
                      "q_pkt_cnt": q_pkt_cnt,
                      "limit": 80}
            self.write_params("wrr", params)

    def __define_wrr_chg(self):
        q_pkt_cnt = []
        weight_list = []
        lossy_queues_chg = self.get_queues_on_same_scheduler(QosSaiBase.TARGET_LOSSY_QUEUE_SCHED)
        lossless_queues_chg = self.get_queues_on_same_scheduler(QosSaiBase.TARGET_LOSSLESS_QUEUE_SCHED)
        for queue, weight in zip(self.q_list, self.weight_list):
            if queue in lossy_queues_chg:
                weight_list.append(8)
            elif queue in lossless_queues_chg:
                weight_list.append(30)
            else:
                weight_list.append(weight)
        pkt_cnt_multiplier = 470/sum(weight_list)
        for weight in weight_list:
            q_pkt_cnt.append(int(weight * pkt_cnt_multiplier))
        if self.should_autogen(["wrr_chg"]):
            params = {"ecn": 1,
                      "dscp_list": self.dscp_list,
                      "q_list": self.q_list,
                      "q_pkt_cnt": q_pkt_cnt,
                      "limit": 80,
                      "lossy_weight": 8,
                      "lossless_weight": 30}
            self.write_params("wrr_chg", params)
