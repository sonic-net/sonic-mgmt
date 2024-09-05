import logging
import math

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
        self.buffer_size = 384
        # If t2 chassis
        self.is_t2 = duthost.facts["modular_chassis"] == "True"
        # Lossless profile attributes
        lossless_prof_name = "pg_lossless_{}_profile".format(self.portSpeedCableLength)
        lossless_prof = self.bufferConfig["BUFFER_PROFILE"][lossless_prof_name]
        # Init device parameters
        # TODO: topo-t2 support
        # Per-asic variable description:
        # 0: Max queue depth in bytes
        # 1: Flow control configuration on this device, either 'separate' or 'shared'.
        # 2: Number of packets margin for the quantized queue watermark tests.
        asic_params = {"gb": (6144000, "separate", 3072),
                       "gr": (24576000, "shared", 18000)}
        self.supports_autogen = dutAsic in asic_params and topo == "topo-any"
        if self.supports_autogen:
            # Asic dependent parameters
            self.max_depth, self.flow_config, self.q_wmk_margin = asic_params[dutAsic]
            # Calculate intermediate variables
            max_drop = self.max_depth * (1 - 0.0748125)
            max_pause = int(max_drop - int(lossless_prof["xoff"]))
            if "dynamic_th" in lossless_prof:
                dynamic_th = int(lossless_prof["dynamic_th"])
                attempted_pause = (2 ** dynamic_th) * self.egress_pool_size
            elif "static_th" in lossless_prof:
                attempted_pause = int(lossless_prof["static_th"])
            else:
                assert False, "Lossless profile had no dynamic_th or static_th: {}".format(lossless_prof)
            pre_pad_pause = min(attempted_pause, max_pause)
            if dutAsic == "gr":
                refined_pause_thr = self.gr_get_hw_thr_buffs(pre_pad_pause // self.buffer_size) * self.buffer_size
                self.log("GR pre-pad pause threshold changed from {} to {}".format(pre_pad_pause, refined_pause_thr))
                pre_pad_pause = refined_pause_thr
            pre_pad_drop = pre_pad_pause + int(lossless_prof["xoff"])
            # Tune thresholds with padding for precise testing
            self.pause_thr = pre_pad_pause + (8 * self.buffer_size)
            self.drop_thr = pre_pad_drop + (12 * self.buffer_size)
            self.log("Max pause thr bytes:       {}".format(max_pause))
            self.log("Attempted pause thr bytes: {}".format(attempted_pause))
            self.log("Pre-pad pause thr bytes:   {}".format(pre_pad_pause))
            self.log("Pause thr bytes:           {}".format(self.pause_thr))
            self.log("Pre-pad drop thr bytes:    {}".format(pre_pad_drop))
            self.log("Drop thr bytes:            {}".format(self.drop_thr))
            self.config_facts = duthost.get_running_config_facts()
            # DSCP value for lossy
            self.dscp_queue0 = self.get_one_dscp_from_queue(0)
            self.dscp_queue1 = self.get_one_dscp_from_queue(1)

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
        self.__define_xon_hysteresis()
        return self.qos_params

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

    def gr_get_hw_thr_buffs(self, thr):
        ''' thr must be in units of buffers '''
        mantissa, exp = self.gr_get_mantissa_exp(thr)
        if mantissa is None or exp is None:
            raise Exception("Failed to convert thr {}".format(thr))
        hw_thr = mantissa * (2 ** exp)
        return hw_thr

    def log(self, msg):
        logger.info("{}{}".format(self.LOG_PREFIX, msg))

    def write_params(self, label, params):
        self.log("Label {} autogenerated params {}".format(label, params))
        self.qos_params[self.portSpeedCableLength][label] = params

    def get_buffer_occupancy(self, packet_size):
        return (packet_size + self.buffer_size - 1) // self.buffer_size

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
                res_1 = {"dscps": [8, 8, 1, 1, 3, 4, 3, 4, 3, 4, 3],
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
        packet_size = 1350
        packet_buffs = self.get_buffer_occupancy(packet_size)
        for param_i, dscp_pg in [(1, 3), (2, 4)]:
            params = {"dscp": dscp_pg,
                      "ecn": 1,
                      "pg": dscp_pg,
                      "pkts_num_trig_pfc": self.pause_thr // self.buffer_size // packet_buffs,
                      "pkts_num_trig_ingr_drp": self.drop_thr // self.buffer_size // packet_buffs,
                      "packet_size": packet_size}
            self.write_params("xoff_{}".format(param_i), params)

    def __define_pfc_xon_limit(self):
        if not self.should_autogen(["xon_1", "xon_2"]):
            return
        packet_size = 1350
        packet_buffs = self.get_buffer_occupancy(packet_size)
        for param_i, dscp_pg in [(1, 3), (2, 4)]:
            params = {"dscp": dscp_pg,
                      "ecn": 1,
                      "pg": dscp_pg,
                      "pkts_num_trig_pfc": (self.pause_thr // self.buffer_size // packet_buffs) - 1,
                      "pkts_num_dismiss_pfc": 2,
                      "packet_size": packet_size}
            self.write_params("xon_{}".format(param_i), params)

    def __define_pg_shared_watermark(self):
        common_params = {"ecn": 1,
                         "pkts_num_fill_min": 0,
                         "pkts_num_margin": 4,
                         "packet_size": 1350,
                         "cell_size": self.buffer_size}
        if self.should_autogen(["wm_pg_shared_lossless"]):
            lossless_params = common_params.copy()
            # In this context, pkts_num_trig_pfc is the maximal watermark value reachable
            # by sending lossless traffic, which includes the headroom. So the drop
            # threshold is used instead of the pause threshold.
            lossless_params.update({"dscp": 3,
                                    "pg": 3,
                                    "pkts_num_trig_pfc": (self.drop_thr // self.buffer_size) - 8})
            self.write_params("wm_pg_shared_lossless", lossless_params)
        if self.should_autogen(["wm_pg_shared_lossy"]):
            lossy_params = common_params.copy()
            lossy_params.update({"dscp": 8,
                                 "pg": 0,
                                 "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size})
            self.write_params("wm_pg_shared_lossy", lossy_params)

    def __define_buffer_pool_watermark(self):
        packet_size = 1350
        packet_buffs = self.get_buffer_occupancy(packet_size)
        if self.should_autogen(["wm_buf_pool_lossless"]):
            lossless_params = {"dscp": 3,
                               "ecn": 1,
                               "pg": 3,
                               "queue": 3,
                               "pkts_num_fill_ingr_min": 0,
                               "pkts_num_trig_pfc": self.drop_thr // self.buffer_size // packet_buffs,
                               "cell_size": self.buffer_size,
                               "packet_size": packet_size}
            self.write_params("wm_buf_pool_lossless", lossless_params)
        if self.should_autogen(["wm_buf_pool_lossy"]):
            lossy_params = {"dscp": 8,
                            "ecn": 1,
                            "pg": 0,
                            "queue": 0,
                            "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size // packet_buffs,
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
                               "pkts_num_trig_ingr_drp": self.drop_thr // self.buffer_size,
                               "pkts_num_margin": self.q_wmk_margin,
                               "cell_size": self.buffer_size}
            self.write_params("wm_q_shared_lossless", lossless_params)
        if self.should_autogen(["wm_q_shared_lossy"]):
            lossy_params = {"dscp": 8,
                            "ecn": 1,
                            "queue": 0,
                            "pkts_num_fill_min": 0,
                            "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size,
                            "pkts_num_margin": self.q_wmk_margin,
                            "cell_size": self.buffer_size}
            self.write_params("wm_q_shared_lossy", lossy_params)

    def __define_lossy_queue_voq(self):
        if self.should_autogen(["lossy_queue_voq_1"]):
            params = {"dscp": 8,
                      "ecn": 1,
                      "pg": 0,
                      "flow_config": self.flow_config,
                      "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": 64,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_voq_1", params)
        if self.should_autogen(["lossy_queue_voq_2"]):
            params = {"dscp": 8,
                      "ecn": 1,
                      "pg": 0,
                      "flow_config": "shared",
                      "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": 64,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_voq_2", params)
        if self.should_autogen(["lossy_queue_voq_3"]):
            params = {"dscp": 8,
                      "ecn": 1,
                      "pg": 0,
                      "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": 64,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_voq_3", params)

    def __define_lossy_queue(self):
        if self.should_autogen(["lossy_queue_1"]):
            params = {"dscp": 8,
                      "ecn": 1,
                      "pg": 0,
                      "pkts_num_trig_egr_drp": self.max_depth // self.buffer_size,
                      "pkts_num_margin": 4,
                      "packet_size": 1350,
                      "cell_size": self.buffer_size}
            self.write_params("lossy_queue_1", params)

    def __define_lossless_voq(self):
        packet_size = 1350
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
        packet_size = 1350
        packet_buffs = self.get_buffer_occupancy(packet_size)
        if self.should_autogen(["wm_q_wm_all_ports"]):
            params = {"ecn": 1,
                      "pkt_count": self.max_depth // self.buffer_size // packet_buffs,
                      "pkts_num_margin": self.q_wmk_margin,
                      "cell_size": self.buffer_size,
                      "packet_size": packet_size}
            self.write_params("wm_q_wm_all_ports", params)

    def __define_pg_drop(self):
        drop_buffers = self.drop_thr // self.buffer_size
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

    def __define_xon_hysteresis(self):
        if self.is_t2:
            return

        self.log("Autogenerating qos params for test labels {}".format("xon_hysteresis_"))
        cell_size = 384
        packet_size = 1350

        def mb_to_pkt_count(sq_occupancies_mb):
            pkt_counts = []
            cell_per_pkt = math.ceil(packet_size/cell_size)
            for sq_occupancy_mb in sq_occupancies_mb:
                pkt_counts.append(math.ceil(sq_occupancy_mb * 1024 ** 2 / (cell_per_pkt * cell_size)))
            return pkt_counts

        if self.is_large_sms:
            if self.is_deep_buffer: # Crocodile/8111/Graphene/G100
                if self.portSpeedCableLength.find('400000') == 0:
                    # Crocodile 400G

                    # 20*3 + 10.1 = 70.1 MB
                    # 1st flow is to relieve and trigger SQG or Ctr-A region transition
                    # last flow is flow under test
                    sq_occupancies_mb = [20, 20, 20, 10.1]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [3, 3, 4, 3],
                                "pgs":        [3, 3, 4, 3],
                                "queues":     [3, 3, 4, 3],
                                "src_port_i": [0, 1, 1, 2],
                                "dst_port_i": [3, 4, 4, 5],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_1", params_1)

                    # 7 + 20*3 + 8 + 2.6 = 76.6 MB
                    sq_occupancies_mb = [7, 20, 20, 20, 8, 2.6]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [3, 3, 4, 3, 4, 3],
                                "pgs":        [3, 3, 4, 3, 4, 3],
                                "queues":     [3, 3, 4, 3, 4, 3],
                                "src_port_i": [0, 1, 1, 2, 2, 3],
                                "dst_port_i": [4, 5, 5, 6, 6, 7],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_2", params_1)

                    # lossy 7 + 10 = 17 MB
                    # lossless 20*3 + 9 = 69 MB
                    # Ctr-A 86 -> 79 MB
                    sq_occupancies_mb = [7, 10, 20, 20, 20, 9]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [self.dscp_queue1, self.dscp_queue1,
                                               3, 4, 3, 4],
                                "pgs":        [0, 0, 3, 4, 3, 4],
                                "queues":     [1, 1, 3, 4, 3, 4],
                                "src_port_i": [0, 1, 1, 1, 2, 2],
                                "dst_port_i": [3, 4, 4, 4, 5, 5],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_3", params_1)

                    # lossy 2 + 17 = 19 MB
                    # lossless 20*2 + 19 + 7.5 + 2.5 + 0.1 = 69.1 MB
                    # Ctr-A 19 + 69.1 = 88.1 MB -> 86.1 MB
                    sq_occupancies_mb = [2, 17, 20, 20, 19, 7.5, 2.5, 0.1]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [self.dscp_queue1, self.dscp_queue1,
                                               3, 4, 3, 4, 3, 4],
                                "pgs":        [0, 0, 3, 4, 3, 4, 3, 4],
                                "queues":     [1, 1, 3, 4, 3, 4, 3, 4],
                                "src_port_i": [0, 1, 1, 1, 2, 2, 3, 3],
                                "dst_port_i": [4, 5, 5, 5, 6, 6, 7, 7],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_4", params_1)

                    # lossy 2 + 9 = 11 MB
                    # lossless 20*3 + 10 + 4.5 + 2.5 + 0.1 = 77.1 MB
                    # Ctr-A 11 + 77.1 = 88.1 MB -> 86.1 MB
                    sq_occupancies_mb = [2, 9, 20, 20, 20, 10, 4.5, 2.5, 0.1]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [self.dscp_queue1, self.dscp_queue1,
                                               3, 4, 3, 4, 3, 4, 3],
                                "pgs":        [0, 0, 3, 4, 3, 4, 3, 4, 3],
                                "queues":     [1, 1, 3, 4, 3, 4, 3, 4, 3],
                                "src_port_i": [0, 1, 1, 1, 2, 2, 3, 3, 4],
                                "dst_port_i": [5, 6, 6, 6, 7, 7, 8, 8, 9],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_5", params_1)

                    # lossy 3 MB
                    # SQG0: 2 + 20*3 + 10 + 3.4 + 2.6 = 78 MB -> 76 MB
                    # Ctr-A 3 + 78 = 81 MB -> 79 MB
                    sq_occupancies_mb = [2, 3, 20, 20, 20, 10, 3.4, 2.6]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [3, self.dscp_queue1, 3, 4, 3, 4, 3, 4],
                                "pgs":        [3, 0, 3, 4, 3, 4, 3, 4],
                                "queues":     [3, 1, 3, 4, 3, 4, 3, 4],
                                "src_port_i": [0, 1, 1, 1, 2, 2, 3, 3],
                                "dst_port_i": [4, 5, 5, 5, 6, 6, 7, 7],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_6", params_1)

                    # SQG0: 2.5 + 20*3 + 7.5 * 2 + 2.5 + 0.1 = 80.1 MB -> 77.6 MB
                    sq_occupancies_mb = [2.5, 20, 20, 20, 7.5, 7.5, 2.5, 0.1]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [3, 3, 4, 3, 4, 3, 4, 3],
                                "pgs":        [3, 3, 4, 3, 4, 3, 4, 3],
                                "queues":     [3, 3, 4, 3, 4, 3, 4, 3],
                                "src_port_i": [0, 1, 1, 2, 2, 3, 3, 4],
                                "dst_port_i": [5, 6, 6, 7, 7, 8, 8, 9],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_7", params_1)

                    # SQG0: 2 + 20*3 + 8 + 7.5 + 2.5 + 0.1 = 80.1 MB -> 78.1 MB
                    sq_occupancies_mb = [2, 20, 20, 20, 8, 7.5, 2.5, 0.1]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [3, 3, 4, 3, 4, 3, 4, 3],
                                "pgs":        [3, 3, 4, 3, 4, 3, 4, 3],
                                "queues":     [3, 3, 4, 3, 4, 3, 4, 3],
                                "src_port_i": [0, 1, 1, 2, 2, 3, 3, 4],
                                "dst_port_i": [5, 6, 6, 7, 7, 8, 8, 9],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_8", params_1)

                    # Lossy: 2 + 6.5 = 8.5 MB
                    # SQG0: 20*3 + 10 + 7 + 2.5 + 0.1 = 79.6 MB
                    # Ctr-A: 8.5 + 79.6 = 88.1 - 2 = 86.1 MB
                    sq_occupancies_mb = [2, 6.5, 20, 20, 20, 10, 7, 2.5, 0.1]
                    params_1 = {"packet_size": packet_size,
                                "ecn": 1,
                                "dscps":      [self.dscp_queue1, self.dscp_queue1, 3, 4, 3, 4, 3, 4, 3],
                                "pgs":        [0, 0, 3, 4, 3, 4, 3, 4, 3],
                                "queues":     [1, 1, 3, 4, 3, 4, 3, 4, 3],
                                "src_port_i": [0, 1, 1, 1, 2, 2, 3, 3, 4],
                                "dst_port_i": [5, 6, 6, 6, 7, 7, 8, 8, 9],
                                "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                    self.write_params("xon_hysteresis_9", params_1)

            else: # Churchill-Mono/8101/Gibraltar/Q200

                # 5*10 + 4 = 54 MB
                sq_occupancies_mb = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4]
                params_1 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":  [3, 4, 3, 4, 3, 4, 3, 4, 3, 3, 3],
                            "pgs":    [3, 4, 3, 4, 3, 4, 3, 4, 3, 3, 3],
                            "queues": [3, 4, 3, 4, 3, 4, 3, 4, 3, 3, 3],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_1", params_1)

                # 3 + 2 + 5*9 + 3(3) = 59 MB
                sq_occupancies_mb = [3, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 3]
                params_2 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "pgs":        [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "queues":     [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_2", params_2)

                # Total: 67.5 MB
                # lossy: 5(5) = 25
                # lossless: 3 + 2 + 5(5) + 4 + 3(2) + 2.5 = 42.5
                sq_occupancies_mb = [3, 5, 5, 5, 5, 5, 2, 5, 5, 5, 5, 5, 4, 3, 3, 2.5]
                params_3 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [3, self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "pgs":        [3, 0, 0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "queues":     [3, 1, 0, 1, 0, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 9],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_3", params_3)

                # Total: 72.4 MB
                # lossy: 5(5) = 25
                # lossless: 3 + 2 + 5(5) + 4 + 3(2) + 1.5(4) + 1.4 = 47.4
                sq_occupancies_mb = [3, 5, 5, 5, 5, 5, 2, 5, 5, 5, 5, 5, 4, 3, 3, 1.5, 1.5, 1.5, 1.5, 1.4]
                params_4 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [3, self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "pgs":        [3, 0, 0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4],
                            "queues":     [3, 1, 0, 1, 0, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 9, 10, 10, 11, 11],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_4", params_4)

                # Total: 73 MB
                # lossy: 3 + 2 + 5(3) = 20MB
                # lossless: 5(7) + 3(3) + 1.5(6) = 53MB
                sq_occupancies_mb = [3, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 3, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5]
                params_5 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "pgs":        [0, 0, 0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,  4,  3,  4,  3,  4],
                            "queues":     [1, 0, 1, 0, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,  4,  3,  4,  3,  4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 9, 10, 10, 11, 11, 12],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_5", params_5)

                # Total: 64MB MB
                # lossy: 5 MB
                # lossless: 3 + 2 + 5(9) + 3(3) = 59MB
                sq_occupancies_mb = [3, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 3]
                params_6 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [3, 4, self.dscp_queue1, 3, 4, 3, 4, 3, 4, 3,
                                           4, 3, 4, 3, 4],
                            "pgs":        [3, 4, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "queues":     [3, 4, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_6", params_6)

                # 3*2 + 4 + 5*8 + 3(2) + 1(9) = 65 MB
                sq_occupancies_mb = [3, 3, 4, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                params_7 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4,  3,  4],
                            "pgs":        [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4,  3,  4],
                            "queues":     [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4,  3,  4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 9, 10, 10, 11, 11, 12, 12],
                            "dst_port_i": [7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8,  8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_7", params_7)

                # 3 + 2 + 5*9 + 3(2) + 1(9) = 65 MB
                sq_occupancies_mb = [3, 2, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                params_8 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4,  3,  4],
                            "pgs":        [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4,  3,  4],
                            "queues":     [3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,  3,  4,  3,  4,  3,  4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 9, 10, 10, 11, 11, 12, 12],
                            "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8,  8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_8", params_8)

                # Total: 72.5 MB
                # lossy: 5*2 + 4 = 14MB
                # lossless: 5(9) + 3(2) + 1.5(5) = 58.5MB
                sq_occupancies_mb = [5, 5, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 1.5, 1.5, 1.5, 1.5, 1.5]
                params_9 = {"packet_size": packet_size,
                            "ecn": 1,
                            "dscps":      [self.dscp_queue1, self.dscp_queue0,
                                           self.dscp_queue1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4,
                                           3, 4, 3, 4, 3, 4],
                            "pgs":        [0, 0, 0, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,  4,  3,  4],
                            "queues":     [1, 0, 1, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,  4,  3,  4],
                            "src_port_i": [0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 9, 9, 10, 10, 11],
                            "dst_port_i": [7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8],
                            "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
                self.write_params("xon_hysteresis_9", params_9)

        else: # Matilda64/8102/Gibraltar/Q200

            # 4 + 5*5 + 2.5 = 31.5 MB
            # 1st flow do "tx enable" to trigger SQG transition from region 1 to region 0
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [4, 5, 5, 5, 5, 5, 2.5]
            params_1 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps": [3, 3, 3, 3, 3, 3, 3],
                        "pgs":   [3, 3, 3, 3, 3, 3, 3],
                        "queues": [3, 3, 3, 3, 3, 3, 3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_1", params_1)

            # 6*5 + 2.25*3 + 0.8 = 37.55 MB
            # 1st flow do "tx enable" to trigger SQG transition from region 2 to region 1
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [5, 5, 5, 5, 5, 5, 2.25, 2.25, 2.25, 0.8]
            params_2 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [3, 3, 3, 3, 3, 3, 3, 3,  3,  3],
                        "pgs":        [3, 3, 3, 3, 3, 3, 3, 3,  3,  3],
                        "queues":     [3, 3, 3, 3, 3, 3, 3, 3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_2", params_2)

            # CTR-A: 20 + 24 = 44MB
            # Lossless: 2 + 3 + 5*2 + 2.25*4 = 24MB
            # Lossy: 5*4 = 20MB
            # 1st flow do "tx enable" to trigger CTR-A transition from region 2 to region 1
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [2, 5, 5, 5, 5, 3, 5, 5, 2.25, 2.25, 2.25, 2.25]
            params_3 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [3, self.dscp_queue1, self.dscp_queue1,
                                       self.dscp_queue1, self.dscp_queue1, 3, 3, 3, 3, 3, 3, 3],
                        "pgs":        [3, 0, 0, 0, 0, 3, 3, 3,  3,  3,  3,  3],
                        "queues":     [3, 1, 1, 1, 1, 3, 3, 3,  3,  3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_3", params_3)

            # CTR-A: 25.25 + 20 = 45.25 MB
            # Lossless: 3 + 2 + 5*2 + 2.25*3 + 0.5*7 = 25.25
            # Lossy: 5*4 = 20 MB
            # 1st flow do "tx enable" to trigger CTR-A transition from region 3 to region 2
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [3, 5, 5, 5, 5, 2, 5, 5, 2.25, 2.25, 2.25, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
            params_4 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [3, self.dscp_queue1, self.dscp_queue1,
                                       self.dscp_queue1, self.dscp_queue1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                        "pgs":        [3, 0, 0, 0, 0, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "queues":     [3, 1, 1, 1, 1, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_4", params_4)

            # CTR-A: 46.25 MB
            # Lossless: 5(4) + 2.25*3 + 0.5(9) = 31.25 MB
            # Lossy: 3 + 2 + 5(2) = 15 MB
            # 1st flow do "tx enable" to trigger CTR-A transition from region 3 to region 2
            # SQG in region 1 throughout
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [3, 2, 5, 5, 5, 5, 5, 5, 2.25, 2.25, 2.25, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
            params_5 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [self.dscp_queue1, self.dscp_queue1,
                                       self.dscp_queue1, self.dscp_queue1,
                                       3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                        "pgs":        [0, 0, 0, 0, 3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "queues":     [1, 1, 1, 1, 3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_5", params_5)

            # CTR-A: 37.75 + 4 = 41.75 MB
            # Lossless: 6*5 + 2.25*3 + 1 = 37.75 MB
            # Lossy: 4MB
            # 1st flow do "tx enable" to trigger SQG transition from region 2 to region 1
            # CTR-A must stay in region 1
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [5, 4, 5, 5, 5, 5, 5, 2.25, 2.25, 2.25, 1]
            params_6 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [3, self.dscp_queue1, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                        "pgs":        [3, 0, 3, 3, 3, 3, 3, 3,  3,  3,  3],
                        "queues":     [3, 1, 3, 3, 3, 3, 3, 3,  3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_6", params_6)

            # CTR-A = 40.1 + 1.5 = 41.6 MB
            # Lossy: 1.5 MB
            # Lossless: 2.5 + 5*5 + 2.25*4 + 0.62*5 + 0.5 = 40.1 MB
            # 1st flow do "tx enable" to trigger SQG transition from region 3 to region 2
            # CTR-A must stay in region 1
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [2.5, 1.5, 5, 5, 5, 5, 5, 2.25, 2.25, 2.25, 2.25, 0.62, 0.62, 0.62, 0.62, 0.62, 0.5]
            params_8 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [3, self.dscp_queue1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                                       3, 3, 3, 3, 3],
                        "pgs":        [3, 0, 3, 3, 3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "queues":     [3, 1, 3, 3, 3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                        "dst_port_i": [7, 8, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8,  8,  8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_8", params_8)

            # CTR-A: 44.98 MB
            # Lossless: 5*5 + 3.5 + 2.25*2 + 2 + 0.62*4 + 0.5 = 37.98 MB
            # Lossy: 3.5 * 2 = 7MB
            # 1st flow do "tx enable" to trigger CTRA transition from region 3 to region 1
            # SQG must stay in region 2
            # last flow is target SQ, keep XOFF state after SQG transition
            sq_occupancies_mb = [3.5, 3.5, 5, 5, 5, 5, 5, 3.5, 2.25, 2.25, 2, 0.62, 0.62, 0.62, 0.62, 0.5]
            params_9 = {"packet_size": packet_size,
                        "ecn": 1,
                        "dscps":      [self.dscp_queue1, self.dscp_queue1,
                                       3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                        "pgs":        [0, 0, 3, 3, 3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "queues":     [1, 1, 3, 3, 3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3],
                        "src_port_i": [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                        "dst_port_i": [7, 7, 8, 8, 8, 8, 8, 8,  8,  8,  8,  8,  8,  8,  8,  8],
                        "pkt_counts": mb_to_pkt_count(sq_occupancies_mb)}
            self.write_params("xon_hysteresis_9", params_9)
