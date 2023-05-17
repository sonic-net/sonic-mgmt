class QosParamCisco(object):
    SMALL_SMS_PLATFORMS = ["x86_64-8102_64h_o-r0"]

    def __init__(self, qos_params, duthost, bufferConfig):
        '''
        Initialize parameters all tests will use
        '''
        self.qos_params = qos_params
        self.bufferConfig = bufferConfig
        self.ingress_pool_size = None
        self.ingress_pool_headroom = None
        if "ingress_lossless_pool" in self.bufferConfig["BUFFER_POOL"]:
            self.ingress_pool_size = self.bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["size"]
            self.ingress_pool_headroom = self.bufferConfig["BUFFER_POOL"]["ingress_lossless_pool"]["xoff"]
        self.egress_pool_size = None
        if "egress_lossy_pool" in self.bufferConfig["BUFFER_POOL"]:
            self.egress_pool_size = self.bufferConfig["BUFFER_POOL"]["egress_lossy_pool"]["size"]
        # Find SMS size
        self.is_large_sms = duthost.facts['platform'] not in self.SMALL_SMS_PLATFORMS

    def run(self):
        '''
        Define parameters for each test.

        Each function takes common parameters and outputs to the relevant section of the
        self.qos_params structure.
        '''
        self.__define_shared_reservation_size()
        return self.qos_params

    def __mark_skip(self, testcase, reason):
        self.qos_params[testcase]["skip"] = reason

    def __define_shared_reservation_size(self):
        if self.ingress_pool_size is None or self.ingress_pool_headroom is None:
            skip_reason = "ingress_lossless_pool not defined, nothing to test"
            self.__mark_skip("shared_res_size_1", skip_reason)
            self.__mark_skip("shared_res_size_2", skip_reason)
            return
        if self.is_large_sms:
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
            self.qos_params["shared_res_size_1"] = res_1
            self.qos_params["shared_res_size_2"] = res_2
