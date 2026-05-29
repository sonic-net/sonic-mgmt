'''
generate and update qos params for brcm platform
so far, only return the original qos_params to testcase
'''


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
        self.qos_params = qos_params
        return

    def run(self):
        return self.qos_params
