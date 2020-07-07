import math

class QosParamMellanox(object):
    def __init__(self, qos_params, asictype, speed_cablelen, ingressLosslessProfile, ingressLossyProfile, egressLosslessProfile, egressLossyProfile):
        asic_param_dic = {
            'spc1': {
                'cellsize': 96,
                'headroom_overhead': 95,
                'hysteresis': 0
            },
            'spc2': {
                'cellsize': 144,
                'headroom_overhead': 64,
                'hysteresis': 0
            },
            'spc3': {
                'cellsize': 144,
                'headroom_overhead': 64,
                'hysteresis': 0
            }
        }

        self.asictype = asictype
        self.cellsize = asic_param_dic[asictype]['cellsize']
        self.headroom_overhead = asic_param_dic[asictype]['headroom_overhead']
        self.hysteresis = asic_param_dic[asictype]['hysteresis']
        self.speed_cablelen = speed_cablelen
        self.lossless_profile = "pg_lossless_{}_profile".format(speed_cablelen)
        self.pools_info = {}
        self.qos_parameters = {}
        self.qos_params_mlnx = qos_params
        self.qos_params_mlnx[self.speed_cablelen] = self.qos_params_mlnx['profile']
        self.ingressLosslessProfile = ingressLosslessProfile
        self.ingressLossyProfile = ingressLossyProfile
        self.egressLosslessProfile = egressLosslessProfile
        self.egressLossyProfile = egressLossyProfile

        return

    def run(self):
        """
            Main method of the class
            Returns the dictionary containing all the parameters required for the qos test
        """
        self.collect_qos_configurations()
        self.calculate_parameters()
        return self.qos_params_mlnx

    def collect_qos_configurations(self):
        """
            Collect qos configuration from the following fixtures
                ingressLosslessProfile
                egressLossyProfile
        """
        xon = int(math.ceil(float(self.ingressLosslessProfile['xon']) / self.cellsize))
        xoff = int(math.ceil(float(self.ingressLosslessProfile['xoff']) / self.cellsize))
        headroom = xon + xoff
        ingress_lossless_size = int(math.ceil(float(self.ingressLosslessProfile['static_th']) / self.cellsize)) - headroom
        egress_lossy_size = int(math.ceil(float(self.egressLossyProfile['static_th']) / self.cellsize))

        pkts_num_trig_pfc = ingress_lossless_size + xon
        pkts_num_trig_ingr_drp = ingress_lossless_size + headroom - self.headroom_overhead
        pkts_num_dismiss_pfc = ingress_lossless_size + 1
        pkts_num_trig_egr_drp = egress_lossy_size + 1

        self.qos_parameters['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        self.qos_parameters['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        self.qos_parameters['pkts_num_dismiss_pfc'] = pkts_num_dismiss_pfc
        self.qos_parameters['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp

    def calculate_parameters(self):
        """
            Generate qos test parameters based on the configuration
                xon
                xoff
                wm_pg_headroom
                wm_pg_shared_lossless
                wm_q_shared_lossless
                lossy_queue_1
                wm_pg_shared_lossy
                wm_q_shared_lossy
                wm_buf_pool_lossless
                wm_buf_pool_lossy
        """
        pkts_num_trig_pfc = self.qos_parameters['pkts_num_trig_pfc']
        pkts_num_trig_ingr_drp = self.qos_parameters['pkts_num_trig_ingr_drp']
        pkts_num_dismiss_pfc = self.qos_parameters['pkts_num_dismiss_pfc']
        pkts_num_trig_egr_drp = self.qos_parameters['pkts_num_trig_egr_drp']

        xoff = {}
        xoff['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        xoff['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        # One motivation of margin is to tolerance the deviation.
        # We need a larger margin on SPC2/3
        if self.asictype != 'spc1':
            xoff['pkts_num_margin'] = 3
        self.qos_params_mlnx[self.speed_cablelen]['xoff_1'].update(xoff)
        self.qos_params_mlnx[self.speed_cablelen]['xoff_2'].update(xoff)

        xon = {}
        xon['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        xon['pkts_num_dismiss_pfc'] = pkts_num_dismiss_pfc
        xon['pkts_num_hysteresis'] = self.hysteresis
        if self.asictype != 'spc1':
            xon['pkts_num_margin'] = 2
        self.qos_params_mlnx['xon_1'].update(xon)
        self.qos_params_mlnx['xon_2'].update(xon)

        wm_pg_headroom = self.qos_params_mlnx[self.speed_cablelen]['wm_pg_headroom']
        wm_pg_headroom['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        wm_pg_headroom['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        wm_pg_headroom['cell_size'] = self.cellsize
        if self.asictype == 'spc1':
            wm_pg_headroom['pkts_num_margin'] = 1
        else:
            wm_pg_headroom['pkts_num_margin'] = 2

        wm_pg_shared_lossless = self.qos_params_mlnx['wm_pg_shared_lossless']
        wm_pg_shared_lossless['pkts_num_trig_pfc'] = pkts_num_dismiss_pfc
        wm_pg_shared_lossless['cell_size'] = self.cellsize

        wm_q_shared_lossless = self.qos_params_mlnx[self.speed_cablelen]['wm_q_shared_lossless']
        wm_q_shared_lossless['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        wm_q_shared_lossless['cell_size'] = self.cellsize

        lossy_queue = self.qos_params_mlnx['lossy_queue_1']
        lossy_queue['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp - 1
        lossy_queue['cell_size'] = self.cellsize

        wm_shared_lossy = {}
        wm_shared_lossy['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        wm_shared_lossy['cell_size'] = self.cellsize
        self.qos_params_mlnx['wm_pg_shared_lossy'].update(wm_shared_lossy)
        self.qos_params_mlnx['wm_q_shared_lossy'].update(wm_shared_lossy)

        wm_buf_pool_lossless = self.qos_params_mlnx['wm_buf_pool_lossless']
        wm_buf_pool_lossless['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        wm_buf_pool_lossless['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        wm_buf_pool_lossless['cell_size'] = self.cellsize

        wm_buf_pool_lossy = self.qos_params_mlnx['wm_buf_pool_lossy']
        wm_buf_pool_lossy['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        wm_buf_pool_lossy['cell_size'] = self.cellsize

        for i in range(4):
            self.qos_params_mlnx['ecn_{}'.format(i+1)]['cell_size'] = self.cellsize
