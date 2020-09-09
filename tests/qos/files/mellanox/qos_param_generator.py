import math

class QosParamMellanox(object):
    def __init__(self, qos_params, asic_type, speed_cable_len, ingressLosslessProfile, ingressLossyProfile, egressLosslessProfile, egressLossyProfile):
        asic_param_dic = {
            'spc1': {
                'cell_size': 96,
                'headroom_overhead': 95
            },
            'spc2': {
                'cell_size': 144,
                'headroom_overhead': 64
            },
            'spc3': {
                'cell_size': 144,
                'headroom_overhead': 64
            }
        }

        self.asic_type = asic_type
        self.cell_size = asic_param_dic[asic_type]['cell_size']
        self.headroom_overhead = asic_param_dic[asic_type]['headroom_overhead']
        if speed_cable_len[0:6] == '400000':
            self.headroom_overhead += 59
        self.speed_cable_len = speed_cable_len
        self.lossless_profile = "pg_lossless_{}_profile".format(speed_cable_len)
        self.pools_info = {}
        self.qos_parameters = {}
        self.qos_params_mlnx = qos_params
        self.qos_params_mlnx[self.speed_cable_len] = self.qos_params_mlnx['profile']
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
        xon = int(math.ceil(float(self.ingressLosslessProfile['xon']) / self.cell_size))
        xoff = int(math.ceil(float(self.ingressLosslessProfile['xoff']) / self.cell_size))
        size = int(math.ceil(float(self.ingressLosslessProfile['size']) / self.cell_size))
        headroom = size
        hysteresis = headroom - (xon + xoff)
        ingress_lossless_size = int(math.ceil(float(self.ingressLosslessProfile['static_th']) / self.cell_size)) - headroom
        egress_lossy_size = int(math.ceil(float(self.egressLossyProfile['static_th']) / self.cell_size))

        pkts_num_trig_pfc = ingress_lossless_size + xon + hysteresis
        pkts_num_trig_ingr_drp = ingress_lossless_size + headroom - self.headroom_overhead
        pkts_num_dismiss_pfc = ingress_lossless_size + 1
        pkts_num_trig_egr_drp = egress_lossy_size + 1

        self.qos_parameters['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        self.qos_parameters['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        self.qos_parameters['pkts_num_dismiss_pfc'] = pkts_num_dismiss_pfc
        self.qos_parameters['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        self.qos_parameters['pkts_num_hysteresis'] = hysteresis

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
        pkts_num_hysteresis = self.qos_parameters['pkts_num_hysteresis']

        xoff = {}
        xoff['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        xoff['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        # One motivation of margin is to tolerance the deviation.
        # We need a larger margin on SPC2/3
        if self.asic_type != 'spc1':
            xoff['pkts_num_margin'] = 3
        self.qos_params_mlnx[self.speed_cable_len]['xoff_1'].update(xoff)
        self.qos_params_mlnx[self.speed_cable_len]['xoff_2'].update(xoff)

        xon = {}
        xon['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        xon['pkts_num_dismiss_pfc'] = pkts_num_dismiss_pfc
        xon['pkts_num_hysteresis'] = pkts_num_hysteresis + 16
        if self.asic_type == 'spc2':
            xon['pkts_num_margin'] = 2
        elif self.asic_type == 'spc3':
            xon['pkts_num_margin'] = 3
        self.qos_params_mlnx['xon_1'].update(xon)
        self.qos_params_mlnx['xon_2'].update(xon)

        wm_pg_headroom = self.qos_params_mlnx[self.speed_cable_len]['wm_pg_headroom']
        wm_pg_headroom['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        wm_pg_headroom['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        wm_pg_headroom['cell_size'] = self.cell_size
        if self.asic_type == 'spc3':
            wm_pg_headroom['pkts_num_margin'] = 3
        else:
            wm_pg_headroom['pkts_num_margin'] = 2

        wm_pg_shared_lossless = self.qos_params_mlnx['wm_pg_shared_lossless']
        wm_pg_shared_lossless['pkts_num_trig_pfc'] = pkts_num_dismiss_pfc
        wm_pg_shared_lossless['cell_size'] = self.cell_size

        wm_q_shared_lossless = self.qos_params_mlnx[self.speed_cable_len]['wm_q_shared_lossless']
        wm_q_shared_lossless['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        wm_q_shared_lossless['cell_size'] = self.cell_size

        lossy_queue = self.qos_params_mlnx['lossy_queue_1']
        lossy_queue['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp - 1
        lossy_queue['cell_size'] = self.cell_size

        wm_shared_lossy = {}
        wm_shared_lossy['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        wm_shared_lossy['cell_size'] = self.cell_size
        self.qos_params_mlnx['wm_pg_shared_lossy'].update(wm_shared_lossy)
        self.qos_params_mlnx['wm_q_shared_lossy'].update(wm_shared_lossy)

        wm_buf_pool_lossless = self.qos_params_mlnx['wm_buf_pool_lossless']
        wm_buf_pool_lossless['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        wm_buf_pool_lossless['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        wm_buf_pool_lossless['cell_size'] = self.cell_size

        wm_buf_pool_lossy = self.qos_params_mlnx['wm_buf_pool_lossy']
        wm_buf_pool_lossy['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        wm_buf_pool_lossy['cell_size'] = self.cell_size

        for i in range(4):
            self.qos_params_mlnx['ecn_{}'.format(i+1)]['cell_size'] = self.cell_size
