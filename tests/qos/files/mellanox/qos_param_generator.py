import math

class QosParamMellanox(object):
    def __init__(self, qos_params, asic_type, speed_cable_len, dutConfig, ingressLosslessProfile, ingressLossyProfile, egressLosslessProfile, egressLossyProfile, sharedHeadroomPoolSize):
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
            # for 400G ports we need an extra margin in case it is filled unbalancely between two buffer units
            self.extra_margin = 16
        else:
            self.extra_margin = 0
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
        if sharedHeadroomPoolSize and int(sharedHeadroomPoolSize) != 0:
            self.sharedHeadroomPoolSize = sharedHeadroomPoolSize
        else:
            self.sharedHeadroomPoolSize = None
        self.dutConfig = dutConfig

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

        if self.sharedHeadroomPoolSize:
            headroom = xon + xoff
            ingress_lossless_size = int(math.ceil(float(self.ingressLosslessProfile['static_th']) / self.cell_size)) - xon
        else:
            headroom = size
            ingress_lossless_size = int(math.ceil(float(self.ingressLosslessProfile['static_th']) / self.cell_size)) - headroom
        hysteresis = headroom - (xon + xoff)

        egress_lossy_size = int(math.ceil(float(self.egressLossyProfile['static_th']) / self.cell_size))

        pkts_num_trig_pfc = ingress_lossless_size + xon + hysteresis
        pkts_num_trig_ingr_drp = ingress_lossless_size + headroom
        if self.sharedHeadroomPoolSize:
            pkts_num_trig_ingr_drp += xoff
        else:
            pkts_num_trig_ingr_drp -= self.headroom_overhead
        pkts_num_dismiss_pfc = ingress_lossless_size + 1
        pkts_num_trig_egr_drp = egress_lossy_size + 1

        if self.sharedHeadroomPoolSize:
            testPortIds = self.dutConfig['testPortIds']
            ingress_ports_num_shp = 8
            pkts_num_trig_pfc_shp = []
            ingress_ports_list_shp = []
            occupancy_per_port = ingress_lossless_size
            self.qos_parameters['dst_port_id'] = testPortIds[0]
            for i in range(1, ingress_ports_num_shp):
                # for the first PG
                pkts_num_trig_pfc_shp.append(occupancy_per_port + xon + hysteresis)
                # for the second PG
                occupancy_per_port /= 2
                pkts_num_trig_pfc_shp.append(occupancy_per_port + xon + hysteresis)
                occupancy_per_port /= 2
                ingress_ports_list_shp.append(testPortIds[i])
            self.qos_parameters['pkts_num_trig_pfc_shp'] = pkts_num_trig_pfc_shp
            self.qos_parameters['src_port_ids'] = ingress_ports_list_shp
            self.qos_parameters['pkts_num_hdrm_full'] = xoff - 2
            self.qos_parameters['pkts_num_hdrm_partial'] = xoff - 2

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

        if self.sharedHeadroomPoolSize:
            hdrm_pool_size = self.qos_params_mlnx[self.speed_cable_len]['hdrm_pool_size']
            hdrm_pool_size['pkts_num_trig_pfc_shp'] = self.qos_parameters['pkts_num_trig_pfc_shp']
            hdrm_pool_size['pkts_num_hdrm_full'] = self.qos_parameters['pkts_num_hdrm_full']
            hdrm_pool_size['pkts_num_hdrm_partial'] = self.qos_parameters['pkts_num_hdrm_partial']
            hdrm_pool_size['dst_port_id'] = self.qos_parameters['dst_port_id']
            hdrm_pool_size['src_port_ids'] = self.qos_parameters['src_port_ids']
            hdrm_pool_size['pgs_num'] = 2 * len(self.qos_parameters['src_port_ids'])
            hdrm_pool_size['cell_size'] = self.cell_size
            hdrm_pool_size['margin'] = 3
        else:
            self.qos_params_mlnx[self.speed_cable_len].pop('hdrm_pool_size')    

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
        xon['pkts_num_dismiss_pfc'] = pkts_num_dismiss_pfc + self.extra_margin
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
        wm_pg_headroom['pkts_num_margin'] = 3

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

        self.qos_params_mlnx['shared-headroom-pool'] = self.sharedHeadroomPoolSize
