import math
import pytest
import logging
import yaml
import random
from tests.qos.qos_sai_base import QosSaiBase
from collections import OrderedDict


class QosParamInnovium(QosSaiBase):
    def __init__(self, dutConfig, duthost, dut_asic, request,
                 speed_cable_len, ingressLosslessProfile, ingressLossyProfile,
                 egressLosslessProfile, egressLossyProfile, src_dut_index, src_asic_index):
        self.asic_param_dic = {
            'tl7': {
                'b_w_s': 32,
                'd_c_s': 224,
                'e_b_tr_off': 50,
                'b_r_s': 48,
                'b_s_t': 400
            }
        }

        self.speed_cable_len = speed_cable_len
        # Placeholder for values coming in from qos.yml
        # as well as values which are not speed/len specific
        if dutConfig['dutAsic'] not in dutConfig["qosConfigs"]['qos_params']:
            pytest.fail('{} not present in qos.yml'.format(
                dutConfig['dutAsic']))
        self.qos_params_invm = dutConfig["qosConfigs"]['qos_params'][dutConfig['dutAsic']][dutConfig["dutTopo"]]

        # Build the class information
        # Ingress lossless will get overwritten if src port changes
        self.ingressLosslessProfile = ingressLosslessProfile
        # Other buffer profiles are same for all ports
        self.ingressLossyProfile = ingressLossyProfile
        self.egressLosslessProfile = egressLosslessProfile
        self.egressLossyProfile = egressLossyProfile
        self.src_dut_index = src_dut_index
        self.src_asic_index = src_asic_index

        # This may be updated for src/dst ports
        self.dutConfig = dutConfig

        # To read the buffer profile
        self.duthost = duthost
        self.dut_asic = dut_asic
        self.request = request

        # To be computed
        self.test_ports = []
        self.g_test_ib = None
        self.g_d_s_l = None
        self.g_d_s_ll = None
        self.p_to_dp_map = {}
        self.dp_to_p_map = {}
        self.dp_to_ib_map = {}
        self.ib_to_p_map = {}
        '''
        '''
        return

    def run(self):
        """
            Main method of the class
            Returns the dictionary containing all the
            parameters required for the qos test
        """
        self.__collect_data()
        self.__update_test_ports_details()
        self.__calculate_qos_parameters()
        self.__dump_generated_params_in_file()

        return self.qos_params_invm

    def __collect_data(self):
        # Collect lane mapping info for all ports
        for port in self.dutConfig['dutInterfaces']:

            eth_str = str(self.dutConfig['dutInterfaces'][port])
            port_lanes = self.duthost.shell(
                'redis-cli -n 4 hget "PORT|{}" "lanes"'.format(eth_str))['stdout']
            if port_lanes is None:
                logging.debug(
                    "Failed to get lane list for Port {} ".format(eth_str))
                pytest.fail(
                    'Failed to get lane list for Port {} '.format(eth_str))
            self.p_to_dp_map[port] = int(port_lanes.split(',')[0])
            self.dp_to_p_map[int(port_lanes.split(',')[0])] = port
        logging.debug("Port to dp mapping {}".format(self.p_to_dp_map))
        # collect port-ib mapping
        op = self.duthost.shell('ivmcmd "port pdinfo"')['stdout']
        for line in op.split('\n')[4:-1]:
            ib = int(line.split('|')[2].strip())
            dp = int(line.split('|')[1].strip())
            self.dp_to_ib_map[dp] = ib
            try:
                self.ib_to_p_map.setdefault(ib, []).append(self.dp_to_p_map[dp])
            except KeyError:
                pass
        logging.debug("dp to ib mapping {}".format(self.dp_to_ib_map))
        return

    def __dump_generated_params_in_file(self):
        logging.debug("Qos params after generation {}".format(
            self.qos_params_invm))
        with open(r'qos/files/qos_gen_tl7.yml', 'w') as fp:
            yaml.dump(self.qos_params_invm, fp, default_flow_style=False)
        return

    def __get_port_ib(self, port_id):
        return self.dp_to_ib_map[self.p_to_dp_map[port_id]]

    def __update_test_ports_details(self):
        """
         - Update the test ports
            - check the passed testPorts to see if they are in same IB
            - If not:
                    - Iterate all and find first 4 in same IB
            - Make note of IB as t_ib
            - Update the dutConfig fixture for testPorts
            - Collect the ingressLosslessProfile for updated ports
            - Also update the fixture ingressLosslessProfile
        """

        input_test_ports = [
            self.dutConfig['testPorts']['src_port_id'],
            self.dutConfig['testPorts']['dst_port_id'],
            self.dutConfig['testPorts']['dst_port_2_id'],
            self.dutConfig['testPorts']['dst_port_3_id']]

        # Case where test runner has passed 'src_port_ids' and 'dsp_port_ids' in qos.yml
        # file and they endup being selected as test ports by logic in qos_sai_base.py
        ib_check_required = False
        if 'src_port_ids' in self.qos_params_invm:
            if input_test_ports[0] in self.qos_params_invm['src_port_ids']:
                ib_check_required = True

        if 'dst_port_ids' in self.qos_params_invm:
            if len(set(input_test_ports[1:]).intersection(set(self.qos_params_invm['dst_port_ids']))) > 0:
                ib_check_required = True

        for ib in self.ib_to_p_map.keys():
            if set(input_test_ports).intersection(set(self.ib_to_p_map[ib])) == set(input_test_ports):
                # all given test ports are in same IB, continue
                self.test_ports = input_test_ports
                self.g_test_ib = ib
                break
        else:
            if ib_check_required:
                pytest.fail("Can't use the src_port_ids {0} and dst_port_ids {1} \
                        given in qos.yml, please correct them".format(
                        self.qos_params_invm['src_port_ids'], self.qos_params_invm['dst_port_ids']))

            # recomoute test ports to be in same ib
            tmp_ib_port_dict = self.ib_to_p_map.copy()
            while (tmp_ib_port_dict):
                ran_ib = random.choice(list(tmp_ib_port_dict.keys()))
                ports_in_same_ib = tmp_ib_port_dict[ran_ib]
                if len(ports_in_same_ib) >= 4 and (set(ports_in_same_ib).intersection(
                     self.dutConfig['testPortIds'][self.src_dut_index][
                         self.src_asic_index]) == set(ports_in_same_ib)):
                    self.test_ports = ports_in_same_ib[0:4]
                    self.g_test_ib = ran_ib
                    break
                else:
                    del tmp_ib_port_dict[ran_ib]

        if not self.test_ports:
            pytest.fail("Can't find 4 ports in same ib that present in self.dutConfig['testPortIds']")

        # Update the dutConfig['testPorts']
        tmp_testPortIps = self.dutConfig['testPortIps'][self.src_dut_index][self.src_asic_index]
        srcPort = self.test_ports[0]
        self.dutConfig['testPorts']['src_port_id'] = srcPort
        self.dutConfig['testPorts']['src_port_ip'] = tmp_testPortIps[srcPort]["peer_addr"]
        self.dutConfig['testPorts']['src_port_vlan'] = tmp_testPortIps[srcPort]['vlan_id'] \
            if 'vlan_id' in tmp_testPortIps[srcPort] else None

        dstPort = self.test_ports[1]
        self.dutConfig['testPorts']['dst_port_id'] = dstPort
        self.dutConfig['testPorts']['dst_port_ip'] = tmp_testPortIps[dstPort]["peer_addr"]
        self.dutConfig['testPorts']['dst_port_vlan'] = tmp_testPortIps[dstPort]['vlan_id'] \
            if 'vlan_id' in tmp_testPortIps[dstPort] else None

        dstPort2 = self.test_ports[2]
        self.dutConfig['testPorts']['dst_port_2_id'] = dstPort2
        self.dutConfig['testPorts']['dst_port_2_ip'] = tmp_testPortIps[dstPort2]["peer_addr"]
        self.dutConfig['testPorts']['dst_port_2_vlan'] = tmp_testPortIps[dstPort2]['vlan_id'] \
            if 'vlan_id' in tmp_testPortIps[dstPort2] else None

        dstPort3 = self.test_ports[3]
        self.dutConfig['testPorts']['dst_port_3_id'] = dstPort3
        self.dutConfig['testPorts']['dst_port_3_ip'] = tmp_testPortIps[dstPort3]["peer_addr"]
        self.dutConfig['testPorts']['dst_port_3_vlan'] = tmp_testPortIps[dstPort3]['vlan_id'] \
            if 'vlan_id' in tmp_testPortIps[dstPort3] else None
        logging.debug("Test Ports: {}".format(self.dutConfig['testPorts']))

        logging.debug("Lossless Buffer profile selected is {}".format(
            self.ingressLosslessProfile["profileName"]))
        # if original src port is different than new one, ingressLossless profile needs change
        if srcPort != input_test_ports[0]:
            self.ingressLosslessProfile = self._QosSaiBase__getBufferProfile(
                    self.request, self.dut_asic, self.duthost.os_version,
                    "BUFFER_PG_TABLE" if self.isBufferInApplDb(self.dut_asic)
                    else "BUFFER_PG", self.dutConfig["dutInterfaces"][srcPort], "3-4")

        logging.debug("Lossless Buffer profile selected is {}".format(
            self.ingressLosslessProfile["profileName"]))
        op = self.duthost.shell('ivmcmd "run partss"')['stdout']
        lines = op.split('\n')[2:]
        if 'Error' in lines[0]:
            pytest.fail('CLI script for partss is not present in CLI server')
        if len(lines) < 2:
            pytest.fail('partss CLI invoke failed')
        for aline in lines:
            if 'ERR' in aline:
                pytest.fail('CLI script for partss has unexpected output')
            retValue = aline.strip().split()
            if 'LS:' in retValue[0]:
                retValue = retValue[1:]
                if len(retValue) < (self.g_test_ib + 1):
                    pytest.fail('CLI script for partss has unexpected output')
                self.g_d_s_l = int(retValue[self.g_test_ib].strip())
            elif 'LL:' in retValue[0]:
                retValue = retValue[1:]
                if len(retValue) < (self.g_test_ib + 1):
                    pytest.fail('CLI script for partss has unexpected output')
                self.g_d_s_ll = int(retValue[self.g_test_ib].strip())
        if self.g_d_s_l is None:
            pytest.fail('Failed to get g_d_s_l')
        if self.g_d_s_ll is None:
            pytest.fail('Failed to get g_d_s_ll')
        logging.debug("ib:{},  g_d_s_l:{} , g_d_s_ll:{}".format(
            self.g_test_ib, self.g_d_s_l, self.g_d_s_ll))

    def __calculate_qos_parameters(self):
        """
            Generate qos test parameters based on the configuration
                xon_1
                xon_2
                lossy_queue_1
                wrr
                wrr_chg
                wm_q_shared_lossy
                  xoff_1
                  xoff_2
                  hdrm_pool_size
                      src_port_ids
                      dst_port_id
                  wm_q_shared_lossless

        """
        # Background information
        ll_i_d_f = pow(2, int(self.ingressLosslessProfile['dynamic_th']))
        b_w_s = self.asic_param_dic[self.dutConfig['dutAsic']]['b_w_s']
        d_c_s = self.asic_param_dic[self.dutConfig['dutAsic']]['d_c_s']
        ll_ip_r_s = int(
            math.ceil(float(self.ingressLosslessProfile['size'])/d_c_s))
        ll_ip_r_o = int(
            math.ceil(float(self.ingressLosslessProfile['xon_offset'])/d_c_s))
        ll_b_i_s = int(
            math.ceil(float(self.ingressLosslessProfile['xoff'])/b_w_s))
        b_r_s = self.asic_param_dic[self.dutConfig['dutAsic']]['b_r_s']
        b_s_t = self.asic_param_dic[self.dutConfig['dutAsic']]['b_s_t']
        packet_size = 64
        b_w_p_p = int(math.ceil(float(packet_size + 4)/b_w_s))
        l_q_r_s = int(math.ceil(float(self.egressLossyProfile['size'])/d_c_s))
        ll_q_r_s = int(
            math.ceil(float(self.egressLosslessProfile['size'])/d_c_s))
        l_q_d_f = pow(2, int(self.egressLossyProfile['dynamic_th']))

        # Base Qos param
        pkts_num_trig_pfc = int(math.floor(float(
            ll_i_d_f * self.g_d_s_ll - self.asic_param_dic[
                self.dutConfig['dutAsic']]['e_b_tr_off']) / (ll_i_d_f + 1) + ll_ip_r_s + 1))
        pkts_num_trig_ingr_drp = int(math.floor(float(ll_i_d_f * self.g_d_s_ll) / (
            ll_i_d_f + 1) + ll_ip_r_s + 1) + math.floor((ll_b_i_s + b_r_s + b_s_t)/b_w_p_p))
        pkts_num_trig_egr_drp = int(math.floor(
            l_q_r_s + (float(l_q_d_f * self.g_d_s_l) / (l_q_d_f + 1)) + 1))

        # Build test case specific param
        xon_1 = {}
        if 'pkts_num_trig_pfc' not in self.qos_params_invm['xon_1']:
            logging.debug("Adding auto generated value for pkts_num_trig_pfc in xon_1")
            xon_1['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        if 'pkts_num_hysteresis' not in self.qos_params_invm['xon_1']:
            logging.debug("Adding auto generated value for pkts_num_hysteresis in xon_1")
            xon_1['pkts_num_hysteresis'] = ll_ip_r_o
        self.qos_params_invm['xon_1'].update(xon_1)

        xon_2 = {}
        if 'pkts_num_trig_pfc' not in self.qos_params_invm['xon_2']:
            logging.debug("Adding auto generated value for pkts_num_trig_pfc in xon_2")
            xon_2['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        if 'pkts_num_hysteresis' not in self.qos_params_invm['xon_2']:
            logging.debug("Adding auto generated value for pkts_num_hysteresis in xon_2")
            xon_2['pkts_num_hysteresis'] = ll_ip_r_o
        self.qos_params_invm['xon_2'].update(xon_2)

        lossy_queue = {}
        if 'pkts_num_trig_egr_drp' not in self.qos_params_invm['lossy_queue_1']:
            logging.debug("Adding auto generated value for pkts_num_trig_egr_drp in lossy_queue_1")
            lossy_queue['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        self.qos_params_invm['lossy_queue_1'].update(lossy_queue)

        wm_q_shared_lossy = {}
        if 'pkts_num_fill_min' not in self.qos_params_invm['wm_q_shared_lossy']:
            logging.debug("Adding auto generated value for pkts_num_fill_min in wm_q_shared_lossy")
            wm_q_shared_lossy['pkts_num_fill_min'] = l_q_r_s
        if 'pkts_num_trig_egr_drp' not in self.qos_params_invm['wm_q_shared_lossy']:
            logging.debug("Adding auto generated value for pkts_num_trig_egr_drp in wm_q_shared_lossy")
            wm_q_shared_lossy['pkts_num_trig_egr_drp'] = pkts_num_trig_egr_drp
        if 'cell_size' not in self.qos_params_invm['wm_q_shared_lossy']:
            logging.debug("Adding auto generated value for cell_size in wm_q_shared_lossy")
            wm_q_shared_lossy['cell_size'] = d_c_s
        self.qos_params_invm['wm_q_shared_lossy'].update(wm_q_shared_lossy)

        if 'hdrm_pool_wm_multiplier' not in self.qos_params_invm:
            logging.debug("Adding auto generated value for hdrm_pool_wm_multiplier")
            self.qos_params_invm['hdrm_pool_wm_multiplier'] = b_w_p_p

        if 'cell_size' not in self.qos_params_invm:
            logging.debug("Adding auto generated value for cell_size")
            self.qos_params_invm['cell_size'] = b_w_s

        xoff_1 = {}
        if 'pkts_num_trig_pfc' not in self.qos_params_invm[self.speed_cable_len]['xoff_1']:
            logging.debug("Adding auto generated value for pkts_num_trig_pfc in xoff_1")
            xoff_1['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        if 'pkts_num_trig_ingr_drp' not in self.qos_params_invm[self.speed_cable_len]['xoff_1']:
            logging.debug("Adding auto generated value for pkts_num_trig_ingr_drp in xoff_1")
            xoff_1['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        self.qos_params_invm[self.speed_cable_len]['xoff_1'].update(xoff_1)

        xoff_2 = {}
        if 'pkts_num_trig_pfc' not in self.qos_params_invm[self.speed_cable_len]['xoff_2']:
            logging.debug("Adding auto generated value for pkts_num_trig_pfc in xoff_2")
            xoff_2['pkts_num_trig_pfc'] = pkts_num_trig_pfc
        if 'pkts_num_trig_ingr_drp' not in self.qos_params_invm[self.speed_cable_len]['xoff_2']:
            logging.debug("Adding auto generated value for pkts_num_trig_ingr_drp in xoff_2")
            xoff_2['pkts_num_trig_ingr_drp'] = pkts_num_trig_ingr_drp
        self.qos_params_invm[self.speed_cable_len]['xoff_2'].update(xoff_2)

        hdrm_pool_size = self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']
        if 'src_port_ids' not in self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']:
            logging.debug("Adding auto generated value for src_port_ids in hdrm_pool_size")
            hdrm_pool_size['src_port_ids'] = self.test_ports[:-1]
        if 'dst_port_id' not in self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']:
            logging.debug("Adding auto generated value for dst_port_ids in hdrm_pool_size")
            hdrm_pool_size['dst_port_id'] = self.test_ports[-1]
        num_pgs = len(self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']['pgs'])
        num_src_ports = len(self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']['src_port_ids'])
        if 'pgs_num' not in self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']:
            logging.debug("Adding auto generated value for pgs_num in hdrm_pool_size")
            hdrm_pool_size['pgs_num'] = num_pgs * num_src_ports
        if 'pkts_num_trig_pfc' not in self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']:
            logging.debug("Adding auto generated value for pkts_num_trig_pfc in hdrm_pool_size")
            hdrm_pool_size['pkts_num_trig_pfc'] = int(math.floor(float(ll_i_d_f * self.g_d_s_ll -
                                                      self.asic_param_dic[self.dutConfig['dutAsic']]['e_b_tr_off']) /
                                                      (hdrm_pool_size['pgs_num'] * ll_i_d_f + 1) + ll_ip_r_s + 1))

        if 'pkts_num_hdrm_full' not in self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']:
            logging.debug("Adding auto generated value for pkts_num_hdrm_full in hdrm_pool_size")
            hdrm_pool_size['pkts_num_hdrm_full'] = int(math.ceil(float(ll_b_i_s + b_s_t + b_r_s) / b_w_p_p))
        if 'pkts_num_hdrm_partial' not in self.qos_params_invm[self.speed_cable_len]['hdrm_pool_size']:
            logging.debug("Adding auto generated value for pkts_num_hdrm_partial in hdrm_pool_size")
            hdrm_pool_size['pkts_num_hdrm_partial'] = int(math.ceil(float(ll_b_i_s + b_s_t + b_r_s) / b_w_p_p))

        wm_q_shared_lossless = self.qos_params_invm[self.speed_cable_len]['wm_q_shared_lossless']
        if 'pkts_num_fill_min' not in self.qos_params_invm[self.speed_cable_len]['wm_q_shared_lossless']:
            logging.debug("Adding auto generated value for pkts_num_fill_min in wm_q_shared_lossless")
            wm_q_shared_lossless['pkts_num_fill_min'] = ll_q_r_s
        if 'pkts_num_trig_ingr_drp' not in self.qos_params_invm[self.speed_cable_len]['wm_q_shared_lossless']:
            logging.debug("Adding auto generated value for pkts_num_trig_ingr_drp in wm_q_shared_lossless")
            wm_q_shared_lossless['pkts_num_trig_ingr_drp'] = int(math.floor(float(ll_i_d_f * self.g_d_s_ll) /
                                                                            (ll_i_d_f + 1) + ll_ip_r_s + 1))
        if 'cell_size' not in self.qos_params_invm[self.speed_cable_len]['wm_q_shared_lossless']:
            logging.debug("Adding auto generated value for cell_size in wm_q_shared_lossless")
            wm_q_shared_lossless['cell_size'] = d_c_s

        # Update src_port_ids and dst_port_ids if not available
        self.qos_params_invm['src_port_ids'] = self.test_ports[0]
        self.qos_params_invm['dst_port_ids'] = self.test_ports[1:]

        # Sort the data for better readability
        self.qos_params_invm = OrderedDict(
            sorted(self.qos_params_invm.items()))
