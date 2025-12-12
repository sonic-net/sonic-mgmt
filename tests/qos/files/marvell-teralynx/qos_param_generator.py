import pytest
import math
import logging
import yaml
import random
from tests.qos.qos_sai_base import QosSaiBase
from collections import OrderedDict


class QosParamMarvell(QosSaiBase):

    def __init__(self, dutConfig, duthost, dut_asic, request,
                 speed_cable_len, ingressLosslessProfile, ingressLossyProfile,
                 egressLosslessProfile, egressLossyProfile, src_dut_index,
                 src_asic_index):

        self.asic_param_dic = {
            'tl7': {
                'b_w_s': 32,
                'd_c_s': 224,
                'e_b_tr_off': 0,
                'b_r_s': 48,
                'b_s_t': 400
            },
            'tl10': {
                'b_w_s': 128,
                'd_c_s': 512,
                'e_b_tr_off': 0,
                'b_r_s': 12,
                'b_s_t': 400
            }
        }

        self.dutConfig = dutConfig
        self.duthost = duthost
        self.dut_asic = dut_asic
        self.request = request
        self.src_dut_index = src_dut_index
        self.src_asic_index = src_asic_index
        self.speed_cable_len = speed_cable_len

        qos_key = dutConfig['dutAsic']
        if qos_key not in dutConfig["qosConfigs"]['qos_params']:
            pytest.fail(f"{qos_key} not present in qos.yml")

        self.topo_qos_params = dutConfig["qosConfigs"]['qos_params'][qos_key][
            dutConfig["dutTopo"]]

        self.ingressLosslessProfile = ingressLosslessProfile
        self.ingressLossyProfile = ingressLossyProfile
        self.egressLosslessProfile = egressLosslessProfile
        self.egressLossyProfile = egressLossyProfile

        self.test_ports = []
        self.g_test_ib = None
        self.g_d_s_l = None
        self.g_d_s_ll = None

        self.p_to_dp_map = {}
        self.dp_to_p_map = {}
        self.dp_to_ib_map = {}
        self.ib_to_p_map = {}

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

        return self.topo_qos_params

    def __collect_data(self):
        # Collect lane mapping info for all ports

        # Initialize mappings if not already present
        self.p_to_dp_map = getattr(self, 'p_to_dp_map', {})
        self.dp_to_p_map = getattr(self, 'dp_to_p_map', {})

        for port in self.dutConfig['dutInterfaces']:
            eth_str = str(self.dutConfig['dutInterfaces'][port])

            cmd = f'redis-cli -n 4 hget "PORT|{eth_str}" "lanes"'
            result = self.duthost.shell(cmd)
            port_lanes = result.get('stdout', '').strip()

            if not port_lanes:
                logging.error(f"Failed to get lane list for Port {eth_str} "
                              "using Redis command")
                pytest.fail(f"Failed to get lane list for Port {eth_str}")

            try:
                first_lane = int(port_lanes.split(',')[0])
                self.p_to_dp_map[port] = first_lane
                self.dp_to_p_map[first_lane] = port
            except (IndexError, ValueError) as e:
                logging.error(f"Error parsing lanes for Port {eth_str}: "
                              f"{port_lanes} — {e}")
                pytest.fail(f"Invalid lane format for Port {eth_str}")

        logging.debug("Port to devport mapping: {}".format(self.p_to_dp_map))

        # Initialize mappings if not already
        self.dp_to_ib_map = getattr(self, 'dp_to_ib_map', {})
        self.ib_to_p_map = getattr(self, 'ib_to_p_map', {})

        pdinfo_output = self.duthost.shell('ivmcmd "port pdinfo"')['stdout']

        if not pdinfo_output or 'Error' in pdinfo_output:
            pytest.fail("CLI script for 'port pdinfo' failed or is not "
                        "present on the CLI server")

        pdinfo_lines = pdinfo_output.strip().split('\n')
        if len(pdinfo_lines) < 5:
            pytest.fail("Unexpected output format from 'port pdinfo' command")

        for line in pdinfo_lines[4:]:
            line = line.strip()
            if not line or line.startswith('+'):
                continue

            fields = [
                field.strip() for field in line.split('|') if field.strip()]
            if len(fields) < 2:
                logging.warning(f"Skipping malformed line: {line}")
                continue

            try:
                devport = int(fields[0])
                ib = int(fields[1])

                self.dp_to_ib_map[devport] = ib

                if devport in self.dp_to_p_map:
                    self.ib_to_p_map.setdefault(ib, []).append(
                        self.dp_to_p_map[devport])
                else:
                    logging.debug(f"Devport {devport} not found in "
                                  "dp_to_p_map, skipping reverse mapping")

            except (ValueError, IndexError) as e:
                logging.warning(
                    f"Skipping line due to parse error: {line} — {e}")

        logging.debug("dp to ib mapping {}".format(self.dp_to_ib_map))

    def __dump_generated_params_in_file(self):
        logging.debug("Qos params after generation {}".format(
            self.topo_qos_params))

        gen_file_path = 'qos/files/qos_gen_{}.yml'.format(
            self.dutConfig['dutAsic'])

        try:
            with open(gen_file_path, 'w') as fp:
                yaml.dump(self.topo_qos_params, fp, default_flow_style=False)
        except Exception as e:
            logging.error("Failed to write QoS params to file {}: {}".format(
                gen_file_path, e))
            pytest.fail("Failed to write QoS params to file {}: {}".format(
                gen_file_path, e))

    def __update_test_ports_details(self):

        input_test_ports = [
            self.dutConfig['testPorts']['src_port_id'],
            self.dutConfig['testPorts']['dst_port_id'],
            self.dutConfig['testPorts']['dst_port_2_id'],
            self.dutConfig['testPorts']['dst_port_3_id']
        ]

        ib_check_required = False
        if 'src_port_ids' in self.topo_qos_params:
            if input_test_ports[0] in self.topo_qos_params['src_port_ids']:
                ib_check_required = True

        if 'dst_port_ids' in self.topo_qos_params:
            if len(set(input_test_ports[1:]).intersection(
                    set(self.topo_qos_params['dst_port_ids']))) > 0:
                ib_check_required = True

        for ib in self.ib_to_p_map.keys():
            if set(input_test_ports).intersection(
                    set(self.ib_to_p_map[ib])) == set(input_test_ports):
                self.test_ports = input_test_ports
                self.g_test_ib = ib
                break
        else:
            if ib_check_required:
                pytest.fail("Can't use the src_port_ids "
                            f"{self.topo_qos_params['src_port_ids']} "
                            "and dst_port_ids "
                            f"{self.topo_qos_params['dst_port_ids']} "
                            "given in qos.yml, please correct them")

            tmp_ib_port_dict = self.ib_to_p_map.copy()
            while (tmp_ib_port_dict):
                ran_ib = random.choice(list(tmp_ib_port_dict.keys()))
                ports_in_same_ib = tmp_ib_port_dict[ran_ib]
                intersection_ports = set(ports_in_same_ib).intersection(
                    self.dutConfig['testPortIds'][
                        self.src_dut_index][self.src_asic_index])
                if len(ports_in_same_ib) >= 4 and \
                        intersection_ports == set(ports_in_same_ib):
                    self.test_ports = ports_in_same_ib[0:4]
                    self.g_test_ib = ran_ib
                    break
                else:
                    del tmp_ib_port_dict[ran_ib]

        if not self.test_ports:
            pytest.fail("Can't find 4 ports in same ib that present in "
                        "self.dutConfig['testPortIds']")

        # Update the dutConfig['testPorts']
        tmp_testPortIps = self.dutConfig['testPortIps'][
            self.src_dut_index][self.src_asic_index]
        srcPort = self.test_ports[0]
        self.dutConfig['testPorts']['src_port_id'] = srcPort
        self.dutConfig['testPorts']['src_port_ip'] = tmp_testPortIps[
            srcPort]["peer_addr"]
        self.dutConfig['testPorts']['src_port_vlan'] = tmp_testPortIps[
            srcPort]['vlan_id'] if 'vlan_id' in tmp_testPortIps[
                srcPort] else None

        dstPort = self.test_ports[1]
        self.dutConfig['testPorts']['dst_port_id'] = dstPort
        self.dutConfig['testPorts']['dst_port_ip'] = tmp_testPortIps[
            dstPort]["peer_addr"]
        self.dutConfig['testPorts']['dst_port_vlan'] = tmp_testPortIps[
            dstPort]['vlan_id'] if 'vlan_id' in tmp_testPortIps[
                dstPort] else None

        dstPort2 = self.test_ports[2]
        self.dutConfig['testPorts']['dst_port_2_id'] = dstPort2
        self.dutConfig['testPorts']['dst_port_2_ip'] = tmp_testPortIps[
            dstPort2]["peer_addr"]
        self.dutConfig['testPorts']['dst_port_2_vlan'] = tmp_testPortIps[
            dstPort2]['vlan_id'] if 'vlan_id' in tmp_testPortIps[
                dstPort2] else None

        dstPort3 = self.test_ports[3]
        self.dutConfig['testPorts']['dst_port_3_id'] = dstPort3
        self.dutConfig['testPorts']['dst_port_3_ip'] = tmp_testPortIps[
            dstPort3]["peer_addr"]
        self.dutConfig['testPorts']['dst_port_3_vlan'] = tmp_testPortIps[
            dstPort3]['vlan_id'] if 'vlan_id' in tmp_testPortIps[
                dstPort3] else None
        logging.debug("Test Ports: {}".format(self.dutConfig['testPorts']))

        logging.debug("Lossless Buffer profile selected is {}".format(
            self.ingressLosslessProfile["profileName"]))

        # If original src port is different than new one,
        # ingressLossless profile needs change
        if srcPort != input_test_ports[0]:
            if hasattr(self, "_QosSaiBase__getBufferProfile"):
                try:
                    self.ingressLosslessProfile = \
                        self._QosSaiBase__getBufferProfile(
                            self.request, self.dut_asic,
                            self.duthost.os_version,
                            "BUFFER_PG_TABLE" if self.isBufferInApplDb(
                                self.dut_asic) else "BUFFER_PG",
                            self.dutConfig["dutInterfaces"][srcPort], "3-4")
                except Exception as e:
                    logging.error("Failed to get buffer profile for port "
                                  f"{srcPort}: {e}")
                    pytest.fail("Failed to get buffer profile for port "
                                f"{srcPort}: {e}")

        partss_output = self.duthost.shell('ivmcmd "run partss"')['stdout']
        partss_lines = partss_output.strip().split('\n')[2:]

        if not partss_lines:
            pytest.fail('partss CLI returned no output')

        # Check for errors
        if 'Error' in partss_lines[0]:
            pytest.fail('CLI script for partss is not present in CLI server')
        if len(partss_lines) < 2:
            pytest.fail('partss CLI invoke failed or incomplete output')

        # Parse each line
        for line in partss_lines:

            if 'err' in line.lower():
                pytest.fail("CLI script for partss has unexpected "
                            f"error in output: {line}")

            tokens = line.strip().split()
            if not tokens:
                continue

            label = tokens[0].rstrip(':')
            values = tokens[1:]

            if len(values) <= self.g_test_ib:
                pytest.fail("CLI output has fewer values than "
                            f"expected IB index {self.g_test_ib}")

            if label == 'LS':
                self.g_d_s_l = int(values[self.g_test_ib])
                logging.debug(f"Selected IB {self.g_test_ib}: LS value "
                              f"(g_d_s_l) set to {self.g_d_s_l}")
            elif label == 'LL':
                self.g_d_s_ll = int(values[self.g_test_ib])
                logging.debug(f"Selected IB {self.g_test_ib}: LL value "
                              f"(g_d_s_ll) set to {self.g_d_s_ll}")
            else:
                pytest.fail(f'Unexpected label in partss output: {label}')

        # Final validation
        if self.g_d_s_l is None:
            pytest.fail('Failed to get g_d_s_l')
        if self.g_d_s_ll is None:
            pytest.fail('Failed to get g_d_s_ll')

        logging.debug("ib:{},  g_d_s_l:{} , g_d_s_ll:{}".format(
            self.g_test_ib, self.g_d_s_l, self.g_d_s_ll))

    def __calculate_qos_parameters(self):
        """Compute and update QoS test parameters for Marvell ASICS."""

        def update_if_missing(target, key, value):
            if key not in target:
                logging.debug(f"Adding auto generated value for {key}")
                target[key] = value

        # ------------------------------------------------------
        # Buffer Management Params
        # ------------------------------------------------------

        asic_params = self.asic_param_dic[self.dutConfig['dutAsic']]
        b_w_s = asic_params['b_w_s']
        e_b_tr_off = asic_params['e_b_tr_off']
        b_r_s = asic_params['b_r_s']
        b_s_t = asic_params['b_s_t']
        packet_size = 64
        b_w_p_p = int(math.ceil(float(packet_size + 4) / b_w_s))

        d_c_s = asic_params['d_c_s']
        d_s_l = self.g_d_s_l
        d_s_ll = self.g_d_s_ll
        l_q_r_s = int(math.ceil(
            float(self.egressLossyProfile['size']) / d_c_s))
        ll_q_r_s = int(math.ceil(
            float(self.egressLosslessProfile['size']) / d_c_s))
        l_q_d_f = 2 ** int(self.egressLossyProfile['dynamic_th'])
        ll_i_d_f = 2 ** int(self.ingressLosslessProfile['dynamic_th'])

        ll_ip_r_s = int(math.ceil(
            float(self.ingressLosslessProfile['size']) / d_c_s))
        ll_ip_r_o = int(math.ceil(
            float(self.ingressLosslessProfile['xon_offset']) / d_c_s))
        ll_b_i_s = int(math.ceil(
            float(self.ingressLosslessProfile['xoff']) / b_w_s))

        # ------------------------------------------------------
        # Packet Trigger Calculations
        # ------------------------------------------------------
        pkts_num_trig_pfc = int(math.ceil(
            float(ll_i_d_f * d_s_ll - e_b_tr_off) /
            (ll_i_d_f + 1)) + ll_ip_r_s)
        pkts_num_trig_ingr_drp = int(math.ceil(
            float(ll_i_d_f * d_s_ll) /
            (ll_i_d_f + 1)) + ll_ip_r_s + 1 +
            math.ceil(float(ll_b_i_s + b_r_s + b_s_t) / b_w_p_p))
        pkts_num_trig_egr_drp = int(math.ceil(
            float(l_q_d_f * d_s_l) / (l_q_d_f + 1)) + l_q_r_s + 1)
        speed_cable_len_qos_params = self.topo_qos_params[self.speed_cable_len]

        # ------------------------------------------------------
        # XON Parameters (Lossless and Lossy)
        # ------------------------------------------------------
        for xon_key in ['xon_1', 'xon_2']:
            update_if_missing(speed_cable_len_qos_params[xon_key],
                              'pkts_num_trig_pfc', pkts_num_trig_pfc)
            update_if_missing(speed_cable_len_qos_params[xon_key],
                              'pkts_num_hysteresis', ll_ip_r_o)

        # ------------------------------------------------------
        # XOFF Parameters (Lossless and Lossy)
        # ------------------------------------------------------
        for xoff_key in ['xoff_1', 'xoff_2']:
            update_if_missing(speed_cable_len_qos_params[xoff_key],
                              'pkts_num_trig_pfc', pkts_num_trig_pfc)
            update_if_missing(speed_cable_len_qos_params[xoff_key],
                              'pkts_num_trig_ingr_drp', pkts_num_trig_ingr_drp)

        # ------------------------------------------------------
        # Lossy Queue Parameters
        # ------------------------------------------------------
        update_if_missing(speed_cable_len_qos_params['lossy_queue_1'],
                          'pkts_num_trig_egr_drp', pkts_num_trig_egr_drp)

        # ------------------------------------------------------
        # Watermark Queue Shared Lossy Parameters
        # ------------------------------------------------------
        wm_q_shared_lossy = speed_cable_len_qos_params['wm_q_shared_lossy']
        update_if_missing(wm_q_shared_lossy, 'pkts_num_fill_min', l_q_r_s)
        update_if_missing(wm_q_shared_lossy, 'pkts_num_trig_egr_drp',
                          pkts_num_trig_egr_drp)
        update_if_missing(wm_q_shared_lossy, 'cell_size', d_c_s)

        # ------------------------------------------------------
        # Watermark Queue Shared Lossless Parameters
        # ------------------------------------------------------
        wm_q_shared_lossless = speed_cable_len_qos_params[
            'wm_q_shared_lossless']
        update_if_missing(wm_q_shared_lossless, 'pkts_num_fill_min', ll_q_r_s)
        update_if_missing(wm_q_shared_lossless, 'pkts_num_trig_ingr_drp',
                          int(math.ceil(float(ll_i_d_f * d_s_ll) /
                                        (ll_i_d_f + 1)) + ll_ip_r_s + 1))
        update_if_missing(wm_q_shared_lossless, 'cell_size', d_c_s)

        # ------------------------------------------------------
        # Headroom Pool Watermark & Headroom Pool Size Parameters
        # ------------------------------------------------------
        # Specific to Headroom Pool Watermark
        update_if_missing(self.topo_qos_params, 'hdrm_pool_wm_multiplier',
                          b_w_p_p)
        update_if_missing(self.topo_qos_params, 'cell_size', b_w_s)

        # Common for both Headroom Pool Watermark & Headroom Pool Size
        hdrm_pool_size = speed_cable_len_qos_params['hdrm_pool_size']
        update_if_missing(hdrm_pool_size, 'src_port_ids', self.test_ports[:-1])
        update_if_missing(hdrm_pool_size, 'dst_port_id', self.test_ports[-1])
        num_pgs = len(hdrm_pool_size['pgs'])
        num_src_ports = len(hdrm_pool_size['src_port_ids'])
        update_if_missing(hdrm_pool_size, 'pgs_num', num_pgs * num_src_ports)
        # Set 'pkts_num_trig_pfc' to '0' since 'pkts_num_trig_pfc_shp'
        # will be used instead
        update_if_missing(hdrm_pool_size, 'pkts_num_trig_pfc', 0)
        # Calculate and append PFC shared pool trigger for each PG
        if 'pkts_num_trig_pfc_shp' not in hdrm_pool_size:
            hdrm_pool_size['pkts_num_trig_pfc_shp'] = []
            shared_size = d_s_ll
            for _ in range(hdrm_pool_size['pgs_num']):
                shared_size_accessible = int(math.ceil(
                    float(ll_i_d_f * shared_size - e_b_tr_off) /
                    (ll_i_d_f + 1)
                ))
                pkt_num_trig_pfc = shared_size_accessible + ll_ip_r_s
                hdrm_pool_size['pkts_num_trig_pfc_shp'].append(
                    pkt_num_trig_pfc)
                shared_size -= shared_size_accessible
        update_if_missing(hdrm_pool_size, 'pkts_num_hdrm_full',
                          int(math.ceil(float(ll_b_i_s + b_s_t + b_r_s) /
                                        b_w_p_p)))
        update_if_missing(hdrm_pool_size, 'pkts_num_hdrm_partial',
                          int(math.ceil(float(ll_b_i_s + b_s_t + b_r_s) /
                                        b_w_p_p)))

        # ------------------------------------------------------
        # Priority Group (PG) Watermark Parameters
        # ------------------------------------------------------
        if self.dutConfig['dutAsic'] not in ['tl7']:
            wm_pg_shared_lossy = speed_cable_len_qos_params[
                'wm_pg_shared_lossy']
            update_if_missing(wm_pg_shared_lossy, 'pkts_num_fill_min', l_q_r_s)
            update_if_missing(wm_pg_shared_lossy, 'pkts_num_trig_egr_drp',
                              pkts_num_trig_egr_drp)
            update_if_missing(wm_pg_shared_lossy, 'cell_size', d_c_s)

            wm_pg_shared_lossless = speed_cable_len_qos_params[
                'wm_pg_shared_lossless']
            update_if_missing(wm_pg_shared_lossless, 'pkts_num_fill_min',
                              ll_ip_r_s)
            update_if_missing(wm_pg_shared_lossless, 'pkts_num_trig_pfc',
                              pkts_num_trig_pfc)
            update_if_missing(wm_pg_shared_lossless, 'cell_size', d_c_s)

            wm_pg_headroom = speed_cable_len_qos_params['wm_pg_headroom']
            update_if_missing(wm_pg_headroom, 'pkts_num_trig_pfc',
                              pkts_num_trig_pfc + b_s_t + b_r_s)
            update_if_missing(wm_pg_headroom, 'pkts_num_trig_ingr_drp',
                              pkts_num_trig_ingr_drp)
            update_if_missing(wm_pg_headroom, 'cell_size', b_w_s)

        # ------------------------------------------------------
        # Buffer Pool Watermark Parameters (Lossless and Lossy)
        # ------------------------------------------------------
        wm_buf_pool_lossy = speed_cable_len_qos_params['wm_buf_pool_lossy']
        update_if_missing(wm_buf_pool_lossy, 'pkts_num_fill_egr_min', l_q_r_s)
        update_if_missing(wm_buf_pool_lossy, 'pkts_num_trig_pfc',
                          pkts_num_trig_pfc)
        update_if_missing(wm_buf_pool_lossy, 'pkts_num_trig_egr_drp',
                          pkts_num_trig_egr_drp)
        update_if_missing(wm_buf_pool_lossy, 'cell_size', d_c_s)
        update_if_missing(wm_buf_pool_lossy, 'extra_cap_margin',
                          b_s_t + b_r_s)

        wm_buf_pool_lossless = speed_cable_len_qos_params[
            'wm_buf_pool_lossless']
        update_if_missing(wm_buf_pool_lossless, 'pkts_num_fill_ingr_min',
                          ll_ip_r_s)
        update_if_missing(wm_buf_pool_lossless, 'pkts_num_trig_pfc',
                          pkts_num_trig_pfc)
        update_if_missing(wm_buf_pool_lossless, 'pkts_num_trig_ingr_drp',
                          pkts_num_trig_ingr_drp)
        update_if_missing(wm_buf_pool_lossless, 'cell_size', d_c_s)

        if self.dutConfig['dutAsic'] == 'tl7':
            d_ll_inf = 32
        else:
            d_ll_inf = 0

        update_if_missing(wm_buf_pool_lossless, 'extra_cap_margin',
                          int(math.ceil((ll_b_i_s * (b_w_s / d_c_s)) +
                                        d_ll_inf + ll_ip_r_s + 1)))

        # ------------------------------------------------------
        # Final Test Port IDs Update
        # ------------------------------------------------------
        self.topo_qos_params['src_port_ids'] = self.test_ports[0]
        self.topo_qos_params['dst_port_ids'] = self.test_ports[1:]

        # ------------------------------------------------------
        # Sort the QoS parameter dictionary for consistency
        # ------------------------------------------------------
        self.topo_qos_params = OrderedDict(sorted(
            self.topo_qos_params.items()))
