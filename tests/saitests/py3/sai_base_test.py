"""
Base classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""
import os
import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils
import json
import socket
import time

################################################################
#
# Thrift interface base tests
#
################################################################

import switch_sai_thrift.switch_sai_rpc as switch_sai_rpc
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import sys
import paramiko
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException

# dictionary of interface_to_front_mapping with key 'src' or 'dst' and the ports for those target
interface_to_front_mapping = {}

from switch import (sai_thrift_port_tx_enable,      # noqa E402
                    sai_thrift_port_tx_disable,
                    sai_thrift_credit_wd_enable,
                    sai_thrift_credit_wd_disable)

DATA_PLANE_QUEUE_LIST = ["0", "1", "2", "3", "4", "5", "6", "7"]
DEFAULT_QUEUE_SCHEDULER_CONFIG = {"0": "scheduler.0",
                                  "1": "scheduler.0",
                                  "2": "scheduler.0",
                                  "3": "scheduler.1",
                                  "4": "scheduler.1",
                                  "5": "scheduler.0",
                                  "6": "scheduler.0",
                                  "7": ""}


class ThriftInterface(BaseTest):

    def setUp(self):
        global interface_to_front_mapping

        BaseTest.setUp(self)

        self.test_params = testutils.test_params_get()

        # server is a list [ <server_ip_for_dut1>, <server_ip_for_dut2>, ... }
        if "src_server" in self.test_params:
            # server has format <server_ip>:<server_port>
            src_server = self.test_params['src_server'].strip().split(":")
            self.src_server_ip = src_server[0]
            src_server_port = src_server[1]
        else:
            self.src_server_ip = 'localhost'
            src_server_port = 9092
        if "dst_server" in self.test_params:
            # server has format <server_ip>:<server_port>
            dst_server = self.test_params['dst_server'].strip().split(":")
            self.dst_server_ip = dst_server[0]
            dst_server_port = dst_server[1]
        else:
            self.dst_server_ip = self.src_server_ip
            dst_server_port = src_server_port
        self.server = self.dst_server_ip
        self.original_dut_port_queue_scheduler_map = {}

        if "port_map_file" in self.test_params:
            user_input = self.test_params['port_map_file']
            interface_to_front_mapping['src'] = {}
            with open(user_input) as f:
                ptf_test_port_map = json.load(f)
                src_dut_index = self.test_params['src_dut_index']
                self.src_asic_index = self.test_params.get('src_asic_index', None)
                dst_dut_index = self.test_params['dst_dut_index']
                self.dst_asic_index = self.test_params.get('dst_asic_index', None)
                for a_ptf_port, a_ptf_port_info in ptf_test_port_map.items():
                    if src_dut_index in a_ptf_port_info['target_dut'] and \
                            a_ptf_port_info['asic_idx'] == self.src_asic_index:
                        interface_to_front_mapping['src'][a_ptf_port] = a_ptf_port_info['dut_port']
                if src_dut_index != dst_dut_index or self.src_asic_index != self.dst_asic_index:
                    interface_to_front_mapping['dst'] = {}
                    for a_ptf_port, a_ptf_port_info in ptf_test_port_map.items():
                        if dst_dut_index in a_ptf_port_info['target_dut'] and \
                                a_ptf_port_info['asic_idx'] == self.dst_asic_index:
                            interface_to_front_mapping['dst'][a_ptf_port] = a_ptf_port_info['dut_port']
                else:
                    interface_to_front_mapping['dst'] = interface_to_front_mapping['src']
        elif "port_map_file_ini" in self.test_params:
            user_input = self.test_params['port_map_file_ini']
            interface_to_front_mapping['src'] = {}
            f = open(user_input, 'r')
            for line in f:
                if (len(line) > 0 and (line[0] == '#' or line[0] == ';' or line[0] == '/')):
                    continue
                interface_front_pair = line.split("@")
                interface_to_front_mapping['src'][interface_front_pair[0]] = interface_front_pair[1].strip()
                # src = dst on single ASIC device.
                # Copy the src to dst cause some function will read this key
                interface_to_front_mapping['dst'] = interface_to_front_mapping['src']
            f.close()
        else:
            exit("No ptf interface<-> switch front port mapping, please specify as parameter or in external file")
        # dictionary with key 'src' or 'dst'
        self.clients = {}
        # Set up thrift client and contact server

        # Below are dictionaries with key dut_index, and value the value for dut at dut_index.
        self.src_transport = TSocket.TSocket(self.src_server_ip, src_server_port)
        self.src_transport = TTransport.TBufferedTransport(self.src_transport)
        self.src_protocol = TBinaryProtocol.TBinaryProtocol(self.src_transport)
        self.src_client = switch_sai_rpc.Client(self.src_protocol)
        self.src_transport.open()
        self.clients['src'] = self.src_client
        if self.src_server_ip == self.dst_server_ip and src_server_port == dst_server_port:
            # using the same client for dst as the src.
            self.dst_client = self.src_client
        else:
            # using different client for dst
            self.dst_transport = TSocket.TSocket(self.dst_server_ip, dst_server_port)
            self.dst_transport = TTransport.TBufferedTransport(self.dst_transport)
            self.dst_protocol = TBinaryProtocol.TBinaryProtocol(self.dst_transport)
            self.dst_client = switch_sai_rpc.Client(self.dst_protocol)
            self.dst_transport.open()
        self.clients['dst'] = self.dst_client

        self.platform_asic = self.test_params.get('platform_asic', None)

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()
        BaseTest.tearDown(self)
        self.src_transport.close()
        if self.dst_client != self.src_client:
            self.dst_transport.close()

    def exec_cmd_on_dut(self, hostname, username, password, cmd):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if isinstance(cmd, list):
            cmd = ' '.join(cmd)

        stdOut = stdErr = []
        retValue = 1
        try:
            client.connect(hostname, username=username,
                           password=password, allow_agent=False)
            si, so, se = client.exec_command(cmd, timeout=20)
            stdOut = so.readlines()
            stdErr = se.readlines()
            retValue = 0
        except AuthenticationException as authenticationException:
            print('SSH Authentication failure with message: %s' %
                  authenticationException, file=sys.stderr)
        except SSHException as sshException:
            print('SSH Command failed with message: %s' %
                  sshException, file=sys.stderr)
        except BadHostKeyException as badHostKeyException:
            print('SSH Authentication failure with message: %s' %
                  badHostKeyException, file=sys.stderr)
        except socket.timeout as e:
            # The ssh session will timeout in case of a successful reboot
            print('Caught exception socket.timeout: {}, {}, {}'.format(
                repr(e), str(e), type(e)), file=sys.stderr)
            retValue = 255
        except Exception as e:
            print('Exception caught: {}, {}, type: {}'.format(
                repr(e), str(e), type(e)), file=sys.stderr)
            print(sys.exc_info(), file=sys.stderr)
        finally:
            client.close()

        return stdOut, stdErr, retValue

    def sai_thrift_port_tx_enable(
            self, client, asic_type, port_list, target='dst', last_port=True, enable_port_by_unblock_queue=True):
        count = 0
        if asic_type == 'mellanox' and enable_port_by_unblock_queue:
            self.enable_mellanox_egress_data_plane(port_list)
        else:
            sai_thrift_port_tx_enable(client, asic_type, port_list, target=target)
        if self.platform_asic and self.platform_asic == "broadcom-dnx" and last_port:
            # need to enable watchdog on the source asic
            # max 3 retries
            while count < 3:
                retValue = sai_thrift_credit_wd_enable(self.src_client)
                if retValue == 0:
                    break
                else:
                    print("Retrying credit_wd_enable")
                    time.sleep(1)
                count += 1
            assert retValue == 0, "enable wd failed on asic '{}' on '{}' with error '{}'".format(
                self.src_asic_index, self.src_server_ip, retValue)

    def sai_thrift_port_tx_disable(self, client, asic_type, port_list, target='dst', disable_port_by_block_queue=True):
        count = 0
        if self.platform_asic and self.platform_asic == "broadcom-dnx":
            # need to disable watchdog on the source asic
            # max 3 retries
            while count < 3:
                retValue = sai_thrift_credit_wd_disable(self.src_client)
                if retValue == 0:
                    break
                else:
                    print("Retrying credit_wd_disable")
                    time.sleep(1)
                count += 1
            assert retValue == 0, "disable wd failed on asic '{}' on '{}' with error '{}'".format(
                self.src_asic_index, self.src_server_ip, retValue)

        if asic_type == 'mellanox' and disable_port_by_block_queue:
            self.disable_mellanox_egress_data_plane(port_list)
        else:
            sai_thrift_port_tx_disable(client, asic_type, port_list, target=target)

    def get_dut_port(self, ptf_port):
        for port_group in interface_to_front_mapping.keys():
            if str(ptf_port) in interface_to_front_mapping[port_group].keys():
                dut_port = interface_to_front_mapping[port_group][str(ptf_port)]
                return dut_port
        return None

    def disable_mellanox_egress_data_plane(self, ptf_port_list):
        dut_port_list = []
        for ptf_port in ptf_port_list:
            dut_port = self.get_dut_port(ptf_port)
            dut_port_list.append(dut_port)
        self.original_dut_port_queue_scheduler_map = self.get_queue_scheduler_name(dut_port_list)
        block_data_plane_scheduler_name = 'scheduler.block_data_plane'
        cmd_set_block_data_plane_scheduler = \
            f'sonic-db-cli CONFIG_DB hset "SCHEDULER|{block_data_plane_scheduler_name}" "type" DWRR "weight" 15 "pir" 1'

        self.exec_cmd_on_dut(self.server, self.test_params['dut_username'], self.test_params['dut_password'],
                             cmd_set_block_data_plane_scheduler)
        for dut_port in dut_port_list:
            for q in DATA_PLANE_QUEUE_LIST:
                cmd_block_q = \
                    f" sonic-db-cli CONFIG_DB hset 'QUEUE|{dut_port}|{q}' scheduler {block_data_plane_scheduler_name}"
                self.exec_cmd_on_dut(
                    self.server, self.test_params['dut_username'], self.test_params['dut_password'], cmd_block_q)

    def get_queue_scheduler_name(self, dut_port_list):
        dut_port_queue_scheduler_map = {}
        for dut_port in dut_port_list:
            dut_port_queue_scheduler_map[dut_port] = {}
            for q in DATA_PLANE_QUEUE_LIST:
                cmd_get_q_scheduler_name = f"sonic-db-cli CONFIG_DB hget 'QUEUE|{dut_port}|{q}' scheduler"
                scheduler_name, _, _ = self.exec_cmd_on_dut(
                    self.server, self.test_params['dut_username'],
                    self.test_params['dut_password'], cmd_get_q_scheduler_name)
                scheduler_name = scheduler_name[0].strip("\n")
                dut_port_queue_scheduler_map[dut_port][q] = scheduler_name
        return dut_port_queue_scheduler_map

    def enable_mellanox_egress_data_plane(self, ptf_port_list):
        for ptf_port in ptf_port_list:
            dut_port = self.get_dut_port(ptf_port)
            for q in DATA_PLANE_QUEUE_LIST:
                scheduler_name = self.original_dut_port_queue_scheduler_map[dut_port][q] if \
                    self.original_dut_port_queue_scheduler_map else DEFAULT_QUEUE_SCHEDULER_CONFIG[q]
                cmd_set_q_scheduler = f" sonic-db-cli CONFIG_DB hset 'QUEUE|{dut_port}|{q}' scheduler {scheduler_name}"
                cmd_del_q_scheduler = f" sonic-db-cli CONFIG_DB hdel 'QUEUE|{dut_port}|{q}' scheduler "
                cmd_recover_q_scheduler_config = cmd_set_q_scheduler if scheduler_name else cmd_del_q_scheduler
                self.exec_cmd_on_dut(
                    self.server, self.test_params['dut_username'],
                    self.test_params['dut_password'], cmd_recover_q_scheduler_config)


class ThriftInterfaceDataPlane(ThriftInterface):
    """
    Root class that sets up the thrift interface and dataplane
    """

    def setUp(self):
        ThriftInterface.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] is not None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()
        ThriftInterface.tearDown(self)
