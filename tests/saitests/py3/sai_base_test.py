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

from switch import (sai_thrift_port_tx_enable,
                    sai_thrift_port_tx_disable)

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
        if config["log_dir"] != None:
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
            client.connect(hostname, username=username, password=password, allow_agent=False)
            si, so, se = client.exec_command(cmd, timeout=20)
            stdOut = so.readlines()
            stdErr = se.readlines()
            retValue = 0
        except AuthenticationException as authenticationException:
            print('SSH Authentication failure with message: %s' % authenticationException, file=sys.stderr)
        except SSHException as sshException:
            print('SSH Command failed with message: %s' % sshException, file=sys.stderr)
        except BadHostKeyException as badHostKeyException:
            print('SSH Authentication failure with message: %s' % badHostKeyException, file=sys.stderr)
        except socket.timeout as e:
            # The ssh session will timeout in case of a successful reboot
            print('Caught exception socket.timeout: {}, {}, {}'.format(repr(e), str(e), type(e)), file=sys.stderr)
            retValue = 255
        except Exception as e:
            print('Exception caught: {}, {}, type: {}'.format(repr(e), str(e), type(e)), file=sys.stderr)
            print(sys.exc_info(), file=sys.stderr)
        finally:
            client.close()

        return stdOut, stdErr, retValue

    def sai_thrift_port_tx_enable(self, client, asic_type, port_list, target='dst', last_port=True):
        if self.platform_asic and self.platform_asic == "broadcom-dnx" and last_port:
            # need to enable watchdog on the source asic using cint script
            cmd = "bcmcmd -n {} \"BCMSAI credit-watchdog enable\"".format(self.src_asic_index)
            stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.src_server_ip,
                                                            self.test_params['dut_username'],
                                                            self.test_params['dut_password'],
                                                            cmd)
            assert ('Success rv = 0' in stdOut[1], "enable wd failed '{}' on asic '{}' on '{}'".format(cmd, self.src_asic_index,
                                                                                            self.src_server_ip))

        sai_thrift_port_tx_enable(client, asic_type, port_list, target=target)

    def sai_thrift_port_tx_disable(self, client, asic_type, port_list, target='dst'):
        if self.platform_asic and self.platform_asic == "broadcom-dnx":
            # need to enable watchdog on the source asic using cint script
            cmd = "bcmcmd -n {} \"BCMSAI credit-watchdog disable\"".format(self.src_asic_index)
            stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.src_server_ip,
                                                            self.test_params['dut_username'],
                                                            self.test_params['dut_password'],
                                                            cmd)
            assert ('Success rv = 0' in stdOut[1]), "disable wd failed '{}' on asic '{}' on '{}'".format(cmd, self.src_asic_index,
                                                                                        self.src_server_ip)
        sai_thrift_port_tx_disable(client, asic_type, port_list, target=target)


class ThriftInterfaceDataPlane(ThriftInterface):
    """
    Root class that sets up the thrift interface and dataplane
    """
    def setUp(self):
        ThriftInterface.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        ThriftInterface.tearDown(self)
