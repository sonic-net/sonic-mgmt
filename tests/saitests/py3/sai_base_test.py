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

################################################################
#
# Thrift interface base tests
#
################################################################

import switch_sai_thrift.switch_sai_rpc as switch_sai_rpc
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import socket
import sys
import paramiko
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException

interface_to_front_mapping = {}

from switch import (sai_thrift_port_tx_enable,      # noqa E402
                    sai_thrift_port_tx_disable)


class ThriftInterface(BaseTest):

    def setUp(self):
        global interface_to_front_mapping

        BaseTest.setUp(self)

        self.test_params = testutils.test_params_get()
        if "server" in self.test_params:
            self.server = self.test_params['server']
        else:
            self.server = 'localhost'
        self.platform_asic = self.test_params.get('platform_asic', None)

        self.asic_id = self.test_params.get('asic_id', None)
        if "port_map" in self.test_params:
            user_input = self.test_params['port_map']
            splitted_map = user_input.split(",")
            for item in splitted_map:
                interface_front_pair = item.split("@")
                interface_to_front_mapping[interface_front_pair[0]
                                           ] = interface_front_pair[1]
        elif "port_map_file" in self.test_params:
            user_input = self.test_params['port_map_file']
            f = open(user_input, 'r')
            for line in f:
                if (len(line) > 0 and (line[0] == '#' or line[0] == ';' or line[0] == '/')):
                    continue
                interface_front_pair = line.split("@")
                interface_to_front_mapping[interface_front_pair[0]
                                           ] = interface_front_pair[1].strip()
            f.close()
        else:
            exit("No ptf interface<-> switch front port mapping, please specify as parameter or in external file")

        # Set up thrift client and contact server
        self.transport = TSocket.TSocket(self.server, 9092)
        self.transport = TTransport.TBufferedTransport(self.transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        self.client = switch_sai_rpc.Client(self.protocol)
        self.transport.open()

    def tearDown(self):
        if config["log_dir"] is not None:
            self.dataplane.stop_pcap()
        BaseTest.tearDown(self)
        self.transport.close()

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

    def sai_thrift_port_tx_enable(self, client, asic_type, port_list, last_port=True):
        if self.platform_asic and self.platform_asic == "broadcom-dnx" and last_port:
            # need to enable watchdog on the source asic using cint script
            cmd = "bcmcmd -n {} \"BCMSAI credit-watchdog enable\"".format(
                self.asic_id)
            stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.server,
                                                            self.test_params['dut_username'],
                                                            self.test_params['dut_password'],
                                                            cmd)
            assert ('Success rv = 0' in stdOut[1]), "enable wd failed '{}' on asic '{}' on '{}'"\
                .format(cmd, self.asic_id, self.server)

        sai_thrift_port_tx_enable(client, asic_type, port_list)

    def sai_thrift_port_tx_disable(self, client, asic_type, port_list):
        if self.platform_asic and self.platform_asic == "broadcom-dnx":
            # need to enable watchdog on the source asic using cint script
            cmd = "bcmcmd -n {} \"BCMSAI credit-watchdog disable\"".format(
                self.asic_id)
            stdOut, stdErr, retValue = self.exec_cmd_on_dut(self.server,
                                                            self.test_params['dut_username'],
                                                            self.test_params['dut_password'],
                                                            cmd)
            assert ('Success rv = 0' in stdOut[1]), "disable wd failed '{}' on asic '{}' on '{}'"\
                .format(cmd, self.asic_id, self.server)
        sai_thrift_port_tx_disable(client, asic_type, port_list)


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
