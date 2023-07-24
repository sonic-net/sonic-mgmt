import pytest
import logging
import json
import paramiko
import time

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)

class TRexHost(AnsibleHostBase):
    """
    @summary: Class for TRex

    Instance of this class can run ansible modules on the TRex host which is running on same server with pytest.
    """

    def __init__(self, ansible_adhoc, duthost, hostname, ip,
                 cmds_path="./trex/trex_cmds.json", login="admin5", password="admin"):
        self.ip = ip
        self.cmds_path = cmds_path
        self.login = login
        self.password = password
        self.duthost = duthost
        self.result = ""
        self.res = ""

        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

        self.conn = paramiko.SSHClient()
        self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.conn.connect(self.ip,
                          username=self.login,
                          password=self.password,
                          allow_agent=False,
                          look_for_keys=False)
        self.shell = self.conn.invoke_shell()
        self.shell.keep_this = self.conn  # to keep the session go on

        with open(self.cmds_path) as f:
            self.cmds_json = json.load(f)

    def start_trex_server(self, cfg_path="/etc/trex_cfg.yaml"):
        """
        @summary: start TRex server

        @param cfg_path: TRex configuration file's full path, default is "/etc/trex_cfg.yaml"
        """
        self.start_trex_server = paramiko.SSHClient()
        self.start_trex_server.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.start_trex_server.connect(self.ip,
                                       username=self.login,
                                       password=self.password,
                                       allow_agent=False,
                                       look_for_keys=False)
        client = self.start_trex_server.invoke_shell()
        client.send("cd /opt/trex/v2.87" + '\n')
        client.send("sudo ./t-rex-64 -i --cfg {}".format(cfg_path) + '\n')
        # server_output_test = client.recv(10240)
        time.sleep(20)
        # logging.warning("server_output_test: {}".format(server_output_test))
        # while True:
        #         server_output = client.recv(1024)
        #         if server_output[-2:] in "# " or server_output[-1:] in ">" or server_output[-1:] in "$ ":
        #             break
        # logging.warning("server_output: {}".format(server_output))

        self.do_cmd("ps -aux | grep 't-rex-64' | grep -v 'grep'")
        if "t-rex-64" in self.result:
            logging.info("TRex server started.")
        else:
            logging.info("TRex server failed to start.")

        return

    def stop_trex_server(self):
        """
        @summary: stop TRex server
        """
        self.command("cd /opt/trex/v2.87; \
                      sudo pkill _t-rex-64")

    def do_cmd(self, cmd, dut=False):
        if cmd is not None:
            self.result = ""
            if dut:
                logging.info("dut cmd executed: {}".format(cmd))
                self.result = self.duthost.shell(cmd)['stdout']
                time.sleep(3)
            else:
                logging.info("cmd executed: {}".format(cmd))
                self.shell.send(cmd + '\n')
                time.sleep(5)
                while True:
                    output = self.shell.recv(1024)
                    self.result = self.result + output
                    if self.result[-2:] in "# " or self.result[-1:] in ">" or self.result[-1:] in "$ ":
                        break
            logging.info("result: {}".format(self.result))

        return

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None
        if self.start_trex_server is not None:
            self.start_trex_server.close()
            self.start_trex_server = None

        return

    def run(self, cmd_name, cmds_list='', dut=False):
        if cmds_list == '':
            cmds_list = self.cmds_json[cmd_name]
        else:
            cmds_list = cmds_list

        # self.do_cmd('sudo su')
        # time.sleep(1)

        self.res = ''
        for cmd in cmds_list:
            self.do_cmd(cmd, dut=dut)
            self.res = self.res + self.result
            # time.sleep(5)

        # self.disconnect()

        return

    def set_dut_ip_route(self, duthost):
        """
        @summary: do IP/routes configuration on DUT.
        """
        dut_ip = self.cmds_json["dut_ip"]
        dut_routes = self.cmds_json["dut_routes"]
        duthost.shell("sudo config interface ip add Ethernet{} {}".format(dut_ip["eth_egress"],
                                                                          dut_ip["ip_egress"]))
        duthost.shell("sudo config interface ip add Ethernet{} {}".format(dut_ip["eth_ingress"],
                                                                          dut_ip["ip_ingress"]))
        duthost.shell("sudo config route add prefix {} nexthop {}".format(dut_routes["prefix_egress"],
                                                                          dut_routes["nexthop_egress"]))
        duthost.shell("sudo config route add prefix {} nexthop {}".format(dut_routes["prefix_ingress"],
                                                                          dut_routes["nexthop_ingress"]))

    def set_dut_buffer(self):
        """
        @summary: do buffer configuration on DUT.
        """
        self.run("dut_buffer_config", dut=True)

    def set_dut_pfc(self, eth, pg_list):
        """
        @summary: do pfc configuration on DUT.
        """
        cmds_buffer = self.cmds_json['dut_pfc_config']
        cmds_list = cmds_buffer

        for i in range(len(pg_list)):
            if pg_list[i] == 1:
                cmds_list.pop(-1)
            else:
                cmds_list.insert(i+2, cmds_buffer[1].replace('pg_tbd', str(pg_list[i])))
        cmds_list.pop(1)

        eth_list = eth.split("-")
        cmds_temp = []
        if len(eth_list) == 0:
            pytest.fail("None of Ethernet is defined, please check. Test exited.")
        elif len(eth_list) == 1:
            for cmd in cmds_list:
                cmds_temp.append(cmd.replace('Ethernet55', 'Ethernet{}'.format(eth)))
        elif len(eth_list) == 2:
            for eth in range(int(eth_list[0]), int(eth_list[1])+1):
                for cmd in cmds_list:
                    cmds_temp.append(cmd.replace('Ethernet55', 'Ethernet{}'.format(eth)))
        else:
            pytest.fail("Maybe too many Ethernets are defined, pleach check. Test exited.")
        cmds_list = cmds_temp

        self.run("dut_pfc_config", cmds_list=cmds_list, dut=True)

        # logging.info("cmds_list: {}".format(cmds_list))

        # for cmd in cmds_buffer:
        #     cmds_list.append(cmd.replace('Ethernet55', eth).replace('pg_tbd', pg))
        # # logging.warning("set_dut_pfc cmds_list: {}, length: {}".format(cmds_list, len(cmds_list)))

        # # cmds_buffer = json.dumps(self.cmds_json['dut_buffer_pfc_config'])
        # # logging.warning("set_dut_pfc cmds_buffer: {}".format(cmds_buffer))
        # # cmds_list = self.duthost.shell("echo {} | sed -n 's/Ethernet55/{}/g;p' | \
        # # sed -n 's/pg_tbd/{}/g;p'".format(cmds_buffer, eth, pg))['stdout_lines']
        # # logging.warning("set_dut_pfc cmds_list: {}, length: {}".format(cmds_list, len(cmds_list)))

    def set_dut_pfc_counter(self):
        """
        @summary: do pfc counter configuration on DUT.
        """
        self.run("dut_pfc_counter_config", dut=True)

        return

    def del_dut_pfc(self, eth, pg_list):
        """
        @summary: del pfc configuration on DUT.
        """
        eth_list = []
        eth_temp = eth.split("-")
        if len(eth_temp) == 0:
            pytest.fail("None of Ethernet is defined, please check. Test exited.")
        elif len(eth_temp) == 1:
            eth_list = [int(eth_temp[0])]
        elif len(eth_temp) == 2:
            eth_list = [i for i in range(int(eth_temp[0]), int(eth_temp[1])+1)]
        else:
            pytest.fail("Maybe too many Ethernets are defined, pleach check. Test exited.")

        cmds_list = []
        for eth in eth_list:
            for pg in pg_list:
                cmds_list.append('sudo config interface pfc priority Ethernet{} {} off'.format(eth, pg))
            cmds_list.append('sudo config interface buffer priority-group lossless remove Ethernet{}'.format(eth))

        self.run("dut_disable_pfc", cmds_list=cmds_list, dut=True)

        return self.res

    def del_dut_buffer(self, profile='pg-lossless'):
        """
        @summary: del buffer configuration on DUT.
        """
        cmds_list = self.cmds_json['dut_del_buffer_config']
        cmds_list[0] = cmds_list[0].replace('pg-lossless', profile)
        # logging.info("del_dut_buffer cmds_list: {}".format(cmds_list) )

        self.run("dut_del_buffer_config", cmds_list=cmds_list, dut=True)

        return

    def get_dut_intf(self):
        show_interface = self.duthost.show_interface()['ansible_facts']
        logging.info("show_interface: {}, type: {}".format(show_interface, type(show_interface)))

    def do_dut_buffer_issue_avoidance(self):
        """
        @summary: do buffer issue avoidance on DUT.
        """
        self.run("dut_buffer_issue_avoidance", dut=True)

        return

    def learn_arp(self):
        """
        @summary: learn arp for port(s) of TRex server to generate traffic.
        """
        self.run("learn_arp")

        return

    def portattr(self):
        """
        @summary: show portattr info of TRex server.
        """
        self.run("portattr")

        return self.res

    def start_flow(self):
        """
        @summary: start linear rdma flow.
        """
        logging.info('Start flow')
        self.run("start_flow")

        return

    def start_pfc_flow(self, ls_octet='00'):
        """
        @summary: start PFC packets flow.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.ip,
                    username=self.login,
                    password=self.password,
                    allow_agent=False,
                    look_for_keys=False)
        conn_pfc_mod = ssh.invoke_shell()
        conn_pfc_mod.send('sudo sed -i \'/pad =/s/x[0-9a-f][0-9a-f]/x{}/4\' \
                           /opt/trex/v2.87/stl/pfcPacket.py\n'.format(ls_octet))
        time.sleep(2)
        # result = ''
        # while True:
        #     output = conn_pfc_mod.recv(1024)
        #     result = result + output
        #     if result[-2:] in "# " or result[-1:] in ">" or result[-1:] in "$ ":
        #         break
        # logging.info('ls_octet: {}'.format(ls_octet))
        # logging.info('start_pfc_flow result: {}'.format(result))
        conn_pfc_mod.close()
        logging.info('Start PFC flow')
        self.run("start_pfc_flow")

        return

    def pfc_statistics(self):
        """
        @summary: start PFC statistics.
        """
        logging.info('Start PFC statistics')
        self.run("pfc_statistics", dut=True)

        return

    def dut_counters(self):
        """
        @summary: get dut show int counters.
        """
        logging.info('Dut show int counters')
        self.run("dut_counters", dut=True)

        return

def clean_data(list_data, s1):
    res_list = []
    for temp in list_data[s1:]:
        n = temp.split(' ')
        n = [i for i in n if i != '']
        res_list.append(n)
    return res_list
