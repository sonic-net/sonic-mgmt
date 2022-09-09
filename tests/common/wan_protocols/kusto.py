import time
import json
import re
from kusto_proxy.teams import PhyNetKustoProxy
from net_devices2 import get_device_handler, get_device


class InteropDevice:
    """
    The definition of interop with device
    :param dut: string
    """

    def __init__(self, dut):
        self.dut = dut
        self.dut_handler = get_device_handler(dut)

    def execute_cmd(self, cmd):
        """
        execute command to DUT
        :param cmd:
        :return: command output results
        """
        output = self.dut_handler.send_commands(cmd)
        output_lines = output[0][cmd].splitlines()
        return output_lines

    def get_port_name(self):
        """
        via LLDP output to get the interface connected SER
        :return: port_name which is connected to SER
        """
        port_name = "None"
        show_lldp_cmd = "show lldp neighbors | json"
        lldp_output = self.dut_handler.send_commands(show_lldp_cmd)
        lldp_res = json.loads(lldp_output[0][show_lldp_cmd])
        lldp_nbr_list = lldp_res["lldpNeighbors"]
        for lldp_nbr in lldp_nbr_list:
            peer_device_att = get_device(lldp_nbr["neighborDevice"])
            if peer_device_att is None:
                continue
            if peer_device_att["NgsDeviceType"] == "SwanRouter":
                port_name = lldp_nbr["port"]
                return True, port_name
        else:
            return False, port_name

    def execute_shutdown(self, port_name, cmd):
        """
        execute (no)shutdown port, check if the command is successful
        :param port_name: the port to be shutdown or no shutdown
        :param cmd: shutdown or no shutdown
        :return: the result of cmd
        """
        interface_cfg = "interface" + " " + port_name
        self.dut_handler.connection.send_config_set(["configure terminal", interface_cfg, cmd])
        show_interface_cmd = "show" + " " + interface_cfg
        interface_lines = self.execute_cmd(show_interface_cmd)
        interface_1st_line = interface_lines[0]
        if cmd == "shutdown":
            expected_output = port_name + " " + "is administratively down, line protocol is down (disabled)"
            return True if interface_1st_line.strip() == expected_output else False

    def convert2_kusto_time_format(self):
        """
        convert time to kusto format
        :return: kusto time format
        """
        time_cmd = "show clock"
        time_lines = self.execute_cmd(time_cmd)
        time_1st_line = time_lines[0]
        timearray = time.strptime(time_1st_line, "%a %b %d %H:%M:%S %Y")
        timestamp = time.mktime(timearray)
        struct_time = time.localtime(timestamp)
        time_query = time.strftime("%Y-%m-%d %X", struct_time)
        return time_query


class InteropKusto:
    """
    interop with Kusto
    """

    def __init__(self, kusto_cluster, kusto_database):
        self.kusto_cluster = kusto_cluster
        self.kusto_database = kusto_database
        self.kusto_client = PhyNetKustoProxy(kusto_cluster=self.kusto_cluster)

    def query_syslog(self, query_lang):
        """
        :param query_lang: what to be query in kusto
        :return: the Message row in kusto query result
        """
        response = self.kusto_client.execute_query(self.kusto_database, query_lang)
        kusto_msg = []
        for row in response.fetchall():
            kusto_msg.append(re.sub("<\\d+>", "", row["Message"]))
        return kusto_msg

    def query_snmpx(self, query_lang):
        """
        :param query_lang: what to be query in kusto
        :return: the Message row in kusto query result
        """
        response = self.kusto_client.execute_query(self.kusto_database, query_lang)
        snmpx_query_res = []
        for row in response.fetchall():
            snmpx_query_res.append(row)
        return snmpx_query_res
