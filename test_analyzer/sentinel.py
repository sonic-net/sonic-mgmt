import time
import json
import requests
import logging
import traceback
import re
import sys
import os
import imp

from logging.handlers import RotatingFileHandler
from threading import Thread
from devutil.ssh_utils import SSHClient
from devutil.inv_helpers import HostManager


sys.path.append('../../')


ANSIBLE_DIR = os.path.abspath(os.path.dirname(__file__))
SONIC_MGMT_DIR = os.path.dirname(ANSIBLE_DIR)
TESTBED_FILE = 'testbed.yaml'

MAX_FAILED_THRESHOLD = 30
MONITOR_INTERVAL = 10
CONNECTION_INTERVAL = 10
REPORT_INTERVAL = 10

logger = logging.getLogger(__name__)

def config_logging():
    """Configure log to rotating file

    * Remove the default handler from app.logger.
    * Add RotatingFileHandler to the app.logger.
        File size: 10MB
        File number: 3
    * The Werkzeug handler is untouched.
    """
    rfh = RotatingFileHandler(
        '/tmp/sentinel.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)s:%(funcName)s %(lineno)d:%(message)s')
    rfh.setFormatter(fmt)
    logger.addHandler(rfh)

def parse_testbed(testbed_name):
    """Return a dictionary containing mapping from server name to testbeds."""
    testbed = imp.load_source('testbed', os.path.join(SONIC_MGMT_DIR, 'tests/common/testbed.py'))
    try:
        tb = testbed.TestbedInfo(TESTBED_FILE).testbed_topo[testbed_name]
    except Exception:
        logger.error("{} doesn't exist in {} file.".format(testbed_name, TESTBED_FILE))
        return
    return tb

class Scheduler(object):
    """
    Class to create threads to connect devices, collect health information and report them
    """

    def __init__(self, monitor, connector, hostmgr, hostmgr_eos, tbinfo):
        self.monitor = monitor
        self.connector = connector

        self.get_creds_info(hostmgr, hostmgr_eos, tbinfo)

        #logger.info("duthosts:{} pfthost:{} eoshosts:{}".format(self.duthosts, self.ptfhost, self.eoshosts))

    def get_creds_info(self, inventory_mgr, hostmgr_eos, tbinfo):
        self.duthosts = {}
        self.ptfhost = {}
        self.eoshosts = {}

        for duthost in tbinfo['duts']:
            # creds = inventory_mgr.get_host_creds(duthost)
            vars = inventory_mgr.get_host_vars(duthost)
            self.duthosts[duthost] = vars

        vars = inventory_mgr.get_host_vars(tbinfo['ptf'])
        self.ptfhost[tbinfo['ptf']] = vars

        vm_base = int(tbinfo['vm_base'][2:])
        vm_name_fmt = 'VM%0{}d'.format(len(tbinfo['vm_base']) - 2)

        for _, v in tbinfo['topo']['properties']['topology']['VMs'].items():
            vm_name = vm_name_fmt % (vm_base + v['vm_offset'])
            vars = hostmgr_eos.get_host_vars(vm_name)
            self.eoshosts[vm_name] = vars
        
    def schedule_jobs_in_background(self):
        """
        Generate three threads:
            connection_thread: to check ssh connection if timeout or connect failed
            monitor_thread: to run monitor process infinitely.
            report_thread: to report the collected data

        Args:
            inverval (int): the interval of monitoring process

        Returns:
            None
        """
        self.connection_thread = Thread(target=self.connector._check_ssh_clients, args=(self,))
        self.connection_thread.deamon = True
        self.connection_thread.start()
        time.sleep(CONNECTION_INTERVAL)
        self.monitor_thread = Thread(target=self._monitor_infinitely, args=(self.connector, self.monitor))
        self.monitor_thread.deamon = True
        self.monitor_thread.start()
        time.sleep(MONITOR_INTERVAL)
        self._report_infinitely(self.monitor)


    def _monitor_infinitely(self, connector, monitor):
        """
        Login the host with it's mgmt_ip, username and password which stored in inventory.ini file.
        return SSHClinet.

        Args:
            scheduler (Scheduler): Scheduler instance
            inverval (int): the interval of monitoring process

        Returns:
            None
        """
        logger.info("Start monitor sentinel...")
        while True:
            logger.debug("Monitoring testbed health status...")
            for duthost, dut_ssh_client in connector.dut_ssh_clients.items():
                try:
                    monitor.get_dut_bgp_info(dut_ssh_client, duthost)
                    monitor.get_dut_interfaces_info(dut_ssh_client, duthost)
                    monitor.get_dut_docker_services_info(dut_ssh_client, duthost)
                    monitor.get_memory_info(dut_ssh_client, duthost)
                    monitor.get_cpu_info(dut_ssh_client, duthost)
                    monitor.get_disk_info(dut_ssh_client, duthost)
                except Exception as e:
                    logger.error("Collect device {} failed with exception: {}".format(duthost, repr(e)))
                    logger.error(traceback.format_exc())
            for ptfhost, ptf_ssh_client in connector.ptf_ssh_client.items():
                try:
                    monitor.get_memory_info(ptf_ssh_client, ptfhost)
                    monitor.get_cpu_info(ptf_ssh_client, ptfhost)
                    monitor.get_disk_info(ptf_ssh_client, ptfhost)
                except Exception as e:
                    logger.error("Collect inforamtion from device {} failed with exception: {}".format(ptfhost, repr(e)))
                    logger.error(traceback.format_exc())

            for eoshost, eos_ssh_client in connector.eos_ssh_clients.items():
                try:
                    monitor.get_eos_bgp_info(eos_ssh_client, eoshost)
                    monitor.get_eos_interfaces_info(eos_ssh_client, eoshost)
                    monitor.get_memory_info(eos_ssh_client, eoshost)
                    monitor.get_cpu_info(eos_ssh_client, eoshost)
                    monitor.get_disk_info(eos_ssh_client, eoshost)
                except Exception as e:
                    logger.error("Collect device {} failed with exception: {}".format(eoshost, repr(e)))
                    logger.error(traceback.format_exc())
            logger.info('Sleeping {}s\n'.format(MONITOR_INTERVAL))
            time.sleep(MONITOR_INTERVAL)

    def report(self, payload):
        """
        Report the collected data to manager server.

        Args:
            payload (dict): The collected data for all devices

        Returns:
            boolean: True or False
        """
        # This is a manager simulator, receive POST request. 
        url = 'http://10.64.247.30:7777/foo'

        headers = {
            'Content-Type': 'text/plain'
        }
        response = None
        # convert dict to json format
        logger.info("Report to manager server:{}".format(payload.keys()))
        payload = json.dumps(payload, indent=4)
        
        try:
            response = requests.request("POST", url, headers=headers, data=payload)
        except Exception as e:
            logger.error("*****Alert***** Failed to report to manager server with exception {}".format(repr(e)))
            self.report_failed_count += 1
            return False

        if response and response.status_code != 200:
            logger.error("reprot failed with status code {} and text {}".format(response.status_code, response.text))
            self.report_failed_count += 1
            return False
        self.report_failed_count = 0
        return True

    def _report_infinitely(self, monitor):
        """
        Report the collected monitor data to manager server infinitlely.

        Args:
            None

        Returns:
            None
        """
        while True:
            logger.info("Post data to manager...")
            self.report(monitor.report_data)
            if self.report_failed_count > MAX_FAILED_THRESHOLD:
                logger.error("Reach maximum failed threshold")
                # TODO: does it need to handle consistant report failure?
            logger.info('Sleeping {}s'.format(REPORT_INTERVAL))
            time.sleep(REPORT_INTERVAL)


class Monitor(object):
    """
    Class to monitor and collect health information for all testbed devices 
    and store them to self.report_data
    """
    def __init__(self):
        self.critical_services = ['telemetry', 'snmp', 'mux', 'radv', 'dhcp_relay', 'lldp', \
                                'syncd', 'teamd', 'swss', 'bgp', 'restapi', 'pmon', 'acms', 'database']
        self.status = {"services":None, "interfaces":None, "bgp":None}
        self.report_data = {}
        self.report_failed_count = 0

    def _parse_column_positions(self, sep_line, sep_char='-'):
        """Parse the position of each columns in the command output

        Args:
            sep_line: The output line separating actual data and column headers
            sep_char: The character used in separation line. Defaults to '-'.

        Returns:
            Returns a list. Each item is a tuple with two elements. The first element is start position of a column. The
            second element is the end position of the column.
        """
        prev = ' ',
        positions = []
        for pos, char in enumerate(sep_line + ' '):
            if char == sep_char:
                if char != prev:
                    left = pos
            else:
                if char != prev:
                    right = pos
                    positions.append((left, right))
            prev = char
        return positions

    def parse_memory(self, output_lines):
        """
                    total        used        free      shared  buff/cache   available
        Mem:       65863932    16154636     2341456      243816    47367840    48148004
        Swap:     134217724      319720   133898004
        Total:    200081656    16474356   136239460
        """
        result = {}
        mem_data = {}
        headers = output_lines[0].lower().strip().split()
        for content_line in output_lines[1:]:
            if len(content_line) == 0:
                break
            columns = content_line.strip().split()
            mem_type = columns[0].lower()
            for index, value in enumerate(columns[1:]):
                mem_data[headers[index]] = value
            result[mem_type] = mem_data

        return result

    def parse_cpu(self, output_lines):
        """
        top - 17:27:58 up 57 days, 55 min,  2 users,  load average: 3.14, 3.54, 3.77
        Tasks: 734 total,   2 running, 730 sleeping,   0 stopped,   2 zombie
        %Cpu(s): 36.3 us, 16.5 sy,  3.3 ni, 44.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
        MiB Mem :  32114.9 total,   1328.2 free,  11864.7 used,  18921.9 buff/cache
        MiB Swap: 131072.0 total, 127497.6 free,   3574.4 used.  18674.2 avail Mem 
        """
        result = {}
        cpu_info = output_lines[2].lower().strip().split(":")[1]
        cpu_items = cpu_info.strip().split(",")
        for item in cpu_items:
            value = item.strip().split()[0]
            item_type = item.strip().split()[1]
            result[item_type] = value

        return result

    def parse_disk(self, output_lines):
        """
        Filesystem      Size  Used Avail Use% Mounted on
        overlay        1007G  224G  733G  24% /
        tmpfs            64M     0   64M   0% /dev
        tmpfs            16G     0   16G   0% /sys/fs/cgroup
        shm              64M     0   64M   0% /dev/shm
        """
        result = []
        disk_info = {}
        headers = output_lines[0].lower().strip().split()

        for content_line in output_lines[1:]:
            if len(content_line) == 0:
                break
            columns = content_line.strip().split()
            for index, value in enumerate(columns):
                header = headers[index]
                disk_info[header] = value
            result.append(disk_info)
        return result

    def parse_docker_stat(self, output_lines):
        """
        CONTAINER ID   NAME             CPU %     MEM USAGE / LIMIT     MEM %     NET I/O   BLOCK I/O         PIDS
        af997282b13c   dhcp_relay       0.17%     30.82MiB / 2.721GiB   1.11%     0B / 0B   545kB / 102kB     10
        d3577dd7416d   telemetry        4.32%     124.4MiB / 2.721GiB   4.46%     0B / 0B   10.4MB / 90.1kB   26
        b8c5fe98cc7d   mgmt-framework   0.27%     109.5MiB / 2.721GiB   3.93%     0B / 0B   5.2MB / 69.6kB    16
        1cbec76487ab   snmp             3.19%     92.07MiB / 2.721GiB   3.30%     0B / 0B   2.75MB / 102kB    9
        f7495680ecbc   radv             0.26%     28MiB / 2.721GiB      1.00%     0B / 0B   369kB / 111kB     8
        223aac530d15   lldp             0.46%     56.48MiB / 2.721GiB   2.03%     0B / 0B   3.89MB / 115kB    11
        e53688c3d9e1   gbsyncd          0.11%     28.83MiB / 2.721GiB   1.03%     0B / 0B   29.7kB / 86kB     6
        e8f471b8d491   syncd            1.88%     67.41MiB / 2.721GiB   2.42%     0B / 0B   3.35MB / 98.3kB   93
        30b7b88f60b9   teamd            1.77%     39.68MiB / 2.721GiB   1.42%     0B / 0B   1.11MB / 94.2kB   16
        0c757e6d42c2   swss             0.75%     86.69MiB / 2.721GiB   3.11%     0B / 0B   10MB / 315kB      40
        eacf7ecde21c   bgp              13.11%    195.7MiB / 2.721GiB   7.02%     0B / 0B   6.02MB / 164MB    22
        7bf3f1036ae0   pmon             0.38%     32.09MiB / 2.721GiB   1.15%     0B / 0B   258kB / 102kB     6
        1007ed4764c7   database         8.31%     119.8MiB / 2.721GiB   4.30%     0B / 0B   40.2MB / 53.2kB   11
        """
        result = []
        headers = []
        positions = [(0, 15), (15, 32), (32, 42), (42, 64), (64, 74), (74, 84), (84, 102), (102, 0)]
        for (left, right) in positions:
            if right:
                header = output_lines[0][left:right].strip()
            else:
                header = output_lines[0][left:].strip()
            headers.append(header)

        for content_line in output_lines[1:]:
            if len(content_line) == 0:
                break
            docker_service = {}
            for idx, (left, right) in enumerate(positions):
                if right:
                    value = content_line[left:right].strip()
                else:
                    value = content_line[left:].strip()
                
                docker_service[headers[idx]] = value
            result.append(docker_service)
        return result

    def show_and_parse(self, output_lines):
        """Run a show command and parse the output using a generic pattern.

        This method can adapt to the column changes as long as the output format follows the pattern of
        'show interface status'.

        The key is to have a line of headers. Then a separation line with '-' under each column header. Both header and
        column content are within the width of '-' chars for that column.

        For example, part of the output of command 'show interface status':

        admin@str-msn2700-02:~$ show interface status
              Interface            Lanes    Speed    MTU    FEC    Alias             Vlan    Oper    Admin             Type    Asym PFC
        ---------------  ---------------  -------  -----  -----  -------  ---------------  ------  -------  ---------------  ----------
              Ethernet0          0,1,2,3      40G   9100    N/A     etp1  PortChannel0002      up       up   QSFP+ or later         off
              Ethernet4          4,5,6,7      40G   9100    N/A     etp2  PortChannel0002      up       up   QSFP+ or later         off
              Ethernet8        8,9,10,11      40G   9100    N/A     etp3  PortChannel0005      up       up   QSFP+ or later         off
        ...

        The parsed example will be like:
            [{
                "oper": "up",
                "lanes": "0,1,2,3",
                "fec": "N/A",
                "asym pfc": "off",
                "admin": "up",
                "type": "QSFP+ or later",
                "vlan": "PortChannel0002",
                "mtu": "9100",
                "alias": "etp1",
                "interface": "Ethernet0",
                "speed": "40G"
              },
              {
                "oper": "up",
                "lanes": "4,5,6,7",
                "fec": "N/A",
                "asym pfc": "off",
                "admin": "up",                                                                                                                                                                                                                             "type": "QSFP+ or later",                                                                                                                                                                                                                  "vlan": "PortChannel0002",                                                                                                                                                                                                                 "mtu": "9100",                                                                                                                                                                                                                             "alias": "etp2",
                "interface": "Ethernet4",
                "speed": "40G"
              },
              {
                "oper": "up",
                "lanes": "8,9,10,11",
                "fec": "N/A",
                "asym pfc": "off",
                "admin": "up",
                "type": "QSFP+ or later",
                "vlan": "PortChannel0005",
                "mtu": "9100",
                "alias": "etp3",
                "interface": "Ethernet8",
                "speed": "40G"
              },
              ...
            ]

        Args:
            show_cmd: The show command that will be executed.

        Returns:
            Return the parsed output of the show command in a list of dictionary. Each list item is a dictionary,
            corresponding to one content line under the header in the output. Keys of the dictionary are the column
            headers in lowercase.
        """
        result = []

        sep_line_pattern = re.compile(r"^( *-+ *)+$")
        sep_line_found = False
        for idx, line in enumerate(output_lines):
            if sep_line_pattern.match(line):
                sep_line_found = True
                header_line = output_lines[idx-1]
                sep_line = output_lines[idx]
                content_lines = output_lines[idx+1:]
                break

        if not sep_line_found:
            logging.error('Failed to find separation line in the show command output')
            return result

        try:
            positions = self._parse_column_positions(sep_line)
        except Exception as e:
            logging.error('Possibly bad command output, exception: {}'.format(repr(e)))
            return result

        headers = []
        for (left, right) in positions:
            headers.append(header_line[left:right].strip().lower())

        for content_line in content_lines:
            # When an empty line is encountered while parsing the tabulate content, it is highly possible that the
            # tabulate content has been drained. The empty line and rest of the lines should not be parsed.
            if len(content_line) == 0:
                break
            item = {}
            for idx, (left, right) in enumerate(positions):
                k = headers[idx]
                v = content_line[left:right].strip()
                item[k] = v
            result.append(item)

        return result

    def check_dut_containers(self, client):
        """
        Check docker container services status on DUT.

        Args:
            client (SSHClient): The SSHClient to login DUT

        Returns:
            None
        """    
        # Initialize service status
        services = {}
        for service in self.critical_services:
            services[service] = False

        # Check and update service status
        try:
            outputs = client.run_command("docker ps --filter status=running --format \{\{.Names\}\}")[1].split('\n')
            for service in self.critical_services:
                if service in outputs:
                    services[service] = True
        except Exception as e:
            logger.error("Critical service status: {}".format(json.dumps(services)))
            logger.error("Get critical service status failed with error {}".format(repr(e)))

        logger.info("Status of critical services: %s" % str(services))
        if all(services.values()):
            self.status['services'] = False
        else:
            self.status['services'] = True
            logger.info("all critical services are running")
        return

    def check_dut_bgp(self, client):
        """
        Check bgp status on DUT.

        Args:
            client (SSHClient): The SSHClient to login DUT

        Returns:
            None
        """
        bgp_cmd = "show ip bgp summary"
        outputs = client.run_command(bgp_cmd)[1].split('\n')
        last_line = outputs[-1:][0]
        if "Total number of neighbors" in last_line:
                tokens = last_line.split()
                neighbor_num = int(tokens[-1])
                logger.info("Total number of neighbors:{}".format(neighbor_num))
        stdout_lines = outputs[10:10+neighbor_num]

        for line in stdout_lines:
            columns = line.strip().split()
            if columns[9].isdigit() or columns[9] == 'Established':
                continue
            else:
                logger.error("bgp is down:{}".format(columns))
                self.status['bgp'] = False
                return
        self.status['bgp'] = True
        logger.info("all bgp sessions are established")
        return

    def check_dut_interfaces(self, client):
        """
        Check interfaces status on DUT.

        Args:
            client (SSHClient): The SSHClient to login DUT

        Returns:
            None
        """
        interfaces_cmd = "show interfaces portchannel"
        outputs = client.run_command(interfaces_cmd)[1].split('\n')

        stdout_lines = outputs[4:]
        for line in stdout_lines:
            columns = line.strip().split()
            if 'LACP(A)(Up)' in columns[2]:
                continue
            else:
                logger.error("protchannel is down:{}".format(columns))
                self.status['interfaces'] = False
                return
        self.status['interfaces'] = True
        logger.info("all portchannels are up")
        return

    @staticmethod
    def _is_json_string(input_string):
        """
        Check if a input string is json format or not

        Args:
            input_string (str): input string

        Returns:
            None
        """
        try:
            json.loads(input_string)
        except (TypeError, ValueError) as e:
            return False
        return True

    def exec_command_helper(self, client, command, host, category, parse_func=None):
        """
        Helper to run command on different host and save the collected data.

        Args:
            client (SSHClient): The SSHClient to the host
            command (str): the command will be executed
            host (str): the host key in report_data
            category (str): the catetory key in report_data for this host

        Returns:
            None
        """
        data = {}
        try:
            output = client.run_command(command)[1] if client else {}      
        except Exception as e:
            logger.error("Exception happened on host {}:{}".format(host, repr(e)))
            logger.error(traceback.format_exc())
            logger.info("Close ssh connection for {}".format(host))
            if client:
                client.close()
            output = {}
        finally:
            print("***Host:{} command: {} OUTPUT>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>:\n{}".format(host, command, output))
            if len(output) == 0:
                data[category] = output
            elif parse_func:
                result = parse_func(output.split("\n"))
                data[category] = result if len(result) != 0 else {}
            elif self._is_json_string(output):
                data[category] = json.loads(output)
            else:
                result = self.show_and_parse(output.split("\n"))
                data[category] = result if len(result) != 0 else {}
            if host in self.report_data:
                self.report_data[host].update(data)
            else:
                self.report_data[host] = data
        return

    def get_dut_bgp_info(self, client, duthost):
        """Collect the bgp info on DUT.

        Args:
            client (SSHClient): The SSHClient to login DUT
            duthost(str): the hostname of DUT

        Returns:
            None
        """
        input_cmd = 'show ip bgp summary'
        self.exec_command_helper(client, input_cmd, duthost, "bgp")

    def get_dut_interfaces_info(self, client, duthost):
        """Collect the bgp info on DUT.

        Args:
            client (SSHClient): The SSHClient to login DUT
            duthost(str): the hostname of DUT

        Returns:
            None
        """
        input_cmd = 'show interfaces status'
        self.exec_command_helper(client, input_cmd, duthost, "interfaces")

    def get_dut_docker_services_info(self, client, duthost):
        """
        Collect the docker services stats on DUT.

        Args:
            client (SSHClient): The SSHClient to login ptf
            duthost(str): the hostname of DUT

        Returns:
            None
        """
        input_cmd = 'docker stats --no-stream'
        self.exec_command_helper(client, input_cmd, duthost, "services", parse_func=self.parse_docker_stat)

    def get_eos_bgp_info(self, client, eoshost):
        """
        Collect the bgp info on eoshost.

        Args:
            client (SSHClient): The SSHClient to login eos
            eoshost(str): the hostname of eos

        Returns:
            None
        """
        input_cmd = 'Cli -c \"show ip bgp summary | json\"'
        self.exec_command_helper(client, input_cmd, eoshost, "bgp")

    def get_eos_interfaces_info(self, client, eoshost):
        """
        Collect the interfaces info on eoshost.

        Args:
            client (SSHClient): The SSHClient to login eos
            eoshost(str): the hostname of eos

        Returns:
            None
        """
        input_cmd = 'Cli -c \"show interface status | json\"'
        self.exec_command_helper(client, input_cmd, eoshost, "interfaces")

    def get_memory_info(self, client, host):
        """
        Collect the memory info on ptf.

        Args:
            client (SSHClient): The SSHClient to login ptf
            host(str): the hostname of target device

        Returns:
            None
        """
        input_cmd = 'free -m'
        self.exec_command_helper(client, input_cmd, host, "memory", parse_func=self.parse_memory)

    def get_cpu_info(self, client, host):
        """
        Collect the cpu info on ptf.

        Args:
            client (SSHClient): The SSHClient to login ptf
            host(str): the hostname of target device

        Returns:
            None
        """
        input_cmd = 'top -b -n 1'
        self.exec_command_helper(client, input_cmd, host, "cpu", parse_func=self.parse_cpu)

    def get_disk_info(self, client, host):
        """
        Collect the disk info on ptf.

        Args:
            client (SSHClient): The SSHClient to login ptf
            host(str): the hostname of target device

        Returns:
            None
        """
        input_cmd = 'df -h'
        self.exec_command_helper(client, input_cmd, host, "disk", parse_func=self.parse_disk)


class Connector(object):
    """
    Class to login testbed devices and maintain ssh connections
    """

    def __init__(self):
        self.dut_ssh_clients = {}
        self.eos_ssh_clients = {}
        self.ptf_ssh_client = {}

    def login_devices(self, host_vars):
        """
        Login the host with it's mgmt_ip, username and password which stored in inventory.ini file.
        return SSHClinet.

        Args:
            hostname(str): The hostname in inventory.ini file.

        Returns:
            SSHClient
        """
        client = SSHClient()
        logger.info("ip:{}, username:{}, password:{}".format(host_vars['ansible_host'], host_vars['creds']['username'], host_vars['creds']['password']))
        client.connect(hostname=host_vars['ansible_host'], username=host_vars['creds']['username'], passwords=host_vars['creds']['password'])
        return client

    def _is_connection_active(self, hostname, ssh_client):
        """
        Check if ssh connection is active.

        Args:
            hostname (str): the target hostname
            ssh_client (SSHClient): The SSHClient to login host

        Returns:
            None
        """
        if ssh_client and ssh_client.get_transport() is not None:
            exception_str = ssh_client.get_transport().get_exception()
            if exception_str:
                logger.error("{}'s SSH transport has exception:{}".format(hostname, repr(exception_str)))
                return False
            return ssh_client.get_transport().is_active()
        return False

    def _check_ssh_clients(self, scheduler):
        """
        Login duthosts, ptfhost and eoshosts in this fuction.
        Thread wil be created for each SSH connection, for avoiding creating too many SSH connections,
        just login once before while True and save ssh connection clients.

        Args:
            None

        Returns:
            None
        """
        # For the first time or connection is not active, we have to try to login device until it's success.
        while True:
            logger.debug("Checking SSH connections...")
            for duthost, vars in scheduler.duthosts.items():
                if duthost in self.dut_ssh_clients and self._is_connection_active(duthost, self.dut_ssh_clients[duthost]):
                    continue
                else:
                    try:
                        self.dut_ssh_clients[duthost] = self.login_devices(vars)
                    except Exception as e:
                        logger.error("SSH login device {} failed with exception: {}".format(duthost, repr(e)))
                        logger.error(traceback.format_exc())
                        self.dut_ssh_clients[duthost] = None

            for ptfhost, vars in scheduler.ptfhost.items():
                if not self.ptf_ssh_client or not self._is_connection_active(ptfhost, self.ptf_ssh_client[ptfhost]):
                    try:
                        self.ptf_ssh_client[ptfhost] = self.login_devices(vars)
                    except Exception as e:
                        logger.error("SSH login device {} failed with exception: {}".format(ptfhost, repr(e)))
                        self.ptf_ssh_client[ptfhost] = None

            for eoshost, vars in scheduler.eoshosts.items():
                if eoshost in self.eos_ssh_clients and self._is_connection_active(eoshost, self.eos_ssh_clients[eoshost]):
                    continue
                try:
                    self.eos_ssh_clients[eoshost] = self.login_devices(vars)
                except Exception as e:
                    self.eos_ssh_clients[eoshost] = None
                    logger.error("SSH login device {} failed with exception: {}".format(eoshost, repr(e)))
            time.sleep(CONNECTION_INTERVAL)

if __name__ == '__main__':

    usage = '\n'.join([
        'Start sentinel for specific testbed:',
        '  $ sudo python <prog> <testbed> [-v]',
        'Specify "-v" for DEBUG level logging and enabling traceback in response in case of exception.'])

    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)

    testbed = sys.argv[1]

    if '-v' in sys.argv:
        logger.setLevel(logging.DEBUG)
        # logger.config['VERBOSE'] = True
    else:
        logger.setLevel(logging.INFO)
        # logger.config['VERBOSE'] = False

    config_logging()
    SENTINEL_LOGO = '\n'.join([
        '',
        ' ####  ###### #    # ##### # #    # ###### #      ',
        '#      #      ##   #   #   # ##   # #      #      ',
        ' ####  #####  # #  #   #   # # #  # #####  #      ',
        '     # #      #  # #   #   # #  # # #      #      ',
        '#    # #      #   ##   #   # #   ## #      #      ',
        ' ####  ###### #    #   #   # #    # ###### ###### ',
        '',
    ])
    logger.info(SENTINEL_LOGO)
    logger.info('Starting sentinel process')

    tbinfo = parse_testbed(testbed)
    if tbinfo is None:
        logger.error("Can't find information for testbed {}, please verify if testbed name is correct.".format(testbed))
        exit(-1)
    monitor = Monitor()
    connector = Connector()
    hostmgr = HostManager(tbinfo['inv_name'])
    hostmgr_eos = HostManager("veos")
    scheduler = Scheduler(monitor, connector, hostmgr, hostmgr_eos, tbinfo)

    scheduler.schedule_jobs_in_background()