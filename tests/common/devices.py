"""
Classes for various devices that may be used in testing.

There are other options for interacting with the devices used in testing, for example netmiko, fabric.
We have a big number of customized ansible modules in the sonic-mgmt/ansible/library folder. To reused these
modules, we have no other choice, at least for interacting with SONiC, localhost and PTF.

We can consider using netmiko for interacting with the VMs used in testing.
"""
import json
import logging
import os
import re
import inspect
import ipaddress
from multiprocessing.pool import ThreadPool
from datetime import datetime

from errors import RunAnsibleModuleFail
from errors import UnsupportedAnsibleModule


class AnsibleHostBase(object):
    """
    @summary: The base class for various objects.

    This class filters an object from the ansible_adhoc fixture by hostname. The object can be considered as an
    ansible host object although it is not under the hood. Anyway, we can use this object to run ansible module
    on the host.
    """

    def __init__(self, ansible_adhoc, hostname, connection=None, become_user=None):
        if hostname == 'localhost':
            self.host = ansible_adhoc(connection='local', host_pattern=hostname)[hostname]
        else:
            if connection is None:
                if become_user is None:
                    self.host = ansible_adhoc(become=True)[hostname]
                else:
                    self.host = ansible_adhoc(become=True, become_user=become_user)[hostname]
            else:
                logging.debug("connection {} for {}".format(connection, hostname))
                if become_user is None:
                    self.host = ansible_adhoc(become=True, connection=connection)[hostname]
                else:
                    self.host = ansible_adhoc(become=True, connection=connection, become_user=become_user)[hostname]
        self.hostname = hostname

    def __getattr__(self, module_name):
        if self.host.has_module(module_name):
            self.module_name = module_name
            self.module = getattr(self.host, module_name)

            return self._run

        return super(AnsibleHostBase, self).__getattr__(module_name)

    def _run(self, *module_args, **complex_args):

        previous_frame = inspect.currentframe().f_back
        filename, line_number, function_name, lines, index = inspect.getframeinfo(previous_frame)

        logging.debug("{}::{}#{}: [{}] AnsibleModule::{}, args={}, kwargs={}"\
            .format(filename, function_name, line_number, self.hostname,
                    self.module_name, json.dumps(module_args), json.dumps(complex_args)))

        module_ignore_errors = complex_args.pop('module_ignore_errors', False)
        module_async = complex_args.pop('module_async', False)

        if module_async:
            def run_module(module_args, complex_args):
                return self.module(*module_args, **complex_args)[self.hostname]
            pool = ThreadPool()
            result = pool.apply_async(run_module, (module_args, complex_args))
            return pool, result

        res = self.module(*module_args, **complex_args)[self.hostname]
        logging.debug("{}::{}#{}: [{}] AnsibleModule::{} Result => {}"\
            .format(filename, function_name, line_number, self.hostname, self.module_name, json.dumps(res)))

        if (res.is_failed or 'exception' in res) and not module_ignore_errors:
            raise RunAnsibleModuleFail("run module {} failed".format(self.module_name), res)

        return res


class Localhost(AnsibleHostBase):
    """
    @summary: Class for localhost

    For running ansible module on localhost
    """
    def __init__(self, ansible_adhoc):
        AnsibleHostBase.__init__(self, ansible_adhoc, "localhost")


class PTFHost(AnsibleHostBase):
    """
    @summary: Class for PTF

    Instance of this class can run ansible modules on the PTF host.
    """
    def __init__(self, ansible_adhoc, hostname):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

    # TODO: Add a method for running PTF script


class SonicHost(AnsibleHostBase):
    """
    A remote host running SONiC.

    This type of host contains information about the SONiC device (device info, services, etc.),
    and also provides the ability to run Ansible modules on the SONiC device.
    """

    _DEFAULT_CRITICAL_SERVICES = ["swss", "syncd", "database", "teamd", "bgp", "pmon", "lldp", "snmp"]

    def __init__(self, ansible_adhoc, hostname):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        self._facts = self._gather_facts()
        self._os_version = self._get_os_version()

        self.reset_critical_services_tracking_list()

    @property
    def facts(self):
        """
        Platform information for this SONiC device.

        Returns:
            dict: A dictionary containing the device platform information.

            For example:
            {
                "platform": "x86_64-arista_7050_qx32s",
                "hwsku": "Arista-7050-QX-32S",
                "asic_type": "broadcom",
                "num_asic": 1,
            }
        """

        return self._facts

    @property
    def os_version(self):
        """
        The OS version running on this SONiC device.

        Returns:
            str: The SONiC OS version (e.g. "20181130.31")
        """

        return self._os_version

    @property
    def critical_services(self):
        """
        The critical services running on this SONiC device.

        Note:
            This list is used for tracking purposes ONLY. This list does not
            show which critical services are currently running. See the
            critical_services_status method for that info.

        Returns:
            list[str]: A list of the critical services (e.g. ["swss", "syncd"])
        """

        return self._critical_services

    @critical_services.setter
    def critical_services(self, var):
        """
        Updates the list of critical services running on this device.

        Note:
            This list is used for tracking purposes ONLY. Updating the list does
            not actually modify any services running on the device.
        """

        if self.facts["num_asic"] > 1:
            self._critical_services = self._generate_critical_services_for_multi_asic(var)
        else:
            self._critical_services = var

        logging.debug(self._critical_services)

    def reset_critical_services_tracking_list(self):
        """
        Resets the list of critical services to the default.
        """

        self.critical_services = self._DEFAULT_CRITICAL_SERVICES

    def _gather_facts(self):
        """
        Gather facts about the platform for this SONiC device.
        """

        facts = dict()
        facts.update(self._get_platform_info())
        facts["num_asic"] = self._get_asic_count(facts["platform"])

        logging.debug("Gathered SonicHost facts: %s" % json.dumps(facts))
        return facts

    def _get_asic_count(self, platform):
        """
        Gets the number of asics for this device.
        """
        num_asic = 1
        asic_conf_file_path = os.path.join("/usr/share/sonic/device", platform, "asic.conf")
        try:
            output = self.shell("cat {}".format(asic_conf_file_path))["stdout_lines"]
            logging.debug(output)

            for line in output:
                key, value = line.split("=")
                if key.strip().upper() == "NUM_ASIC":
                    num_asic = value.strip()
                    break

            logging.debug("num_asic = %s" % num_asic)

            return int(num_asic)
        except:
            return int(num_asic)


    def _generate_critical_services_for_multi_asic(self, services):
        """
        Generates a fully-qualified list of critical services for multi-asic platforms, based on a
        base list of services.

        Example:
        ["swss", "syncd"] -> ["swss0", "swss1", "swss2", "syncd0", "syncd1", "syncd2"]
        """

        m_service = []
        for service in services:
            for asic in range(self.facts["num_asic"]):
                asic_service = service + str(asic)
                m_service.insert(asic, asic_service)
        return m_service

    def _get_platform_info(self):
        """
        Gets platform information about this SONiC device.
        """

        platform_info = self.command("show platform summary")["stdout_lines"]
        result = {}
        for line in platform_info:
            if line.startswith("Platform:"):
                result["platform"] = line.split(":")[1].strip()
            elif line.startswith("HwSKU:"):
                result["hwsku"] = line.split(":")[1].strip()
            elif line.startswith("ASIC:"):
                result["asic_type"] = line.split(":")[1].strip()
        return result

    def _get_os_version(self):
        """
        Gets the SONiC OS version that is running on this device.
        """

        output = self.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
        return output["stdout_lines"][0].strip()

    def get_service_props(self, service, props=["ActiveState", "SubState"]):
        """
        @summary: Use 'systemctl show' command to get detailed properties of a service. By default, only get
            ActiveState and SubState of the service.
        @param service: Service name.
        @param props: Properties of the service to be shown.
        @return: Returns a dictionary containing properties of the specified service, for example:
            {
                "ActivateState": "active",
                "SubState": "running"
            }
        """
        props = " ".join(["-p %s" % prop for prop in props])
        output = self.command("systemctl %s show %s" % (props, service))
        result = {}
        for line in output["stdout_lines"]:
            fields = line.split("=")
            if len(fields) >= 2:
                result[fields[0]] = fields[1]
        return result

    def is_service_fully_started(self, service):
        """
        @summary: Check whether a SONiC specific service is fully started.

        This function assumes that the final step of all services checked by this function is to spawn a Docker
        container with the same name as the service. We determine that the service has fully started if the
        Docker container is running.

        @param service: Name of the SONiC service
        """
        try:
            output = self.command("docker inspect -f \{\{.State.Running\}\} %s" % service)
            if output["stdout"].strip() == "true":
                return True
            else:
                return False
        except:
            return False

    def critical_services_status(self):
        result = {}
        for service in self.critical_services:
            result[service] = self.is_service_fully_started(service)
        return result

    def critical_services_fully_started(self):
        """
        @summary: Check whether all the SONiC critical services have started
        """
        result = self.critical_services_status()
        logging.debug("Status of critical services: %s" % str(result))
        return all(result.values())

    def critical_process_status(self, service):
        """
        @summary: Check whether critical process status of a service.

        @param service: Name of the SONiC service
        """
        result = {'status': True}
        result['exited_critical_process'] = []
        result['running_critical_process'] = []
        critical_process_list = []

        # return false if the service is not started
        service_status = self.is_service_fully_started(service)
        if service_status == False:
            result['status'] = False
            return result

        # get critical process list for the service
        output = self.command("docker exec {} bash -c '[ -f /etc/supervisor/critical_processes ] && cat /etc/supervisor/critical_processes'".format(service), module_ignore_errors=True)
        for l in output['stdout'].split():
            # If ':' exists, the second field is got. Otherwise the only field is got.
            critical_process_list.append(l.split(':')[-1].rstrip())
        if len(critical_process_list) == 0:
            return result

        # get process status for the service
        output = self.command("docker exec {} supervisorctl status".format(service))
        logging.info("====== supervisor process status for service {} ======".format(service))

        for l in output['stdout_lines']:
            (pname, status, info) = re.split("\s+", l, 2)
            if status != "RUNNING":
                if pname in critical_process_list:
                    result['exited_critical_process'].append(pname)
                    result['status'] = False
            else:
                if pname in critical_process_list:
                    result['running_critical_process'].append(pname)

        return result

    def all_critical_process_status(self):
        """
        @summary: Check whether all critical processes status for all critical services
        """
        result = {}
        for service in self.critical_services:
            result[service] = self.critical_process_status(service)
        return result

    def get_crm_resources(self):
        """
        @summary: Run the "crm show resources all" command and parse its output
        """
        result = {"main_resources": {}, "acl_resources": [], "table_resources": []}
        output = self.command("crm show resources all")["stdout_lines"]
        current_table = 0   # Totally 3 tables in the command output
        for line in output:
            if len(line.strip()) == 0:
                continue
            if "---" in line:
                current_table += 1
                continue
            if current_table == 1:      # content of first table, main resources
                fields = line.split()
                if len(fields) == 3:
                    result["main_resources"][fields[0]] = {"used": int(fields[1]), "available": int(fields[2])}
            if current_table == 2:      # content of the second table, acl resources
                fields = line.split()
                if len(fields) == 5:
                    result["acl_resources"].append({"stage": fields[0], "bind_point": fields[1],
                        "resource_name": fields[2], "used_count": int(fields[3]), "available_count": int(fields[4])})
            if current_table == 3:      # content of the third table, table resources
                fields = line.split()
                if len(fields) == 4:
                    result["table_resources"].append({"table_id": fields[0], "resource_name": fields[1],
                        "used_count": int(fields[2]), "available_count": int(fields[3])})

        return result

    def get_pmon_daemon_states(self):
        """
        @summary: get state list of daemons from pmon docker.
                  Referencing (/usr/share/sonic/device/{platform}/pmon_daemon_control.json)
                  if some daemon is disabled in the config file, then remove it from the daemon list.

        @return: dictionary of { service_name1 : state1, ... ... }
        """
        # some services are meant to have a short life span or not part of the daemons
        exemptions = ['lm-sensors', 'start.sh', 'rsyslogd']

        daemons = self.shell('docker exec pmon supervisorctl status')['stdout_lines']

        daemon_list = [ line.strip().split()[0] for line in daemons if len(line.strip()) > 0 ]

        daemon_ctl_key_prefix = 'skip_'
        daemon_config_file_path = os.path.join('/usr/share/sonic/device', self.facts["platform"], 'pmon_daemon_control.json')

        try:
            output = self.shell('cat %s' % daemon_config_file_path)
            json_data = json.loads(output["stdout"])
            logging.debug("Original file content is %s" % str(json_data))
            for key in daemon_list:
                if (daemon_ctl_key_prefix + key) not in json_data:
                    logging.debug("Daemon %s is enabled" % key)
                elif not json_data[daemon_ctl_key_prefix + key]:
                    logging.debug("Daemon %s is enabled" % key)
                else:
                    logging.debug("Daemon %s is disabled" % key)
                    exemptions.append(key)
        except:
            # if pmon_daemon_control.json not exist, then it's using default setting,
            # all the pmon daemons expected to be running after boot up.
            pass

        # Collect state of services that are not on the exemption list.
        daemon_states = {}
        for line in daemons:
            words = line.strip().split()
            if len(words) >= 2 and words[0] not in exemptions:
                daemon_states[words[0]] = words[1]

        logging.info("Pmon daemon state list for this platform is %s" % str(daemon_states))
        return daemon_states

    def num_asics(self):
        """
        return the number of NPUs on the DUT
        """
        return self.facts["num_asic"]

    def get_syncd_docker_names(self):
        """
        @summary: get the list of syncd dockers names for the number of NPUs present on the DUT
        for a single NPU dut the list will have only "syncd" in it
        """
        syncd_docker_names = []
        if self.facts["num_asic"] == 1:
            syncd_docker_names.append("syncd")
        else:
            num_asics = int(self.facts["num_asic"])
            for asic in range(0,num_asics):
                syncd_docker_names.append("syncd{}".format(asic))
        return syncd_docker_names

    def get_swss_docker_names(self):
        swss_docker_names = []
        if self.facts["num_asic"] == 1:
            swss_docker_names.append("swss")
        else:
            num_asics = self.facts["num_asic"]
            for asic in range(0,num_asics):
                swss_docker_names.append("swss{}".format(asic))
        return swss_docker_names

    def get_up_time(self):
        up_time_text = self.command("uptime -s")["stdout"]
        return datetime.strptime(up_time_text, "%Y-%m-%d %H:%M:%S")

    def get_now_time(self):
        now_time_text = self.command('date +"%Y-%m-%d %H:%M:%S"')["stdout"]
        return datetime.strptime(now_time_text, "%Y-%m-%d %H:%M:%S")

    def get_uptime(self):
        return self.get_now_time() - self.get_up_time()

    def get_networking_uptime(self):
        start_time = self.get_service_props("networking", props=["ExecMainStartTimestamp",])
        try:
            return self.get_now_time() - datetime.strptime(start_time["ExecMainStartTimestamp"],
                                                           "%a %Y-%m-%d %H:%M:%S UTC")
        except Exception as e:
            logging.error("Exception raised while getting networking restart time: %s" % repr(e))
            return None

    def get_image_info(self):
        """
        @summary: get list of images installed on the dut.
                  return a dictionary of "current, next, installed_list"
        """
        lines = self.command("sonic_installer list")["stdout_lines"]
        ret    = {}
        images = []
        for line in lines:
            words = line.strip().split()
            if len(words) == 2:
                if words[0] == 'Current:':
                    ret['current'] = words[1]
                elif words[0] == 'Next:':
                    ret['next'] = words[1]
            elif len(words) == 1 and words[0].startswith('SONiC-OS'):
                images.append(words[0])

        ret['installed_list'] = images
        return ret

    def shutdown(self, ifname):
        """
            Shutdown interface specified by ifname

            Args:
                ifname: the interface to shutdown
        """
        return self.command("sudo config interface shutdown {}".format(ifname))

    def no_shutdown(self, ifname):
        """
            Bring up interface specified by ifname

            Args:
                ifname: the interface to bring up
        """
        return self.command("sudo config interface startup {}".format(ifname))

    def get_ip_route_info(self, dstip):
        """
        @summary: return route information for a destionation IP

        @param dstip: destination IP (either ipv4 or ipv6)

============ 4.19 kernel ==============
admin@vlab-01:~$ ip route list match 0.0.0.0
default proto bgp src 10.1.0.32 metric 20
        nexthop via 10.0.0.57 dev PortChannel0001 weight 1
        nexthop via 10.0.0.59 dev PortChannel0002 weight 1
        nexthop via 10.0.0.61 dev PortChannel0003 weight 1
        nexthop via 10.0.0.63 dev PortChannel0004 weight 1

admin@vlab-01:~$ ip -6 route list match ::
default proto bgp src fc00:1::32 metric 20
        nexthop via fc00::72 dev PortChannel0001 weight 1
        nexthop via fc00::76 dev PortChannel0002 weight 1
        nexthop via fc00::7a dev PortChannel0003 weight 1
        nexthop via fc00::7e dev PortChannel0004 weight 1 pref medium

============ 4.9 kernel ===============
admin@vlab-01:~$ ip route list match 0.0.0.0
default proto 186 src 10.1.0.32 metric 20
        nexthop via 10.0.0.57  dev PortChannel0001 weight 1
        nexthop via 10.0.0.59  dev PortChannel0002 weight 1
        nexthop via 10.0.0.61  dev PortChannel0003 weight 1
        nexthop via 10.0.0.63  dev PortChannel0004 weight 1

admin@vlab-01:~$ ip -6 route list match ::
default via fc00::72 dev PortChannel0001 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::76 dev PortChannel0002 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::7a dev PortChannel0003 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::7e dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium

        """

        if dstip.version == 4:
            rt = self.command("ip route list match {}".format(dstip))['stdout_lines']
        else:
            rt = self.command("ip -6 route list match {}".format(dstip))['stdout_lines']

        logging.info("route raw info for {}: {}".format(dstip, rt))

        rtinfo = {'set_src': None, 'nexthops': [] }

        # parse set_src
        m = re.match(r"^default proto (bgp|186) src (\S+)", rt[0])
        m1 = re.match(r"^default via (\S+) dev (\S+) proto 186 src (\S+)", rt[0])
        if m:
            rtinfo['set_src'] = ipaddress.ip_address(m.group(2))
        elif m1:
            rtinfo['set_src'] = ipaddress.ip_address(m1.group(3))

        # parse nexthops
        for l in rt:
            m = re.search(r"(default|nexthop)\s+via\s+(\S+)\s+dev\s+(\S+)", l)
            if m:
                rtinfo['nexthops'].append((ipaddress.ip_address(m.group(2)), m.group(3)))

        logging.info("route parsed info for {}: {}".format(dstip, rtinfo))

        return rtinfo

    def check_default_route(self, ipv4=True, ipv6=True):
        """
        @summary: return default route status

        @param ipv4: check ipv4 default
        @param ipv6: check ipv6 default
        """
        if ipv4:
            rtinfo_v4 = self.get_ip_route_info(ipaddress.ip_address(u'0.0.0.0'))
            if len(rtinfo_v4['nexthops']) == 0:
                return False

        if ipv6:
            rtinfo_v6 = self.get_ip_route_info(ipaddress.ip_address(u'::'))
            if len(rtinfo_v6['nexthops']) == 0:
                return False

        return True

    def get_bgp_neighbor_info(self, neighbor_ip):
        """
        @summary: return bgp neighbor info

        @param neighbor_ip: bgp neighbor IP
        """
        nbip = ipaddress.ip_address(neighbor_ip)
        if nbip.version == 4:
            out = self.command("vtysh -c \"show ip bgp neighbor {} json\"".format(neighbor_ip))
        else:
            out = self.command("vtysh -c \"show bgp ipv6 neighbor {} json\"".format(neighbor_ip))
        nbinfo = json.loads(re.sub(r"\\\"", '"', re.sub(r"\\n", "", out['stdout'])))
        logging.info("bgp neighbor {} info {}".format(neighbor_ip, nbinfo))

        return nbinfo[str(neighbor_ip)]

    def get_bgp_neighbors(self):
        """
        Get a diction of BGP neighbor states

        Args: None

        Returns: dictionary { (neighbor_ip : info_dict)* }

        """
        bgp_facts = self.bgp_facts()['ansible_facts']
        return bgp_facts['bgp_neighbors']

    def check_bgp_session_state(self, neigh_ips, state="established"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param state: target state
        """
        neigh_ips = [ip.lower() for ip in neigh_ips]
        neigh_ok = []
        bgp_facts = self.bgp_facts()['ansible_facts']
        logging.info("bgp_facts: {}".format(bgp_facts))
        for k, v in bgp_facts['bgp_neighbors'].items():
            if v['state'] == state:
                if k.lower() in neigh_ips:
                    neigh_ok.append(k)
        logging.info("bgp neighbors that match the state: {}".format(neigh_ok))
        if len(neigh_ips) == len(neigh_ok):
            return True

        return False

    def check_bgp_session_nsf(self, neighbor_ip):
        """
        @summary: check if bgp neighbor session enters NSF state or not

        @param neighbor_ip: bgp neighbor IP
        """
        nbinfo = self.get_bgp_neighbor_info(neighbor_ip)
        if nbinfo['bgpState'].lower() == "Active".lower():
            if nbinfo['bgpStateIs'].lower() == "passiveNSF".lower():
                return True
        return False

    def get_dut_iface_mac(self, iface_name):
        """
        Gets the MAC address of specified interface.

        Returns:
            str: The MAC address of the specified interface, or None if it is not found.
        """
        for iface, iface_info in self.setup()['ansible_facts'].items():
            if iface_name in iface:
                return iface_info["macaddress"]

        return None

    def get_feature_status(self):
        """
        Gets the list of features and states

        Returns:
            dict: feature status dict. { <feature name> : <status: enabled | disabled> }
            bool: status obtained successfully (True | False)
        """
        feature_status = {}
        command_output = self.shell('show features', module_ignore_errors=True)
        if command_output['rc'] != 0:
            return feature_status, False

        features_stdout = command_output['stdout_lines']
        lines = features_stdout[2:]
        for x in lines:
            result = x.encode('UTF-8')
            r = result.split()
            feature_status[r[0]] = r[1]
        return feature_status, True

class EosHost(AnsibleHostBase):
    """
    @summary: Class for Eos switch

    For running ansible module on the Eos switch
    """

    def __init__(self, ansible_adhoc, hostname, eos_user, eos_passwd, shell_user=None, shell_passwd=None, gather_facts=False):
        '''Initialize an object for interacting with EoS type device using ansible modules

        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the EOS device
            eos_user (string): Username for accessing the EOS CLI interface
            eos_passwd (string): Password for the eos_user
            shell_user (string, optional): Username for accessing the Linux shell CLI interface. Defaults to None.
            shell_passwd (string, optional): Password for the shell_user. Defaults to None.
            gather_facts (bool, optional): Whether to gather some basic facts. Defaults to False.
        '''
        self.eos_user = eos_user
        self.eos_passwd = eos_passwd
        self.shell_user = shell_user
        self.shell_passwd = shell_passwd
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def __getattr__(self, module_name):
        if module_name.startswith('eos_'):
            evars = {
                'ansible_connection':'network_cli',
                'ansible_network_os':'eos',
                'ansible_user': self.eos_user,
                'ansible_password': self.eos_passwd,
                'ansible_ssh_user': self.eos_user,
                'ansible_ssh_pass': self.eos_passwd,
                'ansible_become_method': 'enable'
            }
        else:
            if not self.shell_user or not self.shell_passwd:
                raise Exception("Please specify shell_user and shell_passwd for {}".format(self.hostname))
            evars = {
                'ansible_connection':'ssh',
                'ansible_network_os':'linux',
                'ansible_user': self.shell_user,
                'ansible_password': self.shell_passwd,
                'ansible_ssh_user': self.shell_user,
                'ansible_ssh_pass': self.shell_passwd,
                'ansible_become_method': 'sudo'
            }
        self.host.options['variable_manager'].extra_vars.update(evars)
        return super(EosHost, self).__getattr__(module_name)

    def shutdown(self, interface_name):
        out = self.eos_config(
            lines=['shutdown'],
            parents='interface %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.eos_config(
            lines=['no shutdown'],
            parents='interface %s' % interface_name)
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def check_intf_link_state(self, interface_name):
        show_int_result = self.eos_command(
            commands=['show interface %s' % interface_name])
        return 'Up' in show_int_result['stdout_lines'][0]

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.eos_config(
            lines=['lacp rate %s' % mode],
            parents='interface %s' % interface_name)
        logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def kill_bgpd(self):
        out = self.eos_config(lines=['agent Rib shutdown'])
        return out

    def start_bgpd(self):
        out = self.eos_config(lines=['no agent Rib shutdown'])
        return out

    def check_bgp_session_state(self, neigh_ips, neigh_desc, state="established"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param neigh_desc: bgp neighbor description
        @param state: target state
        """
        neigh_ips = [ip.lower() for ip in neigh_ips]
        neigh_ips_ok = []
        neigh_desc_ok = []
        neigh_desc_available = False

        out_v4 = self.eos_command(
            commands=['show ip bgp summary | json'])
        logging.info("ip bgp summary: {}".format(out_v4))

        out_v6 = self.eos_command(
            commands=['show ipv6 bgp summary | json'])
        logging.info("ipv6 bgp summary: {}".format(out_v6))

        for k, v in out_v4['stdout'][0]['vrfs']['default']['peers'].items():
            if v['peerState'].lower() == state.lower():
                if k in neigh_ips:
                    neigh_ips_ok.append(k)
                if 'description' in v:
                    neigh_desc_available = True
                    if v['description'] in neigh_desc:
                        neigh_desc_ok.append(v['description'])

        for k, v in out_v6['stdout'][0]['vrfs']['default']['peers'].items():
            if v['peerState'].lower() == state.lower():
                if k.lower() in neigh_ips:
                    neigh_ips_ok.append(k)
                if 'description' in v:
                    neigh_desc_available = True
                    if v['description'] in neigh_desc:
                        neigh_desc_ok.append(v['description'])
        logging.info("neigh_ips_ok={} neigh_desc_available={} neigh_desc_ok={}"\
            .format(str(neigh_ips_ok), str(neigh_desc_available), str(neigh_desc_ok)))
        if neigh_desc_available:
            if len(neigh_ips) == len(neigh_ips_ok) and len(neigh_desc) == len(neigh_desc_ok):
                return True
        else:
            if len(neigh_ips) == len(neigh_ips_ok):
                return True

        return False

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
            fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["stdout"]))


class OnyxHost(AnsibleHostBase):
    """
    @summary: Class for ONYX switch

    For running ansible module on the ONYX switch
    """

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname, connection="network_cli")
        evars = {'ansible_connection':'network_cli',
                'ansible_network_os':'onyx',
                'ansible_user': user,
                'ansible_password': passwd,
                'ansible_ssh_user': user,
                'ansible_ssh_pass': passwd,
                'ansible_become_method': 'enable'
                }

        self.host.options['variable_manager'].extra_vars.update(evars)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['shutdown'],
            parents='interface %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['no shutdown'],
            parents='interface %s' % interface_name)
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def check_intf_link_state(self, interface_name):
        show_int_result = self.host.onyx_command(
            commands=['show interfaces ethernet {} | include "Operational state"'.format(interface_name)])[self.hostname]
        return 'Up' in show_int_result['stdout'][0]

    def command(self, cmd):
        out = self.host.onyx_command(commands=[cmd])
        return out

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.host.onyx_config(
            lines=['lacp rate %s' % mode],
            parents='interface ethernet %s' % interface_name)
        logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        """
        Execute ansible playbook with specified parameters
        """
        playbook_template = 'cd {ansible_path}; ansible-playbook {playbook} -i {inventory} -l {fanout_host} --extra-vars \'{extra_vars}\' -vvvvv'
        cli_cmd = playbook_template.format(ansible_path=ansible_root, playbook=ansible_playbook, inventory=inventory,
            fanout_host=self.hostname, extra_vars=json.dumps(kwargs))
        res = self.localhost.shell(cli_cmd)

        if res["localhost"]["rc"] != 0:
            raise Exception("Unable to execute template\n{}".format(res["localhost"]["stdout"]))


class IxiaHost (AnsibleHostBase):
    """ This class is a place-holder for running ansible module on Ixia
    fanout devices in future (TBD).
    """
    def __init__ (self, ansible_adhoc, os, hostname, device_type) :
        """ Initializing Ixia fanout host for using ansible modules.

        Note: Right now, it is just a place holder.

        Args:
            ansible_adhoc :The pytest-ansible fixture
            os (str): The os type of Ixia Fanout.
            hostname (str): The Ixia fanout host-name
            device_type (str): The Ixia fanout device type.
        """ 

        self.ansible_adhoc = ansible_adhoc
        self.os            = os
        self.hostname      = hostname
        self.device_type   = device_type
        super().__init__(IxiaHost, self)
   
    def get_host_name (self):
        """Returns the Ixia hostname

        Args:
            This function takes no argument.
        """    
        return self.hostname

    def get_os (self) :
        """Returns the os type of the ixia device.

        Args:
            This function takes no argument.
        """    
        return self.os

    def execute (self, cmd) :
        """Execute a given command on ixia fanout host.
         
        Args: 
           cmd (str): Command to be executed.
        """ 
        if (self.os == 'ixia') :
            eval(cmd)


class FanoutHost():
    """
    @summary: Class for Fanout switch

    For running ansible module on the Fanout switch
    """

    def __init__(self, ansible_adhoc, os, hostname, device_type, user, passwd, shell_user=None, shell_passwd=None):
        self.hostname = hostname
        self.type = device_type
        self.host_to_fanout_port_map = {}
        self.fanout_to_host_port_map = {}
        if os == 'sonic':
            self.os = os
            self.host = SonicHost(ansible_adhoc, hostname)
        elif os == 'onyx':
            self.os = os
            self.host = OnyxHost(ansible_adhoc, hostname, user, passwd)
        elif os == 'ixia':
            # TODO: add ixia chassis abstraction
            self.os = os
            self.host = IxiaHost(ansible_adhoc, os, hostname, device_type)
        else:
            # Use eos host if the os type is unknown
            self.os = 'eos'
            self.host = EosHost(ansible_adhoc, hostname, user, passwd, shell_user=shell_user, shell_passwd=shell_passwd)

    def __getattr__(self, module_name):
        return getattr(self.host, module_name)

    def get_fanout_os(self):
        return self.os

    def get_fanout_type(self):
        return self.type

    def shutdown(self, interface_name):
        return self.host.shutdown(interface_name)

    def no_shutdown(self, interface_name):
        return self.host.no_shutdown(interface_name)

    def __str__(self):
        return "{ os: '%s', hostname: '%s', device_type: '%s' }" % (self.os, self.hostname, self.type)

    def __repr__(self):
        return self.__str__()

    def add_port_map(self, host_port, fanout_port):
        """
            Fanout switch is build from the connection graph of the
            DUT. So each fanout switch instance is relevant to the
            DUT instance in the test. As result the port mapping is
            unique from the DUT perspective. However, this function
            need update when supporting multiple DUT
        """
        self.host_to_fanout_port_map[host_port]   = fanout_port
        self.fanout_to_host_port_map[fanout_port] = host_port

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        return self.host.exec_template(ansible_root, ansible_playbook, inventory, **kwargs)
