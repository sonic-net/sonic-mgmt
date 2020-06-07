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

    def __init__(self, ansible_adhoc, hostname, connection=None):
        if hostname == 'localhost':
            self.host = ansible_adhoc(connection='local', host_pattern=hostname)[hostname]
        else:
            if connection is None:
                self.host = ansible_adhoc(become=True)[hostname]
            else:
                logging.debug("connection {} for {}".format(connection, hostname))
                self.host = ansible_adhoc(become=True, connection=connection)[hostname]
        self.hostname = hostname

    def __getattr__(self, item):
        if self.host.has_module(item):
            self.module_name = item
            self.module = getattr(self.host, item)

            return self._run
        else:
            raise UnsupportedAnsibleModule("Unsupported module")

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

        if res.is_failed and not module_ignore_errors:
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
    @summary: Class for SONiC switch

    For running ansible module on the SONiC switch
    """
    CRITICAL_SERVICES = ["swss", "syncd", "database", "teamd", "bgp", "pmon", "lldp", "snmp"]

    def __init__(self, ansible_adhoc, hostname, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        if gather_facts:
            self.gather_facts()

    def _get_critical_services_for_multi_npu(self):
        """
        Update the critical_services with the service names for multi-npu platforms
        """
        m_service = []
        for service in self.CRITICAL_SERVICES:
            for npu in self.facts["num_npu"]:
                npu_service = service+npu
                m_service.insert(npu, npu_service)
        self.CRITICAL_SERVICES = m_service
        print self.CRITICAL_SERVICES

    def _get_npu_info(self):
        """
        Check if the DUT is multi-npu platfrom and store the number of npus in the facts
        """
        asic_conf_file_path = os.path.join('/usr/share/sonic/device', self.facts["platform"], 'asic.conf')
        try:
            output = self.shell('cat %s' % asic_conf_file_path)["stdout_lines"]
            print output
            for line in output:
                num_npu=line.split("=",1)[1].strip()
            print "num_npu = {}".format(num_npu)
            self.facts["num_npu"] = int(num_npu)
        except:
            self.facts["num_npu"] =1

        if self.facts["num_npu"] > 1:
            self._get_critical_services_for_multi_npu


    def get_platform_info(self):
        """
        @summary: Get the platform information of the SONiC switch.
        @return: Returns a dictionary containing preperties of the platform information, for example:
            {
                "platform": "",
                "hwsku": "",
                "asic_type": ""
            }
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

    def gather_facts(self):
        """
        @summary: Gather facts of the SONiC switch and store the gathered facts in the dict type 'facts' attribute.
        """
        self.facts = {}
        platform_info = self.get_platform_info()
        self.facts.update(platform_info)
        self._get_npu_info()
        logging.debug("SonicHost facts: %s" % json.dumps(self.facts))

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
        for service in self.CRITICAL_SERVICES:
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
            critical_process_list.append(l.rstrip())
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
        for service in self.CRITICAL_SERVICES:
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

    def num_npus(self):
        """
        return the number of NPUs on the DUT
        """
        return self.facts["num_npu"]

    def get_syncd_docker_names(self):
        """
        @summary: get the list of syncd dockers names for the number of NPUs present on the DUT
        for a single NPU dut the list will have only "syncd" in it
        """
        syncd_docker_names = []
        if self.facts["num_npu"] == 1:
            syncd_docker_names.append("syncd")
        else:
            num_npus = int(self.facts["num_npu"])
            for npu in range(0,num_npus):
                syncd_docker_names.append("syncd{}".format(npu))
        return syncd_docker_names

    def get_swss_docker_names(self):
        swss_docker_names = []
        if self.facts["num_npu"] == 1:
            swss_docker_names.append("swss")
        else:
            num_npus = self.facts["num_npu"]
            for npu in range(0,num_npus):
                swss_docker_names.append("swss{}".format(npu))
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

    def get_asic_type(self):
        return self.facts["asic_type"]

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
            m = re.search(r"(default|nexthop) via (\S+) dev (\S+)", l)
            if m:
                rtinfo['nexthops'].append((ipaddress.ip_address(m.group(2)), m.group(3)))

        logging.info("route parsed info for {}: {}".format(dstip, rtinfo))

        return rtinfo

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

    def check_bgp_session_state(self, neigh_ips, state="established"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param state: target state
        """
        neigh_ok = []
        bgp_facts = self.bgp_facts()['ansible_facts']
        logging.info("bgp_facts: {}".format(bgp_facts))
        for k, v in bgp_facts['bgp_neighbors'].items():
            if v['state'] == state:
                if k in neigh_ips:
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

    def get_version(self):
        """
            Gets the SONiC version this device is running.

            Returns:
                str: the firmware version number (e.g. 20181130.31)
        """
        output = dut.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
        return output["stdout_lines"][0].strip()

class EosHost(AnsibleHostBase):
    """
    @summary: Class for Eos switch

    For running ansible module on the Eos switch
    """

    def __init__(self, ansible_adhoc, hostname, user, passwd, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname, connection="network_cli")
        evars = { 'ansible_connection':'network_cli', \
                  'ansible_network_os':'eos', \
                  'ansible_user': user, \
                  'ansible_password': passwd, \
                  'ansible_ssh_user': user, \
                  'ansible_ssh_pass': passwd, \
                  'ansible_become_method': 'enable' }
        self.host.options['variable_manager'].extra_vars.update(evars)
        self.localhost = ansible_adhoc(inventory='localhost', connection='local', host_pattern="localhost")["localhost"]

    def shutdown(self, interface_name):
        out = self.host.eos_config(
            lines=['shutdown'],
            parents='interface %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.host.eos_config(
            lines=['no shutdown'],
            parents='interface %s' % interface_name)
        logging.info('No shut interface [%s]' % interface_name)
        return out

    def check_intf_link_state(self, interface_name):
        show_int_result = self.host.eos_command(
            commands=['show interface %s' % interface_name])[self.hostname]
        return 'Up' in show_int_result['stdout_lines'][0]

    def command(self, cmd):
        out = self.host.eos_command(commands=[cmd])
        return out

    def set_interface_lacp_rate_mode(self, interface_name, mode):
        out = self.host.eos_config(
            lines=['lacp rate %s' % mode],
            parents='interface %s' % interface_name)
        logging.info("Set interface [%s] lacp rate to [%s]" % (interface_name, mode))
        return out

    def kill_bgpd(self):
        out = self.host.eos_config(lines=['agent Rib shutdown'])
        return out

    def start_bgpd(self):
        out = self.host.eos_config(lines=['no agent Rib shutdown'])
        return out

    def check_bgp_session_state(self, neigh_ips, neigh_desc, state="established"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param neigh_desc: bgp neighbor description
        @param state: target state
        """
        neigh_ips_ok = []
        neigh_desc_ok = []
        out_v4 = self.host.eos_command(
            commands=['show ip bgp summary | json'])[self.hostname]
        logging.info("ip bgp summary: {}".format(out_v4))

        out_v6 = self.host.eos_command(
            commands=['show ipv6 bgp summary | json'])[self.hostname]
        logging.info("ipv6 bgp summary: {}".format(out_v6))

        for k, v in out_v4['stdout'][0]['vrfs']['default']['peers'].items():
            if v['peerState'].lower() == state.lower():
                if k in neigh_ips:
                    neigh_ips_ok.append(neigh_ips)
                if v['description'] in neigh_desc:
                    neigh_desc_ok.append(v['description'])

        for k, v in out_v6['stdout'][0]['vrfs']['default']['peers'].items():
            if v['peerState'].lower() == state.lower():
                if k in neigh_ips:
                    neigh_ips_ok.append(neigh_ips)
                if v['description'] in neigh_desc:
                    neigh_desc_ok.append(v['description'])

        if len(neigh_ips) == len(neigh_ips_ok) and len(neigh_desc) == len(neigh_desc_ok):
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
            parents='interface ethernet %s' % interface_name)
        logging.info('Shut interface [%s]' % interface_name)
        return out

    def no_shutdown(self, interface_name):
        out = self.host.onyx_config(
            lines=['no shutdown'],
            parents='interface ethernet %s' % interface_name)
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
            raise Exception("Unable to execute template\n{}".format(res["stdout"]))


class FanoutHost():
    """
    @summary: Class for Fanout switch

    For running ansible module on the Fanout switch
    """

    def __init__(self, ansible_adhoc, os, hostname, device_type, user, passwd):
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
        else:
            # Use eos host if the os type is unknown
            self.os = 'eos'
            self.host = EosHost(ansible_adhoc, hostname, user, passwd)

    def get_fanout_os(self):
        return self.os

    def get_fanout_type(self):
        return self.type

    def shutdown(self, interface_name):
        return self.host.shutdown(interface_name)[self.hostname]

    def no_shutdown(self, interface_name):
        return self.host.no_shutdown(interface_name)[self.hostname]

    def command(self, cmd):
        return self.host.command(cmd)[self.hostname]

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
