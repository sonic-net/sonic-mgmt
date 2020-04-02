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
            self.host = ansible_adhoc(inventory='localhost', connection='local', host_pattern=hostname)[hostname]
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
        module_ignore_errors = complex_args.pop('module_ignore_errors', False)
        module_async = complex_args.pop('module_async', False)

        if module_async:
            def run_module(module_args, complex_args):
                return self.module(*module_args, **complex_args)[self.hostname]
            pool = ThreadPool()
            result = pool.apply_async(run_module, (module_args, complex_args))
            return pool, result

        res = self.module(*module_args, **complex_args)[self.hostname]
        if res.is_failed and not module_ignore_errors:
            raise RunAnsibleModuleFail("run module {} failed, errmsg {}".format(self.module_name, res))

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
    CRITICAL_SERVICES = ["swss", "syncd", "database", "teamd", "bgp", "pmon", "lldp"]

    def __init__(self, ansible_adhoc, hostname, gather_facts=False):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        if gather_facts:
            self.gather_facts()

    def _get_critical_services_for_multi_npu():
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


    def _platform_info(self):
        platform_info = self.command("show platform summary")["stdout_lines"]
        for line in platform_info:
            if line.startswith("Platform:"):
                self.facts["platform"] = line.split(":")[1].strip()
            elif line.startswith("HwSKU:"):
                self.facts["hwsku"] = line.split(":")[1].strip()
            elif line.startswith("ASIC:"):
                self.facts["asic_type"] = line.split(":")[1].strip()

    def gather_facts(self):
        """
        @summary: Gather facts of the SONiC switch and store the gathered facts in the dict type 'facts' attribute.
        """
        self.facts = {}
        self._platform_info()
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

    def get_pmon_daemon_list(self):
        """
        @summary: get pmon daemon list from the config file (/usr/share/sonic/device/{platform}/{hwsku}/pmon_daemon_control.json)
                  if some daemon is disabled in the config file, then remove it from the daemon list.
        """
        full_daemon_tup = ('xcvrd', 'ledd', 'psud', 'syseepromd')
        daemon_ctl_key_prefix = 'skip_'
        daemon_list = []
        daemon_config_file_path = os.path.join('/usr/share/sonic/device', self.facts["platform"], 'pmon_daemon_control.json')

        try:
            output = self.shell('cat %s' % daemon_config_file_path)
            json_data = json.loads(output["stdout"])
            logging.debug("Original file content is %s" % str(json_data))
            for key in full_daemon_tup:
                if (daemon_ctl_key_prefix + key) not in json_data:
                    daemon_list.append(key)
                    logging.debug("Daemon %s is enabled" % key)
                elif not json_data[daemon_ctl_key_prefix + key]:
                    daemon_list.append(key)
                    logging.debug("Daemon %s is enabled" % key)
                else:
                    logging.debug("Daemon %s is disabled" % key)
        except:
            # if pmon_daemon_control.json not exist, then it's using default setting,
            # all the pmon daemons expected to be running after boot up.
            daemon_list = list(full_daemon_tup)

        logging.info("Pmon daemon list for this platform is %s" % str(daemon_list))
        return daemon_list

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
            self.logger.error("Exception raised while getting networking restart time: %s" % repr(e))
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
            words = line.strip().split(' ')
            if len(words) == 2:
                if words[0] == 'Current:':
                    ret['current'] = words[1]
                elif words[0] == 'Next:':
                    ret['next'] = words[1]
            elif len(words) == 1 and words[0].startswith('SONiC-OS'):
                images.append(words[0])

        ret['installed_list'] = images
        return ret

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
                  'ansible_become_method': 'enable' }
        self.host.options['variable_manager'].extra_vars.update(evars)
