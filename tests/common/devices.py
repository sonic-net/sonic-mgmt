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
import copy
import time
from multiprocessing.pool import ThreadPool
from datetime import datetime
from collections import defaultdict

from ansible import constants
from ansible.plugins.loader import connection_loader

from errors import RunAnsibleModuleFail
from errors import UnsupportedAnsibleModule
from tests.common.cache import cached
from tests.common.helpers.constants import DEFAULT_ASIC_ID, DEFAULT_NAMESPACE, NAMESPACE_PREFIX
from tests.common.helpers.dut_utils import is_supervisor_node

# HACK: This is a hack for issue https://github.com/Azure/sonic-mgmt/issues/1941 and issue
# https://github.com/ansible/pytest-ansible/issues/47
# Detailed root cause analysis of the issue: https://github.com/Azure/sonic-mgmt/issues/1941#issuecomment-670434790
# Before calling callback function of plugins to return ansible module result, ansible calls the
# ansible.executor.task_result.TaskResult.clean_copy method to remove some keys like 'failed' and 'skipped' in the
# result dict. The keys to be removed are defined in module variable ansible.executor.task_result._IGNORE. The trick
# of this hack is to override this pre-defined key list. When the 'failed' key is not included in the list, ansible
# will not remove it before returning the ansible result to plugins (pytest_ansible in our case)
try:
    from ansible.executor import task_result
    task_result._IGNORE = ('skipped', )
except Exception as e:
    logging.error("Hack for https://github.com/ansible/pytest-ansible/issues/47 failed: {}".format(repr(e)))

logger = logging.getLogger(__name__)

class AnsibleHostBase(object):
    """
    @summary: The base class for various objects.

    This class filters an object from the ansible_adhoc fixture by hostname. The object can be considered as an
    ansible host object although it is not under the hood. Anyway, we can use this object to run ansible module
    on the host.
    """

    def __init__(self, ansible_adhoc, hostname, *args, **kwargs):
        if hostname == 'localhost':
            self.host = ansible_adhoc(connection='local', host_pattern=hostname)[hostname]
        else:
            self.host = ansible_adhoc(become=True, *args, **kwargs)[hostname]
            self.mgmt_ip = self.host.options["inventory_manager"].get_host(hostname).vars["ansible_host"]
        self.hostname = hostname

    def __getattr__(self, module_name):
        if self.host.has_module(module_name):
            self.module_name = module_name
            self.module = getattr(self.host, module_name)

            return self._run
        raise AttributeError(
            "'%s' object has no attribute '%s'" % (self.__class__, module_name)
            )

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


    def __init__(self, ansible_adhoc, hostname,
                 shell_user=None, shell_passwd=None):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

        if shell_user and shell_passwd:
            im = self.host.options['inventory_manager']
            vm = self.host.options['variable_manager']
            sonic_conn = vm.get_vars(
                host=im.get_hosts(pattern='sonic')[0]
                )['ansible_connection']
            hostvars = vm.get_vars(host=im.get_host(hostname=self.hostname))
            # parse connection options and reset those options with
            # passed credentials
            connection_loader.get(sonic_conn, class_only=True)
            user_def = constants.config.get_configuration_definition(
                "remote_user", "connection", sonic_conn
                )
            pass_def = constants.config.get_configuration_definition(
                "password", "connection", sonic_conn
                )
            for user_var in (_['name'] for _ in user_def['vars']):
                if user_var in hostvars:
                    vm.extra_vars.update({user_var: shell_user})
            for pass_var in (_['name'] for _ in pass_def['vars']):
                if pass_var in hostvars:
                    vm.extra_vars.update({pass_var: shell_passwd})

        self._facts = self._gather_facts()
        self._os_version = self._get_os_version()
        self.is_multi_asic = True if self.facts["num_asic"] > 1 else False
        self._kernel_version = self._get_kernel_version()


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
                "router_mac": "52:54:00:f0:ac:9d",
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
    def kernel_version(self):
        """
        The kernel version running on this SONiC device.

        Returns:
            str: The SONiC kernel version (e.g. "4.9.0")
        """
        return self._kernel_version

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
        self._critical_services = var

        logging.debug(self._critical_services)

    def reset_critical_services_tracking_list(self, service_list):
        """
        Resets the list of critical services.
        """

        self.critical_services = service_list

    @cached(name='basic_facts')
    def _gather_facts(self):
        """
        Gather facts about the platform for this SONiC device.
        """

        facts = dict()
        facts.update(self._get_platform_info())
        facts["num_asic"] = self._get_asic_count(facts["platform"])
        facts["router_mac"] = self._get_router_mac()

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

    def _get_router_mac(self):
        return self.command("sonic-cfggen -d -v 'DEVICE_METADATA.localhost.mac'")["stdout_lines"][0].decode("utf-8")


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

        if result["platform"]:
            platform_file_path = os.path.join("/usr/share/sonic/device", result["platform"], "platform.json")

            try:
                out = self.command("cat {}".format(platform_file_path))
                platform_info = json.loads(out["stdout"])
                for key, value in platform_info.iteritems():
                    result[key] = value

            except Exception:
                # if platform.json does not exist, then it's not added currently for certain platforms
                # eventually all the platforms should have the platform.json
                logging.debug("platform.json is not available for this platform, "
                              + "DUT facts will not contain complete platform information.")

        return result

    def _get_os_version(self):
        """
        Gets the SONiC OS version that is running on this device.
        """

        output = self.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
        return output["stdout_lines"][0].strip()

    def _get_kernel_version(self):
        """
        Gets the SONiC kernel version
        :return:
        """
        output = self.command('uname -r')
        return output["stdout"].split('-')[0]

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

    def is_supervisor_node(self):
        """Check if the current node is a supervisor node in case of multi-DUT.

        Returns:
            Currently, we are using 'type' in the inventory to make the decision. If 'type' for the node is defined in
            the inventory, and it is 'supervisor', then return True, else return False. In future, we can change this
            logic if possible to derive it from the DUT.
        """
        im = self.host.options['inventory_manager']
        inv_files = im._sources
        return is_supervisor_node(inv_files, self.hostname)

    def is_frontend_node(self):
        """Check if the current node is a frontend node in case of multi-DUT.

        Returns:
            True if it is not any other type of node. Currently, the only other type of node supported is 'supervisor'
            node. If we add more types of nodes, then we need to exclude them from this method as well.
        """
        return not self.is_supervisor_node()

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

    def is_container_present(self, service):
        """
        Checks where a container exits.

        @param service: Container name

        Returns:
            True or False
        """
        status = self.command(
            "docker ps -f name={}".format(service),
            module_ignore_errors=True
        )

        if len(status["stdout_lines"]) > 1:
            logging.info("container {} status: {}".format(
                service, status["stdout"])
            )
        else:
            logging.info("container {} does not exist".format(service))

        return len(status["stdout_lines"]) > 1

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

    def get_monit_services_status(self):
        """
        @summary: Get metadata (service name, service status and service type) of services
                  which were monitored by Monit.
        @return: A dictionary in which key is the service name and values are service status
                 and service type.
        """
        monit_services_status = {}

        services_status_result = self.shell("sudo monit status", module_ignore_errors=True)

        exit_code = services_status_result["rc"]
        if exit_code != 0:
            return monit_services_status

        for index, service_info in enumerate(services_status_result["stdout_lines"]):
            if "status" in service_info and "monitoring status" not in service_info:
                service_type_name = services_status_result["stdout_lines"][index - 1]
                service_type = service_type_name.split("'")[0].strip()
                service_name = service_type_name.split("'")[1].strip()
                service_status = service_info[service_info.find("status") + len("status"):].strip()

                monit_services_status[service_name] = {}
                monit_services_status[service_name]["service_status"] = service_status
                monit_services_status[service_name]["service_type"] = service_type

        return monit_services_status

    def get_critical_group_and_process_lists(self, container_name):
        """
        @summary: Get critical group and process lists by parsing the
                  critical_processes file in the specified container
        @return: Two lists which include the critical groups and critical processes respectively
        """
        critical_group_list = []
        critical_process_list = []
        succeeded = True


        file_content = self.shell("docker exec {} bash -c '[ -f /etc/supervisor/critical_processes ] \
                && cat /etc/supervisor/critical_processes'".format(container_name), module_ignore_errors=True)
        for line in file_content["stdout_lines"]:
            line_info = line.strip().split(':')
            if len(line_info) != 2:
                if '201811' in self._os_version and len(line_info) == 1:
                    identifier_value = line_info[0].strip()
                    critical_process_list.append(identifier_value)
                    continue

                succeeded = False
                break

            identifier_key = line_info[0].strip()
            identifier_value = line_info[1].strip()
            if identifier_key == "group" and identifier_value:
                critical_group_list.append(identifier_value)
            elif identifier_key == "program" and identifier_value:
                critical_process_list.append(identifier_value)
            else:
                succeeded = False
                break

        # For PMon container, since different daemons are enabled in different platforms, we need find common processes
        # which are not only in the critical_processes file and also are configured to run on that platform.
        if succeeded and container_name == "pmon":
            expected_critical_group_list = []
            expected_critical_process_list = []
            process_list = self.shell("docker exec {} supervisorctl status".format(container_name), module_ignore_errors=True)
            for process_info in process_list["stdout_lines"]:
                process_name = process_info.split()[0].strip()
                process_status = process_info.split()[1].strip()
                if ":" in process_name:
                    group_name = process_name.split(":")[0]
                    process_name = process_name.split(":")[1]
                    if process_status == "RUNNING" and group_name in critical_group_list:
                        expected_critical_group_list.append(process_name)
                else:
                    if process_status == "RUNNING" and process_name in critical_process_list:
                        expected_critical_process_list.append(process_name)

            critical_group_list = expected_critical_group_list
            critical_process_list = expected_critical_process_list

        return critical_group_list, critical_process_list, succeeded

    def critical_process_status(self, service):
        """
        @summary: Check whether critical process status of a service.

        @param service: Name of the SONiC service
        """
        result = {'status': True}
        result['exited_critical_process'] = []
        result['running_critical_process'] = []
        critical_group_list = []
        critical_process_list = []

        # return false if the service is not started
        service_status = self.is_service_fully_started(service)
        if service_status == False:
            result['status'] = False
            return result

        # get critical group and process lists for the service
        critical_group_list, critical_process_list, succeeded = self.get_critical_group_and_process_lists(service)
        if succeeded == False:
            result['status'] = False
            return result

        # get process status for the service
        output = self.command("docker exec {} supervisorctl status".format(service), module_ignore_errors=True)
        logging.info("====== supervisor process status for service {} ======".format(service))

        for l in output['stdout_lines']:
            (pname, status, info) = re.split("\s+", l, 2)
            if status != "RUNNING":
                if pname in critical_group_list or pname in critical_process_list:
                    result['exited_critical_process'].append(pname)
                    result['status'] = False
            else:
                if pname in critical_group_list or pname in critical_process_list:
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
        exemptions = ['lm-sensors', 'start.sh', 'rsyslogd', 'start', 'dependent-startup']

        daemons = self.shell('docker exec pmon supervisorctl status', module_ignore_errors=True)['stdout_lines']

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

    def get_ip_route_info(self, dstip, ns=""):
        """
        @summary: return route information for a destionation. The destination coulb an ip address or ip prefix.

        @param dstip: destination. either ip_address or ip_network

        Please beware: if dstip is an ip network, you will receive all ECMP nexthops
        But if dstip is an ip address, only one nexthop will be returned, the one which is going to be used to send a packet to the destination.

        Exanples:
----------------
get_ip_route_info(ipaddress.ip_address(unicode("192.168.8.0")))
returns {'set_src': IPv4Address(u'10.1.0.32'), 'nexthops': [(IPv4Address(u'10.0.0.13'), u'PortChannel0004')]}

raw data
192.168.8.0 via 10.0.0.13 dev PortChannel0004 src 10.1.0.32
    cache
----------------
get_ip_route_info(ipaddress.ip_network(unicode("192.168.8.0/25")))
returns {'set_src': IPv4Address(u'10.1.0.32'), 'nexthops': [(IPv4Address(u'10.0.0.1'), u'PortChannel0001'), (IPv4Address(u'10.0.0.5'), u'PortChannel0002'), (IPv4Address(u'10.0.0.9'), u'PortChannel0003'), (IPv4Address(u'10.0.0.13'), u'PortChannel0004')]}

raw data
192.168.8.0/25 proto 186 src 10.1.0.32 metric 20
        nexthop via 10.0.0.1  dev PortChannel0001 weight 1
        nexthop via 10.0.0.5  dev PortChannel0002 weight 1
        nexthop via 10.0.0.9  dev PortChannel0003 weight 1
        nexthop via 10.0.0.13  dev PortChannel0004 weight 1
----------------
get_ip_route_info(ipaddress.ip_address(unicode("20c0:a818::")))
returns {'set_src': IPv6Address(u'fc00:1::32'), 'nexthops': [(IPv6Address(u'fc00::1a'), u'PortChannel0004')]}

raw data
20c0:a818:: from :: via fc00::1a dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium
----------------
get_ip_route_info(ipaddress.ip_network(unicode("20c0:a818::/64")))
returns {'set_src': IPv6Address(u'fc00:1::32'), 'nexthops': [(IPv6Address(u'fc00::2'), u'PortChannel0001'), (IPv6Address(u'fc00::a'), u'PortChannel0002'), (IPv6Address(u'fc00::12'), u'PortChannel0003'), (IPv6Address(u'fc00::1a'), u'PortChannel0004')]}

raw data
20c0:a818::/64 via fc00::2 dev PortChannel0001 proto 186 src fc00:1::32 metric 20  pref medium
20c0:a818::/64 via fc00::a dev PortChannel0002 proto 186 src fc00:1::32 metric 20  pref medium
20c0:a818::/64 via fc00::12 dev PortChannel0003 proto 186 src fc00:1::32 metric 20  pref medium
20c0:a818::/64 via fc00::1a dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium
----------------
get_ip_route_info(ipaddress.ip_network(unicode("0.0.0.0/0")))
returns {'set_src': IPv4Address(u'10.1.0.32'), 'nexthops': [(IPv4Address(u'10.0.0.1'), u'PortChannel0001'), (IPv4Address(u'10.0.0.5'), u'PortChannel0002'), (IPv4Address(u'10.0.0.9'), u'PortChannel0003'), (IPv4Address(u'10.0.0.13'), u'PortChannel0004')]}

raw data
default proto 186 src 10.1.0.32 metric 20
        nexthop via 10.0.0.1  dev PortChannel0001 weight 1
        nexthop via 10.0.0.5  dev PortChannel0002 weight 1
        nexthop via 10.0.0.9  dev PortChannel0003 weight 1
        nexthop via 10.0.0.13  dev PortChannel0004 weight 1
----------------
get_ip_route_info(ipaddress.ip_network(unicode("::/0")))
returns {'set_src': IPv6Address(u'fc00:1::32'), 'nexthops': [(IPv6Address(u'fc00::2'), u'PortChannel0001'), (IPv6Address(u'fc00::a'), u'PortChannel0002'), (IPv6Address(u'fc00::12'), u'PortChannel0003'), (IPv6Address(u'fc00::1a'), u'PortChannel0004')]}

raw data
default via fc00::2 dev PortChannel0001 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::a dev PortChannel0002 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::12 dev PortChannel0003 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::1a dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium
----------------
        """

        rtinfo = {'set_src': None, 'nexthops': [] }

        if isinstance(dstip, ipaddress.IPv4Network) or isinstance(dstip, ipaddress.IPv6Network):
            if dstip.version == 4:
                rt = self.command("ip {} route list exact {}".format(ns, dstip))['stdout_lines']
            else:
                rt = self.command("ip {} -6 route list exact {}".format(ns , dstip))['stdout_lines']

            logging.info("route raw info for {}: {}".format(dstip, rt))

            if len(rt) == 0:
                return rtinfo

            # parse set_src
            m = re.match(r"^(default|\S+) proto (zebra|bgp|186) src (\S+)", rt[0])
            m1 = re.match(r"^(default|\S+) via (\S+) dev (\S+) proto (zebra|bgp|186) src (\S+)", rt[0])
            if m:
                rtinfo['set_src'] = ipaddress.ip_address(unicode(m.group(3)))
            elif m1:
                rtinfo['set_src'] = ipaddress.ip_address(unicode(m1.group(5)))

            # parse nexthops
            for l in rt:
                m = re.search(r"(default|nexthop|\S+)\s+via\s+(\S+)\s+dev\s+(\S+)", l)
                if m:
                    rtinfo['nexthops'].append((ipaddress.ip_address(unicode(m.group(2))), unicode(m.group(3))))

        elif isinstance(dstip, ipaddress.IPv4Address) or isinstance(dstip, ipaddress.IPv6Address):
            rt = self.command("ip {} route get {}".format(ns, dstip))['stdout_lines']
            logging.info("route raw info for {}: {}".format(dstip, rt))

            if len(rt) == 0:
                return rtinfo

            m = re.match(".+\s+via\s+(\S+)\s+.*dev\s+(\S+)\s+.*src\s+(\S+)\s+", rt[0])
            if m:
                nexthop_ip = ipaddress.ip_address(unicode(m.group(1)))
                gw_if = m.group(2)
                rtinfo['nexthops'].append((nexthop_ip, gw_if))
                rtinfo['set_src'] = ipaddress.ip_address(unicode(m.group(3)))
        else:
            raise ValueError("Wrong type of dstip")

        logging.info("route parsed info for {}: {}".format(dstip, rtinfo))
        return rtinfo

    def check_default_route(self, ipv4=True, ipv6=True):
        """
        @summary: return default route status

        @param ipv4: check ipv4 default
        @param ipv6: check ipv6 default
        """
        if ipv4:
            rtinfo_v4 = self.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))
            if len(rtinfo_v4['nexthops']) == 0:
                return False

        if ipv6:
            rtinfo_v6 = self.get_ip_route_info(ipaddress.ip_network(u'::/0'))
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

    def get_bgp_statistic(self, stat):
        """
        Get the named bgp statistic

        Args: stat - name of statistic

        Returns: statistic value or None if not found

        """
        ret = None
        bgp_facts = self.bgp_facts()['ansible_facts']
        if stat in bgp_facts['bgp_statistics']:
            ret = bgp_facts['bgp_statistics'][stat]
        return ret

    def check_bgp_statistic(self, stat, value):
        val = self.get_bgp_statistic(stat)
        return val == value

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
        if 'bgpState' in nbinfo and nbinfo['bgpState'].lower() == "Active".lower():
            if 'bgpStateIs' in nbinfo and nbinfo['bgpStateIs'].lower() == "passiveNSF".lower():
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

    def get_container_autorestart_states(self):
        """
        @summary: Get container names and their autorestart states by analyzing
                  the command output of "show feature autorestart"
        @return:  A dictionary where keys are the names of containers which have the
                  autorestart feature implemented and values are the autorestart feature
                  state for that container
        """
        container_autorestart_states = {}

        show_cmd_output = self.shell("show feature autorestart")
        for line in show_cmd_output["stdout_lines"]:
            container_name = line.split()[0].strip()
            container_state = line.split()[1].strip()
            if container_state in ["enabled", "disabled"]:
                container_autorestart_states[container_name] = container_state

        return container_autorestart_states

    def get_feature_status(self):
        """
        Gets the list of features and states

        Returns:
            dict: feature status dict. { <feature name> : <status: enabled | disabled> }
            bool: status obtained successfully (True | False)
        """
        feature_status = {}
        command_list = ['show feature status', 'show features']
        for cmd in command_list:
            command_output = self.shell(cmd, module_ignore_errors=True)
            if command_output['rc'] == 0:
                break
        else:
            return feature_status, False

        features_stdout = command_output['stdout_lines']
        lines = features_stdout[2:]
        for x in lines:
            result = x.encode('UTF-8')
            r = result.split()
            feature_status[r[0]] = r[1]
        return feature_status, True

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


    def _parse_show(self, output_lines):

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
            item = {}
            for idx, (left, right) in enumerate(positions):
                k = headers[idx]
                v = content_line[left:right].strip()
                item[k] = v
            result.append(item)

        return result

    def show_and_parse(self, show_cmd, **kwargs):
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
        output = self.shell(show_cmd, **kwargs)["stdout_lines"]
        return self._parse_show(output)

    @cached(name='mg_facts')
    def get_extended_minigraph_facts(self, tbinfo):
        mg_facts = self.minigraph_facts(host = self.hostname)['ansible_facts']
        mg_facts['minigraph_ptf_indices'] = mg_facts['minigraph_port_indices'].copy()

        # Fix the ptf port index for multi-dut testbeds. These testbeds have
        # multiple DUTs sharing a same PTF host. Therefore, the indices from
        # the minigraph facts are not always match up with PTF port indices.
        try:
            dut_index = tbinfo['duts'].index(self.hostname)
            map = tbinfo['topo']['ptf_map'][str(dut_index)]
            if map:
                for port, index in mg_facts['minigraph_port_indices'].items():
                    mg_facts['minigraph_ptf_indices'][port] = map[str(index)]
        except (ValueError, KeyError):
            pass

        return mg_facts

    def get_route(self, prefix):
        cmd = 'show bgp ipv4' if ipaddress.ip_network(unicode(prefix)).version == 4 else 'show bgp ipv6'
        return json.loads(self.shell('vtysh -c "{} {} json"'.format(cmd, prefix))['stdout'])

    def run_redis_cli_cmd(self, redis_cmd):
        cmd = "/usr/bin/redis-cli {}".format(redis_cmd)
        return self.command(cmd)

    def get_asic_name(self):
        asic = "unknown"
        output = self.shell("lspci", module_ignore_errors=True)["stdout"]
        if ("Broadcom Limited Device b960" in output or
            "Broadcom Limited Broadcom BCM56960" in output):
            asic = "th"
        elif "Broadcom Limited Device b971" in output:
            asic = "th2"
        elif "Broadcom Limited Device b850" in output:
            asic = "td2"
        elif "Broadcom Limited Device b870" in output:
            asic = "td3"

        return asic

    def get_running_config_facts(self):
        return self.config_facts(host=self.hostname, source='running')['ansible_facts']

    def get_vlan_intfs(self):
        '''
        Get any interfaces belonging to a VLAN
        '''
        vlan_members_facts = self.get_running_config_facts()['VLAN_MEMBER']
        vlan_intfs = []

        for vlan in vlan_members_facts:
            for intf in vlan_members_facts[vlan]:
                vlan_intfs.append(intf)

        return vlan_intfs

    def get_crm_facts(self):
        """Run various 'crm show' commands and parse their output to gather CRM facts

        Executed commands:
            crm show summary
            crm show thresholds
            crm show resources all

        Example output:
            {
                "acl_group": [
                    {
                        "resource name": "acl_group",
                        "bind point": "PORT",
                        "available count": "200",
                        "used count": "24",
                        "stage": "INGRESS"
                    },
                   ...
                ],
                "acl_table": [
                    {
                        "table id": "",
                        "resource name": "",
                        "used count": "",
                        "available count": ""
                    },
                    ...
                ],
                "thresholds": {
                        "ipv4_route": {
                            "high": 85,
                            "type": "percentage",
                            "low": 70
                        },
                    ...
                },
                "resources": {
                    "ipv4_route": {
                        "available": 100000,
                        "used": 16
                    },
                    ...
                },
                "polling_interval": 300
            }

        Returns:
            dict: Gathered CRM facts.
        """
        crm_facts = {}

        # Get polling interval
        output = self.command('crm show summary')['stdout']
        parsed = re.findall(r'Polling Interval: +(\d+) +second', output)
        if parsed:
            crm_facts['polling_interval'] = int(parsed[0])

        # Get thresholds
        crm_facts['thresholds'] = {}
        thresholds = self.show_and_parse('crm show thresholds all')
        for threshold in thresholds:
            crm_facts['thresholds'][threshold['resource name']] = {
                'high': int(threshold['high threshold']),
                'low': int(threshold['low threshold']),
                'type': threshold['threshold type']
            }

        # Get output of all resources
        output = self.command('crm show resources all')['stdout_lines']
        in_section = False
        sections = defaultdict(list)
        section_id = 0
        for line in output:
            if len(line.strip()) != 0:
                if not in_section:
                    in_section = True
                    section_id += 1
                sections[section_id].append(line)
            else:
                in_section=False
                continue
        # Output of 'crm show resources all' has 3 sections.
        #   section 1: resources usage
        #   section 2: ACL group
        #   section 3: ACL table
        if 1 in sections.keys():
            crm_facts['resources'] = {}
            resources = self._parse_show(sections[1])
            for resource in resources:
                crm_facts['resources'][resource['resource name']] = {
                    'used': int(resource['used count']),
                    'available': int(resource['available count'])
                }

        if 2 in sections.keys():
            crm_facts['acl_group'] = self._parse_show(sections[2])

        if 3 in sections.keys():
            crm_facts['acl_table'] = self._parse_show(sections[3])

        return crm_facts

    def stop_service(self, service_name, docker_name):
        logging.debug("Stopping {}".format(service_name))
        if self.is_service_fully_started(docker_name):
            self.command("systemctl stop {}".format(service_name))
        logging.debug("Stopped {}".format(service_name))

    def delete_container(self, service):
        if self.is_container_present(service):
            self.command("docker rm {}".format(service))

    def is_bgp_state_idle(self):
        bgp_summary = self.command("show ip bgp summary")["stdout_lines"]

        idle_count = 0
        expected_idle_count = 0
        for line in bgp_summary:
            if "Idle (Admin)" in line:
                idle_count += 1

            if "Total number of neighbors" in line:
                tokens = line.split()
                expected_idle_count = int(tokens[-1])

        return idle_count == expected_idle_count

    def is_service_running(self, service_name, docker_name):
        service_status = self.command(
            "docker exec {} supervisorctl status {}".format(
                docker_name, service_name
            ),
            module_ignore_errors=True
        )["stdout"]

        logging.info("service {}:{} status: {} ".format(
            docker_name, service_name, service_status)
        )

        return "RUNNING" in service_status


class K8sMasterHost(AnsibleHostBase):
    """
    @summary: Class for Ubuntu KVM that hosts Kubernetes master

    For running ansible module on the K8s Ubuntu KVM host
    """

    def __init__(self, ansible_adhoc, hostname, is_haproxy):
        """ Initialize an object for interacting with Ubuntu KVM using ansible modules

        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the Ubuntu KVM
            is_haproxy (boolean): True if node is haproxy load balancer, False if node is backend master server

        """
        self.hostname = hostname
        self.is_haproxy = is_haproxy
        super(K8sMasterHost, self).__init__(ansible_adhoc, hostname)
        evars = {
            'ansible_become_method': 'enable'
        }
        self.host.options['variable_manager'].extra_vars.update(evars)

    def check_k8s_master_ready(self):
        """
        @summary: check if all Kubernetes master node statuses reflect target state "Ready"

        """
        k8s_nodes_statuses = self.shell('kubectl get nodes | grep master', module_ignore_errors=True)["stdout_lines"]
        logging.info("k8s master node statuses: {}".format(k8s_nodes_statuses))

        for line in k8s_nodes_statuses:
            if "NotReady" in line:
                return False
        return True

    def shutdown_api_server(self):
        """
        @summary: Shuts down API server container on one K8sMasterHost server

        """
        self.shell('sudo systemctl stop kubelet')
        logging.info("Shutting down API server on backend master server hostname: {}".format(self.hostname))
        api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout_lines"]
        for id in api_server_container_ids:
            self.shell('sudo docker kill {}'.format(id))
        api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout"]
        assert not api_server_container_ids

    def start_api_server(self):
        """
        @summary: Starts API server container on one K8sMasterHost server

        """
        self.shell('sudo systemctl start kubelet')
        logging.info("Starting API server on backend master server hostname: {}".format(self.hostname))
        timeout_wait_secs = 60
        poll_wait_secs = 5
        api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout_lines"]
        while ((len(api_server_container_ids) < 2) and (timeout_wait_secs > 0)):
            logging.info("Waiting for Kubernetes API server to start")
            time.sleep(poll_wait_secs)
            timeout_wait_secs -= poll_wait_secs
            api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout_lines"]
        assert len(api_server_container_ids) > 1

    def ensure_kubelet_running(self):
        """
        @summary: Ensures kubelet is running on one K8sMasterHost server

        """
        logging.info("Ensuring kubelet is started on {}".format(self.hostname))
        kubelet_status = self.shell("sudo systemctl status kubelet | grep 'Active: '", module_ignore_errors=True)
        for line in kubelet_status["stdout_lines"]:
            if not "running" in line:
                self.shell("sudo systemctl start kubelet")


class K8sMasterCluster(object):
    """
    @summary: Class that encapsulates Kubernetes master cluster

    For operating on a group of K8sMasterHost objects that compose one HA Kubernetes master cluster
    """

    def __init__(self, k8smasters):
        """Initialize a list of backend master servers, and identify the HAProxy load balancer node

        Args:
            k8smasters: fixture that allows retrieval of K8sMasterHost objects

        """
        self.backend_masters = []
        for hostname, k8smaster in k8smasters.items():
            if k8smaster['host'].is_haproxy:
                self.haproxy = k8smaster['host']
            else:
                self.backend_masters.append(k8smaster)

    @property
    def vip(self):
        """
        @summary: Retrieve VIP of Kubernetes master cluster

        """
        return self.haproxy.mgmt_ip

    def shutdown_all_api_server(self):
        """
        @summary: shut down API server on all backend master servers

        """
        for k8smaster in self.backend_masters:
            logger.info("Shutting down API Server on master node {}".format(k8smaster['host'].hostname))
            k8smaster['host'].shutdown_api_server()

    def start_all_api_server(self):
        """
        @summary: Start API server on all backend master servers

        """
        for k8smaster in self.backend_masters:
            logger.info("Starting API server on master node {}".format(k8smaster['host'].hostname))
            k8smaster['host'].start_api_server()

    def check_k8s_masters_ready(self):
        """
        @summary: Ensure that Kubernetes master is in healthy state

        """
        for k8smaster in self.backend_masters:
            assert k8smaster['host'].check_k8s_master_ready()

    def ensure_all_kubelet_running(self):
        """
        @summary: Ensures kubelet is started on all backend masters, start kubelet if necessary

        """
        for k8smaster in self.backend_masters:
            k8smaster['host'].ensure_kubelet_running()


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

        if out['failed'] == True:
            # new eos deprecate lacp rate and use lacp timer command
            out = self.eos_config(
                lines=['lacp timer %s' % mode],
                parents='interface %s' % interface_name)
            if out['changed'] == False:
                logging.warning("Unable to set interface [%s] lacp timer to [%s]" % (interface_name, mode))
                raise Exception("Unable to set interface [%s] lacp timer to [%s]" % (interface_name, mode))
            else:
                logging.info("Set interface [%s] lacp timer to [%s]" % (interface_name, mode))
        else:
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

    def get_route(self, prefix):
        cmd = 'show ip bgp' if ipaddress.ip_network(unicode(prefix)).version == 4 else 'show ipv6 bgp'
        return self.eos_command(commands=[{
            'command': '{} {}'.format(cmd, prefix),
            'output': 'json'
        }])['stdout'][0]


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


class SonicAsic(object):
    """ This class represents an ASIC on a SONiC host. This class implements wrapper methods for ASIC/namespace related operations.
    The purpose is to hide the complexity of handling ASIC/namespace specific details.
    For example, passing asic_id, namespace, instance_id etc. to ansible module to deal with namespaces.
    """

    _DEFAULT_ASIC_SERVICES =  ["bgp", "database", "lldp", "swss", "syncd", "teamd"]
    _MULTI_ASIC_SERVICE_NAME = "{}@{}"   # service name, asic_id
    _MULTI_ASIC_DOCKER_NAME = "{}{}"     # docker name,  asic_id

    def __init__(self, sonichost, asic_index):
        """ Initializing a ASIC on a SONiC host.

        Args:
            sonichost : SonicHost object to which this asic belongs
            asic_index: ASIC / namespace id for this asic.
        """
        self.sonichost = sonichost
        self.asic_index = asic_index
        if self.sonichost.is_multi_asic:
            self.namespace = "{}{}".format(NAMESPACE_PREFIX, self.asic_index)
            self.cli_ns_option = "-n {}".format(self.namespace)
        else:
            # set the namespace to DEFAULT_NAMESPACE(None) for single asic
            self.namespace = DEFAULT_NAMESPACE
            self.cli_ns_option = ""

    def get_critical_services(self):
        """This function returns the list of the critical services
           for the namespace(asic)

           If the dut is multi asic, then the asic_id is appended t0 the
            _DEFAULT_ASIC_SERVICES list
        Returns:
            [list]: list of the services running the namespace/asic
        """
        a_service = []
        for service in self._DEFAULT_ASIC_SERVICES:
           a_service.append("{}{}".format(
               service, self.asic_index if self.sonichost.is_multi_asic else ""))
        return a_service

    def get_service_name(self, service):
        service_name = "{}{}".format(service, "@{}".format(self.asic_index) if self.sonichost.is_multi_asic else "")
        return service_name

    def is_it_frontend(self):
        if self.sonichost.is_multi_asic:
            sub_role_cmd = 'sudo sonic-cfggen -d  -v DEVICE_METADATA.localhost.sub_role -n {}'.format(self.namespace)
            sub_role = self.sonichost.shell(sub_role_cmd)["stdout_lines"][0].decode("utf-8")
            if sub_role is not None and sub_role.lower() == 'frontend':
                return True
        return False

    def is_it_backend(self):
        if self.sonichost.is_multi_asic:
            sub_role_cmd = 'sudo sonic-cfggen -d  -v DEVICE_METADATA.localhost.sub_role -n {}'.format(self.namespace)
            sub_role = self.sonichost.shell(sub_role_cmd)["stdout_lines"][0].decode("utf-8")
            if sub_role is not None and sub_role.lower() == 'backend':
                return True
        return False

    def get_docker_cmd(self, cmd, container_name):
        if self.sonichost.is_multi_asic:
            return "sudo docker exec {}{} {}".format(container_name, self.asic_index, cmd)
        return cmd

    def get_asic_namespace(self):
        if self.sonichost.is_multi_asic:
            return self.namespace
        return DEFAULT_NAMESPACE

    def bgp_facts(self, *module_args, **complex_args):
        """ Wrapper method for bgp_facts ansible module.
        If number of asics in SonicHost are more than 1, then add 'instance_id' param for this Asic

        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Returns:
            if SonicHost has only 1 asic, then return the bgp_facts for the global namespace, else bgp_facts for the bgp instance for my asic_index.
        """
        if self.sonichost.facts['num_asic'] != 1:
            complex_args['instance_id'] = self.asic_index
        return self.sonichost.bgp_facts(*module_args, **complex_args)

    def config_facts(self, *module_args, **complex_args):
        """ Wrapper method for config_facts ansible module.
        If number of asics in SonicHost are more than 1, then add 'namespace' param for this Asic
        If 'host' is not specified in complex_args, add it - as it is a mandatory param for the config_facts module

        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Returns:
            if SonicHost has only 1 asic, then return the config_facts for the global namespace, else config_facts for namespace for my asic_index.
        """
        if 'host' not in complex_args:
            complex_args['host'] = self.sonichost.hostname
        if self.sonichost.is_multi_asic:
            complex_args['namespace'] = self.namespace
        return self.sonichost.config_facts(*module_args, **complex_args)

    def show_interface(self, *module_args, **complex_args):
        """Wrapper for the ansible module 'show_interface'

        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Returns:
            [dict]: [the output of show interface status command]
        """
        complex_args['namespace'] = self.namespace
        return self.sonichost.show_interface(*module_args, **complex_args)

    def show_ip_interface(self, *module_args, **complex_args):
        """Wrapper for the ansible module 'show_ip_interface'

        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Returns:
            [dict]: [the output of show interface status command]
        """
        complex_args['namespace'] = self.namespace
        return self.sonichost.show_ip_interface(*module_args, **complex_args)

    def run_redis_cli_cmd(self, redis_cmd):
        if self.namespace != DEFAULT_NAMESPACE:
            redis_cli = "/usr/bin/redis-cli"
            cmd = "sudo ip netns exec {} {} {}".format(self.namespace, redis_cli,redis_cmd)
            return self.sonichost.command(cmd)
        # for single asic platforms there are not Namespaces, so the redis-cli command is same the DUT host
        return self.sonichost.run_redis_cli_cmd(redis_cmd)

    def get_ip_route_info(self, dstip):
        return self.sonichost.get_ip_route_info(dstip, self.cli_ns_option)

    @property
    def os_version(self):
        return self.sonichost.os_version

    def interface_facts(self, *module_args, **complex_args):
        """Wrapper for the interface_facts ansible module.
        
        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Returns:
            For a single ASIC platform, the namespace = DEFAULT_NAMESPACE, will retrieve interface facts for the global namespace
            In case of multi-asic, if namespace = <ns>, will retrieve interface facts for that namespace.
        """
        complex_args['namespace'] = self.namespace
        return self.sonichost.interface_facts(*module_args, **complex_args)


    def stop_service(self, service):
        if not self.sonichost.is_multi_asic:
            service_name = service
            docker_name = service
        else:
            service_name = self._MULTI_ASIC_SERVICE_NAME.format(
                service, self.asic_index
            )
            docker_name = self._MULTI_ASIC_DOCKER_NAME.format(
                service, self.asic_index
            )
        return self.sonichost.stop_service(service_name, docker_name)

    def delete_container(self, service):
        if self.sonichost.is_multi_asic:
            service = self._MULTI_ASIC_DOCKER_NAME.format(
                service, self.asic_index
            )
        return self.sonichost.delete_container(service)

    def is_container_present(self, service):
        if self.sonichost.is_multi_asic:
            service = self._MULTI_ASIC_DOCKER_NAME.format(
                service, self.asic_index
            )
        return self.sonichost.is_container_present(service)

    def is_service_running(self, service_name, docker_name):
        if self.sonichost.is_multi_asic:
            docker_name = self._MULTI_ASIC_DOCKER_NAME.format(
                docker_name, self.asic_index
            )
        return self.sonichost.is_service_running(service_name, docker_name)


class MultiAsicSonicHost(object):
    """ This class represents a Multi-asic SonicHost It has two attributes:
    sonic_host: a SonicHost instance. This object is for interacting with the SONiC host through pytest_ansible.
    asics: a list of SonicAsic instances.

    The 'duthost' fixture will return an instance of a MultiAsicSonicHost.
    So, even a single asic pizza box is represented as a MultiAsicSonicHost with 1 SonicAsic.
    """

    _DEFAULT_SERVICES = ["pmon", "snmp", "lldp", "database"]

    def __init__(self, ansible_adhoc, hostname):
        """ Initializing a MultiAsicSonicHost.

        Args:
            ansible_adhoc : The pytest-ansible fixture
            hostname: Name of the host in the ansible inventory
        """
        self.sonichost = SonicHost(ansible_adhoc, hostname)
        self.asics = [SonicAsic(self.sonichost, asic_index) for asic_index in range(self.sonichost.facts["num_asic"])]

        # Get the frontend and backend asics in a multiAsic device.
        self.frontend_asics = []
        self.backend_asics = []
        if self.sonichost.is_multi_asic:
            for asic in self.asics:
                if asic.is_it_frontend():
                    self.frontend_asics.append(asic)
                elif asic.is_it_backend():
                    self.backend_asics.append(asic)

        self.critical_services_tracking_list()

    def critical_services_tracking_list(self):
        """Get the list of services running on the DUT
           The services on the sonic devices are:
              - services running on the host
              - services which are replicated per asic
            Returns:
            [list]: list of the services running the device
        """
        service_list = []
        service_list+= self._DEFAULT_SERVICES
        for asic in self.asics:
            service_list += asic.get_critical_services()
        self.sonichost.reset_critical_services_tracking_list(service_list)

    def get_default_critical_services_list(self):
        return self._DEFAULT_SERVICES

    def _run_on_asics(self, *module_args, **complex_args):
        """ Run an asible module on asics based on 'asic_index' keyword in complex_args

        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Raises:
            ValueError:  if asic_index is specified and it is neither an int or string 'all'.
            ValueError: if asic_index is specified and is an int, but greater than number of asics in the SonicHost

        Returns:
            if asic_index is not specified, then we return the output of the ansible module on global namespace (using SonicHost)
            else
                if asic_index is an int, the output of the ansible module on that asic namespace
                    - for single asic SonicHost this would still be the same as the ansible module on the global namespace
                else if asic_index is string 'all', then a list of ansible module output for all the asics on the SonicHost
                    - for single asic, this would be a list of size 1.
        """
        if "asic_index" not in complex_args:
            # Default ASIC/namespace
            return getattr(self.sonichost, self.multi_asic_attr)(*module_args, **complex_args)
        else:
            asic_complex_args = copy.deepcopy(complex_args)
            asic_index = asic_complex_args.pop("asic_index")
            if type(asic_index) == int:
                # Specific ASIC/namespace
                if self.sonichost.facts['num_asic'] == 1:
                    if asic_index != 0:
                        raise ValueError("Trying to run module '{}' against asic_index '{}' on a single asic dut '{}'".format(self.multi_asic_attr, asic_index, self.sonichost.hostname))
                return getattr(self.asics[asic_index], self.multi_asic_attr)(*module_args, **asic_complex_args)
            elif type(asic_index) == str and asic_index.lower() == "all":
                # All ASICs/namespace
                return [getattr(asic, self.multi_asic_attr)(*module_args, **asic_complex_args) for asic in self.asics]
            else:
                raise ValueError("Argument 'asic_index' must be an int or string 'all'.")

    def get_frontend_asic_ids(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_ASIC_ID]

        return [asic.asic_index for asic in self.frontend_asics]

    def get_frontend_asic_namespace_list(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_NAMESPACE]

        return [asic.namespace for asic in self.frontend_asics]

    def get_backend_asic_ids(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_ASIC_ID]

        return [asic.asic_index for asic in self.backend_asics]

    def get_backend_asic_namespace_list(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_NAMESPACE]

        return [asic.namespace for asic in self.backend_asics]

    def get_asic_ids(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_ASIC_ID]

        return [asic.asic_index for asic in self.asics]

    def get_asic_namespace_list(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_NAMESPACE]

        return [asic.namespace for asic in self.asics]

    def get_asic_id_from_namespace(self, namespace):
        if self.sonichost.facts['num_asic'] == 1:
            return DEFAULT_ASIC_ID

        for asic in self.asics:
            if namespace == asic.namespace:
                return asic.asic_index

        # Raise an error if we reach here
        raise ValueError("Invalid namespace '{}' passed as input".format(namespace))

    def get_namespace_from_asic_id(self, asic_id):
        if self.sonichost.facts['num_asic'] == 1:
            return DEFAULT_NAMESPACE

        for asic in self.asics:
            if asic_id == asic.asic_index:
                return asic.namespace

        # Raise an error if we reach here
        raise ValueError("Invalid asic_id '{}' passed as input".format(asic_id))

    def get_vtysh_cmd_for_namespace(self, cmd, namespace):
        asic_id = self.get_asic_id_from_namespace(namespace)
        if asic_id == DEFAULT_ASIC_ID:
            return cmd
        ns_cmd = cmd.replace('vtysh', 'vtysh -n {}'.format(asic_id))
        return ns_cmd

    def __getattr__(self, attr):
        """ To support calling an ansible module on a MultiAsicSonicHost.

        Args:
            attr: attribute to get

        Returns:
            if attr doesn't start with '_' and is a method of SonicAsic, attr will be ansible module that has dependency on ASIC,
                return the output of the ansible module on asics requested - using _run_on_asics method.
            else
                return the attribute from SonicHost.
        """
        sonic_asic_attr = getattr(SonicAsic, attr, None)
        if not attr.startswith("_") and sonic_asic_attr and callable(sonic_asic_attr):
            self.multi_asic_attr = attr
            return self._run_on_asics
        else:
            return getattr(self.sonichost, attr)  # For backward compatibility

    def get_asic(self, asic_id):
        if asic_id == DEFAULT_ASIC_ID:
            return self.asics[0]
        return self.asics[asic_id]

    def stop_service(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.stop_service(service, service)

        for asic in self.asics:
            asic.stop_service(service)

    def delete_container(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.delete_container(service)

        for asic in self.asics:
            asic.delete_container(service)

    def is_container_present(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.is_container_present(service)

        for asic in self.asics:
            if asic.is_container_present(service):
                return True

        return False

    def is_bgp_state_idle(self):
        return self.sonichost.is_bgp_state_idle()

    def is_service_running(self, service_name, docker_name=None):
        docker_name = service_name if docker_name is None else docker_name

        if docker_name in self._DEFAULT_SERVICES:
            return self.sonichost.is_service_running(service_name, docker_name)

        for asic in self.asics:
            if not asic.is_service_running(service_name, docker_name):
                return False

        return True


class DutHosts(object):
    """ Represents all the DUTs (nodes) in a testbed. class has 3 important attributes:
    nodes: List of all the MultiAsicSonicHost instances for all the SONiC nodes (or cards for chassis) in a multi-dut testbed
    frontend_nodes: subset of nodes and holds list of MultiAsicSonicHost instances for DUTs with front-panel ports (like linecards in chassis
    supervisor_nodes: subset of nodes and holds list of MultiAsicSonicHost instances for supervisor cards.
    """
    class _Nodes(list):
        """ Internal class representing a list of MultiAsicSonicHosts """
        def _run_on_nodes(self, *module_args, **complex_args):
            """ Delegate the call to each of the nodes, return the results in a dict."""
            return {node.hostname: getattr(node, self.attr)(*module_args, **complex_args) for node in self}

        def __getattr__(self, attr):
            """ To support calling ansible modules on a list of MultiAsicSonicHost
            Args:
                attr: attribute to get

            Returns:
               a dictionary with key being the MultiAsicSonicHost's hostname, and value being the output of ansible module
               on that MultiAsicSonicHost
            """
            self.attr = attr
            return self._run_on_nodes

        def __eq__(self, o):
            """ To support eq operator on the DUTs (nodes) in the testbed """
            return list.__eq__(o)

        def __ne__(self, o):
            """ To support ne operator on the DUTs (nodes) in the testbed """
            return list.__ne__(o)

        def __hash__(self):
            """ To support hash operator on the DUTs (nodes) in the testbed """
            return list.__hash__()

    def __init__(self, ansible_adhoc, tbinfo):
        """ Initialize a multi-dut testbed with all the DUT's defined in testbed info.

        Args:
            ansible_adhoc: The pytest-ansible fixture
            tbinfo - Testbed info whose "duts" holds the hostnames for the DUT's in the multi-dut testbed.

        """
        # TODO: Initialize the nodes in parallel using multi-threads?
        self.nodes = self._Nodes([MultiAsicSonicHost(ansible_adhoc, hostname) for hostname in tbinfo["duts"]])
        self.supervisor_nodes = self._Nodes([node for node in self.nodes if node.is_supervisor_node()])
        self.frontend_nodes = self._Nodes([node for node in self.nodes if node.is_frontend_node()])

    def __getitem__(self, index):
        """To support operations like duthosts[0] and duthost['sonic1_hostname']

        Args:
            index (int or string): Index or hostname of a duthost.

        Raises:
            KeyError: Raised when duthost with supplied hostname is not found.
            IndexError: Raised when duthost with supplied index is not found.

        Returns:
            [MultiAsicSonicHost]: Returns the specified duthost in duthosts. It is an instance of MultiAsicSonicHost.
        """
        if type(index) == int:
            return self.nodes[index]
        elif type(index) in [ str, unicode ]:
            for node in self.nodes:
                if node.hostname == index:
                    return node
            raise KeyError("No node has hostname '{}'".format(index))
        else:
            raise IndexError("Bad index '{}' type {}".format(index, type(index)))

    # Below method are to support treating an instance of DutHosts as a list
    def __iter__(self):
        """ To support iteration over all the DUTs (nodes) in the testbed"""
        return iter(self.nodes)

    def __len__(self):
        """ To support length of the number of DUTs (nodes) in the testbed """
        return len(self.nodes)

    def __eq__(self, o):
        """ To support eq operator on the DUTs (nodes) in the testbed """
        return self.nodes.__eq__(o)

    def __ne__(self, o):
        """ To support ne operator on the DUTs (nodes) in the testbed """
        return self.nodes.__ne__(o)

    def __hash__(self):
        """ To support hash operator on the DUTs (nodes) in the testbed """
        return self.nodes.__hash__()

    def __getattr__(self, attr):
        """To support calling ansible modules directly on all the DUTs (nodes) in the testbed
         Args:
            attr: attribute to get

        Returns:
            a dictionary with key being the MultiAsicSonicHost's hostname, and value being the output of ansible module
            on that MultiAsicSonicHost
        """
        return getattr(self.nodes, attr)

    def config_facts(self, *module_args, **complex_args):
        result = {}
        for node in self.nodes:
            complex_args['host'] = node.hostname
            result[node.hostname] = node.config_facts(*module_args, **complex_args)['ansible_facts']
        return result


class FanoutHost(object):
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
            self.host = SonicHost(ansible_adhoc, hostname,
                                  shell_user=shell_user,
                                  shell_passwd=shell_passwd)
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

            host_port is a encoded string of <host name>|<port name>,
            e.g. sample_host|Ethernet0.
        """
        self.host_to_fanout_port_map[host_port]   = fanout_port
        self.fanout_to_host_port_map[fanout_port] = host_port

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        return self.host.exec_template(ansible_root, ansible_playbook, inventory, **kwargs)
