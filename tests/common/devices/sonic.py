
import ipaddress
import json
import logging
import os
import re

from collections import defaultdict
from datetime import datetime

from ansible import constants
from ansible.plugins.loader import connection_loader

from tests.common.devices.base import AnsibleHostBase
from tests.common.helpers.dut_utils import is_supervisor_node
from tests.common.cache import cached
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)


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

    def is_container_running(self, service):
        """
        Checks where a container exits.

        @param service: Container name

        Returns:
            True or False
        """
        status = self.command(
            "docker ps -f name={}".format(service), module_ignore_errors=True
        )

        if len(status["stdout_lines"]) > 1:
            logging.info("container {} status: {}".format(
                service, status["stdout"])
            )
        else:
            logging.info("container {} is not running".format(service))

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

        services_status_result = self.shell("sudo monit status", module_ignore_errors=True, verbose=False)

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

    def get_namespace_ids(self, container_name):
        """
        Gets ids of namespace where the container should reside in.

        Returns:
            A list contains ids of namespace such as [DEFAULT_ASIC_ID, "0", "1", ...]}
        """
        has_global_scope = ""
        has_per_asic_scope = ""
        namespace_ids = []

        num_asics = int(self.facts["num_asic"])
        command_config_entry = "sonic-db-cli CONFIG_DB hgetall \"FEATURE|{}\"".format(container_name)
        command_output = self.shell(command_config_entry)
        exit_code = command_output["rc"]
        if exit_code != 0:
            return namespace_ids, False

        config_info = command_output["stdout_lines"]
        for index, item in enumerate(config_info):
            if item == "has_global_scope":
                has_global_scope = config_info[index + 1]
            elif item == "has_per_asic_scope":
                has_per_asic_scope = config_info[index + 1]

        if num_asics > 1:
            if has_global_scope == "True":
                namespace_ids.append(DEFAULT_ASIC_ID)
            if has_per_asic_scope == "True":
                for asic_id in range(0, num_asics):
                    namespace_ids.append(str(asic_id))
        else:
            namespace_ids.append(DEFAULT_ASIC_ID)

        return namespace_ids, True


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
                    if str(index) in map:
                        mg_facts['minigraph_ptf_indices'][port] = map[str(index)]
        except (ValueError, KeyError):
            pass

        return mg_facts

    def run_redis_cli_cmd(self, redis_cmd):
        cmd = "/usr/bin/redis-cli {}".format(redis_cmd)
        return self.command(cmd, verbose=False)

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
        elif "Broadcom Limited Device b980" in output:
            asic = "th3"

        return asic

    def get_running_config_facts(self):
        return self.config_facts(host=self.hostname, source='running', verbose=False)['ansible_facts']

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
        self.command(
            "docker rm {}".format(service), module_ignore_errors=True
        )

    def is_bgp_state_idle(self):
        """
        Check if all BGP peers are in IDLE state.

        Returns:
            True or False
        """
        bgp_summary = self.command("show ip bgp summary")["stdout_lines"]

        idle_count = 0
        expected_idle_count = 0
        bgp_monitor_count = 0
        for line in bgp_summary:
            if "Idle (Admin)" in line:
                idle_count += 1

            if "Total number of neighbors" in line:
                tokens = line.split()
                expected_idle_count = int(tokens[-1])

            if "BGPMonitor" in line:
                bgp_monitor_count += 1

        return idle_count == (expected_idle_count - bgp_monitor_count)

    def is_service_running(self, service_name, docker_name):
        """
        Check if service is running. Service can be a service within a docker

        Args:
            service name, docker name
        Returns:
            True or False
        """
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

    def remove_ssh_tunnel_sai_rpc(self):
        """
        Removes any ssh tunnels if present created for syncd RPC communication

        Returns:
            None
        """
        try:
            pid_list = self.shell(
                'pgrep -f "ssh -o StrictHostKeyChecking=no -fN -L \*:9092"'
            )["stdout_lines"]
        except RunAnsibleModuleFail:
            return
        for pid in pid_list:
            self.shell("kill {}".format(pid))

    def get_up_ip_ports(self):
        """
        Get a list for all up ip interfaces
        """
        up_ip_ports = []
        ip_intf_facts = self.show_ip_interface()['ansible_facts']['ip_interfaces']
        for intf in ip_intf_facts:
            try:
                if ip_intf_facts[intf]['oper_state'] == 'up':
                    up_ip_ports.append(intf)
            except KeyError:
                pass
        return up_ip_ports
