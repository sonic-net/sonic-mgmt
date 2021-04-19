import logging
import socket

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE, NAMESPACE_PREFIX
from tests.common.errors import RunAnsibleModuleFail
from tests.common.platform.ssh_utils import ssh_authorize_local_user

logger = logging.getLogger(__name__)


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
        self.ns_arg = ""
        if self.sonichost.is_multi_asic:
            self.namespace = "{}{}".format(NAMESPACE_PREFIX, self.asic_index)
            self.cli_ns_option = "-n {}".format(self.namespace)
            self.ns_arg = "sudo ip netns exec {} ".format(self.namespace)
        else:
            # set the namespace to DEFAULT_NAMESPACE(None) for single asic
            self.namespace = DEFAULT_NAMESPACE
            self.cli_ns_option = ""
        self.ports = None
        self.queue_oid = set()

        self.sonic_db_cli = "sonic-db-cli {}".format(self.cli_ns_option)
        self.ip_cmd = "sudo ip {}".format(self.cli_ns_option)

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
            return self.sonichost.command(cmd, verbose=False)
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

    def get_docker_name(self, service):
        if (not self.sonichost.is_multi_asic or
            service not in self._DEFAULT_ASIC_SERVICES
        ):
            return service

        return self._MULTI_ASIC_DOCKER_NAME.format(service, self.asic_index)

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

    def is_container_running(self, service):
        if self.sonichost.is_multi_asic:
            service = self._MULTI_ASIC_DOCKER_NAME.format(
                service, self.asic_index
            )
        return self.sonichost.is_container_running(service)

    def is_service_running(self, service_name, docker_name):
        if self.sonichost.is_multi_asic:
            docker_name = self._MULTI_ASIC_DOCKER_NAME.format(
                docker_name, self.asic_index
            )
        return self.sonichost.is_service_running(service_name, docker_name)

    def ping_v4(self, ipv4, count=1):
        """
        Returns 'True' if ping to IP address works, else 'False'
        Args:
            IPv4 address

        Returns:
            True or False
        """
        try:
            socket.inet_aton(ipv4)
        except socket.error:
            raise Exception("Invalid IPv4 address {}".format(ipv4))

        try:
            self.sonichost.shell("{}ping -q -c{} {} > /dev/null".format(
                self.ns_arg, count, ipv4
            ))
        except RunAnsibleModuleFail:
            return False
        return True

    def is_backend_portchannel(self, port_channel):
        mg_facts = self.sonichost.minigraph_facts(
            host = self.sonichost.hostname
        )['ansible_facts']
        if port_channel in mg_facts["minigraph_portchannels"]:
            port_name = next(
                iter(
                    mg_facts["minigraph_portchannels"][port_channel]["members"]
                )
            )
            if "Ethernet-BP" not in port_name:
                return False
        return True

    def get_active_ip_interfaces(self):
        """
        Return a dict of active IP (Ethernet or PortChannel) interfaces, with
        interface and peer IPv4 address.

        Returns:
            Dict of Interfaces and their IPv4 address
        """
        ip_ifs = self.show_ip_interface()["ansible_facts"]["ip_interfaces"]
        return self.sonichost.active_ip_interfaces(ip_ifs, self.ns_arg)

    def bgp_drop_rule(self, ip_version, state="present"):
        """
        Programs iptable rule to either add or remove DROP for
        BGP control frames

        Args:
            ip_version: IPv4 or IPv6
            state = "present" or "absent" (add or remove)

        Returns:
            None
        """
        ipcmd = "iptables" if ip_version == "ipv4" else "ip6tables"
        run_opt = "-I INPUT 1" if state == "present" else "-D INPUT"
        check_opt = "-C INPUT"
        cmd = (
            "{}/sbin/{} -t filter {{}} -p tcp -j DROP --destination-port bgp"
        ).format(self.ns_arg, ipcmd)

        check_cmd = cmd.format(check_opt)
        run_cmd = cmd.format(run_opt)

        output = "Rule {} needs no action".format(run_cmd)
        try:
            self.sonichost.command(check_cmd)
            if state == "absent":
                output = self.sonichost.command(run_cmd)
        except RunAnsibleModuleFail as e:
            if state == "present":
                output = self.sonichost.command(run_cmd)

        logger.debug(output)

    def remove_ssh_tunnel_sai_rpc(self):
        """
        Removes any ssh tunnels if present created for syncd RPC communication

        Returns:
            None
        """
        if not self.sonichost.is_multi_asic:
            return
        return self.sonichost.remove_ssh_tunnel_sai_rpc()

    def create_ssh_tunnel_sai_rpc(self):
        """
        Create ssh tunnel between host and ASIC namespace on syncd RPC
        port. This is used to forward thrift calls to and from the syncd
        running on this ASIC.

        Returns:
            None
        """
        if not self.sonichost.is_multi_asic:
            return
        self.remove_ssh_tunnel_sai_rpc()
        ssh_authorize_local_user(self.sonichost)

        ip_ifs = self.show_ip_interface(
            namespace=self.namespace
        )["ansible_facts"]

        # create SSH tunnel to ASIC namespace
        ns_docker_if_ipv4 = ip_ifs["ip_interfaces"]["eth0"]["ipv4"]
        try:
            socket.inet_aton(ns_docker_if_ipv4)
        except socket.error:
            raise Exception("Invalid V4 address {}".format(ns_docker_if_ipv4))

        self.sonichost.shell(
            ("ssh -o StrictHostKeyChecking=no -fN"
             " -L *:9092:{}:9092 localhost"
            ).format(ns_docker_if_ipv4)
        )

    def command(self, cmdstr):
        """
            Prepend 'ip netns' option for commands meant for this ASIC

            Args:
                cmdstr
            Returns:
                Output from the ansible command module
        """
        if not self.sonichost.is_multi_asic or self.namespace == DEFAULT_NAMESPACE:
            return self.sonichost.command(cmdstr)

        cmdstr = "sudo ip netns exec {} {}".format(self.namespace, cmdstr)

        return self.sonichost.command(cmdstr)

    def run_redis_cmd(self, argv=[]):
        """
        Runs redis command on DUT.

        Args:
            argv (list): List of command options to run on duthost

        Returns:
            stdout (list): List of stdout lines spewed by the invoked command
        """
        if self.sonichost.is_multi_asic:
            db_docker_instance = self.get_docker_name("database")
            argv = ["docker", "exec", db_docker_instance] + argv

        result = self.sonichost.shell(argv=argv)
        pytest_assert(
            result["rc"] == 0,
            "Failed to run Redis command '{0}' with error '{1}'".format(
                " ".join(map(str, argv)), result["stderr"]
            )
        )

        return result["stdout_lines"]

    def port_exists(self, port):
        """
        Check if a given port exists in ASIC instance
        Args:
            port: port ID
        Returns:
            True or False
        """
        if self.ports is not None:
            return port in self.ports

        if_db = self.show_interface(
            command="status"
        )["ansible_facts"]["int_status"]

        self.ports = set(if_db.keys())
        return port in self.ports

    def get_queue_oid(self, port, queue_num):
        """
        Get the queue OID of given port and queue number. The queue OID is
        saved for the purpose of returning the ASIC instance of the
        queue OID

        Args:
            port: Port ID
            queue_num: Queue
        Returns:
            Queue OID
        """
        redis_cmd = [
            "redis-cli", "-n", "2", "HGET", "COUNTERS_QUEUE_NAME_MAP",
            "{}:{}".format(port, queue_num)
        ]
        queue_oid = next(iter(self.run_redis_cmd(redis_cmd)), None)

        pytest_assert(
            queue_oid != None,
            "Queue OID not found for port {}, queue {}".format(
                port, queue_num
            )
        )
        # save the queue OID, will be used to retrieve ASIC instance for
        # this queue's OID
        self.queue_oid.add(queue_oid)
        return queue_oid

    def get_extended_minigraph_facts(self, tbinfo):
          return self.sonichost.get_extended_minigraph_facts(tbinfo, self.namespace)

    def startup_interface(self, interface_name):
        return self.sonichost.shell("sudo config interface {ns} startup {intf}".
                                    format(ns=self.cli_ns_option, intf=interface_name))

    def shutdown_interface(self, interface_name):
        return self.sonichost.shell("sudo config interface {ns} shutdown {intf}".
                                    format(ns=self.cli_ns_option, intf=interface_name))

    def config_ip_intf(self, interface_name, ip_address, op):
        return self.sonichost.shell("sudo config interface {ns} ip {op} {intf} {ip}"
                          .format(ns=self.cli_ns_option,
                                  op=op,
                                  intf=interface_name,
                                  ip=ip_address))

    def config_portchannel_member(self, pc_name, interface_name, op):
        return self.sonichost.shell("sudo config portchannel {ns} member {op} {pc} {intf}"
                          .format(ns=self.cli_ns_option,
                                  op=op,
                                  pc=pc_name,
                                  intf=interface_name))

    def switch_arptable(self, *module_args, **complex_args):
        complex_args['namespace'] = self.namespace
        return self.sonichost.switch_arptable(*module_args, **complex_args)

    def shell(self, *module_args, **complex_args):
        return self.sonichost.shell(*module_args, **complex_args)
