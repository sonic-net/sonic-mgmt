"""
Classes for various devices that may be used in testing.

There are other options for interacting with the devices used in testing, for example netmiko, fabric.
We have a big number of customized ansible modules in the sonic-mgmt/ansible/library folder. To reused these
modules, we have no other choice, at least for interacting with SONiC, localhost and PTF.

We can consider using netmiko for interacting with the VMs used in testing.
"""
import json
import logging
from multiprocessing import Process, Queue

from errors import RunAnsibleModuleFail
from errors import UnsupportedAnsibleModule

class AnsibleHostBase(object):
    """
    @summary: The base class for various objects.

    This class filters an object from the ansible_adhoc fixture by hostname. The object can be considered as an
    ansible host object although it is not under the hood. Anyway, we can use this object to run ansible module
    on the host.
    """

    def __init__(self, ansible_adhoc, hostname):
        if hostname == 'localhost':
            self.host = ansible_adhoc(inventory='localhost', connection='local', host_pattern=hostname)[hostname]
        else:
            self.host = ansible_adhoc(become=True)[hostname]
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
            q = Queue()
            def run_module(queue, module_args, complex_args):
                res = self.module(*module_args, **complex_args)
                q.put(res[self.hostname])
            p = Process(target=run_module, args=(q, module_args, complex_args))
            p.start()
            return p, q

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

        The last step in the starting script of all SONiC services is to run "docker wait <service_name>". This command
        will not exit unless the docker container of the service is stopped. We use this trick to determine whether
        a SONiC service has completed starting.

        @param service: Name of the SONiC service
        """
        try:
            output = self.command('pgrep -f "docker wait %s"' % service)
            if output["stdout_lines"]:
                return True
            else:
                return False
        except:
            return False

    def critical_services_fully_started(self):
        """
        @summary: Check whether all the SONiC critical services have started
        """
        result = {}
        for service in self.CRITICAL_SERVICES:
            result[service] = self.is_service_fully_started(service)

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
