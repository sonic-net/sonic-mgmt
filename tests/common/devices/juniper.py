import re
import time
import json
import logging
from paramiko import SSHClient, AutoAddPolicy
from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


class JuniperHost(AnsibleHostBase):
    """
    @summary: Class for Juniper host
    """

    def __init__(self, ansible_adhoc, hostname, ansible_user, ansible_passwd):
        """Initialize an object for interacting with juniper device using ansible modules
        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the juniper device
            ansible_user (string): Username for accessing the juniper CLI interface
            ansible_passwd (string): Password for the ansible_user
        """
        self.ansible_user = ansible_user
        self.ansible_passwd = ansible_passwd
        self._session_type = "netconf"
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)
        # Reserved for execute ansible commands in local device
        self.localhost = ansible_adhoc(inventory="localhost", connection="local", host_pattern="localhost")[
            "localhost"
        ]

    def __getattr__(self, module_name):
        if module_name.startswith("junos_"):
            evars = {
                "ansible_connection": self._session_type,
                "ansible_network_os": module_name.split("_", 1)[0],
                "ansible_ssh_user": self.ansible_user,
                "ansible_ssh_pass": self.ansible_passwd,
            }
        else:
            raise Exception("Does not have module: {}".format(module_name))
        self.host.options["variable_manager"].extra_vars.update(evars)
        return super(JuniperHost, self).__getattr__(module_name)

    def __str__(self):
        return "<JuniperHost {}>".format(self.hostname)

    def commands(self, session_type="netconf", *args, **kwargs):
        self._session_type = session_type
        output = self.junos_command(*args, **kwargs)
        if self._session_type != "netconf":
            self._session_type = "netconf"
        return output

    def config(self, *args, **kwargs):
        return self.junos_config(*args, **kwargs)

    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        """
        This function will run show command on the junos and get data in json and return json format dict.
        """
        try:
            cmd_result = self.commands(commands=[command], display="json")
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(cmd_result["stdout"][0], lookup_key, lookup_val)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(cmd_result["stdout"][0], lookup_key)
            else:
                return cmd_result["stdout"][0]
        except Exception as e:
            return {"error": e}

    def extract_val_from_json(self, json_data, lookup_key):
        """
        This function only support juniper command json output!
        Based on the lookup_key provided, and return a list of values from json_data
        example input json_data:
        {
            "lldp-neighbors-information" : [
            {
                "attributes" : {"junos:style" : "brief"},
                "lldp-neighbor-information" : [
                {
                    "lldp-local-port-id" : [
                    {
                        "data" : "et-0/0/28:1"
                    }
                    ],
                    "lldp-local-parent-interface-name" : [
                    {
                        "data" : "ae61"
                    }
                    ]
                },
                {
                    "lldp-local-port-id" : [
                    {
                        "data" : "et-0/0/28:0"
                    }
                    ],
                    "lldp-local-parent-interface-name" : [
                    {
                        "data" : "ae61"
                    }
                    ]
                }
                ]
            }
            ]
        }
        lookup_key: "lldp-local-port-id"
        example output:
        [[{"data" : "et-0/0/28:1"}], [{"data" : "et-0/0/28:0"}]]
        Based on the example, you can see the function is trying to narrow down the data that you are looking for
        """
        result = []

        def help(json_data, lookup_key, result):
            if isinstance(json_data, dict):
                for k, v in json_data.items():
                    if k == lookup_key:
                        result.append(v)
                    elif isinstance(v, (list, dict)):
                        sub_result = help(v, lookup_key, result)
                        if sub_result:
                            result.append(sub_result)
            elif isinstance(json_data, list):
                for ele in json_data:
                    if isinstance(ele, (list, dict)):
                        sub_result = help(ele, lookup_key, result)
                        if sub_result:
                            result.append(sub_result)

        help(json_data, lookup_key, result)
        return result

    def extract_key_val_pair_from_json(self, json_data, lookup_key, lookup_val):
        """
        This function only support juniper command json output!
        Based on the lookup_key and lookup_val provided, and return all of same level json_data
        example input json_data:
        {
            "lldp-neighbors-information" : [
            {
                "attributes" : {"junos:style" : "brief"},
                "lldp-neighbor-information" : [
                {
                    "lldp-local-port-id" : [
                    {
                        "data" : "et-0/0/28:1"
                    }
                    ],
                    "lldp-local-parent-interface-name" : [
                    {
                        "data" : "ae61"
                    }
                    ]
                },
                {
                    "lldp-local-port-id" : [
                    {
                        "data" : "et-0/0/28:0"
                    }
                    ],
                    "lldp-local-parent-interface-name" : [
                    {
                        "data" : "ae61"
                    }
                    ]
                }
                ]
            }
            ]
        }
        lookup_key: "lldp-local-port-id", lookup_value: "et-0/0/28:1"
        example output:
        [
           "lldp-local-port-id" : [
           {
               "data" : "et-0/0/28:1"
           }
           ],
           "lldp-local-parent-interface-name" : [
           {
               "data" : "ae61"
           }
           ]
        ]
        Based on the example output, you can use lookup_key and lookup_value find out related data
        """
        result = []

        def help(json_data, lookup_key, lookup_val, result):
            if isinstance(json_data, dict):
                for k, v in json_data.items():
                    if k == lookup_key and v[0]["data"] == lookup_val:
                        result.append(json_data)
                    elif isinstance(v, (list, dict)):
                        sub_result = help(v, lookup_key, lookup_val, result)
                        if sub_result:
                            result.append(sub_result)
            elif isinstance(json_data, list):
                for ele in json_data:
                    if isinstance(ele, (list, dict)):
                        sub_result = help(ele, lookup_key, lookup_val, result)
                        if sub_result:
                            result.append(sub_result)

        help(json_data, lookup_key, lookup_val, result)
        return result

    def capture_prechange_config(self, prechange_filename):
        try:
            file_path = "../../" + prechange_filename
            command = "show configuration | no-more"
            savemsg = self.commands(session_type="network_cli", commands=[command], display="text")
            with open(file_path, "w") as f:
                f.write(savemsg["stdout"][0])
            # restore session type to default value which is netconf
            return True, savemsg
        except Exception as e:
            return False, str(e)

    def load_prechange_config(self, prechange_filename):
        try:
            file_path = "../../" + prechange_filename
            commitmsg = self.config(src=file_path, comment="rollback config", update="override", src_format="text")
            return True, commitmsg
        except Exception as e:
            return False, "Failed to load perchange config due to {}".format(str(e))

    def get_prefix_nh_info(self, prefix, table="inet.0"):
        """
        :param prefix: prefix learned from remote device
        :return: Boolean, dict include next-hop ip, interface, label_info, lsp_name
        """
        try:
            nh_result = []
            command = "show route {} table {} active-path exact".format(prefix, table)
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                prefix_info = json_output["stdout"][0]["route-information"][0]["route-table"][0]["rt"][0]
                if prefix in prefix_info["rt-destination"][0]["data"]:
                    nh_info = {"nh_ip": None, "nh_interface": None, "nh_label_info": None, "nh_lsp_name": None}
                    nh_data = prefix_info["rt-entry"][0]["nh"]
                    for nh in nh_data:
                        if "to" in nh:
                            nh_info["nh_ip"] = nh["to"][0]["data"]
                        if "via" in nh:
                            nh_info["nh_interface"] = nh["via"][0]["data"]
                        if "lsp-name" in nh:
                            nh_info["nh_lsp_name"] = nh["lsp-name"][0]["data"]
                        if "mpls-label" in nh:
                            nh_info["nh_lsp_name"] = nh["lsp-name"][0]["data"]
                        nh_result.append(nh_info)
            if nh_result:
                return True, nh_result
            else:
                return False, json_output
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to get nh info due to {}".format(str(e))

    def change_isis_interface_metric(self, metric, interface, level="2"):
        try:
            if ".0" not in interface:
                interface += ".0"
            configs = ["set protocols isis interface {} level {} metric {}".format(interface, level, metric)]
            commitmsg = self.config(
                lines=configs, comment="change isis interface {} metric to {}".format(interface, metric)
            )
            return True, commitmsg
        except Exception as e:
            return False, "Failed to change isis metric on interface {} due to {}".format(interface, str(e))

    def disable_inteface(self, interface):
        try:
            configs = ["set interfaces {} disable".format(interface)]
            commitmsg = self.config(lines=configs, comment="disable interface {}".format(interface))
            return True, commitmsg
        except Exception as e:
            return False, "Failed to disable interface {} due to {}".format(interface, str(e))

    def enable_inteface(self, interface):
        try:
            configs = ["del interfaces {} disable".format(interface)]
            commitmsg = self.config(lines=configs, comment="enable interface {}".format(interface))
            return True, commitmsg
        except Exception as e:
            return False, "Failed to disable interface {} due to {}".format(interface, str(e))

    """
    IPFIX
    """

    def get_list_of_fpc_numbers(self):
        command = "show chassis hardware | match fpc | except CPU"
        output = self.commands(session_type="network_cli", commands=[command], display="text")
        fpc_list = []
        if not output["failed"]:
            for line in output["stdout_lines"][0]:
                if "FPC" in line:
                    fpc_list.append(line.split()[1])
        return fpc_list

    def get_ipfix_export_data_count(self, fpc_no):
        try:
            ipfix_export_data = {"count": 0}
            command = "show services accounting flow inline-jflow fpc-slot {}".format(fpc_no)
            output = self.commands(commands=[command], display="json")
            if not output["failed"]:
                ipfix_export_data["count"] = output["stdout"][0]["services-accounting-information"][0][
                    "inline-jflow-flow-information"
                ][0]["inline-flows-exported"][0]["data"]
            return ipfix_export_data
        except Exception as e:
            return {"error": str(e)}

    def is_ipfix_exporting_data(self):
        try:
            fpc_list = self.get_list_of_fpc_numbers()
            first_time_total_counter = {"count": 0}
            second_time_total_counter = {"count": 0}
            for fpc_no in fpc_list:
                fpc_counter = self.get_ipfix_export_data_count(fpc_no)
                first_time_total_counter["count"] += int(fpc_counter["count"])
            # wait for 30 seconds
            time.sleep(30)
            for fpc_no in fpc_list:
                fpc_counter = self.get_ipfix_export_data_count(fpc_no)
                second_time_total_counter["count"] += int(fpc_counter["count"])
            if first_time_total_counter == second_time_total_counter:
                return (
                    False,
                    "Exported ipfix data are NOT increasing",
                    first_time_total_counter,
                    second_time_total_counter,
                )
            elif second_time_total_counter["count"] > first_time_total_counter["count"]:
                return True, "Exported ipfix data are increasing"
        except Exception as e:
            return False, "Failed to check is ipfix exporting data due to {}".format(str(e))

    def apply_sample_filter_to_interface(self, filter_name, interface):
        try:
            configs = []
            configs.append("set interfaces {} unit 0 family inet filter input {}".format(interface, filter_name))
            output = self.config(lines=configs, comment="push ipfix configs")
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to apply sample filter {} to interface {} due to {}".format(
                filter_name, interface, str(e)
            )

    def pull_ipfix_configs(self):
        """
        :return: Boolean, message, ipv4server address, ipv4 port, ipv6 server address, ipv6 port
        """
        try:
            command = "show configuration forwarding-options sampling instance ipfix_instance"
            json_output = json.loads(
                self.commands(session_type="network_cli", commands=[command], display="json")["stdout"][0]
            )
            """
            output example:
            {"configuration" : {
                "@" : {
                    "junos:commit-seconds" : "1590097048",
                    "junos:commit-localtime" : "2020-05-21 21:37:28 UTC",
                    "junos:commit-user" : "SES-SVC"},
                "forwarding-options" : {
                    "sampling" : {
                        "instance" : [{
                            "name" : "ipfix_instance",
                            "family" : {
                                "inet" : {
                                    "output" : {
                                        "flow-server" : [{
                                            "name" : "10.20.6.16",
                                            "port" : 9777,
                                            "version-ipfix" : {
                                                "template" : {
                                                    "template-name" : "ipv4_template"}}}],
                                              "inline-jflow" : {
                                                 "source-address" : "207.46.35.215",
                                                        "flow-export-rate" : 100}}}}}]}}}}
            Notice: only IPV4 data shown for simplicity
            """
            out = json_output["configuration"]["forwarding-options"]["sampling"]["instance"][0]["family"]
            ipv4_ipfixserver = out["inet"]["output"]["flow-server"][0]["name"]
            ipv4_ipfixport = out["inet"]["output"]["flow-server"][0]["port"]
            ipv6_ipfixserver = out["inet6"]["output"]["flow-server"][0]["name"]
            ipv6_ipfixport = out["inet6"]["output"]["flow-server"][0]["port"]
            # check if both are set
            if not ipv4_ipfixserver or not ipv4_ipfixport or not ipv6_ipfixserver or not ipv6_ipfixport:
                message = "could not get IPFIX server information"
                # return status, message, ipv4 server, ipv4 port, ipv6 server, ipv6 port
                return False, message, False, False, False, False
            else:
                message = "collected IPv4/IPv6 IPFIX server/port information"
                return True, message, ipv4_ipfixserver, ipv4_ipfixport, ipv6_ipfixserver, ipv6_ipfixport
        except Exception as e:
            return False, str(e), False, False, False, False

    def apply_ipfix_configs(
        self, ipv4_ipfixserver, ipv4_ipfixport, ipv6_ipfixserver, ipv6_ipfixport, ipfix_interface=None
    ):
        """
        :param ipv4_ipfixserver: IP address to send ipv4 flow data
        :param ipv4_ipfixport: Port to send IPv4 flow data
        :param ipv6_ipfixserver: IP address to send ipv6 flow data
        :param ipv6_ipfixport: Port to send IPv6 flow data
        :param ipfix_interface: Interface to enable flow data
        :return: Boolean, message, router-id in IP format

        This function adds IPFIX configurations to the specified lab router.
        It first logs into the router to pull the router-id in IP address format.
        """

        # Get the sourc-address from the router to use for IPFIX.
        command = "show configuration routing-options router-id"
        json_output = json.loads(
            self.commands(session_type="network_cli", commands=[command], display="json")["stdout"][0]
        )
        """
        output example:
        {"configuration" :
            {"@"
                {
                "junos:commit-seconds" : "1590169427",
                "junos:commit-localtime" : "2020-05-22 17:43:47 UTC",
                "junos:commit-user" : "root"},
            "routing-options" : {"router-id" : "207.46.33.214"}}}
        """

        routerid = json_output["configuration"]["routing-options"]["router-id"]

        # check if routerid is set
        if not routerid:
            message = "could not get router-id information"
            return False, message, False

        else:
            # collect operational fpc information
            command = "show chassis fpc"
            json_output = json.loads(
                self.commands(session_type="network_cli", commands=[command], display="json")["stdout"][0]
            )
            """
            output example:
            {"fpc-information" : [
                {"attributes" : {"xmlns" : "http://xml.juniper.net/junos/18.2X75/junos-chassis",
                                 "junos:style" : "brief"},
                {
                "slot" : [{"data" : "2"}],
                "state" : [{"data" : "Online"}],
                "temperature" : [{"data" : "41"}],
                "cpu-total" : [{"data" : "41"}],
                "cpu-interrupt" : [{"data" : "3"}],
                "cpu-1min-avg" : [{"data" : "41"}],
                "cpu-5min-avg" : [{"data" : "41"}],
                "cpu-15min-avg" : [{"data" : "41"}],
                "memory-dram-size" : [{"data" : "16384"}],
                "memory-heap-utilization" : [{"data" : "26"}],
                "memory-buffer-utilization" : [{"data" : "47"}]}]}]}
            """

            fpc_slots = []
            # build a list containing all FPC cards that are online
            for fpcslot in json_output["fpc-information"][0]["fpc"]:
                if "Online" in fpcslot["state"][0]["data"]:
                    fpc_slots.append(fpcslot["slot"][0]["data"])

            configs = []
            # remove existing configs
            configs.append("delete services flow-monitoring")
            configs.append("delete forwarding-options sampling instance ipfix_instance")
            for slot in fpc_slots:
                configs.append("delete chassis fpc {} sampling-instance ipfix_instance".format(slot))

            # add configs for each active fpc
            for slot in fpc_slots:
                configs.append("set chassis fpc {} sampling-instance ipfix_instance".format(slot))

            # add ipv4 configs
            configs.append("set services flow-monitoring version-ipfix template ipv4_template flow-active-timeout 60")
            configs.append(
                "set services flow-monitoring version-ipfix template ipv4_template flow-inactive-timeout 15"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv4_template template-refresh-rate packets 1000"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv4_template template-refresh-rate seconds 10"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv4_template option-refresh-rate packets 1000"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv4_template option-refresh-rate seconds 10"
            )
            configs.append("set services flow-monitoring version-ipfix template ipv4_template ipv4-template")

            # add ipv6 configs
            configs.append("set services flow-monitoring version-ipfix template ipv6_template flow-active-timeout 60")
            configs.append(
                "set services flow-monitoring version-ipfix template ipv6_template flow-inactive-timeout 15"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv6_template template-refresh-rate packets 1000"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv6_template template-refresh-rate seconds 10"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv6_template template-refresh-rate seconds 10"
            )
            configs.append(
                "set services flow-monitoring version-ipfix template ipv6_template option-refresh-rate seconds 10"
            )
            configs.append("set services flow-monitoring version-ipfix template ipv6_template ipv6-template")

            # add forwarding options
            configs.append("set forwarding-options sampling instance ipfix_instance input rate 4096")

            # add forwarding options for ipv4
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet "
                "output flow-server {} port {}".format(ipv4_ipfixserver, ipv4_ipfixport)
            )
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet "
                "output flow-server {} version-ipfix template ipv4_template".format(ipv4_ipfixserver)
            )
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet "
                "output inline-jflow source-address {}".format(routerid)
            )
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet "
                "output inline-jflow flow-export-rate 100"
            )

            # add forwarding options for ipv6
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet6 "
                "output flow-server {} port {}".format(ipv6_ipfixserver, ipv6_ipfixport)
            )
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet6 output "
                "flow-server {} version-ipfix template ipv6_template".format(ipv6_ipfixserver)
            )
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet6 output "
                "inline-jflow source-address {}".format(routerid)
            )
            configs.append(
                "set forwarding-options sampling instance ipfix_instance family inet6 output "
                "inline-jflow flow-export-rate 100"
            )

            # apply to the router interface
            if ipfix_interface is not None:
                configs.append("set interfaces {} unit 0 family inet sampling input".format(ipfix_interface))
                configs.append("set interfaces {} unit 0 family inet6 sampling input".format(ipfix_interface))

            try:
                commitmsg = self.config(lines=configs, comment="push ipfix configs")
                return True, commitmsg, routerid

            except Exception as e:
                message = "Command {} failed to execute {}".format(configs, str(e))
                logger.error("Command {} failed to execute {}".format(configs, str(e)))
                return False, message, False

    """
    ISIS
    """

    def get_isis_adjacency(self):
        try:
            command = "show isis adjacency"
            json_output = self.commands(commands=[command], display="json")
            isis_adj_info = {}
            if not json_output["failed"]:
                for line in json_output["stdout"][0]["isis-adjacency-information"][0]["isis-adjacency"]:
                    isis_adj_info.update(
                        {
                            line["interface-name"][0]["data"]: {
                                "neighbor": line["system-name"][0]["data"],
                                "state": line["adjacency-state"][0]["data"],
                            }
                        }
                    )
                return isis_adj_info
            return {"msg": "failed to get isis adjacency info"}
        except Exception as e:
            logger.error(str(e))
            return {"Exception": str(e)}

    def check_isis_adjacency(self, device_b, expected_adjacency_ports=1):
        """
        :param device_b: device adjacent to device_a
        :param expected_adjacency_ports: number of adjacencies between device a and device a
        :return: Boolean, List of adjacency information
        """
        adjacency = []
        juniper_adj = self.get_isis_adjacency()
        for portchannel, isis_neighbor in juniper_adj.items():
            if isis_neighbor["neighbor"].lower() == device_b.lower() and isis_neighbor["state"] == "Up":
                adjacency.append("{}_{}_{}".format(portchannel, isis_neighbor["neighbor"], isis_neighbor["state"]))
        if len(adjacency) == expected_adjacency_ports:
            return True, adjacency
        return False, adjacency

    def get_isis_database(self, queue=None):
        try:
            command = "show isis database"
            json_output = self.commands(commands=[command], display="json")
            lsp_entries = {}
            if not json_output["failed"]:
                for entry in json_output["stdout"][0]["isis-database-information"][0]["isis-database"][1][
                    "isis-database-entry"
                ]:
                    lsp_entries[entry["lsp-id"][0]["data"]] = {
                        "sequence-number": int(entry["sequence-number"][0]["data"], base=16),
                        "checksum": int(entry["checksum"][0]["data"], base=16),
                    }
                if queue:
                    queue.put(lsp_entries)
                return lsp_entries
            lsp_entries["msg"] = "failed to get isis database"
            return lsp_entries
        except Exception as e:
            logger.error(str(e))
            return {"Exception": str(e)}

    """
    LDP
    """

    def check_remote_ldp_sessions(self):
        """
        :param dut: The Device Under Test
        :return: boolean, message
        """
        # get a list of ldp neighbors marked as operational
        try:
            command = "show ldp session"
            json_output = self.commands(commands=[command], display="json")["stdout"][0]
            """
            output example:
            filtered to: ["ldp-session-information"][0]["ldp-session"]
            [{'ldp-neighbor-address': [{'data': '100.3.151.17'}],
              'ldp-session-state': [{'data': 'Operational'}],
              'ldp-connection-state': [{'data': 'Open'}],
              'ldp-remaining-time': [{'data': '21'}],
              'ldp-session-adv-mode': [{'data': 'DU'}]},
            parse to get only IP addresses
            """
            ldp_op_list = []
            for x in json_output["ldp-session-information"][0]["ldp-session"]:
                if "Operational" in x["ldp-session-state"][0]["data"]:
                    ldp_op_list.append(x["ldp-neighbor-address"][0]["data"])

            if ldp_op_list:
                result, message = self.get_core_interfaces(ldp_op_list)
                return result, message
            return False, "No operational LDP session"
        except Exception as e:
            message = "Command {} failed to execute {}".format(command, str(e))
            logger.error(message)
            return False, message

    def get_core_interfaces(self, ldp_op_list):
        """
        :param dut: The Device Under Test
        :param ldp_op_list: list of ldp neighbors marked as operational
        :return: boolean, message
        """
        # for each operational ldp session check the route to get the next-hop
        try:
            ldp_int_list = []
            for ldpneighbor in ldp_op_list:
                command = "show route {}".format(ldpneighbor)
                json_output = json.loads(
                    self.commands(session_type="network_cli", commands=[command], display="json")["stdout"][0]
                )
                ldp_int = json_output["route-information"][0]["route-table"][0]["rt"][0]["rt-entry"][0]["nh"][0][
                    "via"
                ][0]["data"]
                # remove the unit after the interface number and append to the list - ex: ae5.0 to ae5
                ldp_int_list.append(ldp_int.split(".", 1)[0])
            if ldp_int_list:
                result, message = self.verify_core_path(ldp_int_list)
                return result, message
            else:
                message = "could not collect ldp interfaces on {dut}"
                return False, message
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to get core interfaces due to {}".format(str(e))

    def verify_core_path(self, ldp_int_list):
        """
        :param dut: The Device Under Test
        :param ldp_int_list: list of next-hop interfaces for operational ldp sessions
        :return: boolean, message
        """
        try:
            # check each next-hop address and see if the neighbor is an IBR-cisco device
            for interface in ldp_int_list:
                command = "show lldp neighbors | match {}".format(interface)
                json_output = self.commands(commands=[command], display="text")["stdout"][0]
                if "ibr" in json_output.lower():
                    # if more than one match is returned by the router, only take the first
                    match_first = json_output.split("\n")[1]
                    # convert the entry from string to list
                    match_list = match_first.split()[0], match_first.split()[1], match_first.split()[4]
                    message = "{} ldp session traverses the core via: {}".format(self.hostname, match_list)
                    return True, message
                    # stop after finding one match in the list
                    break
            return False, "Could not find an operational ldp session on {} traversing an core device".format(
                self.hostname
                )
        except Exception as e:
            return False, "Failed to verify core path due to {}".format(str(e))

    """
    LLDP
    """

    def get_lldp_neighbors(self):
        """Method to gather lldp neighbor details"""
        lldp_details = {}
        try:
            command = "show lldp neighbors"
            output = self.commands(commands=[command], display="json")
            if not output["failed"]:
                for lines in output["stdout"][0]["lldp-neighbors-information"][0]["lldp-neighbor-information"]:
                    lldp_details.update(
                        {
                            lines["lldp-local-port-id"][0]["data"]: {
                                "local_interface": lines["lldp-local-port-id"][0]["data"],
                                "neighbor": lines["lldp-remote-system-name"][0]["data"],
                            }
                        }
                    )
            return lldp_details
        except Exception as e:
            lldp_details.update({"err": str(e)})
            return lldp_details

    def convert_interface_prefix(self, list_of_interfaces):
        """
        Dummy function, Juniper devices don't need interface names to be converted
        :param list_of_interfaces: List of interfaces which need to be updated for vendor naming convention
        :return converted_list_of_interfaces, converted list of interface names
        """
        return list_of_interfaces

    @staticmethod
    def convert_pc_to_ae(pc_name):
        """
        :param pc_name: port-channel to be converted to junos ae format
        :return: ae formatted ie. port-channel5 returns ae5
        """
        pc_name = pc_name.lower()

        if pc_name.find("port-channel") > -1:
            ae_name = "ae{}".format(pc_name.replace("port-channel", ""))
        elif pc_name.find("portchannel") > -1:
            ae_name = "ae{}".format(pc_name.replace("portchannel", ""))
        else:
            ae_name = pc_name

        return ae_name

    def check_interface_status(self, interface):
        """
        :param
        interface: str - port number e.g. ae15, Port-channel15
        :return:
        is_up: boolean , True if interface is up
        intf_status_output: str - raw output of show interface OR error message
        """
        try:
            # if its a lacp bundle with 'port-channel' in the name instead of 'ae'
            pc_name = self.convert_pc_to_ae(interface)
            command = "show interfaces {}".format(pc_name)
            success_criteria = "physical link is up"
            intf_status_output = self.commands(session_type="network_cli", commands=[command], display="text")
            if not intf_status_output["failed"]:
                logger.info("Interface status check: {} sent to {}".format(command, self.hostname))
                is_up = success_criteria in intf_status_output["stdout"][0].lower()
                return is_up, intf_status_output["stdout"][0]
            return False, intf_status_output
        except Exception as e:
            msg = "Failed to check interface status due to {}".format(str(e))
            logger.error(msg)
            return False, msg

    def get_all_interfaces_in_pc(self, pc_name):
        """
        :param pc_name: port-channel/ae used for this test
        :return interfaces: list of port channel member interfaces
        """
        # if NGS input has Port-channel in name, convert to ae
        pc_name = self.convert_pc_to_ae(pc_name)
        command = "show lacp interfaces {}".format(pc_name)
        try:
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                interfaces_data = self.extract_val_from_json(json_output["stdout"][0], "lag-lacp-protocol")[0]
                interfaces = [line["name"][0]["data"] for line in interfaces_data]
                return interfaces
            return ["failed to get list of port channel member interfaces"]
        except Exception as e:
            return [str(e)]

    def get_all_lldp_neighbor_details_for_port(self, physical_port):
        """
        :param physical_port:
        :return:complete lldp details for the port from json formatted output converted to dictionary
        """
        try:
            command = "show lldp neighbor interface {}".format(physical_port)
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                return json_output["stdout"][0]
            return json_output
        except Exception as e:
            return "Failed to get all_lldp_neighbor_details_for_port due to {}".format(str(e))

    def get_chassis_id_from_cli(self):
        """
        :param interface: Name of the interface you need to get the MAC address for
        :return platform
        """
        command = "show lldp local-information"
        try:
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                chassis_id = json_output["stdout"][0]["lldp-local-info"][0]["lldp-local-chassis-id"][0]["data"]
                return chassis_id
            return "Failed to get chassis info due to {}".format(json_output)
        except Exception as e:
            return "Failed to get chassis info due to {}".format(str(e))

    def get_mgmt_ip_from_cli(self):
        """
        :return ip string
        """
        # On Juniper, the management IP is the IPv4 address used on EM0 if it exists
        # otherwise, it is the IPv6 address of EM0
        try:
            command = "show lldp local-information"
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                mgmt_ip = json_output["stdout"][0]["lldp-local-info"][0]["lldp-local-management-address-address"][0][
                    "data"
                ]
                return mgmt_ip
            return "Failed to get mgmt_ip due to {}".format(json_output)
        except Exception as e:
            return "Failed to get mgmt_ip due to {}".format(str(e))

    def get_platform_from_cli(self):
        """
        :return platform
        """
        try:
            command = "show lldp local-information"
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                system_description = json_output["stdout"][0]["lldp-local-info"][0]["lldp-local-system-description"][
                    0
                ]["data"]
                # Extract platform from system description
                platform = system_description.split(" ")[3]
                return platform
            return "Failed to get platform info due to {}".format(json_output)
        except Exception as e:
            return "Failed to get platform info due to {}".format(str(e))

    def get_version_from_cli(self):
        """
        :return version
        """
        try:
            command = "show version"
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                version = json_output["stdout"][0]["software-information"][0]["junos-version"][0]["data"]
                return version
            return "Failed to get version due to {}".format(json_output)
        except Exception as e:
            return "Failed to get version due to {}".format(str(e))

    def parse_lldp_peer_required_info(self, lldp_details=None):
        """
        :param lldp_details: Output of "show lldp neighbor"
        :return chassis
        """
        # Initialize dictionary to return
        lldp_required_info = {}

        # Get Chassis ID:
        chassis = self.extract_val_from_json(lldp_details, "lldp-remote-chassis-id")
        lldp_required_info["chassis_id"] = chassis[0][0]["data"]

        # Get peer management IP:
        """
        Ignoring as we have issue with Cisco Management IP
        ip = lldp_details["lldp-neighbors-information"][0]["lldp-neighbor-information"][0][
                "lldp-remote-management-address"][0]["data"]
        lldp_required_info['ip'] = ip
        """

        # Get peer name:
        peer_name = self.extract_val_from_json(lldp_details, "lldp-remote-system-name")
        lldp_required_info["name"] = peer_name[0][0]["data"].lower()

        # Get system description
        system_description = self.extract_val_from_json(lldp_details, "lldp-remote-system-description")[0][0]["data"]
        # From this description, extract platform:
        # Arista output looks like "Arista Networks EOS version 4.23.2.1F-DPE running on an Arista Networks DCS-7504"
        if "Arista" in system_description:
            description_list = system_description.split(" ")
            platform = description_list[-1]
        # Cisco output looks like " 6.3.3, NCS-5500"
        elif "NCS" in system_description:
            description_list = system_description.split(",")
            platform = description_list[1].strip()
        elif "8000" in system_description:
            description_list = system_description.split(",")
            platform = description_list[1].strip()
        lldp_required_info["platform"] = platform

        # From the same system description, extract version:
        # Arista output looks like "Arista Networks EOS version 4.23.2.1F-DPE running on an Arista Networks DCS-7504"
        if "Arista" in system_description:
            regex = r"(?<=version ).*(?= running )"
            matches = re.search(regex, system_description, re.MULTILINE)
            version = matches.group()
        # Cisco output looks like " 6.3.3, NCS-5500"
        elif "NCS" in system_description:
            description_list = system_description.split(",")
            version = description_list[0].strip()
        #   Cisco output looks like " 6.3.3, NCS-5500"
        elif "8000" in system_description:
            description_list = system_description.split(",")
            version = description_list[0].strip()
        lldp_required_info["version"] = version

        # Get the peer port ID
        peer_port = self.extract_val_from_json(lldp_details, "lldp-remote-port-id")
        # remove Bundle-Ether interface from peer_port
        peer_port = [port for port in peer_port if "Bundle-Ether" not in port[0]["data"]]
        lldp_required_info["port"] = peer_port[0][0]["data"]

        return lldp_required_info

    """
    MACSEC
    """

    def get_macsec_connection_status_details(self, interface):
        """
        :param interface: interface of macsec adjacency
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            command = "show security mka sessions interface {} detail".format(interface)
            json_output = self.commands(commands=[command], display="json")["stdout"][0]
            """output example:
            {
            "mka-session-information" : [
            {
                "attributes" : {"junos:style" : "brief"},
                "interface-state" : [
                {
                    "data" : "Secured - Primary"
                }
                ],
                "member-identifier" : [
                {
                    "data" : "64B9F944EC9D6A5022BD2D13"
                }
                ],
                "cak-name" : [
                {
                    "data" : "C64CC64CC64CC64CC64CC64CC64CC64CC64CC64CC64CC64CC64CC64CC64CC64C"
                }
            ...
            Output trimmed
            """
            if "session-live" not in json_output["mka-session-information"][0].keys():
                return False, "No session found on {}".format(interface)
            command_2 = "show security macsec connections interface {}".format(interface)
            json_output_2 = self.commands(commands=[command_2], display="json")["stdout"][0]
            """
            output_2 example:
            """
            dict_out = {
                "cipher-suite": json_output_2["macsec-connection-information"][0]["cipher-suite"][0]["data"],
                "pre-shared-key": {
                    "ckn": json_output["mka-session-information"][0]["session-live"][0]["cak-name"][0]["data"]
                },
                "fallback-key": {
                    "ckn": json_output["mka-session-information"][0]["session-cak"][-1]["cak-name"][0]["data"]
                },
                "name": json_output_2["macsec-connection-information"][0]["connectivity-association-name"][0]["data"],
            }
            return True, dict_out
        except Exception as e:
            return False, "Failed to get macsec connection status details due to {}".format(str(e))

    def get_macsec_status_logs(self, interface, last_count="30", log_type="ESTABLISHED"):
        """
        :param interface: interface of macsec adjacency
        :param log_type: ESTABLISHED, FAILURE, ROLLOVER
        :param last_count: optional field to capture number of logs
        :return: boolean, output from logs
        """
        try:
            if log_type == "FAILURE":
                log_type = "MACSEC_SC_UNKNOWN_CAK_ERR"
            command = "show log messages | last {} | match Macsec | match {} | match interface | no-more".format(
                last_count, log_type
            )
            output = self.commands(session_type="network_cli", commands=[command], display="text")
            if not output["failed"]:
                return len(output["stdout_lines"][0]) > 0, output["stdout"][0]
            return False, "Failed to get macsec status logs due to {}".format(output)
        except Exception as e:
            return False, "Failed to get macsec status logs due to {}".format(str(e))

    def get_macsec_profile(self, interface):
        """
        :param interface: interface of device to capture profile name
        :return: profile name
        """
        try:
            command = "show configuration security macsec interfaces {} connectivity-association | display set".format(
                interface
            )
            output = self.commands(session_type="network_cli", commands=[command], display="text")
            """
            example of output:
            set security macsec interfaces et-2/0/14 connectivity-association macsec-xpn-256-ae16
            """
            if not output["failed"]:
                return True, output["stdout"][0].split()[-1]
            return False, "Failed to get macsec profile due to {}".format(output)
        except Exception as e:
            return False, "Failed to get macsec profile due to {}".format(str(e))

    def set_macsec_key(self, profile_name, key, key_type, interface):
        """
        :param profile_name: macsec profile name used for key
        :param key: string key to apply
        :param key_type: fallback or primary
        :param interface: unused for juniper
        :return: boolean and test_msg string
        """
        "set security macsec connectivity-association {profile} pre-shared-key cak {key}"
        "set security macsec connectivity-association {profile} fallback-key cak {key}"
        try:
            if key_type == "primary":
                commands = [
                    "set security macsec connectivity-association {} pre-shared-key ckn {} cak {} ".format(
                        profile_name, key, key
                    )
                ]
                output = self.config(lines=commands, comment="update macsec pre-shared-key")
            elif key_type == "fallback":
                commands = [
                    "set security macsec connectivity-association {} fallback-key ckn {} cak {}".format(
                        profile_name, key, key
                    )
                ]
                output = self.config(lines=commands, comment="update macsec fallback-key")

            else:
                test_msg = "Key type {} not supported".format(key_type)
                output = {"failed": True, "msg": test_msg}

            if not output["failed"]:
                return True, str(output)
            return False, "Failed to set macsec key due to {}".format(output)
        except Exception as e:
            return False, "Failed to set macsec key due to {}".format(str(e))

    def get_macsec_interface_statistics(self, interface):
        """
        :param interface: interface of macsec
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            command = "show security macsec statistics interface {}".format(interface)
            json_output = self.commands(commands=[command], display="json")
            """json_output example:
            {
                "macsec-statistics":[
                {
                ....
                    "secure-channel-received":[
                    {
                    "ok-packets":[
                    {
                        "data" : "4675281081"
                        }
                        ],
                        "validated-bytes":[
                        {
                            "data":"2958355739274"
                        }
                        ],
                        "decrypted-bytes":[
                        {
                            "data":"2958355739274"
                        }
                        ]
                    }
                    ],
                    ...
            }
            ...
            Output trimmed
            """
            if not json_output["failed"]:
                sc_dict_out = json_output["stdout"][0]["macsec-statistics"][0]["secure-channel-received"][0]
                validated_bytes = sc_dict_out["validated-bytes"][0]["data"]
                decrypted_bytes = sc_dict_out["decrypted-bytes"][0]["data"]
                if int(validated_bytes) == int(decrypted_bytes) and int(validated_bytes) > 0:
                    return (
                        True,
                        "validated-bytes {0} and decrypted-bytes {1} is the same on interface {2}".format(
                            validated_bytes, decrypted_bytes, interface
                        ),
                    )
                else:
                    return (
                        False,
                        "validated-bytes {0} and decrypted-bytes {1} is not the same on interface {2}".format(
                            validated_bytes, decrypted_bytes, interface
                        ),
                    )
            else:
                return False, "Failed to get macsec interface statistics from interface {}".format(interface)
        except Exception as e:
            return False, "Failed to get macsec interface statistics due to {}".format(str(e))

    def set_deactivate_macsec_interface(self, interfaces):
        """
        :interfaces: list of interface
        :return: bool, str
        """
        commands = []
        for interface in interfaces:
            commands.append("deactivate security macsec interfaces {}".format(interface))
        try:
            output = self.config(lines=commands, comment="deactivate macsec interface")
            if not output["failed"]:
                return True, output
            return False, "Failed to deactivate macsec interface due to {}".format(output)
        except Exception as e:
            return False, "Failed to deactivate macsec interface due to {}".format(str(e))

    def set_activate_macsec_interface(self, interfaces):
        """
        :interfaces: list of interface
        :return: bool
        """
        commands = []
        for interface in interfaces:
            commands.append("activate security macsec interfaces {}".format(interface))
        try:
            output = self.config(lines=commands, comment="activate macsec interface")
            if not output["failed"]:
                return True, output
            return False, "Failed to activate macsec interface due to {}".format(output)
        except Exception as e:
            return False, "Failed to activate macsec interface due to {}".format(str(e))

    def get_macsec_config(self, interface):
        """
        :param interface: interface of device to capture profile name
        :return: bool, Command set on the device
        """
        command = "show configuration security macsec interfaces {} connectivity-association | display set".format(
            interface
        )
        try:
            output = self.commands(session_type="network_cli", commands=[command], display="text")
            """
            example of output:
            set security macsec interfaces et-2/0/14 connectivity-association macsec-xpn-256-ae16
            """
            if not output["failed"]:
                # strip to remove extra /n with string
                return True, output["stdout"][0].strip()
            return False, "Failed to get macsec config due to {}".format(output)
        except Exception as e:
            return False, "Failed to get macsec config due to {}".format(str(e))

    def apply_macsec_interface_config(self, commands):
        """
        :param commands: List command which need to execute on DTU.
        :return: boolean
        """
        output = self.config(lines=commands, comment="apply_macsec_interface_config")
        try:
            if not output["failed"]:
                return True, output
            return False, "Failed to apply macsec interface config due to {}".format(output)
        except Exception as e:
            return False, "Failed to apply macsec interface config due to {}".format(str(e))

    def delete_macsec_interface_config(self, interface):
        """
        :param interface: remove MACSEC from physical interface
        :return: bool
        """
        command = "delete security macsec interfaces {}".format(interface)
        try:
            output = self.config(lines=[command], comment="remove MACSEC from physical interface")
            if not output["failed"]:
                return True, output
            return False, "Failed to delete macsec interface config due to {}".format(output)
        except Exception as e:
            return False, "Failed to delete macsec interface config due to {}".format(str(e))

    def set_rekey_period(self, profile_name, rekey_period_value):
        """
        :param profile_name: policy to change rekey value on
        :param rekey_period_value: value to set rekey in seconds, value range between 60 and 2592000
        :return: boolean, output from rekey implementation
        """
        try:
            command = "set security macsec connectivity-association {} mka sak-rekey-interval {}".format(
                profile_name, rekey_period_value
            )
            output = self.config(lines=[command], comment="rekey macsec interval")
            if not output["failed"]:
                return True, output
            return False, "Failed to set rekey period due to {}".format(output)
        except Exception as e:
            return False, "Failed to set rekey period due to {}".format(str(e))

    """
    TACACS
    """

    def run_configure_command_test(self):
        """
        This function is intend to test current account can get into config mode and do harmless config
        and confirm the account has priviliage to configure the router.
        """
        try:
            command = "set system location building microsoft"
            output = self.config(lines=[command], comment="test configure command")
            if not output["failed"]:
                rollback_command = "del system location building microsoft"
                self.config(lines=[rollback_command], comment="rollback test configure command")
                return True, output
            return False, "Failed to run configure command test due to {}".format(output)
        except Exception as e:
            return False, "Failed to run configure command test due to {}".format(str(e))

    def pull_tacplus_source_address(self):
        """
        :return: tacplus server source address
        """
        try:
            command = "show configuration system tacplus-server | display set | match source-address"
            output = self.commands(session_type="network_cli", commands=[command], display="text")
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if "source-address" in line:
                        return line.split()[-1]
            else:
                message = "Failed to get tacplus source address"
                return message
        except Exception as e:
            return "Failed to get tacplus source address due {}".format(str(e))

    def apply_check_tacacs_config_and_rollback(self, prod_tacacsserver, tacacs_secret, accounting_secret, usr, pwd):
        """
        :param prod_tacacsserver: list of configured production TACACS servers
        :param tacacs_secret: TACACS secret key
        :param acccounting_secret: TACACS secret key
        :param source_address: lab router source IP address
        :param prod_device: random production router name
        :param usr: production username used with scripts
        :param pwd: production password used with scripts
        :return: Boolean, message
        """
        # running this function will execute the following processes in parallel
        try:
            src_address = self.pull_tacplus_source_address()
            result, msg = self.apply_prod_tacacs(prod_tacacsserver, tacacs_secret, accounting_secret, src_address)
            if result:
                # waiting for 20 seconds before test the prod device username and password
                time.sleep(20)
                result, msg = self.check_prod_tacacs(usr, pwd)
                return result, msg
            else:
                return False, "Failed to apply prod tacacs config"
        except Exception as e:
            return False, "Failed to test tacplus due to {}".format(str(e))

    def apply_prod_tacacs(self, prod_tacacsserver, tacacs_secret, accounting_secret, source_address):
        """
        :param prod_tacacsserver: list of configured production TACACS servers
        :param tacacs_secret: TACACS secret key
        :param acccounting_secret: TACACS secret key
        :param source_address: lab router source IP address
        :return: Boolean, message

        This function pushes production TACACS configurations to the router.
        At the end it executes a "commit confirmed 2" command on the router.
        After 120 seconds the router will automatically restore the original configurations.
        This function is running in parallel with check_prod_tacacs().
        """
        prod_configs = []
        prod_configs.append("delete system tacplus-server")
        prod_configs.append("delete system accounting destination tacplus server")
        prod_configs.append("set groups default_prod_tacserver_setup system tacplus-server <*> port 49")
        prod_configs.append(
            "set groups default_prod_tacserver_setup system tacplus-server <*> secret {}".format(tacacs_secret)
        )
        prod_configs.append("set groups default_prod_tacserver_setup system tacplus-server <*> timeout 10")
        prod_configs.append("set groups default_prod_tacserver_setup system tacplus-server <*> single-connection")
        prod_configs.append(
            "set groups default_prod_tacaccounting_setup system accounting destination tacplus server <*> port 49"
        )
        prod_configs.append(
            "set groups default_prod_tacaccounting_setup system accounting \
            destination tacplus server <*> secret {}".format(
                accounting_secret
            )
        )
        prod_configs.append(
            "set groups default_prod_tacaccounting_setup system accounting destination tacplus server <*> timeout 5"
        )
        prod_configs.append(
            "set groups default_prod_tacaccounting_setup system accounting \
            destination tacplus server <*> single-connection"
        )
        prod_configs.append(
            "set system tacplus-server {} apply-groups default_prod_tacserver_setup".format(prod_tacacsserver)
        )
        prod_configs.append("set system tacplus-server {} source-address {}".format(prod_tacacsserver, source_address))
        prod_configs.append(
            "set system accounting destination tacplus server {} apply-groups default_prod_tacaccounting_setup".format(
                prod_tacacsserver
            )
        )
        prod_configs.append(
            "set system accounting destination tacplus server {} source-address {}".format(
                prod_tacacsserver, source_address
            )
        )
        try:
            output = self.config(lines=prod_configs, confirm=2)
            if not output["failed"]:
                return True, "prod configs pushed to lab router, will rollback by itself in 2 minutes"
            return False, "Failed to apply prod tacacs config due to {}".format(output)
        except Exception as e:
            return False, "Failed to apply prod tacacs config due to {}".format(str(e))

    def check_prod_tacacs(self, usr, pwd):
        """
        :param usr: production username used with scripts
        :param pwd: production password used with scripts
        :return: Boolean, message

        This function logs into the lab router with production credentials.
        It is running in parallel with apply_prod_tacacs()
        This function must complete before the expiration of the rollback timer.
        """
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            ssh.load_system_host_keys()
            ssh.connect(self.hostname, username=usr, password=pwd)
            stdin, stdout, stderr = ssh.exec_command("show version")
            reply_error = stderr.readlines()
            if not reply_error:
                return True, stdout.readlines()
            else:
                return False, "Failed to check prod tacacs server due to {}".format(reply_error)
        except Exception as e:
            return False, "Failed to check prod tacacs server due to {}".format(str(e))

    """
    BGP
    """

    def get_bgp_status(self):
        """
        :return bgp session status
        """
        try:
            command = "show bgp summary"
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                json_output_dict = json_output["stdout"][0]["bgp-information"][0]["bgp-peer"]
                bgp_status = {}
                for bgp_speak in json_output_dict:
                    bgp_status.update({bgp_speak["peer-address"][0]["data"]: bgp_speak["peer-state"][0]["data"]})
                return bgp_status
            return "Failed to get bgp status from device {} due to {}".format(self.hostname, json_output)
        except Exception as e:
            logger.error(str(e))
            return "Failed to get bgp status due to {}".format(str(e))

    def get_bgp_session_details(self, peer_ip):
        """
        :param peer_ip: bgp peer ip
        :return: dictionary with bgp session details
        """
        command = "show bgp neighbor {}".format(peer_ip)
        try:
            json_output_dict = self.commands(commands=[command], display="json")
            return json_output_dict
        except Exception as e:
            return {"msg": str(e)}

    def get_bgp_session_status(self, peer_ip):
        """
        :param peer_ip:
        :return: bgp session status e.g. Established
        """
        try:
            bgp_peer_details = self.get_bgp_session_details(peer_ip)
            if not bgp_peer_details["failed"]:
                session_status = bgp_peer_details["stdout"][0]["bgp-information"][0]["bgp-peer"][0]["peer-state"][0][
                    "data"
                ]
                return session_status
            return "Failed to get bgp session status due to {}".format(bgp_peer_details)
        except Exception as e:
            return "Failed to get bgp session status due to {}".format(str(e))

    def check_for_aggregate_route_generation(self, agg_prefix):
        """
        :param agg_prefix: aggregate prefix
        :return: Aggregate prefix status "True" or "False"
        """
        try:
            command = "show route protocol aggregate {} exact".format(agg_prefix)
            agg_route_gen_status = False
            output = self.commands(session_type="network_cli", commands=[command], display="text")
            if not output["failed"]:
                for line in output["stdout_lines"][0]:
                    if agg_prefix in line:
                        agg_route_gen_status = True
                        break
            return agg_route_gen_status, output["stdout"][0]
        except Exception as e:
            return False, "Failed to verify the aggregate route due to {}".format(str(e))

    def is_prefix_advertised_to_peer(self, prefix, peer_ip):
        """
        :param prefix:
        :param peer_ip:
        :return: Boolean status of whether prefix is advertised to the peer or not
        """
        try:
            command = "show route advertising-protocol bgp {} {} exact".format(peer_ip, prefix)
            json_output = self.commands(commands=[command], display="json")
            prefix_adv_status = False
            if not json_output["failed"]:
                route_table = json_output["stdout"][0]["route-information"][0]["route-table"][0]["rt"]
                for element in route_table:
                    if "rt-destination" in element:
                        if element["rt-destination"][0]["data"] == prefix:
                            prefix_adv_status = True
                            break
            return prefix_adv_status, json_output["stdout"][0]
        except Exception as e:
            return False, "Failed to verify is the prefix advertised to peer due to {}".format(str(e))

    # need to update protocol level code as return content changed from Success/failed to True/False
    def deactivate_bgp_with_ser(self):
        """
        :return:
        """

        try:
            commands = [
                "deactivate protocols bgp group RWA-SWAN",
                "deactivate protocols bgp group IPV6-RWA-SWAN",
                "deactivate protocols bgp group ICR-SWAN",
                "deactivate protocols bgp group IPV6-ICR-SWAN",
            ]
            output = self.config(lines=commands, comment="deactivate bgp with ser")
            if not output["failed"]:
                return True
            return False
        except Exception as e:
            logger.error(str(e))
            return False

    # need to update protocol level code as return content changed from Success/failed to True/False
    def activate_bgp_with_ser(self):
        """
        :return:
        """
        try:
            commands = [
                "activate protocols bgp group RWA-SWAN",
                "activate protocols bgp group IPV6-RWA-SWAN",
                "activate protocols bgp group ICR-SWAN",
                "activate protocols bgp group IPV6-ICR-SWAN",
            ]
            output = self.config(lines=commands, comment="activate bgp with ser")
            if not output["failed"]:
                return True
            return False
        except Exception as e:
            logger.error(str(e))
            return False

    # need to update protocol level code as return content changed from Success/failed to True/False
    def deactivate_protocol_rsvp(self):
        """
        :return:
        """
        try:
            output = self.config(lines=["deactivate protocols rsvp"], comment="deactivate protocol rsvp")
            if not output["failed"]:
                return True, output
            return False, "Failed to deactivate rsvp protocol due to {}".format(output)
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to deactivate rsvp protocol due to {}".format(str(e))

    # need to update protocol level code as return content changed from Success/failed to True/False
    def activate_protocol_rsvp(self):
        """
        :return:
        """
        try:
            output = self.config(lines=["activate protocols rsvp"], comment="activate protocol rsvp")
            if not output["failed"]:
                return True, output
            else:
                return False, "Failed to activate rsvp protocol due to {}".format(output)
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to activate rsvp protocol due to {}".format(str(e))

    def get_active_route_details(self, prefix_with_mask, table):
        try:
            command = "show route {} table {} active-path exact".format(prefix_with_mask, table)
            json_output = self.commands(commands=[command], display="json")
            if not json_output["failed"]:
                if "route-table" in json_output["stdout"][0]["route-information"][0]:
                    route_table = json_output["stdout"][0]["route-information"][0]["route-table"][0]
                    destination = route_table["rt"][0]["rt-destination"][0]["data"]
                    source_protocol = route_table["rt"][0]["rt-entry"][0]["protocol-name"][0]["data"]
                    label_info = route_table["rt"][0]["rt-entry"][0]["nh"][0]["mpls-label"][0]["data"]
                    return True, destination, source_protocol, label_info
            else:
                return False, prefix_with_mask, None, None
        except Exception as e:
            logger.error(str(e))
            return False, prefix_with_mask, None, None

    def shutdown_swan_agent(self):
        """
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            commands = [
                "deactivate system extensions extension-service application file agentjunos",
                "deactivate system extensions extension-service application file apcacertagent-junos",
            ]
            output = self.config(lines=commands, comment="deactivate swan agent")
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to shutdown swan agent due to {}".format(str(e))

    def enable_swan_agent(self):
        """
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            commands = [
                "activate system extensions extension-service application file agentjunos",
                "activate system extensions extension-service application file apcacertagent-junos",
            ]
            output = self.config(lines=commands, comment="activate swan agent")
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            logger.error(str(e))
            return False, "Failed to enable swan agent due to {}".format(str(e))

    """
    RSVP
    """

    def check_rsvp_nbr(self, neighbor):
        """
        :param neighbor: neighbor of rsvp
        :return: boolean, failure message or dict_out containing dictionary of attributes
        """
        try:
            command = "show rsvp neighbor"
            json_output = self.commands(commands=[command], display="json")
            """json_output example:
                {
                    "rsvp-neighbor-information" : [
                    {
                        "attributes" : {"xmlns" : "http://xml.juniper.net/junos/18.2X75/junos-routing"},
                        "rsvp-neighbor-count" : [
                        {
                        "data" : "6"
                        }
                        ],
                        "rsvp-neighbor" : [
                        {
                            "attributes" : {"junos:style" : "brief"},
                            "rsvp-neighbor-address" : [
                            {
                                "data" : "100.3.151.29"
                            }
                            "neighbor-idle" : [
                            {
                                "data" : "0",
                                "attributes" : {"junos:seconds" : "0"}
                            }
                            ],
                            "neighbor-up-count" : [
                            {
                                "data" : "1"
                            }
                            ],
                            "neighbor-down-count" : [
                            {
                                "data" : "0"
                            }
                            ],
                        ...
                        },
                    }
                    ]
                }
                ...
             Output trimmed
            """
            if not json_output["failed"]:
                rsvp_nbrs = json_output["stdout"][0]["rsvp-neighbor-information"][0]["rsvp-neighbor"]
                for rsvp_nbr in rsvp_nbrs:
                    if str(rsvp_nbr["rsvp-neighbor-address"][0]["data"]) == str(neighbor):
                        nbr_up_count = rsvp_nbr["neighbor-up-count"][0]["data"]
                        nbr_down_count = rsvp_nbr["neighbor-down-count"][0]["data"]
                        if int(nbr_up_count) >= int(nbr_down_count):
                            return True, "RSVP neighor {0} is up".format(neighbor)
                        else:
                            return False, "RSVP neighor {0} is down".format(neighbor)
                else:
                    return False, "RSVP neighor {0} is not found".format(neighbor)
            else:
                return False, "Failed to get RSVP neighbor info from ansible"
        except Exception as e:
            return False, "Failed to get RSVP neighbor info due to {}".format(str(e))

    def get_loopback_ipv4_addr(self):
        """
        :return: loopback ipv4 addr string
        """
        command = "show configuration interfaces lo0"
        try:
            json_output = self.commands(commands=[command], display="json")["stdout"][0]
            if not json_output["failed"]:
                ipv4_addresses = json_output["configuration"]["interfaces"]["interface"][0]["unit"][0]["family"][
                    "inet"
                ]["address"]
                for address in ipv4_addresses:
                    if "primary" in address:
                        return address["name"]
                else:
                    return "loopback ipv4 address not find"
            else:
                return "Failed to get IPv4 address via ansible"
        except Exception as e:
            return "Failed to get IPv4 address due to {}".format(str(e))

    def remove_int_from_portchan(self, interface, pcnum):
        """
        remove interface from interface ae
        :param interface: The interface name
        :param pcnum: portchannel number
        :return: boolean, message
        """
        try:
            commands = ["deactivate interfaces {} gigether-options 802.3ad".format(interface)]
            output = self.config(lines=commands, comment="deactivate interface {} from ae {}".format(interface, pcnum))
            if not output["failed"]:
                return True, "Deactivated interface {} from ae{}".format(interface, pcnum)
            return False, "Failed to deactivate interface {} from ae{}".format(interface, pcnum)
        except Exception as e:
            return False, "Failed to deactivate interface {} from ae{} due to {}".format(interface, pcnum, str(e))

    def put_int_in_portchan(self, interface, pcnum):
        """
        remove interface from ae
        :param interface: The interface name
        :param pcnum: portchannel number
        :return:  boolean, message
        """
        try:
            commands = ["activate interfaces {} gigether-options 802.3ad".format(interface)]
            output = self.config(lines=commands, comment="activate interface {} from ae {}".format(interface, pcnum))
            if not output["failed"]:
                return True, "Activated interface {} from ae{}".format(interface, pcnum)
            return False, "Failed to activate interface {} from ae{}".format(interface, pcnum)
        except Exception as e:
            return False, "Failed to activate interface {} from ae{} due to {}".format(interface, pcnum, str(e))

    def reboot_chassis(self):
        try:
            command = "request system reboot both-routing-engines"
            output = self.commands(commands=[command])
            if not output["failed"]:
                return True, output
            return False, output
        except Exception as e:
            return False, "Failed to reboot the device {}. due to {}".format(self.hostname, str(e))
