import re
import time
import json
from tests.common.devices.vendor import VendorHost


class JuniperHost(VendorHost):
    """
    @summary: Class for Juniper host
    """
    def __init__(self, hostname, hostaddr, shell_user, shell_passwd):
        super(JuniperHost, self).__init__(hostname, hostaddr, shell_user, shell_passwd)

    def connect(self):
        super(JuniperHost, self).connect(prompt='>')
        self.command('set cli screen-length 0')

    def __str__(self):
        return '<JuniperHost {}>'.format(self.hostname)

    def get_prompt(self, first_prompt, init_prompt):
        lines = first_prompt.split('\n')
        prompt = lines[-1]
        # match all modes - rwa02.str01>, rwa02.str01#
        return prompt.strip()[:-1] + '.'

    def enter_junos_config_mode(self):
        #enter junos config mode
        self.command("configure exclusive")

    def exit_junos_config_mode(self):
        self.command("top")
        self.command("exit")
    
    def junos_commit_config(self):
        #commit junos config
        self.command("commit confirm 1")
        time.sleep(40)
        self.command("commit")

    def config_command(self, command):
        """
        This function try to load command/s into the device from config mode,
        """
        try:
            self.enter_junos_config_mode()
            #one line string command
            if isinstance(command, str):
                self.command(command)
            #list of one line string commands
            elif isinstance(command, list):
                for cmd in command:
                    self.command(cmd)
            self.junos_commit_config()
            self.exit_config_mode()
            self.disconnect()
            return (True, "The command {} loaded into device {}".format(command, self.hostname))
        except Exception as e:
            return (False, e)

    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        '''
        This function will run show command on the junos and get data in json and return json format dict.
        '''
        try:
            json_command = command + '| display json'
            if not self._connected:
                self.connect()
            cmd_result = self.command(json_command)
            time.sleep(0.5)
            self.disconnect()
            json_result = self._convert_json_output_to_dict(command, cmd_result)
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(json_result, lookup_key, lookup_val)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(json_result, lookup_key)
            else:
                return json_result
        except Exception as e:
            return {"error": e}

    def _convert_json_output_to_dict(self, cmd, cmd_output):
        '''
        >>>This function will remove redundant content and convert the output to dict and verified the following show command output:
        show lldp neighbor
        show lacp interface
        show version
        show isis adj
        show isis interface
        show bgp summary
        show bgp neighbor
        show config
        show interface extensive
        show interface terse
        show interfaces diagnostics optics
        >>>The following command is not currently support:
        show interface descripitions
        request pfe execute
        '''
        try:
            left_index = 0
            right_index = 0
            cmd_output = cmd_output.split("\r\n")
            #find first "{" index as left_index
            for index in range(len(cmd_output)):
                if '{' in cmd_output[index]:
                    left_index = index
                    break
            #find last "}" index as right_index
            for index in range(len(cmd_output) - 1, -1, -1):
                if '}' in cmd_output[index]:
                    right_index = index + 1
                    break
            #slice the content to remove redundant content and keep the json only
            cmd_output = cmd_output[left_index:right_index]
            return json.loads('\n'.join(cmd_output), strict = False)
        except Exception as e:
            return {'error':'Please check if function _convert_json_output_to_dict is support command {} output ?\r\n{}'.format(cmd,e)}

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
                for k, v in json_data.iteritems():
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
                for k, v in json_data.iteritems():
                    if k == lookup_key and v[0]['data'] == lookup_val:
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
