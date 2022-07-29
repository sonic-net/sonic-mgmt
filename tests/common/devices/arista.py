import json
import re
from tests.common.devices.cisco import VendorHost


SAMPLE_COMMAND_DATA = ''' vlab-04#show lldp neighbors | json 
{
    "tablesLastChangeTime": 1652231658.9400651,
    "tablesAgeOuts": 2,
    "tablesInserts": 5,
    "lldpNeighbors": [
        {
            "ttl": 120,
            "neighborDevice": "vlab-03",
            "neighborPort": "fortyGigE0/12",
            "port": "Ethernet4"
        },
        {
            "ttl": 120,
            "neighborDevice": "ARISTA02T1",
            "neighborPort": "fortyGigE0/0",
            "port": "Ethernet7"
        }
    ],
    "tablesDeletes": 3,
    "tablesDrops": 0
} '''


class AristaHost(VendorHost):
    """
    @summary: Class for Arista host
    """
    def __init__(self, hostname, hostaddr, shell_user, shell_passwd):
        super(AristaHost, self).__init__(hostname, hostaddr, shell_user, shell_passwd)
    
    def connect(self):
        super(AristaHost, self).connect(prompt='#')
        self.command('terminal length 0')

    def __str__(self):
        return '<AristaHost {}>'.format(self.hostname)

    def show_lldp_neighbor(self):
        cmd_result = self.command("show lldp neighbors | json")
        cmd_result = "\n".join(cmd_result.split("\r\n")[1:-1])
        return json.loads(cmd_result, strict=False)

    def isis_config_auth(self, key):
        # enter configure mode
        self.enter_config_mode()

        # configure lsp authentication key
        cmd = """
            router isis test1
            authentication mode md5
            authentication key {} level-2
            """.format(key)
        self.command(cmd)

        # configure hello authentication key
        cmd = """
            interface Port-Channel2
            isis authentication mode md5
            isis authentication key {} level-2
            """.format(key)
        self.command(cmd)
    
    def isis_remove_auth(self, key):
        # enter configure mode
        self.enter_config_mode()

        # remove lsp authentication key
        cmd = """
            router isis test1
            no authentication mode md5
            no authentication key {} level-2
            """.format(key)
        self.command(cmd)

        # remove hello authentication key
        cmd = """
            interface Port-Channel2
            no isis authentication mode md5
            no isis authentication key {} level-2
            """.format(key)
        self.command(cmd)
    
    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        try:
            json_command = command + " | json"
            output_result = self.command(json_command)
            self.disconnect()
            output_result = "\n".join(output_result.split("\r\n")[1:-1])
            json_result = json.loads(output_result, strict=False)
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(json_result, lookup_key, lookup_val)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(json_result, lookup_key)
            else:
                return json_result
        except Exception as e:
            return {"error": e}

    def extract_val_from_json(self, json_data, lookup_key):
        """
        Function to recursivly match provided key in all levels and put the matched key's value into a list for return
        """
        result = []

        def help(data, lookup_key, result):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == lookup_key:
                        result.append(v)
                    elif isinstance(v, (list, dict)):
                        sub_result = help(v, lookup_key, result)
                        if sub_result:
                            result.append(sub_result)
            elif isinstance(data, list):
                for ele in data:
                    if isinstance(ele, (list, dict)):
                        sub_result = help(ele, lookup_key, result)
                        if sub_result:
                            result.append(sub_result)
        help(json_data, lookup_key, result)
        return result

    def extract_key_val_pair_from_json(self, data, lookup_key, lookup_val):
        """
        Function to recursivly match provided key in all levels and put the matched key and value pair into a list for return
        """
        result = []
        
        def help(data, lookup_key, lookup_val, result):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == lookup_key and v == lookup_val:
                        result.append(data)
                    elif isinstance(v, (list, dict)):
                        sub_result = help(v, lookup_key, lookup_val, result)
                        if sub_result:
                            result.append(sub_result)
            elif isinstance(data, list):
                for ele in data:
                    if isinstance(ele, (list, dict)):
                        sub_result = help(ele, lookup_key, lookup_val, result)
                        if sub_result:
                            result.append(sub_result)
        help(data, lookup_key, lookup_val, result)
        return result

    def config_command(self, command):
        """
        This function try to load command/s into the device from config mode
        """
        try:
            self.exit_config_mode()
            self.enter_config_mode()
            #one line string command
            if isinstance(command, str):
                self.command(command)
            #list of one line string commands
            elif isinstance(command, list):
                for cmd in command:
                    self.command(cmd)
            self.exit_config_mode()
            #save configuration
            self.command("write memory")
            self.disconnect()
            return (True, "The command {} loaded into device {}".format(command, self.hostname))
        except Exception as e:
            return (False, e)
