import re
import xml.etree.ElementTree as ET
import json
import time
from tests.common.devices.vendor import VendorHost



SAMPLE_COMMAND_DATA = '''
Fri May  6 07:39:37.061 UTC
Capability codes:
        (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
        (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other

Device ID       Local Intf               Hold-time  Capability     Port ID
vlab-02         GigabitEthernet0/0/0/1   120        B,R             fortyGigE0/4
ARISTA01T1      GigabitEthernet0/0/0/4   120        B,R             fortyGigE0/0

Total entries displayed: 2
'''


# def parse_cisco_lldp_neighbors(cmd_result):
#     '''
#     parse lldp neighbors facts
#     '''
#     facts = defaultdict(dict)
#     header = 'Device ID       Local Intf               Hold-time  Capability     Port ID'
#     footer = 'Total entries displayed:'
#     result_lines = cmd_result
#     table_start = False
#     while len(result_lines) != 0:
#         line = result_lines.pop(0)
#         if not table_start:
#             if header in line:
#                 table_start = True
#                 continue
#         elif footer in line:
#             break
#         elif len(line) > 0:
#             entry = dict()
#             fields = line.strip().split()
#             if len(fields) == 5:
#                 entry['deviceid'] = fields[0]
#                 entry['holdtime'] = fields[2]
#                 entry['capability'] = fields[3]
#                 entry['portid'] = fields[4]
#                 facts['lldp_neighbor'][fields[1]] = entry
#     return facts


def parse_header(header, pattern):
    # Parse header, store keys to fields
    elems = re.finditer(pattern, header)

    # Get field span for every fields
    span = []
    for elem in elems:
        span.append(elem.span()[0])

    # Get field length except the last one
    fieldslen = [span[i+1] - span[i] for i in range(len(span)-1)]

    # Setup pattern, grasp the fixed length of every field
    line_pattern = ''
    for length in fieldslen:
        line_pattern += '(.{{{}}})'.format(length)

    # For the last field, grasp the remaining content
    line_pattern += '(.*)'

    return fieldslen, line_pattern

def parse_content(header, header_pattern, line, line_pattern):
    # Find header fields
    header_fields = re.findall(header_pattern, header)

    # Find line fields
    result = re.match(line_pattern, line)

    line_dict = dict()
    for index, field in enumerate(header_fields, start=1):
        line_dict[field] = result.group(index).strip()

    return line_dict

def parse_table(cmd_result, header, footer):
    # Remove escape character
    cmd_result = cmd_result.replace('\r', '')
    # The first line is the command, so ignore the command
    cmd_lines = cmd_result.split("\n")[1:-1]
    # Remove empty lines
    cmd_lines = [item for item in cmd_lines if item != '']

    header_pattern = r'\S+ \S+|\S+'

    # Get every fields length and line pattern
    fieldslen, line_pattern = parse_header(header, header_pattern)

    table_start = False
    result = dict()
    while len(cmd_lines) != 0:
        line = cmd_lines.pop(0)
        if not table_start:
            if header in line:
                table_start = True
                continue
        elif footer in line:
            break
        else:
            result[len(result)] = parse_content(header, header_pattern, line, line_pattern)
    
    return result


class CiscoHost(VendorHost):
    """
    @summary: Class for Cisco host
    """
    def __init__(self, hostname, hostaddr, shell_user, shell_passwd):
        super(CiscoHost, self).__init__(hostname, hostaddr, shell_user, shell_passwd)
    
    def connect(self):
        super(CiscoHost, self).connect(prompt='#')
        self.command('terminal length 0')
        self.enter_config_mode()

    def __str__(self):
        return '<CiscoHost {}>'.format(self.hostname)

    def show_lldp_neighbor(self):
        self.exit_config_mode()
        cmd_result = self.command('show lldp neighbors')
        return parse_table(cmd_result,
                        header='Device ID       Local Intf               Hold-time  Capability     Port ID',
                        footer='Total entries displayed:')

    def isis_config_auth(self, key):
        # enter configure mode
        self.enter_config_mode()

        # configure key chain
        key_chain = """
                    key chain ISIS key 1 accept-lifetime 00:00:00 december 01 2014 infinite
                    key chain ISIS key 1 send-lifetime 00:00:00 december 01 2014 infinite
                    key chain ISIS key 1 cryptographic-algorithm HMAC-MD5
                    """
        self.command(key_chain)
        self.command('key chain ISIS key 1 key-string clear {}'.format(key))

        # configure key chain to isis
        self.command('router isis test lsp-password keychain ISIS level 2')
        self.command('router isis test interface Bundle-Ether1 hello-password keychain ISIS')
        self.command('commit')

    def isis_remove_auth(self, key):
        # enter configure mode
        self.enter_config_mode()

        # remove key chain
        self.command('no router isis test lsp-password keychain ISIS level 2')
        self.command('no router isis test interface Bundle-Ether1 hello-password keychain ISIS')

        # remove key chain to isis
        self.command('no key chain ISIS')
        self.command('commit')

    def ping_dest(self, dest):
        self.exit_config_mode()
        cmd_result = self.command('ping {} count 5'.format(dest))
        return re.search('!!!!!', cmd_result) != None
    
    def show_command_to_xml(self, command):
        """
        This function will pull the show operationalcommand output as XML string and convert it XML object and return
        """
        input_buffer = self.exit_config_mode()
        clock_output = self.command("show clock")
        xml_command = command + " xml"
        output = self.command(xml_command)
        #remove first and last 2 lines
        self.disconnect()
        output = "\r\n".join(output.split("\r\n")[2:-2])
        return  ET.fromstring(output)

    def show_command_to_json(self, command, lookup_key=None, lookup_val=None):
        """
        This function will pull the show operational command output as json string and convert it json object and return
        """
        try:
            self.exit_config_mode()
            json_command = command + " json"
            clock_output = self.command("show clock")
            output = self.command(json_command)
            self.disconnect()
            output = "\n".join(output.split("\r\n")[2:-1])
            json_result = json.loads(output, strict=False)
            if all([lookup_key, lookup_val]):
                return self.extract_key_val_pair_from_json(json_result, lookup_key)
            elif lookup_key is not None and lookup_val is None:
                return self.extract_val_from_json(json_result, lookup_key)
            else:
                return json_result
        except Exception as e:
            return {"error": e}

    def extract_key_val_pair_from_json(self, data, lookup_key):
        """
        Function to recursivly match provided key in all levels and return list of same level data
        """
        result = []

        def help(data, lookup_key, result):
            if isinstance(data, dict):
                for k, v in data.items():
                    if k == lookup_key:
                        result.append(data)
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
        help(data, lookup_key, result)
        return result
    
    def extract_val_from_json(self, json_data, lookup_key):
        """
        Function to recursivly match provided key in all levels and return matched key's value into a list
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

    def cisco_xr_commit_config(self):
        #commit junos config
        self.command("commit confirm 60")
        time.sleep(40)
        self.command("commit")

    def config_command(self, command):
        """
        This function try to load and commit command/s into the device from config mode, only support IOS XR only. 
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
            self.cisco_xr_commit_config()
            self.exit_config_mode()
            self.disconnect()
            return (True, "The command {} loaded into device {}".format(command, self.hostname))
        except Exception as e:
            return (False, e)
