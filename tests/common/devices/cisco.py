import re
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
