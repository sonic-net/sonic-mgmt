import json
import re
import pdb
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
        super(AristaHost, self).connect(prompt='>')
        self.command('enable')
        self.command('terminal length 0')
        self.enter_config_mode()

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






