from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.utils.display import Display
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError

import re

DOCUMENTATION = """
        lookup: cisco_8101_port_convert
        version_added: "1.0"
        short_description: find port name and alias for Cisco-8101 devices
        description:
            - This lookup returns [port name, port alias] of the given port.
        options:
          _terms:
            description: list of port name
            required: True
          output:
            description: output port type, could only be sonic or alias
            required: True
          speed:
            description: speed of input port
            required: False
"""

display = Display()

# name         lanes                  alias   index  speed     subport
port_config = """
Ethernet0      2304,2305,2306,2307    etp0a     0    100000      1
Ethernet4      2308,2309,2310,2311    etp0b     0    100000      2
Ethernet8      2320,2321,2322,2323    etp1a     1    100000      1
Ethernet12     2324,2325,2326,2327    etp1b     1    100000      2
Ethernet16     2312,2313,2314,2315    etp2a     2    100000      1
Ethernet20     2316,2317,2318,2319    etp2b     2    100000      2
Ethernet24     2056,2057,2058,2059    etp3a     3    100000      1
Ethernet28     2060,2061,2062,2063    etp3b     3    100000      2
Ethernet32     1792,1793,1794,1795    etp4a     4    100000      1
Ethernet36     1796,1797,1798,1799    etp4b     4    100000      2
Ethernet40     2048,2049,2050,2051    etp5a     5    100000      1
Ethernet44     2052,2053,2054,2055    etp5b     5    100000      2
Ethernet48     2560,2561,2562,2563    etp6a     6    100000      1
Ethernet52     2564,2565,2566,2567    etp6b     6    100000      2
Ethernet56     2824,2825,2826,2827    etp7a     7    100000      1
Ethernet60     2828,2829,2830,2831    etp7b     7    100000      2
Ethernet64     2832,2833,2834,2835    etp8a     8    100000      1
Ethernet68     2836,2837,2838,2839    etp8b     8    100000      2
Ethernet72     2816,2817,2818,2819    etp9a     9    100000      1
Ethernet76     2820,2821,2822,2823    etp9b     9    100000      2
Ethernet80     2568,2569,2570,2571    etp10a   10    100000      1
Ethernet84     2572,2573,2574,2575    etp10b   10    100000      2
Ethernet88     2576,2577,2578,2579    etp11a   11    100000      1
Ethernet92     2580,2581,2582,2583    etp11b   11    100000      2
Ethernet96     1536,1537,1538,1539    etp12a   12    100000      1
Ethernet100    1540,1541,1542,1543    etp12b   12    100000      2
Ethernet104    1800,1801,1802,1803    etp13a   13    100000      1
Ethernet108    1804,1805,1806,1807    etp13b   13    100000      2
Ethernet112    1552,1553,1554,1555    etp14a   14    100000      1
Ethernet116    1556,1557,1558,1559    etp14b   14    100000      2
Ethernet120    1544,1545,1546,1547    etp15a   15    100000      1
Ethernet124    1548,1549,1550,1551    etp15b   15    100000      2
Ethernet128    1296,1297,1298,1299    etp16a   16    100000      1
Ethernet132    1300,1301,1302,1303    etp16b   16    100000      2
Ethernet136    1288,1289,1290,1291    etp17a   17    100000      1
Ethernet140    1292,1293,1294,1295    etp17b   17    100000      2
Ethernet144    1280,1281,1282,1283    etp18a   18    100000      1
Ethernet148    1284,1285,1286,1287    etp18b   18    100000      2
Ethernet152    1032,1033,1034,1035    etp19a   19    100000      1
Ethernet156    1036,1037,1038,1039    etp19b   19    100000      2
Ethernet160    264,265,266,267        etp20a   20    100000      1
Ethernet164    268,269,270,271        etp20b   20    100000      2
Ethernet168    272,273,274,275        etp21a   21    100000      1
Ethernet172    276,277,278,279        etp21b   21    100000      2
Ethernet176    16,17,18,19            etp22a   22    100000      1
Ethernet180    20,21,22,23            etp22b   22    100000      2
Ethernet184    0,1,2,3                etp23a   23    100000      1
Ethernet188    4,5,6,7                etp23b   23    100000      2
Ethernet192    256,257,258,259        etp24a   24    100000      1
Ethernet196    260,261,262,263        etp24b   24    100000      2
Ethernet200    8,9,10,11              etp25a   25    100000      1
Ethernet204    12,13,14,15            etp25b   25    100000      2
Ethernet208    1024,1025,1026,1027    etp26a   26    100000      1
Ethernet212    1028,1029,1030,1031    etp26b   26    100000      2
Ethernet216    768,769,770,771        etp27a   27    100000      1
Ethernet220    772,773,774,775        etp27b   27    100000      2
Ethernet224    524,525,526,527        etp28a   28    100000      1
Ethernet228    520,521,522,523        etp28b   28    100000      2
Ethernet232    776,777,778,779        etp29a   29    100000      1
Ethernet236    780,781,782,783        etp29b   29    100000      2
Ethernet240    516,517,518,519        etp30a   30    100000      1
Ethernet244    512,513,514,515        etp30b   30    100000      2
Ethernet248    528,529,530,531        etp31a   31    100000      1
Ethernet252    532,533,534,535        etp31b   31    100000      2
"""


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        display.debug("Cisco-8101 port lookup: {}".format(terms))
        self.set_options(var_options=variables, direct=kwargs)
        output = self.get_option("output")
        speed = self.get_option("speed")
        ret = []
        for port in terms:
            match_result = re.findall(r"(^etp([0-9]+)([ab]?)$)|(^Ethernet([0-9]+)$)", port)
            if len(match_result) != 1:
                raise AnsibleError("port {} is illegal".format(port))
            match_result = match_result[0]
            if match_result[0]:
                alias = match_result[0]
                sonic_port_index = int(match_result[1]) * 8 + 4 * (match_result[2] == "b")
                sonic_name = "Ethernet{}".format(sonic_port_index)
            elif match_result[3]:
                sonic_name = match_result[3]
                sonic_port_index = int(match_result[4])
                if speed == "400000":
                    if sonic_port_index % 8:
                        raise AnsibleError("port {} is not legal 400G port".format(port))
                    alias = "etp{}".format(sonic_port_index // 8)
                elif speed == "100000":
                    if sonic_port_index % 4:
                        raise AnsibleError("port {} is not legal 100G port".format(port))
                    alias = "etp{}{}".format(sonic_port_index // 8, "b" if sonic_port_index // 4 % 2 else "a")
                else:
                    raise AnsibleError("speed {} is illegal".format(speed))
            if output == "alias":
                ret.append(alias)
            elif output == "sonic":
                ret.append(sonic_name)
            elif output == "lanes":
                lines = port_config.splitlines()
                regex = re.compile(r"^\S+\s+(\S+)")
                line_index = sonic_port_index // 4 + 1
                if speed == "100000":
                    ret.append(regex.findall(lines[line_index])[0])
                elif speed == "400000":
                    ret.append(regex.findall(lines[line_index])[0] + "," + regex.findall(lines[line_index + 1])[0])
            elif output == "index":
                ret.append(str(sonic_port_index // 8))
            elif output == "subport":
                if speed == "100000":
                    ret.append(str(1 + sonic_port_index // 4 % 2))
                elif speed == "100000":
                    ret.append("0")
            else:
                raise AnsibleError("output parameter must be provided (sonic, alias, lanes, index, or subport)")
        return ret
