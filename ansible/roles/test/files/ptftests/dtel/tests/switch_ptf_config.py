import os
import sys
from ptf_infra import *
this_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(this_dir, '../euclid'))
from sonic import sonic_switch
import collections
from dtel.infra import *

set_int_l45_dscp(value=0x01, mask=0x01)

mac_all_zeros = '00:00:00:00:00:00'

# change the following params per your target test switch perspective
swports = [0, 1, 2]
fpports = ['1/-', '2/-', '3/-']
# For access to DUT we are tunneling from PTF-host via the mgmt docker
switch_ip = '127.0.0.1'
mac_self = '00:90:fb:5c:e1:91'
ipaddr_nbr = ['10.0.0.1', '10.0.0.3', '10.0.0.5']
mac_nbr = ['3c:fd:fe:a2:80:60', '3c:fd:fe:a2:80:60', '3c:fd:fe:a2:80:60']

report_ports = [2]
report_src = switch_ip
report_dst = ['10.0.0.5']
report_udp_port = UDP_PORT_DTEL_REPORT
report_truncate_size = 512
switch_id = 1
high_latency_sensitivity = MAX_QUANTIZATION
low_latency_sensitivity = 0
