from tests.common.snappi.snappi_fixtures import create_ip_list
from functools import reduce

###############################################################
#                  Declaring Global variables
###############################################################
TGEN_AS_NUM = 65300
TIMEOUT = 30
FLAP_TIME = 45
BGP_TYPE = 'ebgp'
ITERATION = 2
NG_LIST = []
AS_PATHS = [64000]
ROUTE_TYPE = 'ipv4'
NO_OF_ROUTES = 16000
#RX_DUTS_PORT_RATIO is nth DUT and n number of ports associated on the receiver side
RX_DUTS_PORT_RATIO = [(1, 0), (2, 1), (3,1)]
NO_OF_TX_PORTS = 1

sleep10 = 10
ipMask = 24
ipv6Mask = 64
port_speed = "speed_400_gbps"
tolerenceVal = 10
tolerence_pkts = 500
no_of_ports=int(NO_OF_TX_PORTS) + reduce(lambda x,y : x+y , [val[1] for val in RX_DUTS_PORT_RATIO]) 
dutIps = create_ip_list("100.1.0.1", no_of_ports, mask=8)
tgenIps = create_ip_list("100.1.0.2", no_of_ports, mask=8)
dutV6Ips = create_ip_list("1000:0:0:1:0:0:0:1", no_of_ports, mask=64)
tgenV6Ips = create_ip_list("1000:0:0:1:0:0:0:2", no_of_ports, mask=64)
dutsAsNum = [65000, 65001, 65002]
inter_dut_network_start = '20.0.0.1'
if ROUTE_TYPE == 'ipv6':
    tgenIps = tgenV6Ips