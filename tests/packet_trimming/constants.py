from tests.packet_trimming.packet_trimming_config import PacketTrimmingConfig

# ACL configuration constants
ACL_TABLE_TYPE_NAME = "TRIMMING_L3"
ACL_TABLE_NAME = "TRIM_TABLE"
ACL_RULE_NAME = "TRIM_RULE"
ACL_RULE_PRIORITY = "999"
ACL_DISABLE_SRC_IP = "1.1.1.1/32"
ACL_NORMAL_SRC_IP = "1.1.1.2/32"

# Packet constants
DEFAULT_SRC_IP = "10.0.0.1"
DEFAULT_DST_IP = "10.0.0.2"
DEFAULT_SRC_IPV6 = "2001:db8::1"
DEFAULT_DST_IPV6 = "2001:db8::2"
DEFAULT_SRC_PORT = 4321
DEFAULT_DST_PORT = 1234
DEFAULT_DSCP = 1   # Map to queue1
DEFAULT_PACKET_SIZE = 400
DEFAULT_TTL = 64
JUMBO_PACKET_SIZE = 5000
MIN_PACKET_SIZE = 100
DUMMY_IP = "8.8.8.8"
DUMMY_IPV6 = "8000::2"
DUMMY_MAC = "00:11:22:33:44:55"
PACKET_COUNT = 1000
BATCH_PACKET_COUNT = 10000
ECN = 2   # ECN Capable Transport(0), ECT(0)

# Buffer configuration constants
TRIM_QUEUE_PROFILE = "egress_lossy_profile"
DYNAMIC_TH = "3"
TRIMMING_CAPABILITY = "SAI_ADAPTIVE_ROUTING_CIRCULATION_PORT=257"
STATIC_THRESHOLD_MULTIPLIER = 1.5   # Multiplier to ensure the buffer can be fully exhausted

# Asymmetric DSCP constants
ASYM_PORT_1_DSCP = 10
ASYM_PORT_2_DSCP = 20

# Test constants
PORT_TOGGLE_COUNT = 10    # number of times to toggle admin state
CONFIG_TOGGLE_COUNT = 10  # number of times to toggle configuration
MODE_TOGGLE_COUNT = 5     # number of times to toggle Symmetric and Asymmetric mode
NORMAL_PACKET_DSCP = 4    # DSCP value for normal packet

BLOCK_DATA_PLANE_SCHEDULER_NAME = "SCHEDULER_BLOCK_DATA_PLANE"
SCHEDULER_TYPE = "DWRR"
SCHEDULER_WEIGHT = 15
SCHEDULER_PIR = 1
SCHEDULER_CIR = 1
SCHEDULER_METER_TYPE = 'packets'

DATA_PLANE_QUEUE_LIST = ["0", "1", "2", "3", "4", "5", "6"]
DEFAULT_QUEUE_SCHEDULER_CONFIG = {
    "0": "scheduler.0",
    "1": "scheduler.0",
    "2": "scheduler.0",
    "3": "scheduler.1",
    "4": "scheduler.1",
    "5": "scheduler.0",
    "6": "scheduler.0"
}

PACKET_TYPE = ['ipv4_tcp', 'ipv4_udp', 'ipv6_tcp', 'ipv6_udp']
SERVICE_PORT = "Ethernet512"

# Constants for packet trimming with SRv6 tests
SRV6_INNER_SRC_IP = '1.1.1.1'
SRV6_INNER_DST_IP = '2.2.2.2'
SRV6_INNER_SRC_IPV6 = '2000::1'
SRV6_INNER_DST_IPV6 = '3000::2'
SRV6_OUTER_SRC_IPV6 = '1000:1000::1'

SRV6_UN = 'uN'
SRV6_PREFIX_LEN = '48'
SRV6_PIPE_MODE = 'pipe'
SRV6_UNIFORM_MODE = 'uniform'

SRV6_PACKETS = [
    {   # SRv6 packet without srh header
        'action': SRV6_UN,
        'packet_type': 'reduced_srh',
        'srh_seg_left': None,
        'srh_seg_list': None,
        'inner_dscp': None,
        'outer_dscp': None,
        'dst_ipv6': '2001:1000:0100:0200::',
        'exp_dst_ipv6': '2001:1000:0200::',
        'exp_inner_dscp_pipe': None,
        'exp_outer_dscp_uniform': PacketTrimmingConfig.DSCP << 2,
        'exp_srh_seg_left': None,
        'inner_pkt_ver': '4',
        'exp_process_result': 'forward',
    },
    {   # SRv6 packet with srh header
        'action': SRV6_UN,
        'packet_type': 'two_u_sid',
        'srh_seg_left': 1,
        'inner_dscp': None,
        'outer_dscp': None,
        'srh_seg_list': [
            '2001:3000:0500:0600::',
            '2001:3000:0600:0700:0800:0900:0a00::'
        ],
        'dst_ipv6': '2001:3000:0500::',
        'exp_dst_ipv6': '2001:3000:0500:0600::',
        'exp_inner_dscp_pipe': None,
        'exp_outer_dscp_uniform': PacketTrimmingConfig.DSCP << 2,
        'exp_srh_seg_left': 0,
        'inner_pkt_ver': '4',
        'exp_process_result': 'forward'
    }
]

SRV6_MY_LOCATOR_LIST = [
    ['locator_1', '2001:1000:100::'],
    ['locator_2', '2001:1001:200::'],
    ['locator_3', '2001:2000:300::'],
    ['locator_4', '2001:2001:400::'],
    ['locator_5', '2001:3000:500::'],
    ['locator_6', '2001:3001:600::'],
    ['locator_7', '2001:4000:700::'],
    ['locator_8', '2001:4001:800::'],
    ['locator_9', '2001:5000:900::'],
    ['locator_10', '2001:5001:a00::']
]

SRV6_TUNNEL_MODE = [SRV6_PIPE_MODE]

SRV6_MY_SID_LIST = [
    [SRV6_MY_LOCATOR_LIST[0][0], SRV6_MY_LOCATOR_LIST[0][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[1][0], SRV6_MY_LOCATOR_LIST[1][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[2][0], SRV6_MY_LOCATOR_LIST[2][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[3][0], SRV6_MY_LOCATOR_LIST[3][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[4][0], SRV6_MY_LOCATOR_LIST[4][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[5][0], SRV6_MY_LOCATOR_LIST[5][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[6][0], SRV6_MY_LOCATOR_LIST[6][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[7][0], SRV6_MY_LOCATOR_LIST[7][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[8][0], SRV6_MY_LOCATOR_LIST[8][1], SRV6_UN, 'default'],
    [SRV6_MY_LOCATOR_LIST[9][0], SRV6_MY_LOCATOR_LIST[9][1], SRV6_UN, 'default']
]

# Drop counter
SWITCH_INTERVAL = 1000
PORT_INTERVAL = 100
QUEUE_INTERVAL = 100

COUNTER_TYPE = [
    ("switch", "SWITCH_STAT", SWITCH_INTERVAL),
    ("port", "PORT_STAT", PORT_INTERVAL),
    ("queue", "QUEUE_STAT", QUEUE_INTERVAL),
]

# Mirror session configuration
MIRROR_SESSION_NAME = "test_mirror"
MIRROR_SESSION_SRC_IP = "1.1.1.1"
MIRROR_SESSION_DST_IP = "2.2.2.2"
MIRROR_SESSION_DSCP = 8
MIRROR_SESSION_TTL = 64
MIRROR_SESSION_GRE = 0x8949
MIRROR_SESSION_QUEUE = 0
