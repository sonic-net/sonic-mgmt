
"""
Platform SNT (System Network Test) Configuration Schema

This module defines the configuration schema for SNT traffic testing and BGP route
advertisement across different Cisco platform variants. It provides a centralized
configuration structure for VRF traffic testing, BGP route configuration, and
platform-specific parameters.

Schema Structure:
================

1. Traffic Configurations (vrf_traffic_configs)
   - Defines various traffic patterns for network testing
   - Supports IPv4 traffic streams with customizable parameters
   - Includes pre/inline/post actions for complex test scenarios

2. BGP Route Advertisement Configurations (bgp_route_adv_configs)
   - Defines BGP route advertisement patterns
   - Supports IPv4 route configurations with variable route counts
   - Configurable prefix ranges and route quantities

3. Platform Configurations (platform_vrf_config)
   - Platform-specific network parameters
   - Port mappings and bandwidth specifications
   - BGP ASN assignments and IP addressing schemes

Traffic Configuration Types:
===========================

fixed_traffic:
    - Single IPv4 stream with fixed parameters
    - 95% utilization, 120-second duration
    - Fixed 1518-byte frame length
    - Pattern: aa55 (fixed mode)

mixed_traffic:
    - Single IPv4 stream with variable parameters
    - Incremental byte pattern (starts from 00)
    - Variable frame length (64-9000 bytes)
    - Increment length mode

snt_traffic:
    - Complex multi-stream traffic pattern (6 streams)
    - Multiple patterns with BGP route advertisement actions
    - Random frame lengths (800-1500 bytes)
    - Patterns: aa55, d9d9, 0000, 0F0F, 5555, 0F55

default_traffic:
    - Combination of fixed and mixed traffic patterns
    - Two test scenarios (t1: fixed, t2: mixed)
    - Standard utilization and duration parameters

BGP Route Configuration Types:
=============================

ipv4_300k:
    - 300,000 total IPv4 routes
    - Three prefix ranges: 10.0.1.0, 11.0.1.0, 12.0.1.0
    - 100,000 routes per prefix

ipv4_100k:
    - 100,000 total IPv4 routes
    - Two prefix ranges: 10.0.1.0, 11.0.1.0
    - 50,000 routes per prefix

Platform Configuration Parameters:
=================================

Core Parameters:
    - pid: Platform identifier
    - data_ports: Number of data ports
    - max_bw: Maximum bandwidth per port
    - bidir: Bidirectional traffic support (y/n)
    - cfg_reload_timer: Configuration reload timeout (seconds)

Network Configuration:
    - tgenp1_ipv4/tgenp2_ipv4: Traffic generator port IP addresses
    - dutp1_ipv4/dutp2_ipv4: Device under test port IP addresses
    - tgenp1_mac/tgenp2_mac: Traffic generator MAC addresses
    - tgenp1_asn/tgenp2_asn: Traffic generator BGP ASN numbers
    - dutp1_asn/dutp2_asn: Device under test BGP ASN numbers

Port Mapping:
    - io_ports: Dictionary mapping tx_port and rx_port to Ethernet interfaces
    - bgp_route_cfg_type: Reference to BGP route configuration type
    - traffic_cfg_type: Reference to traffic configuration type

Traffic Stream Schema:
=====================

Stream Object Structure:
    {
        "pattern": "hex_pattern",        # Traffic pattern (e.g., "aa55", "0000")
        "pattern_mode": "mode",          # Pattern generation mode
        "length_mode": "mode",           # Frame length generation mode
        "minframelength": "bytes",       # Minimum frame size
        "maxframelength": "bytes"        # Maximum frame size
    }

Pattern Modes:
    - "fixed": Static pattern throughout test
    - "repeating": Pattern repeats across frames
    - "incr_byte": Incrementing byte pattern

Length Modes:
    - "fixed": Static frame length
    - "increment": Incrementing frame lengths
    - "random": Random frame lengths within range
"""
# Schema capturing the PID and the traffic configuration
# Common traffic configurations that can be reused across platforms
vrf_traffic_configs = {
    "fixed_traffic": [
        {
            "t1": {
                "name": "fixed_traffic",
                "stream_type": "ipv4",
                "stream_addr": "3.3.3.3",
                "bi_stream_addr": "5.5.5.5",
                "no_of_stream" : 1,
                "duration": "120",
                "ttl": "255",
                "pre-action": None,
                "inline-action": None,
                "post-action": None,
                "streams": [
                    {
                        "pattern": "aa55",
                        "pattern_mode": "fixed",
                        "length_mode": "fixed", #frame length ignored
                        "minframelength": "1518",
                        "maxframelength": "1518",
                    }
                ]
            }
        },
    ],
    "mixed_traffic": [
        {
            "t1": {
                "name": "mixed_traffic",
                "stream_type": "ipv4",
                "stream_addr": "3.3.3.3",
                "bi_stream_addr": "5.5.5.5",
                "no_of_stream" : 1,
                "duration": "120",
                "ttl": "255",
                "pre-action": None,
                "inline-action": None,
                "post-action": None,
                "streams": [
                    {
                        "pattern": "0000",
                        "pattern_mode": "incr_byte", #pattern is ignored and starts from 00
                        "length_mode": "increment",
                        "minframelength": "64",
                        "maxframelength": "9000",
                    }
                ]
            }
        },
    ],
    "snt_traffic": [
        {
            "t1": {
                "name": "killer_traffic",
                "stream_type": "ipv4",
                "stream_addr": "3.3.3.3",
                "bi_stream_addr": "5.5.5.5",
                "no_of_stream" : 6,
                "duration": "120",
                "ttl": "255",
                "pre-action": "pre_action_bgp_route_adv",
                "inline-action": "inline_action_bgp_route_adv",
                "post-action": "post_action_bgp_route_adv",
                "streams": [
                    {
                        "pattern": "aa55",
                        "pattern_mode": "repeating",
                        "length_mode": "random",
                        "minframelength": "800",
                        "maxframelength": "1500",
                    },
                    {
                        "pattern": "d9d9",
                        "pattern_mode": "repeating",
                        "length_mode": "random",
                        "minframelength": "800",
                        "maxframelength": "1500",
                    },
                    {
                        "pattern": "0000",
                        "pattern_mode": "repeating",
                        "length_mode": "random",
                        "minframelength": "800",
                        "maxframelength": "1500",
                    },
                    {
                        "pattern": "0F0F",
                        "pattern_mode": "repeating",
                        "length_mode": "random",
                        "minframelength": "800",
                        "maxframelength": "1500",
                    },
                    {
                        "pattern": "5555",
                        "pattern_mode": "repeating",
                        "length_mode": "random",
                        "minframelength": "800",
                        "maxframelength": "1500",
                    },
                    {
                        "pattern": "0F55",
                        "pattern_mode": "repeating",
                        "length_mode": "random",
                        "minframelength": "800",
                        "maxframelength": "1500",
                    }
                ]
            }
        },
    ],
    "default_traffic": [
        {
            "t1": {
                "name": "fixed_traffic",
                "stream_type": "ipv4",
                "stream_addr": "3.3.3.3",
                "bi_stream_addr": "5.5.5.5",
                "no_of_stream" : 1,
                "duration": "120",
                "ttl": "255",
                "pre-action": None,
                "inline-action": None,
                "post-action": None,
                "streams": [
                    {
                        "pattern": "aa55",
                        "pattern_mode": "fixed",
                        "length_mode": "fixed", #frame length ignored
                        "minframelength": "1518",
                        "maxframelength": "1518",
                    }
                ]
            }
        },
        {
            "t2": {
                "name": "mixed_traffic",
                "stream_type": "ipv4",
                "stream_addr": "3.3.3.3",
                "bi_stream_addr": "5.5.5.5",
                "no_of_stream" : 1,
                "duration": "120",
                "ttl": "255",
                "pre-action": None,
                "inline-action": None,
                "post-action": None,
                "streams": [
                    {
                        "pattern": "0000",
                        "pattern_mode": "incr_byte", #pattern is ignored and starts from 00
                        "length_mode": "increment",
                        "minframelength": "64",
                        "maxframelength": "1518",
                    }
                ]
            }
        },
    ]
}

# =============================================================================
# BGP ROUTE ADVERTISEMENT CONFIGURATION DICTIONARY
# =============================================================================

"""
BGP Route Advertisement Configuration Dictionary

This dictionary defines BGP route advertisement patterns for network testing
across different scale scenarios and platform capabilities.

Dictionary Structure:
    <config_type>: BGP route configuration with route prefixes and quantities

Route Configuration Parameters:

    Core Configuration:
        name:        Configuration identifier for logging and tracking
        route_type:  IP protocol version (ipv4, ipv6)
        routes:      List of route prefix configurations

    Route Prefix Configuration:
        prefix:      Base network prefix for route generation
        num_routes:  Number of routes to advertise from this prefix
"""
bgp_route_adv_configs = {
    "ipv4_300k": {
        "name": "snt_routes",
        "route_type": "ipv4",
        "routes": [
            {
                "prefix": "10.0.1.0",
                "num_routes": 60000,
            },
            {
                "prefix": "11.0.1.0",
                "num_routes": 60000,
            },
            {
                "prefix": "12.0.1.0",
                "num_routes": 60000,
            },
            {
                "prefix": "13.0.1.0",
                "num_routes": 60000,
            },
            {
                "prefix": "14.0.1.0",
                "num_routes": 60000,
            },
        ]
    },
    "ipv4_100k": {
        "name": "snt_routes",
        "route_type": "ipv4",
        "routes": [
            {
                "prefix": "10.0.1.0",
                "num_routes": 50000,
            },
            {
                "prefix": "11.0.1.0",
                "num_routes": 50000,
            },
        ]
    },
}


# =============================================================================
# PLATFORM VRF CONFIGURATION DICTIONARY
# =============================================================================

"""
Platform VRF Configuration Dictionary

This dictionary defines platform-specific VRF traffic testing configurations
for System Network Testing (SNT) across Cisco 8000 series platforms.

Dictionary Structure:
    traffic_configs:        Reference to vrf_traffic_configs (traffic patterns)
    bgp_route_adv_configs:  Reference to bgp_route_adv_configs (route advertisements)
    platforms:             Platform-specific network and traffic configurations

Platform Network Configuration Parameters:

    Core Platform Info:
        pid:               Platform identifier matching hardware model
        data_ports:        Number of data/traffic ports available
        max_bw:           Maximum bandwidth per port (100G, 400G, 800G)
        bidir:            Bidirectional traffic support (y/n)
        cfg_reload_timer:  Configuration reload timeout in seconds

    Traffic Generator Network:
        tgenp1_ipv4/tgenp2_ipv4:  Traffic generator port IP addresses
        tgenp1_mac/tgenp2_mac:    Traffic generator MAC addresses  
        tgenp1_asn/tgenp2_asn:    Traffic generator BGP ASN numbers

    Device Under Test Network:
        dutp1_ipv4/dutp2_ipv4:    DUT port IP addresses
        dutp1_asn/dutp2_asn:      DUT BGP ASN numbers

    Port and Configuration References:
        io_ports:             Port mapping for tx_port and rx_port
        bgp_route_cfg_type:   Reference to BGP route configuration type
        traffic_cfg_type:     Reference to traffic configuration type
"""
platform_vrf_config = {
    "traffic_configs": vrf_traffic_configs,
    "bgp_route_adv_configs" : bgp_route_adv_configs,

    "platforms": {
        "8102-64H-O": {
            "pid": "8102-64H-O",
            "data_ports": "64",
            "max_bw": "100G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.64.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.64.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        },
        "8101-32FH-O": {
            "pid": "8101-32FH-O",
            "data_ports": "32",
            "max_bw": "400G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.32.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.32.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        },
        "8101-32FH-O-C01": {
            "pid": "8101-32FH-O-C01",
            "data_ports": "32",
            "max_bw": "400G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.32.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.32.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        },
        "8122-64EH-O": {
            "pid": "8122-64EH-O",
            "data_ports": "64",
            "max_bw": "800G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.64.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.64.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        },
        "8122-64EHF-O": {
            "pid": "8122-64EHF-O",
            "data_ports": "64",
            "max_bw": "800G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.64.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.64.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        },
        "8223-64E-MO": {
            "pid": "8223-64E-MO",
            "data_ports": "64",
            "max_bw": "800G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.64.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.64.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        },
        "HF6100-64ED": {
            "pid": "HF6100-64ED",
            "data_ports": "64",
            "max_bw": "800G",
            "util": "40",
            "bidir": "y",
            "cfg_reload_timer" : 300,
            "tgenp1_ipv4": "192.16.1.2",
            "tgenp2_ipv4": "192.16.64.2",
            "dutp1_ipv4" : "192.16.1.1",
            "dutp2_ipv4" : "192.16.64.1",
            "tgenp1_mac" : "00:0a:01:00:11:01",
            "tgenp2_mac" : "00:01:01:00:11:02",
            "tgenp1_asn" : "65200",
            "tgenp2_asn" : "65205",
            "dutp1_asn"  : "65100",
            "dutp2_asn"  : "65105",
            "bgp_route_cfg_type" : "ipv4_100k",
            "traffic_cfg_type": "fixed_traffic"
        }
    }
}

# Helper function to get traffic configuration for a platform
def get_vrf_traffic_config(traffic_cfg_type):
    """
    Get traffic configuration for a platform by resolving the reference

    Args:
        traffic_cfg_type (str): traffic_type

    Returns:
        list: Traffic configuration or None if not found
    """
    return platform_vrf_config["traffic_configs"].get(traffic_cfg_type)

# Helper function to get traffic configuration for a platform
def get_platform_traffic_config(platform_id):
    """
    Get traffic configuration for a platform by resolving the reference

    Args:
        platform_id (str): Platform identifier

    Returns:
        list: Traffic configuration or None if not found
    """
    platform_cfg = platform_vrf_config["platforms"].get(platform_id)
    if not platform_cfg:
        return None

    traffic_cfg_type = platform_cfg.get("traffic_cfg_type")
    if not traffic_cfg_type:
        return None

    return platform_vrf_config["traffic_configs"].get(traffic_cfg_type)

# Helper function to get bgp route advertisement configuration for a platform
def get_platform_bgp_route_config(platform_id):
    """
    Get BGP route advertisement configuration for a platform by resolving the reference

    Args:
        platform_id (str): Platform identifier (e.g., "8101-32FH-O", "HF6100-64ED")

    Returns:
        dict: BGP route configuration or None if not found
    """
    platform_cfg = platform_vrf_config["platforms"].get(platform_id)
    if not platform_cfg:
        return None

    bgp_route_cfg_type = platform_cfg.get("bgp_route_cfg_type")
    if not bgp_route_cfg_type:
        return None

    return platform_vrf_config["bgp_route_adv_configs"].get(bgp_route_cfg_type)
