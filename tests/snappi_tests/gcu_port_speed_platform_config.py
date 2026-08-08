"""
Platform data for Snappi GCU port speed upgrade tests.

Add platform entries here when a new platform supports the Snappi GCU
100G-to-400G speed conversion flow.
"""

SPEED_100G = "100000"
SPEED_400G = "400000"

PORT_SPEED_UPGRADE_SPEED_LANES_MAP = {
    "x86_64-88_lc0_36fh-r0": {
        SPEED_100G: 4,
        SPEED_400G: 8,
    },
}

SPEED_FEC_MAP = {
    SPEED_100G: ["rs", "none"],
    SPEED_400G: ["rs"],
}


def get_num_lanes_for_speed(platform, speed):
    """
    Return number of lanes for a platform and speed.
    """
    return PORT_SPEED_UPGRADE_SPEED_LANES_MAP.get(platform, {}).get(speed)


def get_fec_modes_for_speed(speed):
    """
    Return configured FEC modes for a speed.
    """
    return SPEED_FEC_MAP.get(speed)
