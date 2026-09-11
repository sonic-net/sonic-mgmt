"""
Platform data for Snappi GCU port speed upgrade tests.

Add platform entries in files/gcu_port_speed_platforms.yaml when a new
platform supports the Snappi GCU 100G-to-400G speed conversion flow.
"""

import os

import yaml

PLATFORM_CONFIG_FILE = os.path.join(
    os.path.dirname(__file__),
    "files",
    "gcu_port_speed_platforms.yaml",
)


def _load_platform_config():
    """
    Load Snappi GCU platform speed metadata.
    """
    with open(PLATFORM_CONFIG_FILE) as config_file:
        return yaml.safe_load(config_file) or {}


def get_num_lanes_for_speed(platform, speed):
    """
    Return number of lanes for a platform and speed.
    """
    platform_config = _load_platform_config().get("platforms", {})
    return platform_config.get(platform, {}).get(
        "speed_lanes", {}
    ).get(str(speed))


def get_fec_modes_for_speed(speed):
    """
    Return configured FEC modes for a speed.
    """
    return _load_platform_config().get("speed_fec_map", {}).get(str(speed))
