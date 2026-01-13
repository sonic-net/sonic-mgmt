"""
This module defines mappings and relationships between various
platforms and their supported network speeds, and configuration parameters.

Attributes:
    PLATFORM_SUPPORTED_SPEEDS_MAP (dict):
        A mapping of platform identifiers to the list of supported
        network speeds (in Mbps). Each key is a platform identifier
        (e.g., 'x86_64-nokia_ixr7250e_36x400g-r0'), and the value is
        a list of supported speed values as strings.

    PLATFORM_SPEED_LANES_MAP (dict):
        A nested mapping of platform identifiers to speed-specific lanes configuration.
        For each platform identifier, there is a dictionary
        where keys are supported speed values and values are the number
        of lanes required for that speed.

    SPEED_FEC_MAP (dict):
        A mapping of network speeds to their supported Forward Error
        Correction (FEC) modes. The keys are speed values (as strings)
        and the values are lists of FEC modes (e.g., "rs", "none").

Usage:
    These mappings enable quick lookups to validate supported configurations
    for specific platforms, as in some times these mappings exist in
    platform files but this is not always the case for all platforms.
    They are used by test_port_speed_change.py.
"""

PLATFORM_SUPPORTED_SPEEDS_MAP = {
    'x86_64-nokia_ixr7250e_36x400g-r0': ['100000', '400000']
}

PLATFORM_SPEED_LANES_MAP = {
    'x86_64-nokia_ixr7250e_36x400g-r0': {
        '100000': 4,
        '400000': 8
    }
}

SPEED_FEC_MAP = {
        '100000': ["rs", "none"],
        '400000': ["rs"]
}
