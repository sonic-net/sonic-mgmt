"""Transceiver configuration string parsing.

Format:
{TYPE}-{SPEED}-{FORM_FACTOR}-{DEPLOYMENT}-{MEDIA_LANE_MASK}-{HOST_LANE_MASK}

Examples:
AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF
LR-1-SFP-1G_STRAIGHT-0x01-0x01

Raises ValueError for malformed strings.
"""


EXPECTED_COMPONENTS = 6


def parse_transceiver_configuration(config_string):
    """Parse the transceiver configuration string into components.

    Returns a dict with keys:
      cable_type, speed_gbps, form_factor, deployment,
      media_lane_mask, host_lane_mask, media_lane_count, host_lane_count
    """
    if not config_string:
        raise ValueError("Empty transceiver configuration string")

    components = config_string.split('-')
    if len(components) != EXPECTED_COMPONENTS:
        raise ValueError(
            (
                "Invalid transceiver configuration format "
                f"'{config_string}' - expected {EXPECTED_COMPONENTS} components, got {len(components)}"
            )
        )

    cable_type, speed_str, form_factor, deployment, media_lane_mask, host_lane_mask = components

    def _parse_lane_mask(mask_str):
        # Accept forms like 0xF, 0x0F, 0xFF etc
        try:
            return int(mask_str, 16)
        except ValueError as e:
            raise ValueError(f"Invalid hexadecimal lane mask '{mask_str}' in '{config_string}'") from e

    media_mask_value = _parse_lane_mask(media_lane_mask)
    host_mask_value = _parse_lane_mask(host_lane_mask)
    media_lane_count = bin(media_mask_value).count('1')
    host_lane_count = bin(host_mask_value).count('1')

    try:
        speed_gbps = int(speed_str)
    except ValueError as e:
        raise ValueError(f"Speed component '{speed_str}' is not an integer in '{config_string}'") from e

    return {
        'cable_type': cable_type,
        'speed_gbps': speed_gbps,
        'form_factor': form_factor,
        'deployment': deployment,
        'media_lane_mask': media_lane_mask,
        'host_lane_mask': host_lane_mask,
        'media_lane_count': media_lane_count,
        'host_lane_count': host_lane_count,
    }
