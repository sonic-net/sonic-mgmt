import pytest


def add_normal_reboot_args(parser):
    """
    Adding arguments required for normal reboot test cases
    """
    parser.addoption(
        "--power_off_delay",
        action="append",
        type=int,
        default=[],
        help="Power off delay seconds for test_power_off_reboot",
    )