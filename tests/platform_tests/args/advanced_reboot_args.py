import pytest


def add_advanced_reboot_args(parser):
    '''
    Adding arguments required for fast reboot test cases
    '''
    parser.addoption(
        "--vnet",
        action="store",
        type=bool,
        default=False,
        help="Vnet Packets file provided",
    )

    parser.addoption(
        "--vnet_pkts",
        action="store",
        type=str,
        default="",
        help="Vnet Packets json file",
    )

    parser.addoption(
        "--reboot_limit",
        action="store",
        type=int,
        help="Reboot time limit in sec",
    )

    parser.addoption(
        "--stay_in_target_image",
        action="store",
        type=bool,
        default=True,
        help="Stay in target image after reboot",
    )

    parser.addoption(
        "--cleanup_old_sonic_images",
        action="store",
        type=bool,
        default=False,
        help="Remove old SONiC image",
    )

    parser.addoption(
        "--allow_vlan_flooding",
        action="store",
        type=bool,
        default=False,
        help="Allow vlan flooding during reboot",
    )

    parser.addoption(
        "--sniff_time_incr",
        action="store",
        type=int,
        default=60,
        help="Sniff time increment",
    )

    parser.addoption(
        "--new_sonic_image",
        action="store",
        type=str,
        default=None,
        help="URL of new sonic image",
    )

    parser.addoption(
        "--ready_timeout",
        action="store",
        type=int,
        default=180,
        help="DUT reboot ready timout",
    )

    parser.addoption(
        "--replace_fast_reboot_script",
        action="store",
        type=bool,
        default=False,
        help="Replace fast-reboot script on DUT",
    )

    parser.addoption(
        "--post_reboot_check_script",
        action="store",
        type=str,
        default=None,
        help="Script for checking additional states on DUT"
    )

    parser.addoption(
        "--bgp_v4_v6_time_diff",
        action="store",
        type=int,
        default=40,
        help="Time difference (in sec) between BGP V4 and V6 establishment time"
    )
