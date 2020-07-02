import pytest


def add_cont_warm_reboot_args(parser):
    '''
    Adding arguments required for continuous warm-reboot test case
    '''
    parser.addoption(
        "--cont_reboot_limit",
        action="store",
        type=int,
        default=10,
        help="Reboot time limit in sec",
    )
