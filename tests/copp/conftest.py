"""
    Pytest configuration used by the COPP tests.
"""


def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the COPP tests.
    """

    parser.addoption(
        "--copp_swap_syncd",
        action="store_true",
        default=False,
        help="Swap syncd container with syncd-rpc container",
    )
    parser.addoption(
        "--send_rate_limit",
        action="store",
        default=2000,
        help="Set custom server send rate limit",
    )
    parser.addoption(
        "--copp_reboot_type",
        action="store",
        type=str,
        default="cold",
        help="reboot type such as cold, fast, warm, soft"
    )
