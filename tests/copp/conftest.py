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
