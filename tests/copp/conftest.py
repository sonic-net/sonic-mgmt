"""
    Pytest configuration used by the COPP tests.
"""

def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the COPP tests.
    """

    parser.addoption(
        "--nn_target_port",
        action="store",
        type=int,
        default=3,
        help="Which port to send traffic to",
    )

    parser.addoption(
        "--pkt_tx_count",
        action="store",
        type=int,
        default=100000,
        help="How many packets to send to the DUT"
    )

    parser.addoption(
        "--copp_swap_syncd",
        action="store_true",
        default=False,
        help="Swap syncd container with syncd-rpc container",
    )
