from tests.common.utilities import str2bool


def add_ecn_args(parser):
    """
    Add arguments required for ECN test cases

    Args:
        parser: pytest parser object
    Returns:
        None
    """
    ecn_group = parser.getgroup("ECN test suite options")

    ecn_group.addoption(
        "--disable_ecn_test",
        action="store",
        type=str2bool,
        default=False,
        help="Control execution of ECN tests",
    )

    ecn_group.addoption(
        "--pkt_size",
        action="store",
        type=int,
        default=None,
        help="Pls provide a packet size to use"
    )

