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
        default=True,
        help="Control execution of ECN tests",
    )

    ecn_group.addoption(
        "--ixia_ptf_name",
        action="store",
        type=str,
        default=None,
        help="Provide the name of the PTF host for ixia tests"
    )
    ecn_group.addoption(
        "--qos_swap_syncd",
        action="store",
        type=str,
        default=None,
        help="First swap the syncd image with syncd-rpc image"
    )
