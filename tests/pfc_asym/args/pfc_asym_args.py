from tests.common.utilities import str2bool


def add_pfc_asym_args(parser):
    """
        Adding arguments required for pfc_asym test cases

       Args:
            parser: pytest parser object

        Returns:
            None
    """
    pfc_asym_group = parser.getgroup("PFC Asym test suite options")

    pfc_asym_group.addoption(
        "--server_ports_num",
        action="store",
        default=20,
        type=int,
        help="Number of server ports to use"
        )

    pfc_asym_group.addoption(
        "--pfc-asym-swap-syncd",
        action="store",
        type=str2bool,
        default=True,
        help="Swap syncd container with syncd-rpc container"
        )
