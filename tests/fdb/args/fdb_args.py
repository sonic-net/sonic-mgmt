# FDB MAC Expire Args file

def add_fdb_mac_expire_args(parser):
    """
        Adding arguments required for FDB MAC expire test cases

       Args:
            parser: pytest parser object

        Returns:
            None
    """
    fdb_group = parser.getgroup("FDB test suite options")

    fdb_group.addoption(
        "--fdb_aging_time",
        action="store",
        type=int,
        default=60,
        help="FDB aging time in seconds",
    )
