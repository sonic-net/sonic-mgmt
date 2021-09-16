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
        "--disable_ecn_snappi_test",
        action="store",
        type=bool,
        default=True,
        help="Control execution of ECN tests",
    )
