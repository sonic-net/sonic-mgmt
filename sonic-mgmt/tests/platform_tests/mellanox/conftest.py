def pytest_addoption(parser):
    '''
        Adds option to Mellanox specific pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    mellanox_group = parser.getgroup("Mellanox test suite options")

    mellanox_group.addoption(
        "--mock_any_testbed",
        action="store_true",
        help="Mock on testbeds which do not support PSU power thresholds",
    )
