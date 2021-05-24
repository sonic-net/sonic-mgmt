"""
    Pytest configuration used by the sFlow tests.
"""
def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the sFlow tests.
    """
    parser.addoption(
        "--enable_sflow_feature",
        action="store_true",
        default=False,
        help="Enable sFlow feature on DUT",
    )
    
