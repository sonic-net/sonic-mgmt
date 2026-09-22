"""
    Pytest configuration used by the syslog source ip tests.
"""


def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the ssip tests.
    """

    parser.addoption(
        "--ssip_reboot_type",
        action="store",
        type=str,
        default="cold",
        help="reboot type such as cold, fast, warm, soft, random"
    )
