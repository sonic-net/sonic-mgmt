"""
    Pytest configuration used by the cpu queue shaper tests.
"""


def pytest_addoption(parser):
    """
        Adds options to pytest that are used by the cpu queue shaper tests.
    """

    parser.addoption(
        "--cpu_shaper_reboot_type",
        action="store",
        type=str,
        default="cold",
        help="reboot type such as cold, fast, warm, soft"
    )
