"""
conftest.py for config_setup tests.
"""


def pytest_addoption(parser):
    parser.addoption(
        "--ztp_image",
        action="store_true",
        default=False,
        help="Set if the DUT image has ZTP enabled (built with INCLUDE_ZTP=y)."
    )
