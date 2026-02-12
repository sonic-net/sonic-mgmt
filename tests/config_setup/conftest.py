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
    parser.addoption(
        "--config_setup_test_mode",
        choices=["auto", "harness", "real"],
        default="auto",
        help="Test execution mode for config-setup tests. "
             "'harness' uses a mock script (safe, no config changes). "
             "'real' runs actual config-setup boot (destructive, recoverable on KVM). "
             "'auto' (default) uses 'real' on VS/KVM and 'harness' on physical DUTs."
    )
