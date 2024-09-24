# conftest.py for L2 configuration.


def pytest_addoption(parser):
    # Target image to upgrade to.
    parser.addoption(
        "--target_image",
        action="store",
        default="",
        help="Specify a target image for upgrade",
        )
