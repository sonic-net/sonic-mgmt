"""
    Pytest configuration used by the read MAC tests.
"""

def pytest_addoption(parser):
    """
        Adding arguments required for read MAC metadata testcase
    """
    read_mac_group = parser.getgroup("Read MAC metadata test suite options")

    read_mac_group.addoption(
        "--iteration",
        action="store",
        type=int,
        help="Number of image installing iterations",
        required=True,
    )

    read_mac_group.addoption(
        '--image1',
        action='store',
        type=str,
        help='1st image to download and install',
        required=True,
    )

    read_mac_group.addoption(
        '--image2',
        action='store',
        type=str,
        help='2nd image to download and install',
        required=True,
    )

    read_mac_group.addoption(
        '--minigraph1',
        action='store',
        type=str,
        help='path to the minigraph1',
    )
    read_mac_group.addoption(
        '--minigraph2',
        action='store',
        type=str,
        help='path to the minigraph2',
    )
