"""
    Pytest configuration used by the read MAC tests.
"""

def pytest_addoption(parser):
    """
        Adding arguments required for read MAC metadata testcase
    """
    parser.addoption(
        "--iteration",
        action="store",
        type=int,
        help="Number of image installing iterations",
    )

    parser.addoption(
        '--image1',
        action='store',
        type=str,
        help='1st image to download and install',
    )

    parser.addoption(
        '--image2',
        action='store',
        type=str,
        help='2nd image to download and install',
    )

    parser.addoption(
        '--minigraph1',
        action='store',
        type=str,
        help='path to the minigraph1',
    )
    parser.addoption(
        '--minigraph2',
        action='store',
        type=str,
        help='path to the minigraph2',
    )
