import enum

class CompletenessLevel(enum.IntEnum):
    Debug = 0 # Minimum execution
    Basic = 1
    Confident = 2
    Thorough = 3 # Maximum execution


def pytest_addoption(parser):
    parser.addoption(
        "--test_completeness_level",
        metavar="TEST_LEVEL",
        action="store",
        type=int,
        help="Coverage level of test - partial to full execution.\n Defined levels: \
            Debug = 0, Basic = 1, Confident = 2, Thorough = 3")
