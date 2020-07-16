import sys
import logging
import pytest
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

@pytest.fixture
def test_completeness_level(request):
    '''
    Pytest test fixture that sets test's completeness level
        @param request: pytest request object
    '''
    def set_completeness_level(**kwargs):
        '''
        API to set the completeness level. If the specified level does not match
        a defined level in the testcase, level-normalization is done based on:
        Cases:
        1. Completeness level not specified - run the lowest defined level (full test if no defined level)
        2. Test does not define any completeness level - run the full testcase
        3. Specified completeness level do not match any defined level in a test case:
            3.1 Specified level is higher than any defined level - go to highest level defined
            3.2 Specified level is lower than any defined level - go to lowest level defined
            3.3 Specified level is in between two defined levels - go to next lower level
        4. Specified level matches one of the defined levels
        '''
        specified_level = request.config.getoption("--test_completeness_level")
        if not specified_level: # Case 1
            logging.info("Completeness level not set during test execution. Setting to default level: {}".format(CompletenessLevel.Debug))
            specified_level = CompletenessLevel.Debug

        defined_levels = kwargs.get("levels")
        if defined_levels is None: # Case 2
            logging.info("Test has no defined levels")
            return
        
        logging.info("Setting test completeness level. Specified: {}. Defined: {}".format(specified_level, str(defined_levels)))

        if specified_level not in defined_levels:
            if specified_level > max(defined_levels): # Case 3.1
                completeness_level = max(defined_levels)
            elif specified_level < min(defined_levels): # Case 3.2
                completeness_level = min(defined_levels)
            else: # Case 3.3
                # Find the maximum defined level less than specified_level
                lesser_defined_level_dist = sys.maxsize
                for level in defined_levels:
                    if level <= specified_level and lesser_defined_level_dist > (specified_level - level):
                        completeness_level = level
                        lesser_defined_level_dist = lesser_defined_level_dist - level
            logging.info("Specified level ({}) not found in defined levels. Setting level to {}".format(specified_level, completeness_level))
        else: # Case 4
            completeness_level = specified_level
        return completeness_level

    return set_completeness_level
