#### CompletenessLevel API and Fixture usage
CompletenessLevel API and fixture enables testcases to be executed in different meaningful levels.
Each level is a representation of the scope of execution of a testcase. This document describes the usage of CompletenessLevel fixture.

#### To use CompletenessLevel:
- Use pytest command line option ```--test_completeness_level```
- Identified meaningful levels - 
        
        0. Debug
        
        1. Basic
        
        2. Confident
        
        3. Thorough

### Different cases for CompletenessLevel

    1. Completeness level not specified - run the lowest defined level (full test if no defined level)

    2. Test does not define any completeness level - run the full testcase
    
    3. Specified completeness level do not match any defined level in a test case:
        3.1 Specified level is higher than any defined level - go to highest level defined
        3.2 Specified level is lower than any defined level - go to lowest level defined
        3.3 Specified level is in between two defined levels - go to next lower level
    
    4. Specified level matches one of the defined levels

### CompletenessLevel fixture usage example
```python
import pytest
import logging
from tests.common.plugins.test_completeness import CompletenessLevel

@pytest.mark.usefixtures('test_completeness_level')
def test_test_completeness_lower_level(request, test_completeness_level):
    defined_levels = [CompletenessLevel.Confident, CompletenessLevel.Thorough]
    # Get test completeness level - normalize level between specified and defined level
    test_level = test_completeness_level(levels=defined_levels)
    logger.info("Test completeness level set to: {}".format(test_level))
```

### CompletenessLevel execution examples

#### Case - No specified level - set to lowest meaningful level
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_defined call ====================
>     __init__.py:set_completeness_level:43: Completeness level not set during test execution. Setting to default level: 0
>     __init__.py:set_completeness_level:54: Setting test completeness level. Specified: 0. Defined: [<CompletenessLevel.Debug: 0>]
>     test_test_completeness.py:test_test_completeness_defined:12: Test completeness level set to: 0
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_defined call done ====================

#### Case - Specified level higher than any defined level - set to highest defined level
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_defined call ====================
>     __init__.py:set_completeness_level:54: Setting test completeness level. Specified: 1. Defined: [<CompletenessLevel.Debug: 0>]
>     __init__.py:set_completeness_level:69: Specified level (1) not found in defined levels. Setting level to 0
>     test_test_completeness.py:test_test_completeness_defined:12: Test completeness level set to: 0
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_defined call done ====================

#### Case - Specified level lesser than any defined level - set to lowest defined level
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_lower_level call ====================
>     __init__.py:set_completeness_level:54: Setting test completeness level. Specified: 1. Defined: [<CompletenessLevel.Confident: 2>, <CompletenessLevel.Thorough: 3>]
>     __init__.py:set_completeness_level:69: Specified level (1) not found in defined levels. Setting level to 2
>     test_test_completeness.py:test_test_completeness_lower_level:19: Test completeness level set to: 2
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_lower_level call done ====================

#### Case - Specified level present in the defined levels
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_highest_level call ====================
>     __init__.py:set_completeness_level:54: Setting test completeness level. Specified: 1. Defined: [<CompletenessLevel.Debug: 0>, <CompletenessLevel.Basic: 1>, <CompletenessLevel.>     Confident: 2>, <CompletenessLevel.Thorough: 3>]
>     test_test_completeness.py:test_test_completeness_highest_level:27: Test completeness level set to: 1
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_highest_level call done ====================

#### Case - Specified level between two defined levels - set to lesser defined level
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_unsorted call ====================
>     __init__.py:set_completeness_level:54: Setting test completeness level. Specified: 1. Defined: [<CompletenessLevel.Confident: 2>, <CompletenessLevel.Thorough: 3>, <CompletenessLevel.>     Debug: 0>]
>     __init__.py:set_completeness_level:69: Specified level (1) not found in defined levels. Setting level to 0
>     test_test_completeness.py:test_test_completeness_unsorted:35: Test completeness level set to: 0
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_unsorted call done ====================

#### Case - Testcase does not define any level but checks the completeness level
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_undefined call ====================
>     __init__.py:set_completeness_level:51: Test has no defined levels
>     test_test_completeness.py:test_test_completeness_undefined:43: Test completeness level set to: None
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_undefined call done ====================

#### Case - Testcase does not define any level and proceeds without fixture
>     conftest.py:pytest_runtest_call:363: ==================== test_test_completeness.py::test_test_completeness_no_fixture call ====================
>     test_test_completeness.py:test_test_completeness_no_fixture:46: Test continue without checking completeness
>     conftest.py:pytest_runtest_call:365: ==================== test_test_completeness.py::test_test_completeness_no_fixture call done ====================