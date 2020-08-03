### CompletenessLevel markers
CompletenessLevel marker enables testcases to be executed in different meaningful levels.
Each level is a representation of a scope of execution of a testcase. This document describes the usage of CompletenessLevel marker.
Identified meaningful levels (in increasing order) -
        
        Debug
        
        Basic
        
        Confident
        
        Thorough

### To use CompletenessLevel:
- Mark the testcase with marker ```supported_completeness_level```. This marker is a list of all the completeness levels supported by a testcase.
- During Pytest execution, use command line option ```--completeness_level``` to specify the test completeness level.
- Automatic normalization between specified ```--completeness_level``` and defined ```supported_completeness_level``` will be performed and the test will be executed at the resultant normalized level of completeness.
- If module/session/testcase have different supported levels of completeness, the inner most level will supersede any defined level.
  For eg., if the module and testcase have supported levels "debug, basic, thorough" and "confident" respectively, the resultant defined level for this testcase will be "confident".

### Different cases for CompletenessLevel

To handle any discrepancy between specified and defined completeness levels, normalization will be performed during testcase setup. Normalization accounts for below mentioned cases:
    1. Completeness level not specified during test execution - set the specified level to "basic".

    2. Test does not define any completeness level - run the full testcase by default.
    
    3. Specified completeness level do not match any defined level in a test case:
        3.1 Specified level is higher than any defined level - go to highest level defined
        3.2 Specified level is lower than any defined level - go to lowest level defined
        3.3 Specified level is in between two defined levels - go to next lower level
    
    4. Specified level matches one of the defined levels - run testcase at the specified level.

### CompletenessLevel usage example
```python
import pytest
from tests.common.plugins.test_completeness import CompletenessLevel

pytestmark = [pytest.mark.supported_completeness_level(CompletenessLevel.Debug, CompletenessLevel.Thorough)]

def test_test_completeness_default(request):
    normalized_level = [mark.args for mark in request.node.iter_markers(name="supported_completeness_level")]
    logger.info("Completeness level set to: {}".format(str(normalized_level)))

    ## Continue execution of the testecase until the completeness level specified.
    # Debug - Do something - end the test if the specified level is Debug
    ...
    ...
    # Basic - Do something more - extra tests/verifications - end the test now if the level is Basic
    ...
    ...
    # Thorough - Run entire test - if the set level is Thorough
```

### CompletenessLevel execution snippets

#### Case - Specified level higher than any defined level - set to highest defined level
>      __init__.py:check_test_completeness:139: Setting test completeness level. Specified: CompletenessLevel.basic. Defined: (<CompletenessLevel.debug: 0>,)
>      __init__.py:check_test_completeness:153: Specified level (CompletenessLevel.basic) not found in defined levels. Setting level to CompletenessLevel.debug

#### Case - Specified level lesser than any defined level - set to lowest defined level
>      __init__.py:check_test_completeness:139: Setting test completeness level. Specified: CompletenessLevel.basic. Defined: (<CompletenessLevel.confident: 2>, <CompletenessLevel.thorough: 3>)
>      __init__.py:check_test_completeness:153: Specified level (CompletenessLevel.basic) not found in defined levels. Setting level to CompletenessLevel.confident

#### Case - Specified level present in the defined levels
>      __init__.py:check_test_completeness:139: Setting test completeness level. Specified: CompletenessLevel.basic. Defined: (<CompletenessLevel.debug: 0>, <CompletenessLevel.basic: 1>, <CompletenessLevel.confident: 2>, <CompletenessLevel.thorough: 3>)
>      __init__.py:check_test_completeness:156: Setting the completeness level to CompletenessLevel.basic

#### Case - Specified level between two defined levels - set to lesser defined level
>      __init__.py:check_test_completeness:139: Setting test completeness level. Specified: CompletenessLevel.basic. Defined: (<CompletenessLevel.debug: 0>, <CompletenessLevel.confident: 2>, <CompletenessLevel.thorough: 3>)
>      __init__.py:check_test_completeness:153: Specified level (CompletenessLevel.basic) not found in defined levels. Setting level to CompletenessLevel.debug