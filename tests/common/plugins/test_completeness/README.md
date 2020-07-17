### CompletenessLevel markers
CompletenessLevel marker enables testcases to be executed in different meaningful levels.
Each level is a representation of the scope of execution of a testcase. This document describes the usage of CompletenessLevel marker.

### To use CompletenessLevel:
- Use pytest command line option ```--test_completeness_level```
- Identified meaningful levels - 
        
        0. Debug
        
        1. Basic
        
        2. Confident
        
        3. Thorough
- Mark the testcase with marker ```supported_completeness_level```

### Different cases for CompletenessLevel

    1. Completeness level not specified - run the lowest defined level (full test if no defined level)

    2. Test does not define any completeness level - run the full testcase
    
    3. Specified completeness level do not match any defined level in a test case:
        3.1 Specified level is higher than any defined level - go to highest level defined
        3.2 Specified level is lower than any defined level - go to lowest level defined
        3.3 Specified level is in between two defined levels - go to next lower level
    
    4. Specified level matches one of the defined levels

### CompletenessLevel usage example
```python
import pytest
from tests.common.plugins.test_completeness import CompletenessLevel

pytestmark = [pytest.mark.supported_completeness_level(CompletenessLevel.Debug, CompletenessLevel.Thorough)]

def test_test_completeness_default(request):
    defined_levels = [mark.args for mark in request.node.iter_markers(name="completeness_level")]
    logger.info("Completeness level set to: {}".format(str(defined_levels)))

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
>      __init__.py:check_test_completeness:132: Setting test completeness level. Specified: 1. Defined: (<CompletenessLevel.Debug: 0>,)
>      __init__.py:check_test_completeness:146: Specified level (1) not found in defined levels. Setting level to 0

#### Case - Specified level lesser than any defined level - set to lowest defined level
>      __init__.py:check_test_completeness:132: Setting test completeness level. Specified: 1. Defined: (<CompletenessLevel.Confident: 2>, <CompletenessLevel.Thorough: 3>)
>      __init__.py:check_test_completeness:146: Specified level (1) not found in defined levels. Setting level to 2

#### Case - Specified level present in the defined levels
>      __init__.py:check_test_completeness:132: Setting test completeness level. Specified: 2. Defined: (<CompletenessLevel.Confident: 2>, <CompletenessLevel.Thorough: 3>)
>      __init__.py:check_test_completeness:151: Setting the completeness level to MarkDecorator(mark=Mark(name='completeness_level', args=(2,), kwargs={}))

#### Case - Specified level between two defined levels - set to lesser defined level
>      __init__.py:check_test_completeness:132: Setting test completeness level. Specified: 2. Defined: (<CompletenessLevel.Thorough: 3>, <CompletenessLevel.Debug: 0>, <CompletenessLevel.Basic: 1>)
>      __init__.py:check_test_completeness:146: Specified level (2) not found in defined levels. Setting level to 1