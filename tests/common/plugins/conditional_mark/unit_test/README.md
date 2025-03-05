## Unit Test for conditional marks
We have unit tests to verify the correct selection of marks for each test case. The core logic resides in the `find_all_matches` function within `tests/common/plugins/conditional_mark/__init__.py`.
Therefore, our unit tests are primarily focused on testing this function.

### Code sturcture
To test the `find_all_matches` function, we primarily need two key parameters: nodeid and conditions.
- nodeid represents the test case name and serves as the lookup key in `tests_conditions.yaml`.
- conditions are read from `tests_conditions.yaml`, which contains the predefined marks and conditions for test scripts.

For the session parameter, we will use MagicMock to create a mock session.
As for the other parameters, they are not the primary focus of our unit tests, so we will assign them default values.

### Test coverage
The unit tests cover the following scenarios:
- The condition in the longest matching entry is fully satisfied.
- The condition in the longest matching entry is partially unsatisfied.
- All conditions along the matching path are unsatisfied.
- The condition in the longest matching entry is empty
- Test logic operation `or`
- Test default logic operation
- Test logic operation `and`
- Test duplicated conditions
- Test contradicting conditions
- Test no matches
- Test only use the longest match

### How to run tests
To execute the unit tests, we can follow below command
```buildoutcfg
yutongzhang@sonic_mgmt:/data/sonic-mgmt$ python -m pytest --noconftest --capture=no tests/common/plugins/conditional_mark/unit_test/unittest_find_all_matches.py -v -s
```
