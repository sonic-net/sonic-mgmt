# Conditional Mark

This is a plugin for adding any mark to specified test cases based on conditions in a centralized file.

The centralized file can be supplied in pytest command line option `--mark-conditions-file`. If no conditions file is specified, use the default conditions file located at `tests/common/plugins/conditional_mark/test_mark_conditions.yaml`.


## How it works
This plugin works at the collection stage of pytest. It mainly uses two pytest hook function:
    * `pytest_collection`
    * `pytest_collection_modifyitems`

In `pytest_collection` hook function, it reads the specified conditions file and collect some basic facts that can be used in condition evaluation. The loaded information is stored in pytest object `session.config.cache`.

In `pytest_collection_modifyitems`, it checks each collected test item (test case). For each item, it searches for the longest match test case name defined in the conditions content. If a match is found, then it will add the marks specified for this case based on conditions for each of the marks.

## Format of the conditions file

The conditions file must be a yaml file. First level of key should be test case name. Parametrized test case name is supported.
Second level of should be mark name that can be added for the test case. Any mark name is supported. For example, we can specify marks like `skip` or `xfail`.
Third level supports two type of keys:
* `reason`: Optional string text. It's for specifying reason of adding this mark.
* `strict`: Optional bool. It is only valid for `xfail` mark. For other marks, it will just be ignored.
* `conditions`: Its value can be a string or list of strings. The condition string should can be evaluated using python's `eval()` function. Issue URL is supported in the condition string. The plugin will query the issue website to get state of the issue. Then in the condition string, issue URLs will be replaced with either `True` or `False` based on its state. When getting issue state failed, it will always be considered as active. And the URL will be replaced as `True`. If this field is a list of condition strings, all the condition evaluation result is combined using `AND` logical operation.

Example conditions:
```
folder1/test_file1.py::test_case1:
  skip:
    reason: "skip file1/case1"
    conditions:
      - "release in ['master'] or asic_type=='vs'"
      - https://github.com/Azure/sonic-mgmt/issues/1234
      - https://github.com/Azure/sonic-mgmt/issues/1235
folder1/test_file1.py::test_case2[2+4-6]:
  skip:
    reason: "test file1/case2[2+4-6] skip"
folder1/test_file1.py:
  fallback_mark:
    reason: "For rest of the test cases in folder1/test_file1.py, add this fallback_mark unconditionally"
folder2/test_file2.py::TestMarkers::test_case1:
  xfail:
    reason: "test file2/case1 xfail"
    conditions:
      - https://github.com/Azure/sonic-mgmt/issues/1235 and topo_name == 't1-lag'
      -              # Empty condition will be ignored. Equivalent to True.
folder2/test_file2.py::TestMarkers::test_case2:
  xfail:
    reason: "test file2/case2 strict xfail"
    strict:
    conditions:      # Empty conditions will be evaluated to True. It means no condition.
folder2/test_file2.py::TestMarkers::test_case3:
  any_mark_is_supported:
    reason: "Example for adding any mark to tests"
    conditions: "build_number == 36262"
folder3:
  skip:
    reason: "Skip all the test scripts under subfolder 'folder3'"
```

## Longest match rule

This plugin process each expanded (for parametrized test cases) test cases one by one. For each test case, the marks specified in the longest match entry in the conditions file will take precedence.

Then we can easily apply a set of marks for specific test case in a script file and another set of marks for rest of the test cases in the same script file.

Assume we have conditions like below:
```
feature_a/test_file_1.py:
  skip:
    reason: "all testcases in test_file_1.py should be skipped for 201911 image"
    conditions:
      - "release in ['201911']"
feature_a/test_file_1.py::testcase_3:
  xfail:
    reason: "testcase_i are suppose to fail because an issue"
    conditions:
      - https://github.com/Azure/sonic-mgmt/issues/1234
```

And assume we have below test script:

feature_a/test_file_1.py:
```
def testcase_1

def testcase_2

def testcase_3
```
In this example, `testcase_1` and `testcase_2` will have nodeid like `feature_a/test_file_1.py::testcase_1` and `feature_a/test_file_1.py::testcase_2`. They will match entry `feature_a/test_file_1.py`. So, the `skip` mark will be added to `testcase_1` and `testcase_2` when `release in ['201911']`.
For `testcase_3`, its nodeid will be `feature_a/test_file_1.py::testcase_3`. Then it will only match `feature_a/test_file_1.py::testcase_3`. The `xfail` mark will be added to `testcase_3` when the Github issue is still open. Entry `feature_a/test_file_1.py` also matches its nodeid. But, because it is not the longest match, it will simply be ignored.

In a summary, under such scenario, the `skip` mark will be conditionally added to `testcase_1` and `testcase_2`. The `xfail` mark will be conditionally added to `testcase_3`.

If a test case is parameterized, we can even specify different mark for different parameter value combinations for the same test case.

## Example variables can be used in condition string:

Example variables can be used in condition string:
```
    {
      "commit_id": "db529af20",
      "build_date": "Mon Sep 13 17:41:03 UTC 2021",
      "sonic_utilities": 1.2,
      "kernel_version": "4.19.0-12-2-amd64",
      "debian_version": "10.10",
      "built_by": "AzDevOps@sonic-build-workers-000OU4",
      "libswsscommon": "1.0.0",
      "build_version": "master.36262-db529af20",
      "branch": "master",
      "release": "master",
      "topo_type": "t0",
      "topo_name": "t0"
      "platform": "x86_64-kvm_x86_64-r0",
      "hwsku": "Force10-S6000",
      "build_number": 36262,
      "asic_type": "vs",
      "num_asic": 1,
      "is_multi_asic": False,
    }
```

## New pytest options
A new pytest command line option is added for specifying location of the conditions file. If the option is not supplied, default conditions file located at `tests/common/plugins/conditional_mark/test_mark_conditions.yaml` will be used.
```
    parser.addoption(
        '--mark-conditions-file',
        action='store',
        dest='mark_conditions_file',
        default='',
        help="Location of your own mark conditions file. If it is not specified, the default file will be used.")

    parser.addoption(
        '--ignore-conditional-mark',
        action='store_true',
        dest='ignore_conditional_mark',
        default=False,
        help="Ignore the conditional mark plugin. No conditional mark will be added.")
```

## Possible extensions
The plugin is open for extension in couple of areas:
* Collect more facts. Then more variables can be used in condition string for evaluation.
* Add more arguments for marks, not just the current `reason` argument.
