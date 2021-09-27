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
* `reason`: Its value should be a string. It's for specifying reason of adding this mark.
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
folder2/test_file2.py::TestMarkers::test_case2:
  any_mark_is_supported:
    reason: "Example for adding any mark to tests"
    conditions: "build_number == 36262"
folder3:
  skip:
    reason: "Skip all the test scripts under subfolder 'folder3'"
```

## New pytest options
A new pytest command line option is added for specifying location of the conditions file. If the option is not supplied, default conditions file located at `tests/common/plugins/conditional_mark/test_mark_conditions.yaml` will be used.
```
    parser.addoption(
        '--mark-conditions-file',
        dest='mark_conditions_file',
        default='',
        help="Enable DUT hardware resources monitoring")
```

## Possible extensions
The plugin is open for extension in couple of areas:
* Collect more facts. Then more variables can be used in condition string for evaluation.
* Add more arguments for marks, not just the current `reason` argument.
