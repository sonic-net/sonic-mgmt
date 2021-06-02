#### Custom_skipif plugin usage example

Below is described possibility of custom_skipif plugin usage.

##### Structure
custom_skipif plugin allows to skip test cases dynamically based on GitHub issue or Platform

Plugin can use different issue/ticket systems: GitHub, Jira, Redmine etc.
By default implemented only GitHub support. Jira, Redmine etc. can be implemented by users.

##### How it works
By default plugin will do nothing.
If in plugin folder available file "tests_to_be_skipped_conditionally.yaml" - it will read this file and do skip for
tests according to this file.

Example how to skip test "test platform_tests/cli/test_show_platform.py::test_show_platform_fan"
Code below will skip test if we have active issue in: ((GitHub or Jira or Redmine) and current platform is "msn4600")

````
platform_tests/cli/test_show_platform.py::test_show_platform_fan:
  GitHub:
    - https://github.com/Azure/sonic-buildimage/issues/7602
    - https://github.com/Azure/sonic-buildimage/issues/7643
  Jira:
    - http://jira.aaa.com/1234
  Redmine:
    - http://redmine.bbb.com/1234
  Platform:
    operand: "and"
    platforms:
      - msn4600
````

##### How to add additional issues/tickets system support(Jira, Redmine, etc.)
To add support for additional issues/tickets system  we need to do next(example below for Redmine):
- Create file called "Redmine.py"
- In file "Readmine.py" create class with name "Redmine" and inherit it from "CustomSkipIf" class
````
from CustomSkipIf import CustomSkipIf

class Redmine(CustomSkipIf):
    def __init__(self, ignore_list, extra_params):
        self.name = __name__
        self.ignore_list = ignore_list
        self.extra_params = extra_params

    def is_skip_required(self, skip_dict):
        # Implement here logic for check if Redmine issue is active       
        is_issue_active, issue_url = check_if_issue_active()
        if is_issue_active:
            skip_dict[self.name] = issue_url
        return skip_dict
````
- Add to file "tests_to_be_skipped_conditionally.yaml" skip item for specific test case by Redmine issue id
