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
  - GitHub:
    - https://github.com/Azure/sonic-buildimage/issues/7602
    - https://github.com/Azure/sonic-buildimage/issues/7643
    Platform:
      - msn4600
  - Jira:
    - http://jira.aaa.com/1234
    Platform:
      - msn4600
  - Redmine:
    - http://redmine.bbb.com/1234
    Platform:
      - msn4600
````

##### How to add additional issues/tickets system support(Jira, Redmine, etc.)
To add support for additional issues/tickets system  we need to do next(example below for Redmine):
- Create file called "Redmine.py"
- In file "Readmine.py" create class with name "SkipIf" and inherit it from "CustomSkipIf" class
````
from CustomSkipIf import CustomSkipIf

class SkipIf(CustomSkipIf):
    def __init__(self, ignore_list, pytest_item_obj):
        super(SkipIf, self).__init__(ignore_list, pytest_item_obj)
        self.name = 'Redmine'

    def is_skip_required(self, skip_dict):
        is_issue_active, issue_id = is_redmine_issue_active(self.ignore_list)
        if is_issue_active:
            issue_url = 'https://redmine.bbb.com/issues/{}'.format(issue_id)
            skip_dict[self.name] = issue_url

        return skip_dict
````
- Add to file "tests_to_be_skipped_conditionally.yaml" skip item for specific test case by Redmine issue id
