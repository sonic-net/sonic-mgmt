## How to use pre-commit hooks to check the order in the yaml files
We keep the test cases in alphabetical order in the yaml files, and we use pre-commit hook to check if the test cases in correct order.
In order to use git hook, we should specify the hook folder using`git config core.hooksPath 'path'` before commit.

Assume we use git under the `sonic-mgmt` folder, we can use `git config core.hooksPath .hooks` to specify the hook folder.
And we **must** make sure the script `pre-commit` is executable using `chmod +x .hooks/pre-commit`.

If we add a test case in one of the yaml files and break the alphabetical order, we can not commit successfully and will get the prompt `Pleace check the order in tests/common/plugins/conditional_mark/tests_mark_conditions*.yaml`.