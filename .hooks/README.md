## How to use pre-commit hooks to check the order in the yaml files
We keep the test cases in alphabetical order in the yaml files, and we use pre-commit hook to check if the test cases in correct order.
In order to use git hook, we should specify the hook folder using`git config core.hooksPath 'path'` before commit. We config this path using `init_hooks.sh` under the folder `sonic-mgmt`.

Assume we use git under the `sonic-mgmt` folder, firstly we give the execute permission to init file using `chmod u+x init_hooks.sh` and then we can config hook path by executing the script `init_hooks.sh`.

If we add a test case in one of the yaml files and break the alphabetical order, we can not commit successfully and will get the prompt `Pleace check the order in tests/common/plugins/conditional_mark/tests_mark_conditions*.yaml`.
