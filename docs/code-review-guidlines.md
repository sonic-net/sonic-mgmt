# SONiC-MGMT code review guidelines

## Style guide
- Avoid usage of hardcoded values, define constants instead.
- Always prefer self-descriptive naming over comments. However, when comments are not avoidable, Comments should be clear and useful, and mostly explain why instead of what.
- The naming of variables and functions should imply the purpose.
- Avoid print statements, use the logging module instead.
- Spaces are the preferred indentation method.
- Add logs to indicate the state transitions, exceptions, errors, assertions, meaningful points, and so on.
- Logs to be contained and rotated, to avoid the exhaustion of the host memory.


## Checklist for the PR author
- The code shall be fully tested before the developer asks for an internal review.
- For new test: the test should pass successfully at least 3 times on any supported topology.
- For infra changes: all the impacted tests should pass successfully at least once.
- The test should be accustomed to support multi-asic devices.
- Make sure that no secrets (username, password, internal IP address...) are leaked in this PR.

## PR author & code reviewer shared responsibilities
- Check the code reusability and communalization.
- Check if all the return values are validated and all the exceptions handled.
- The test script should perform a proper clean-up, also under error conditions.
- All the supported topologies are specified in the test if this is a new test script.
- Run the pre-commit checker before uploading the PR.
- Remove any TODO/FIXME statement from the code, unless justified by the author and approved by the code reviewer.
- Check if all the return values are validated and all the exceptions handled.
- For new test suites, at least one test should be supported on VS(Virtual SONiC).
- Verify that the code optimized in terms of time and space complexity.
- The test run time should comply with the test budget, as defined in the test plan review. A new test case, in any case, should not consume more than 30 minutes.
- Specify to which branches the test/fix should be backported. The testing guidelines mentioned above applies for backporting as well. Note: backporting should always start with the latest version. For example: backport to 202012 and not to 202205 is not allowed.
- New control plane test cases should be included in the kvmtest.sh script.
- Use allure steps for better visualization(optional).

## Checklist for the code reviewer
- If you see something nice in the PR, tell the developer, especially when they addressed one of your comments in a great way. Code reviews often just focus on mistakes, but they should offer encouragement and appreciation for good practices, as well.
- Look at every line of code that you have been assigned to review.
- Log levels should be properly set.
- Use allure steps for better visualization.
