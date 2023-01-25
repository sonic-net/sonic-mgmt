# SONiC-MGMT code review guidlines

## Checklist for the PR author
- The code shall be fully tested before the developer asks for an internal review.
- The test should pass succesfully for X iterations.
- The developer shall make sure there is no degradation after introducing the new code.
- The code is PEP-8 compiant.


## Checklist for the code reviewer
- If you see something nice in the PR, tell the developer, especially when they addressed one of your comments in a great way. Code reviews often just focus on mistakes, but they should offer encouragement and appreciation for good practices, as well.
- Look at every line of code that you have been assigned to review.
- No hardcoding. 
- Comments are clear and useful, and mostly explain why instead of what.
- The naming of variables and functions should imply the purpose.
- Add logs to indicate the state transitions, exceptions, error, meaningful points and so on.
- Log levels should be properly set.
- Check the code reusability and communalization.
- Check if all the return values validated and all the exceptions handled.
- Use allure steps for better visualization.
- make sure that no secrets (username, password, internal IP address...) leaked in this PR.
- The developer isn’t implementing things they might need in the future but don’t know they need now.
- Avoid print statements, use the logging modle instead.
- All the supported topologies are specified in the test.
- The test script should perform a proper clean-up, also under error conditions.
- For new test suites, at least one test should be supported on VS.
- Remove any TODO from the code.
- Is the code optimised for in terms of time and space complexity
- The test run time should be in compliance with the test budget, as defined in the test plan review. New test case, in any case, should not consume more than X minutes.
