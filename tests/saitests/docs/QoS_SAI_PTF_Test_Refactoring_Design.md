
# QoS SAI PTF Test Refactoring Design
**xuchen@microsoft.com**


## Agenda
- What is QosS SAI PTF test
- Pain Points
- Class Hierarchy Refactoring
- How to add new testcase class
- How to add new platform class
- Instantiate Platform Sequence
- Calling Platform Function Sequence
- Calling Topology Function Sequence
- Test Step Decorator


## What is QoS SAI PTF Test

- Locate in “/tests/saitests/” in the sonic-mgmt repo, so also called “saitests”
- Run in PTF docker, send traffic to DUT via PTF, and measure  DUT MMU behaviors
- In addition, “test_qos_sai” is another part of QoS SAI test, which is used to prepare test environment, and start PTF command to trigger “saitests”. But it is not the focus of this article

![What is QoS SAI PTF Test](images/What_is_QoS_SAI_PTF_Test.png)


## Pain Points

| **Description of pain points**                                                       | **Addressed in this refactoring**                      |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------ |
| <span style="color: green;">Regression caused by mix PI and PD code</span>           | <span style="color: green;">Yes</span>                 |
| <span style="color: green;">Difficult to troubleshooting</span>                      | <span style="color: green;">Yes</span>                 |
| <span style="color: green;">Difficult to maintain</span>                             | <span style="color: green;">Yes</span>                 |
| <span style="color: green;">Miss PR test, and lead to undetected syntax error</span> | <span style="color: green;">Yes</span>                 |
| <span style="color: green;">Difficult to triage issue</span>                         | <span style="color: green;">Yes</span>                 |
| Frequent nightly failure due to port selection                                       | Will address in following "test_qos_sai"'s refactoring |
| Long test duration                                                                   | Will address in following "test_qos_sai"'s refactoring |
| Frequent nightly failure due to syncd rpc image download issue                       | Will address in following "test_qos_sai"'s refactoring |
| Frequent nightly failure due to fixture order inconsistencies                        | Will address in following "test_qos_sai"'s refactoring |
| Test scenario miss                                                                   | Will address in following "test_qos_sai"'s refactoring |


## Class Hierarchy Refactoring

![Class Hierarchy Refactoring](images/Class_Hierarchy_Refactoring.png)


## How to add new testcase class

![How to add new testcase class](images/add_new_testcase.png)


## How to add new platform class

![How to add new platform class](images/add_new_platform.png)


## Instantiate Platform Sequence

![Instantiate Platform Sequence](images/saitest.refactor.sequence.Instantiate.png)


## Calling Platform Function Sequence

![Calling Platform Function Sequence](images/saitest.refactor.sequence.invoke-platform.png)


## Calling Topology Function Sequence

![Calling Topology Function Sequence](images/saitest.refactor.sequence.invoke-topology.png)


## Test Step Decorator

![Decorator Usage](images/decorator_usage.png)

- focus on the key test logic instead of auxiliary code
- execute decorator function at entry, exit, or both
- support to add plugin function via decorators for small additions without changing step implementation


### Decorator example: show banner and result

- Support add decorator function for printing banner, results

![decorator of step banner and result](images/decorator_banner_result.png)

![Example of step banner and result](images/example_banner_result.png)


### Decorator example: show diag counter

- Run “diag_counter” decorator at exit of test step, to compare various counter change between this step and previous step.
- To help troubleshooting via checking relevant counter changes

![decorator of diag counter](images/decorator_diag_cnt.png)

![example_diag_cnt1](images/example_diag_cnt1.png)

![example_diag_cnt2](images/example_diag_cnt2.png)

![example_diag_cnt3](images/example_diag_cnt3.png)


### Decorator example: test steps pass detection

- Run “check_counter” decorator at both entry and exit of test step.
- Checks if counter change matches the “short_of_pfc_check_rules”. If doesn’t match, raise exception, and the test fails.

![decorator of verify counter](images/decorator_verify-counter.png)


### Skip duplicated decorator functions

- In subclass, override “step_build_param()” method
- Even we defined decorator functions for both subclass and base class, the “SaitestsDecorator” just run outer layer decorator function, and skip duplicated functions.

![decorator functions for base class](images/decorator-base.png)

![decorator functions for base class](images/decorator-sub.png)


## Smooth Migration

- Refactor code is located in “tests/saitests/refactor/” different with legacy folder “tests/saitests/py3/”
- Run refactor testcase and legacy testcase pipeline parallelly. and set XFAIL for refactor testcase, to avoid impact offical nightly
- Monitor test result statistic of refactor code, to prove test affection is better than legacy code.
- Switch offical nightly to refactor test code, when all QoS SAI PTF testcase complete refactor

![call refactor testcase](images/smooth-mig-refac.png)

![call legacy testcase](images/smooth-mig-legacy.png)
