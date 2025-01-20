
# saitests refactor design and POC demo
**MSFT SONiC team**

## Agenda
- Pain Points
- Refactor Design
- Sequence Detail
- Test Step Encapsulation
- Test Step Decorator
- Design Summary
- Smooth Transition and Compatibility

## Pain Points

## Ref doc and Pain Points
Previously completed documents:
- SONiC QoS Test Refactoring Scope
- Refactor Design for saitest

saitest’s Pain points:
- Difficult to troubleshoot
- Difficult to maintain
- Issues caused by combining PI and PD code
- Miss PR test, and frequent nightly failure due to PR test miss
- Difficult to triage issues

## One Regression Example

![One Regression Example](images/one_regression_example.png)

In the above PR, we have 30 conversations for changes:
- Requested fix for several duplicated unnecessary conflict code, syntax issues, incorrect functions
- Manually run local test at MSFT side to avoid bad fixes. It was for Cisco multi-asic device, should not impact other vendor’s single box device. Unfortunately, it changed packet building method for XON case, and test will run into endless loop on non-Cisco platform, causing regression.

## Refactor Design

## Testcase and Platform Abstraction

![Testcase and Platform Abstraction](images/testcase_platform_abstraction.png)

## Add new testcase

![Add new testcase](images/add_new_testcase.png)

## Add new platform

![Add new platform](images/add_new_platform.png)

## Sequence Detail

## Instantiate Platform class

![Instantiate Platform class](images/saitest.refactor.sequence.Instantiate.png)

## Invoke Platform function

![Invoke Platform function](images/saitest.refactor.sequence.invoke-platform.png)

## Invoke Topology function

![Invoke Topology function](images/saitest.refactor.sequence.invoke-topology.png)

## Test Step Encapsulation

## setUp before refactor

![setUp before refactor](images/setup_before_refactor.png)

## setUp after refactor

![setUp after refactor](images/setup_after_refactor.png)

## Build parameter before refactor

![Build parameter before refactor](images/build_param_before.png)

## Build parameter after refactor

![Build parameter after refactor](images/build_param_after.png)

## Build packet before refactor

![Build packet before refactor](images/build_pkt_before.png)

## Build packet after refactor

![Build packet after refactor](images/build_pkt_after.png)

## Detect RX port before refactor

![Detect RX port before refactor](images/detect_port_before.png)

## Detect RX port after refactor
![Detect RX port after refactor](images/detect_port_after.png)

## Disable TX before refactor

![Disable TX before refactor](images/dis_tx_before.png)

## Disable TX after refactor

![Disable TX after refactor](images/dis_tx_after.png)

## Short of triggering PFC before refactor

![Short of triggering PFC before refactor](images/short_of_pfc_before.png)

## Short of triggering PFC after refactor

![Short of triggering PFC after refactor](images/short_of_pfc_after.png)

## Trigger PFC before refactor

![Trigger PFC before refactor](images/pfc_before.png)

## Trigger PFC after refactor

![Trigger PFC before refactor](images/pfc_after.png)

## Short of triggering ingress drop before refactor

![Short of triggering ingress drop before refactor](images/short_ingress_drop_before.png)

## Short of triggering ingress drop after refactor

![Short of triggering ingress drop after refactor](images/short_ingress_drop_after.png)

## Trigger ingress drop before refactor

![Trigger ingress drop before refactor](images/ingress_drop_before.png)

## Trigger ingress drop after refactor

![Trigger ingress drop after refactor](images/ingress_drop_after.png)

## Enable TX before refactor

![Enable TX before refactor](images/en_tx_before.png)

## Enable TX after refactor

![Enable TX after refactor](images/en_tx_after.png)

## Finally, Get clear testcase

![Finally, Get clear testcase](images/finally_refactor.png)

## Test Step Decorator

## Decorator Usage

![Decorator Usage](images/decorator_usage.png)

- Assign additional activities to test steps using the “saitests_decorator.”
- Set the decorator function's execution time, supporting entry, exit, or both.
- Introduce plugin functions via decorators for small additions without changing step implementation.
- Support printing step banner info, execution results, and diagnostic counters.
- Print human-readable messages to aid in troubleshooting.
- Output register dumps before and after steps for easier troubleshooting.

## Example of step banner and result

![Example of step banner and result](images/example_banner_result.png)

## Example of step diagnostic counter

![Example of step diagnostic counter](images/example_diag_cnt.png)

## Design Summary

- The separation of PI and PD code **isolates platform-dependent errors**, making it easier to manage permissions and ensure the **stability and robustness** of platform-independent code.

- The classification of code into Testcase, Platform, and Topology categories facilitates **maintenance, extension, and management**. Especially, support add fake platform to bypass hardware activity to **support PR test in KVM**.

- Encapsulating test steps makes the testing objectives and processes clear and maintainable. Each test step is defined as a distinct method, improving **readability** and simplifying the **debugging process**.

- By using decorators to handle non-test step behaviors, the main code remains **clean and focused on the core testing logic**. This approach enhances maintainability and provides **flexible debugging capabilities**, improving fault diagnosis.

## Smooth Transition and Compatibility

- Compatibility: Maintain original file paths and class names to ensure seamless execution of legacy test cases.

- Coexistence: Commit refactored code to a separate directory (e.g. from saitests to saitests-refactor) to allow parallel development and run legecy testcase and refactored testcase at same time.

- Step-by-Step Refactoring: Refactor and replace test cases incrementally to minimize risks.
