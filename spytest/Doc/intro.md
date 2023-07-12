
<!-- TOC -->

- [Revision](#revision)
- [Scope](#scope)
- [Definitions/Abbreviations](#definitionsabbreviations)
- [Overview](#overview)
  - [Framework](#framework)
  - [TGen APIs](#tgen-apis)
  - [Feature APIs](#feature-apis)
  - [Utility APIs](#utility-apis)
  - [TextFSM Templates](#textfsm-templates)
  - [Test Scripts](#test-scripts)
  - [Packaging](#packaging)
  - [Testbed](#testbed)
  - [Sample topology](#sample-topology)
- [Traffic Generation](#traffic-generation)
  - [Ixia](#ixia)
  - [Spirent](#spirent)
  - [HLTAPI](#hltapi)
  - [Scapy](#scapy)
- [Execution Modes](#execution-modes)
  - [PTF Mode](#ptf-mode)
  - [Standalone Mode](#standalone-mode)
  - [Virtual SONiC](#virtual-sonic)
- [Environment](#environment)
  - [PTF](#ptf)
  - [Standalone](#standalone)
- [Test Execution](#test-execution)
  - [Running test script(s)](#running-test-scripts)
  - [Running tests using PyTest marker](#running-tests-using-pytest-marker)
  - [Running tests using suite name](#running-tests-using-suite-name)
  - [Execution Results and Logs](#execution-results-and-logs)
  - [Command line arguments](#command-line-arguments)
- [Log Files](#log-files)
- [Dashboard](#dashboard)
- [Internals](#internals)
  - [Init sequence](#init-sequence)
  - [Base Configuration](#base-configuration)
  - [Module Configuration](#module-configuration)
  - [Customize Error Patterns](#customize-error-patterns)
  - [Syslog Error Patterns](#syslog-error-patterns)
  - [Batch Processing](#batch-processing)
  - [Static Analysis](#static-analysis)
- [Test Suites](#test-suites)

<!-- /TOC -->

## Revision

Rev  | RevDate      | Author(s)                  | Change Description
---- | ----------   | -------------------------- | ------------------
v1.00 | Apr 14, 2020 | Ram Sasthri, Kristipati    | Initial Version
v2.00 | May 01, 2023 | Ram Sasthri, Kristipati    | Added Table of Contents
v2.10 | Jun 01, 2023 | Ram Sasthri, Kristipati    | Updates
v2.11 | Jun 08, 2023 | Ram Sasthri, Kristipati    | Added test Suites Section
v2.12 | Jun 09, 2023 | Ram Sasthri, Kristipati    | Added syslog patterns

## Scope

This document describes the details for SPyTest Framework.

## Definitions/Abbreviations

* **TGEN** Traffic Generator
* **PyTest** Open Source general purpose automation [framework](https://github.com/pytest-dev/pytest)
* **SCAPY** Scapy is a powerful Python-based interactive packet manipulation program and [library](https://github.com/secdev/scapy)
* **[ROOT]** Refers to [git-repo-clone]/spytest in this document

## Overview

The SPyTest is a test automation framework designed to validate SONiC. It utilizes PyTest as its foundation and leverages various open-source Python packages for tasks such as device access, CLI output parsing and traffic generation.

The components of SPyTest include:

* Framework: This forms the core of the automation framework, providing the necessary infrastructure and functionalities to author test scripts, execute and generate test reports.

* TGen APIs: Traffic Generator APIs enables the generation and control of network traffic for testing purposes. It allows users to configure and manipulate traffic patterns, perform packet-level operations, and measure network performance.

* Feature APIs: The Feature APIs provides a set of functions and methods that allow testers to interact with specific features and functionalities of SONiC. This component simplifies the testing process by providing a higher-level abstraction layer for validating individual features.

* Utility APIs: The Utility APIs offers a collection of utility functions that assist in various testing operations.

* TextFSM Templates: TextFSM is a powerful framework for parsing and extracting structured data from unstructured text outputs, such as command line outputs. SPyTest utilizes TextFSM templates, which define the patterns and rules for extracting relevant information from the CLI outputs of devices under test.

* Test Scripts: Test scripts are the actual test cases written using the SPyTest framework. These scripts combine the functionalities provided by the aforementioned components to define the test scenarios and validate the behavior of SONiC.

### Framework

    Please refer to [ROOT]/spytest/infra.py for list of functions.

These functions are designed to be called from the feature API, providing a higher-level abstraction for device interaction and handling common operations. They abstract various tasks, including:

* Logging: In the SPyTest framework, logging functions are provided to ensure a consistent logging mechanism for users. These functions allow users to generate log messages at various levels of severity, including INFO, DEBUG, WARNING, and ERROR. This allows for detailed information about the test execution flow and any potential issues or errors encountered during the testing process. The logging functionality in SPyTest covers different aspects of logging. It includes the generation of overall log files that capture the execution details of the entire test suite or test run. Additionally, SPyTest provides per device log files, which contain specific logging information related to individual devices involved in the testing. This helps in isolating and analyzing device-specific issues or behaviors. Furthermore, SPyTest supports per module log files, which capture log messages specific to different modules or components being tested. This allows users to focus on the logs relevant to a particular module, aiding in the identification of issues or errors within that specific module.

* Error Pattern Detection and Result Classification: These functions are responsible for detecting error patterns in the output of device interactions and classifying the results accordingly. By analyzing the device responses, they can identify specific error conditions or anomalies, allowing for appropriate actions or reporting.

* Crash Detection and Recovery: These functions are aimed at detecting crashes or abnormal behavior in the device. They monitor the device state and log files to identify signs of a crash, such as system reboots or error messages. Upon detection, they can trigger recovery mechanisms or initiate further investigation to mitigate the impact of the crash.

* Power Cycle Operations using Remote Power Supply (RPS): These functions facilitate power cycle operations on the device using a Remote Power Supply (RPS). They provide an interface to remotely control the power supply unit connected to the device. This enables the automation of power cycling operations, allowing for scenarios such as device reboot or troubleshooting power-related issues.

Feature APIs can leverage these functions to facilitate device interactions and manage common operations without the need to directly address low-level implementation details. As a result, feature APIs become modular, reusable, and more easily maintainable.

### TGen APIs

The SPyTest framework utilizes HLTAPI (High-Level Traffic Application Programming Interface) to establish an interface with commercial traffic generators such as Ixia and Spirent, specifically for traffic generation purposes. By leveraging HLTAPI, SPyTest can seamlessly interact with these traffic generators, enabling the configuration and control of network traffic for testing scenarios.

Additionally, SPyTest also provides an alternative implementation of the same API using SCAPY, a powerful packet manipulation library in Python. This SCAPY-based implementation is specifically designed to generate traffic within the PTF (Packet Test Framework) environment and is also applicable for testing virtual SONiC.

The "Traffic Generation" section of the document provides more details about how traffic generation is handled within the SPyTest framework.

By offering support for both HLTAPI and Scapy, SPyTest provides flexibility in choosing the appropriate traffic generation method based on the testing environment and the availability of commercial traffic generators or the need for custom traffic generation using Scapy.

### Feature APIs

    Please refer to [ROOT]/apis/***/*.py for list of functions.

These functions are designed to be called from test scripts, providing an abstraction layer for handling user interface (UI) interactions and managing version differences. They abstract various tasks, including:

* UI Interaction: These functions handle interactions with the user interface of the system or application being tested. They provide a simplified and standardized way to interact with UI elements such as buttons, menus, forms, and dialogs. By abstracting the UI interactions, these functions make it easier to write test scripts that are not dependent on specific UI implementation details.

* Version Differences: These functions handle version differences in the system or application being tested. They provide a mechanism to identify the current version of the software and adapt the test script's behavior accordingly. This allows for conditional execution of specific test steps or variations in test logic based on the software version. By abstracting version differences, these functions ensure test scripts can be more flexible and compatible across different software versions.

The abstraction provided by these functions helps in creating more maintainable and reusable test scripts. Test scripts can focus on the test logic and flow, while relying on these functions to handle the intricacies of UI interactions and version-specific variations. This abstraction layer reduces the effort required to update test scripts when UI elements change or when working with different software versions, leading to more efficient and robust test automation.

### Utility APIs

    Please refer to [ROOT]/utilities/*.py for list of functions.

The Utility APIs in the SPyTest framework consists of various utility functions that are commonly used and aim to prevent code duplication. These utility functions can be found in the [ROOT]/utilities/*.py files.

The purpose of these utility functions is to provide a centralized and reusable set of functionalities that can be utilized across different test scripts. By encapsulating commonly used operations in utility functions, it avoids duplicating code and promotes cleaner and more efficient test script development.

It's important to note that when adding functions to the Utility API, it is recommended to avoid including Device Under Test (DUT) specific functions. The Utility API should focus on providing general-purpose utilities that can be utilized across different devices or test scenarios. This ensures that the utility functions remain versatile and can be used in various testing environments without being tightly coupled to specific DUTs.

### TextFSM Templates

The SPyTest framework utilizes the SONiC Command Line Interface (CLI) to interact with the Devices Under Test (DUTs). It leverages the Netmiko library, which provides a unified interface for executing commands on telnet or SSH connections to the DUTs. This allows SPyTest to establish a connection with the DUTs and execute CLI commands programmatically.

To process the CLI output and extract structured data, SPyTest employs TextFSM (Text File Stream Model) templates. These templates define patterns and rules for parsing the CLI output and converting it into a structured format, typically a Python dictionary. By using TextFSM, SPyTest can convert unstructured CLI output into a more manageable and machine-readable format, facilitating further processing and analysis.

To incorporate TextFSM templates into the SPyTest framework, the templates should be added to the [ROOT]/templates directory. Additionally, the index file in the same directory needs to be updated to include the newly added templates. This allows the framework to locate and utilize the appropriate template for parsing specific CLI commands.

Sample TextFSM templates for a wide range of commands can be found in the GitHub repository called [ntc-templates.](https://github.com/networktocode/ntc-templates) These templates can serve as a reference or starting point for creating or customizing templates within the SPyTest framework.

For more detailed information about TextFSM and its usage, you can refer to the [TEXTFSM](https://github.com/google/textfsm/wiki/TextFSM) documentation on GitHub. This documentation provides insights into the features, syntax, and functionality of TextFSM, helping users understand how to create and modify templates effectively within the SPyTest framework.

### Test Scripts

A Test Script, also known as a module, is a logical collection of discrete test functions that are grouped together based on functionality within the SPyTest framework. It serves as a container for organizing and executing individual test functions, each responsible for verifying one or more test cases.

In SPyTest, a Test Script typically consists of multiple test functions, each dedicated to validating specific aspects of the system or application being tested. These test functions encapsulate the necessary logic, assertions, and steps to execute the test cases and verify the expected behavior.

By grouping related test functions within a Test Script, it becomes easier to manage and organize the test suite. Test Scripts can be structured based on functional areas, specific features, or any other logical grouping that aligns with the testing requirements. This allows for better modularity, reusability, and maintainability of the test codebase.

Test Scripts serve as an entry point for executing the associated test functions. They can be executed individually or as part of a larger test suite. The framework provides mechanisms for running specific Test Scripts or executing all available Test Scripts, depending on the testing needs.

### Packaging

SPyTest expands its functionality by integrating open-source packages, which include libraries, frameworks, and tools offering additional features and capabilities that are necessary for SPyTest.

![Image](arch.jpg "icon")

### Testbed

The testbed file is an essential input required to run SPyTest. It specifies the topology information necessary for the test execution. The testbed file serves as a configuration file that describes the devices, their connections, and various attributes related to the test environment.

Typically, the testbed file is written in a structured format, such as YAML or JSON, and contains the following information:

* Device Information: The testbed file provides details about the devices involved in the test. This includes information such as the device name, IP address, management interface, and authentication credentials required to establish a connection.

* Connection Details: It specifies the connections between devices in the topology. This information outlines the connectivity between devices and the network interfaces used for communication. It defines how devices are interconnected, enabling SPyTest to understand the network topology and perform tests accordingly.

* Additional Attributes: The testbed file may include additional attributes or metadata associated with each device. These attributes can include information vendor-specific details, configuration parameters, or any other relevant information needed for test scripts.

By providing the topology information through the testbed file, SPyTest gains a clear understanding of the test environment, allowing it to establish connections to devices, execute test functions, and validate the desired behavior across the network.

It is important to ensure the accuracy and completeness of the testbed file, as any inaccuracies or missing information may lead to test execution issues or incorrect results.

### Sample topology

![Image](topo.png "icon")

testbed file content for this topology is given below.

    version: 2.0
    services: {default: !include sonic_services.yaml}

    params: !include sonic_params.yaml
    instrument: !include sonic_instrument.yaml
    builds: !include sonic_builds.yaml
    speeds: !include sonic_speeds.yaml
    errors: !include sonic_errors.yaml
    configs: !include sonic_configs_all.yaml

    devices:
        DUT-01:
            device_type: sonic
            access: {protocol: telnet, ip: 1.2.3.4, port: 2001}
            credentials: {username: admin, password: password, altpassword: YourPaSsWoRd}
            properties: {config: default, build: default, services: default, speed: default}
            breakout: {Ethernet0: 4x10, Ethernet8: 4x10}
            rps: {model: Raritan, ip: 1.2.3.5, outlet: 10, username: admin, password: admin}
        DUT-02:
            device_type: sonic
            access: {protocol: telnet, ip: 1.2.3.4, port: 2001}
            credentials: {username: admin, password: password, altpassword: YourPaSsWoRd}
            properties: {config: default, build: default, services: default, speed: default}
            breakout: {}
            rps: {model: Raritan, ip: 1.2.3.5, outlet: 11, username: admin, password: admin}
        ixia-01:
            device_type: TGEN
            properties: {type: ixia, version: "9.31", ip: 1.2.3.6, ix_server: 1.2.3.7}

    topology:
        DUT-01:
            interfaces:
                Ethernet64: {EndDevice: DUT-02, EndPort: Ethernet64}
                Ethernet68: {EndDevice: DUT-02, EndPort: Ethernet68}
                Ethernet72: {EndDevice: DUT-02, EndPort: Ethernet72}
                Ethernet76: {EndDevice: DUT-02, EndPort: Ethernet76}
                Ethernet48: {EndDevice: ixia-01, EndPort: 1/1}
                Ethernet52: {EndDevice: ixia-01, EndPort: 1/2}
                Ethernet56: {EndDevice: ixia-01, EndPort: 1/3}
                Ethernet60: {EndDevice: ixia-01, EndPort: 1/4}
        DUT-02:
            interfaces:
                Ethernet48: {EndDevice: ixia-01, EndPort: 2/1}
                Ethernet52: {EndDevice: ixia-01, EndPort: 2/2}
                Ethernet56: {EndDevice: ixia-01, EndPort: 2/3}
                Ethernet60: {EndDevice: ixia-01, EndPort: 2/4}

The **services** section contains details on external services like radius/tacacs. The data in each service is decided by test scripts. This helps to abstract the service details from test scripts. Refer to testbeds/sonic_services.yaml for more details

The **builds** section contains details on build locations.
Refer to testbeds/sonic_builds.yaml for more details

The **speeds** section contains details on speed profiles.
Refer to testbeds/sonic_speeds.yaml for more details

The **errors** section contains details on error patterns. This is used to classify the test result when a specific pattern of errors are seen in the CLI output.
Refer to testbeds/sonic_errors.yaml for more details

The **configs** section contains details on configuration to be applied before executing test scripts. Refer to testbeds/sonic_configs.yaml for more details.

**Note:** The above sections can be filled in line or included from other files in testbeds folder

The **devices** section contains list of devices, which are referred in **topology** section.
Each child of of this node represents single device, which can be DUT or TGen as denoted by **device_type** attribute.

* **device_type**
   * Type of the device
   * currently supported devices [sonic, TGEN]

 The details of DUT attributes are as given below:

* **access** DUT access details
     * **protocol** DUT access protocol, currently supported access protocols [telnet, ssh]
     * **ip** IP address for telnet/ssh connection to DUT, Only IPv4 address is currently supported
     * **port** TCP port for telnet/ssh connection to DUT
<p>

* **credentials** DUT access credentials
     * **username** DUT access username
     * **password** DUT access password
     * **altpassword** DUT access alternative password, This is useful if we need to change the default password on first boot

* **properties** DUT properties
     * **config** Configuration profile name to be applied before executing test scripts, the profile details read from yaml section name matching with this name under **configs**, Refer to testbeds/sonic_configs.yaml for more details
     * **build** Build profile name to be applied before executing test scripts, The profile details read from yaml section name matching with this name under **builds**, Refer to testbeds/sonic_builds.yaml for more details
     * **services** Services profile name to be used for external services like radius/tacacs, The profile details read from yaml section name matching with this name under **services**, Refer to testbeds/sonic_services.yaml for more details
     * **speed** Speed profile name to be applied before executing test scripts, The profile details read from yaml section name matching with this name under **speeds**, Refer to testbeds/sonic_speeds.yaml for sample

* **breakout** port breakout configuration, This is essentially list of interface-name, breakout-mode pairs.

* **rps** Remote Power Supply (PDU) details
     * **model** RPS Model, currently supported models [Raritan, ServerTech, Avocent], Telnet protocol to interface with RPS
     * **ip** IP address of RPS, Only IPv4 address is currently supported
     * **outlet** RPS outlet identification
     * **username** RPS telnet username
     * **password** RPS telnet password

 The details of TGen attributes are as given below:

* **properties** TGen properties
     * **type** Traffic Generator Type, Currently supported TGen types [ixia, stc, scapy]
     * **version** Traffic Generator version. Supported versions are ixia 8.42 to 9.31, stc 4.91 and scapy 1.0 [scapy TGEN version is just a place holder and not used]
     * **ip** Traffic Generator chassis IP address, Only IPv4 address is currently supported
     * **ix_server** This is only applicable for Ixia and it should point to IxNetwork Server IP Address, Only IPv4 address is currently supported.

The **topology** section gives interconnect details between DUTs as well as interconnect between each device with TGen. Each child of of this node represents a topology element and should be a DUT name from **devices** section. The interconnections are specified in **interfaces** child of each topology element. Each connected interface will have **EndDevice** and **EndPort** attributes representing the partner and its link.

## Traffic Generation

![Image](tgen.jpg "icon")

SPyTest supports the integration of Ixia and Spirent as third-party traffic generators. These traffic generators provide client libraries that enable communication with the underlying hardware.

### Ixia

For Ixia, SPyTest supports the IxNetwork Server mode. To utilize this mode, users need to set up an intermediate server to host the IxNetwork Server. The IxNetwork API server should be started on the server where the IxNetwork Server is installed. In the setup file, the IP address of the IxNetwork Server should be specified as "ix_server". SPyTest has been verified with IxNetwork versions ranging from 8.42 to 9.31. However, please note that there may be differences in the installation and launch procedures for different versions, so it is advisable to consult the Ixia documentation for more detailed instructions.

### Spirent

For Spirent, SPyTest supports the Spirent Testcenter client mode. SPyTest has been verified with Spirent versions 4.91.

### HLTAPI

All the HLTAPIs are exposed as wrapper functions in the format "tg_[HLTAPI]". There are few differences between Ixia and Spirent which are handled in these wrapper functions. As and when any new differences are identified, we should be able to add them easily in these wrapper functions.

Users can refer to either the Ixia or Spirent HLTAPI reference guides and invoke the tg_[HLTAPI].

### Scapy

![Image](ptf.jpg "icon")

* Scapy is supported using the Scapy service in PTF docker
* Scapy service implements tg_[HLTAPI] functions which are remotely called from SPyTest
* Currently PTF does not support connections between devices through fan-out switch.
  Once this is implemented the direct connections between devices can be removed.
* The PTF docker can also be used for legacy PTF test scripts execution as the Scapy Service will not take control of the PTF ports without SPyTest connecting to it.
* Refer to **Execution Modes**/**PTF Mode** for instructions on setting up PTF environment

![Image](scapy.gif "icon")

* Stateless Traffic Support
    * Only packet types that are exercised are in SPyTest are implemented
        * For example: Ether/Dot1Q/ARP/IPv4/IPv6/UDP/TCP/ICMP/IGMP/Custom Payload
        * Will add new packet types as and when required
    * Various frame sizes
    * Start/Stop/Enable/Disable/Modify streams
    * Capture Clear/Start/Stop/Fetch
    * Stats Reset/Fetch
    * Increment/Decrement
        * SRC/DST MAC/IPv4/TCP Ports/UDP Ports/VLAN
* Host Emulation Support
    * Create/Delete Interfaces
    * Assign IPv4/IPv6 Addresses
    * Ping Support
    * ARP support
* Protocol Emulation Support
    * Currently Not supported fully
    * Only basic BGP neighborship is unit tested

## Execution Modes

The SPyTest supports executing tests in standalone environment and PTF environment.

### PTF Mode

Refer to [README.testbed.md](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/README.testbed.md) for setting up PTF-32  or PTF-64 topology.

### Standalone Mode

In standalone mode, the DUTs can be connected to each other and TGen.

### Virtual SONiC

Refer to [VSNet](https://github.com/ramakristipati/sonic-mgmt/blob/vsnet/spytest/Doc/vsnet.md) for creating virtual SONiC network. Once topology is created VSNet provides commandline options to execute the SPyTest tests.

## Environment

### PTF

Refer to [README.testbed.Overview.md](https://github.com/sonic-net/sonic-mgmt/blob/master/ansible/doc/README.testbed.Overview.md) for setting up PTF environment details.

### Standalone

SPyTest currently supports Python3. The needed packages can be installed using

    [ROOT]/bin/upgrade_requirements.sh

The below environment file need to be modified to suit to your needs

    [ROOT]/bin/env

The traffic generator libraries are expected to be present at below location. The path can be customized using environment variable SCID_TGEN_PATH also.

    /projects/scid/tgen

The traffic generator libraries installation should look similar to content in below file

    [ROOT]/bin/tgen_folders.txt

*Please refer to install.md for more details on installation*

## Test Execution

First step is to create the testbed file with physical connection details.

### Running test script(s)

    [ROOT]/bin/spytest --testbed testbed_file.yaml  \
        [ROOT]/tests/sanity/test_sanity_l2.py \
        [ROOT]/tests/sanity/test_sanity_l3.py \
        --logs-path <folder-to-create-logs>

### Running tests using PyTest marker

    [ROOT]/bin/spytest --testbed testbed_file.yaml  \
        -m community_pass --logs-path <folder-to-create-logs>

### Running tests using suite name

    [ROOT]/bin/spytest --testbed testbed_file.yaml  \
        --test-suite <suite name> --logs-path <folder-to-create-logs>

The test suite files are expected to be present in [ROOT]/reporting/suites folder.
*Please refer to community-ptf for example suite definition.

### Execution Results and Logs

The results are stored in a CSV file with the date (YYYY-MM-DD) and time (HH-MM-SS) included in the file name
e.g. results_2020_04_04_15_27_result.csv

The log messages are stored in a log file with the date (YYYY-MM-DD) and time (HH-MM-SS) included in the file name
e.g. results_2020_04_04_15_27_logs.log

### Command line arguments

To obtain a comprehensive list of command line options available in SPyTest, you can use the following command:

     [ROOT]/bin/spytest --help

Executing this command will display all the command line options along with their associated help strings, which provide explanatory information about each option. These help strings serve as a guide to understand the purpose and functionality of each command line option available in SPyTest.

## Log Files

Below is the list of log files generated during SPyTest execution, each file name contain prefixed by [PREFIX] which is a placeholder for the timestamp in the format results_%Y_%m_%d_%H_%M_%S. It is removed below to minimise the redundent information.

Below is the collection of log files generated during SPyTest execution. Each log file's name is prefixed with [PREFIX], representing the timestamp in the format "results_%Y_%m_%d_%H_%M_%S." In the list provided below, the actual [PREFIX] have been omitted to avoid redundancy.

* dlog-[DUTID]-[DUTNAME].log: This file contains the per DUT log, where [DUTID] represents the DUT identifier (e.g., D1, D2) and [DUTNAME] is the name specified in the testbed file. One file is generated for each DUT in the testbed file.
* logs.log: This file is a consolidated log for the entire test run.
* stdout.log: Similar to logs.log, this file includes any stdout/stderr messages from SPyTest and its dependent libraries.
* summary.txt: This file provides the final summary of the test run, including the number of executed tests, time taken, pass rate, etc.
* functions.csv: This file contains the result of each executed test function, including the result, description, time taken, etc.
* functions.html: This file is an HTML version of functions.csv for easy viewing in a browser.
* testcases.csv: This file contains the result of each executed test case. Test functions may have one or more test cases associated with them. The file includes the result, description, time taken, etc., for each test case.
* testcases.html: This file is an HTML version of testcases.csv.
* modules.csv: This file contains the result counts (number of test functions) in various categories per test module and the time taken for each module.
* modules.html: This file is an HTML version of modules.csv.
* features.csv: This file contains the result counts (number of test cases) in various categories per test component and the time taken for each. The association between test cases and components can be found in [ROOT]/reporting/tcmap.csv. Example component names include "Regression" and "NAT".
* features.html: This file is an HTML version of features.csv.
* stats.txt: This file contains statistics on the time spent on each CLI command and TGen operation for each module.
* stats.csv: This file contains statistics on the total time spent on CLI and TGen operations for each module.
* stats.html: This file is an HTML version of stats.csv.
* syslog.csv: This file contains syslog messages collected from all DUTs in each test module. The severity of messages collected and their frequency can be configured using the --syslog-check command-line option.
* syslog.html: This file is an HTML version of syslog.csv.
* mlog_[module].log: This file is similar to logs.log but specific to each module.
* tgen: This directory contains TGen specific debug logs.
These log files provide valuable information for analyzing test results, debugging issues, and gaining insights into the test execution process. They offer a comprehensive view of the test run, including detailed logs, summaries, statistics, and associated data.

## Dashboard

The dashboard.html file serves as a dashboard or summary report that provides links to various files generated during the SPyTest execution. These files are typically generated as part of the test execution process and contain detailed information about the test results, logs, and other relevant data.

The dashboard.html file is designed to provide a centralized location for accessing these files and navigating through the generated artifacts. It offers a user-friendly interface that allows users to easily access and review the test results and associated files.

Some of the files that are commonly linked in the dashboard.html file include:

Test Results: This could be a detailed test report containing information about the test cases executed, their pass/fail status, and any associated logs or screenshots.
Logs: These can include system logs, device logs, test framework logs, and any other relevant logs generated during the test execution.
Artifacts: Any additional artifacts generated during the test execution, such as captured packets, configuration files, or debug information.
Screenshots: If there are any visual elements or UI testing involved, screenshots may be captured during the test execution and linked in the dashboard for easy access and review.
The dashboard.html file acts as a centralized hub to access and navigate through these files, providing a comprehensive view of the test execution and its associated artifacts. It simplifies the process of reviewing and analyzing the test results and enables users to quickly access the specific files they need for further investigation or reporting purposes.

By leveraging the dashboard.html file, users can efficiently explore the generated files, access relevant information, and gain insights into the test execution without having to manually locate and open each individual file.

## Internals

### Init sequence

Before executing the test modules, SPyTest performs several operations to ensure the test environment is properly set up. These operations include:

* Validation of Testbed File: SPyTest validates the specified testbed file to ensure its correctness and completeness. This validation ensures that the required information about devices, connections, and other configuration details are accurately specified in the testbed file.

* Device and TGen Connection: SPyTest establishes connections to all the devices and Traffic Generators (TGen) specified in the testbed file. This step enables SPyTest to interact with the devices and TGens during test execution.

* Software Upgrade: If specified in the command line arguments or the testbed build profile, SPyTest upgrades the software on the Devices Under Test (DUTs) to the specified version. This ensures that the test environment is running the desired software version for testing.

* Configuration Database Cleanup: SPyTest removes all entries from the configuration database (config_db.json), except for "DEVICE_METADATA", "MGMT_INTERFACE" and "PORT" entries. This cleanup operation ensures that the configuration database is in a clean state before applying the test-specific configurations.

* Port Breakout: If specified in the testbed file, SPyTest performs a static port breakout operation. This operation configures the port breakout mode for specific ports, allowing them to be used in different breakout configurations.

* Port Speed Configuration: SPyTest configures the port speeds according to the specified speed profile in the testbed file. This step ensures that the ports are set to the desired speeds for testing.

* Base Configuration Saving: After applying the configurations, SPyTest saves the resultant configuration as the base configuration. This serves as a reference point for future test executions and enables comparison to track any configuration changes caused by the tests.

By performing these operations, SPyTest ensures that the test environment is properly set up and configured according to the test requirements, providing a consistent and controlled testing environment for the execution of test modules.

### Base Configuration

As described in the "Init Sequence" section, the SPyTest framework creates a base configuration during its initialization process. This base configuration serves as a reference point and represents the desired initial state of the system before any test modules are executed.

The framework ensures that the system is brought to the base configuration state before starting the execution of any test modules. This ensures a consistent starting point for the tests and helps in achieving reliable and reproducible test results.

The base configuration is typically defined based on the testbed file and any additional configuration profiles or settings specified. It includes configurations related to the network devices, interfaces, protocols, services, and any other relevant aspects of the test environment.

By ensuring the system is in the base configuration state, SPyTest provides a controlled environment for running test modules. It helps in eliminating any unwanted side effects or residual configurations from previous tests, ensuring that each test module starts from a clean and predictable state.

This initialization step plays a crucial role in maintaining the integrity and reliability of the test execution process, allowing test modules to focus on specific functionalities or test cases without being influenced by the system's previous state.

### Module Configuration

In SPyTest, test modules are responsible for configuring the device and Traffic Generators (TGen) within their respective module prologue and cleaning up any configurations or resources in the module epilogue. This ensures that the necessary setup and teardown operations are performed before and after each test module execution.

    @pytest.fixture(scope="module", autouse=True)
    def module_hooks(request):
        ########### module prologue #################
        yield
        ########### module epilogue #################

The module prologue function will be automatically called at the beginning of the module execution, allowing you to perform device and TGen configuration. The module epilogue function is executed after all test functions have been executed within the module, ensuring that any necessary cleanup operations are performed.

By leveraging these fixture functions with the appropriate scope and settings, SPyTest ensures the orderly execution of the module prologue before any test functions and the module epilogue after all test functions in the module.

### Customize Error Patterns

The [ROOT]/testbeds/sonic_errors.yaml contains regular expressions of errors and corresponding actions to be performed when those errors are encountered. This configuration file is used to define error patterns and specify the appropriate action to be taken when those patterns match with the encountered errors.

### Syslog Error Patterns

SPyTest collects and consolidates syslog messages after each test. The categorization of syslog messages is based on the information provided in the [ROOT]/reporting/syslogs.yaml file. This file serves as a reference for organizing the messages into different categories.

The syslog messages are categorized as follows:

Yellow: Messages in this category are reported only once for every module. They are considered important and are not discarded.

Green: Messages in this category are silently discarded. They are typically not relevant for test analysis or reporting.

Red: If a syslog message matches a pattern specified in this category, the corresponding test is marked as failed. The first matched message is treated as a DUTIssue, indicating a potential software issue.

By leveraging the [ROOT]/reporting/syslogs.yaml file, SPyTest effectively organizes syslog messages, enabling efficient analysis and reporting of test results.

The introduction of the red and green categories provides a streamlined approach for handling different types of syslog messages. The red category helps automate the identification and analysis of failures related to software issues, while the green category allows for the exclusion of syslog messages that are not pertinent to the analysis or reporting process.

The initial implementation of these categories is currently empty to align with the existing behavior. However, there is room for future contributions to expand the list of regular expressions and categories. This collaborative effort can enhance the failure analysis capabilities and cover a wider range of scenarios.

In summary, this approach facilitates the automation of failure analysis, particularly in identifying software-related issues through the red category. Additionally, it aids in eliminating known noise syslog messages, particularly those originating from third-party code.

In addition to the syslog categorization, SPyTest saves the collected syslog messages from all Device Under Test (DUT) devices in each test module into a syslog.csv file. This file serves as a comprehensive record of the syslog messages and includes information about their severity and frequency. The content of the syslog.csv file can be further customized by configuring the --syslog-check command-line option.

Furthermore, SPyTest provides a syslog.html file, which is an HTML version of the syslog messages. This file offers a user-friendly and visually appealing representation of the syslog data. It can be opened in a web browser, facilitating easy navigation and exploration of the syslog messages. The syslog.html file presents the syslog categories in a more organized and accessible manner, enhancing the usability of the information.

### Batch Processing

The SPyTest framework is designed to handle the execution of a large number of test modules, which may require various types of topologies based on the features being tested. These topologies can range from single-device setups to more complex configurations involving multiple interconnected devices. To efficiently execute these test modules in parallel, the SPyTest framework employs a batch processing technique.

The devices used in the testing environment are typically organized into racks or pods, with interconnecting cables. The batch processing capability allows users to divide these pods into smaller topologies known as gateway (gw) nodes. Users can specify the desired number of DUT topologies for each bucket using command line arguments. For example, specifying "-tclist-buckets 1,2,4" indicates the intention to have 4, 2, and 1 DUT topologies respectively.

Users can further customize the devices used in each bucket by providing the necessary configuration through command line arguments. The configuration can be specified using the "--env SPYTEST_TOPO_4" flag, where "4" represents the bucket number. The selected devices and their interconnections are defined using a specific syntax, with "|" separating groups and "||" indicating multiple groups.

To determine the topology requirements for each module, the SPyTest framework reads the "modules.csv" file. This information is used to associate the appropriate modules with the corresponding nodes created based on the bucket arguments.

Once the nodes and module associations are established, the SPyTest framework starts executing the test modules on the higher bucket nodes first. Before dispatching the actual test modules, a framework test module is launched on these nodes to perform necessary initializations such as image upgrades or breakout configurations.

The framework continues executing the test modules within the current bucket until they are completed. It then progresses to the next lower bucket, repeating the process until all the test cases have been executed. This approach ensures optimal resource utilization and facilitates faster execution of the extensive suite of test modules.

### Static Analysis

To perform static analysis on the SPyTest codebase, you can utilize the lint.sh script located in the [ROOT]/bin directory. This script uses PyLint, a popular Python static code analyzer, to analyze the code and provide feedback on potential issues and code quality improvements. The lint.sh script includes flags that are specifically configured to disable certain unsupported options and settings in PyLint. This ensures that the analysis is performed with the appropriate configuration for the SPyTest codebase.

## Test Suites

The test suites can be found in the directory [ROOT]/reporting/suites. To access the topology requirements for all test modules, one can refer to the file [ROOT]/reporting/modules_stc.csv.

This CSV file provides detailed information about each test module and their corresponding topology requirements. Blank lines and comments (lines starting with '#') are ignored during processing and can be disregarded.

The CSV file contains the following columns:

* TopoBucket: Indicates the number of devices needed for the test module. It represents the bucket or group to which the test module belongs based on the required network topology.

* OrderBucket: Specifies the execution order within each bucket. Test modules with higher values in this column are executed first within their respective bucket.

* Preference (Optional): An optional column that specifies the preference value for the test module. If not specified, the preference value is considered as 1. If there are multiple lines with different preference values, one line is randomly selected.

* Module: Contains the name of the test module relative to the tests folder. It represents the test module's file name or path.

* Topology: Defines the topology requirements for the test module. It is similar to the ensure_minimum_topology notation and describes the specific network configurations or dependencies needed to run the test module successfully.

To illustrate, let's examine the topology requirements for the sanity suite.

    2,4,sanity/test_sanity_l2.py,D1D2:4 D1T1:3 D2T1:1
    2,2,sanity/test_sanity_l3.py,D1D2:1 D1T1:1 D2T1:1
    1,2,sanity/test_sanity_sys.py,D1

 The "test_sanity_l2.py" module requires two devices connected with 4 links, with specific link requirements for each device and the traffic generator. The "test_sanity_l3.py" module also requires two devices connected with 1 link, with each device needing a link to the traffic generator. The "test_sanity_sys.py" module requires a single device.

 To verify the physical devices' topology and validate network connectivity, the option is available to use either Ixia or Spirent as the traffic generator. The latest supported versions for Ixia and Spirent are 9.31 and 4.91, respectively. These versions are recommended for optimal compatibility and performance.

 Once the testbed file is created, below command can be used to execute sanity suite.

     [ROOT]/bin/spytest --testbed testbed_file.yaml  \
        --test-suite dev-sanity --logs-path <folder-to-create-logs>

As mentioned earlier, the results can be checked by referring to the xxx_functions.csv or xxx_functions.html files. These files contain information related to the test functions and their corresponding outcomes.

As an alternative, for a more convenient way to access the results, the <logs>/dashboard.html file can be opened, and the modules link in the left pane can be utilized. Clicking on the modules link will load <logs>/results_modules.html in the right pane, which provides a comprehensive view of the results for all modules. The results can be sorted based on any column in this page, and by clicking on the module name, the corresponding module log file can be opened for detailed analysis. We can search for " Report(" to each to individual function results.

