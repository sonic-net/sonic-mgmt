# Auditd Container & Watchdog Test Plan

## Overview

The purpose of this test plan document is to test the functionality of auditd feature on SONiC switch, which is deployed or upgraded by a Kubernetes master outside SONiC.  

For details of auditd container feature design, please refer to HLD: [auditd HLD](https://github.com/sonic-net/SONiC/pull/1713).  

## Scope

The test is targeting a running SONiC system with fully functioning configuration. The purpose of this test is to verify the function of auditd security functionality and auditd watchdog inside auditd container.  

## Testbed

The test can run on both physical and virtual testbeds with any topology.  

## Limitation

N/A  

## Setup Configuration

No setup pre-configuration is required, test will setup and clean-up all the configuration.  

## Update on Nightly Test

In nightly test per hwsku, we plan to add below new testcases for auditd security domains. They will be part of the nightly test to qualify each SONiC whole image.  

### Test Case

| # | Description | Test | Expected Result |
|---|-------------|------|-----------------|
| 1 | Container Functionality | Test – Auditd container is working properly after pulling docker image from docker registry. | healthy container <br><br>Auditd on host is active and running <br><br>Rules and config files are validated based on hwsku and version <br><br>Auditd are sent to rsyslog <br><br>Container has the correct settings - privileged, pid, net, volume mount settings |
| 2 | Watchdog Functionality | Test – Watchdog reports healthy auditd container | Healthy auditd container - Watchdog returns success http code |
| 3 | file_deletion rule | Log in to DUT as a test user <br><br> Create a dummy test file <br><br> Delete this file | Auditd will record this event made by test user to file_deletion key |
| 4 | process_audit rule | Log in to DUT as a test user <br><br> Execute a dummy command as a test user | Auditd will record this event made by test user to process_audit key |
| 5 | user_group_management rule | Log in to DUT as a test user <br><br> Switch test user to another user | Auditd will record this event made by test user to user_group_management key |
| 6 | docker_commands rule | Log in to DUT as a test user <br><br> Execute a docker command as a test user | Auditd will record this event made by test user to docker_commands key |
| 7 | group_changes rule <br> hosts_changes rule <br> passwd_changes rule <br> shadow_changes rule <br> sudoers_changes rule <br> time_changes rule <br> auth_logs rule <br> cron_changes rule <br> dns_change rule <br> docker_config rule <br> docker_daemon rule <br> docker_service rule <br> docker_socket rule <br> modules_changes rule <br> shutdown_reboot rule | Log in to DUT as a test user <br><br> Modify the watch file <br><br> group_changes: /etc/groups <br> hosts_changes: /etc/hosts <br> passwd_changes: /etc/passwd <br> shadow_changes: /etc/shadow <br> sudoers_changes: /etc/sudoers <br> time_changes: /etc/localtime <br> auth_logs: /var/log/auth.log, /var/log.tmpfs/auth.log <br> cron_changes: /etc/crontab, /etc/cron.d, /etc/cron.daily, /etc/cron.hourly, /etc/cron.weekly, /etc/cron.monthly <br> dns_change: /etc/resolv.conf <br> docker_config: /etc/docker/daemon.json <br> docker_daemon: /usr/bin/dockerd <br> docker_service: /lib/systemd/system/docker.service <br> docker_socket: /lib/systemd/system/docker.socket <br> modules_changes: /sbin/insmod, /sbin/rmmod, /sbin/modprobe <br> shutdown_reboot: /var/log/wtmp | Auditd will record this event made by test user to corresponding key |
| 8 | log_changes rule <br> bin_changes rule <br> sbin_changes rule <br> usr_bin_changes rule <br> usr_sbin_changes rule <br> docker_storage rule | Log in to DUT as a test user <br><br> Create a dummy test file under the watch directory <br><br> log_changes: /var/log/, /var/log.tmpfs/ <br> bin_changes: /bin <br> sbin_changes: /sbin <br> usr_bin_changes: /usr/bin <br> usr_sbin_changes: /usr/sbin <br> docker_storage: /var/lib/docker/ <br><br> Modify this test file | Auditd will record this event made by test user to corresponding key |

Considering auditd security feature is an always enabled feature and may bring whole switch overhead, we will also ensure all other testcases in the nightly has auditd security feature enabled, in order to find performance impact to other testcases during nightly test or PR KVM test.

So Test Case 1 will be run early in each test run, Test Case 2 will be run late in each test run.

Inside Test Case 1, we assume that the pre-install SONiC image has no auditd  security feature. During the testcase, we will pull the docker image with Kubernetes defined golden image version from the docker registry on DUT, start a container from this docker image. There will be no explicit command line to ‘config audit enable’, because it is already achieved by start the auditd container.

We will not implement a Kubernetes/SONiC integration in all the testcases, only using docker command like `docker pull`, `docker run` to simulate the docker behavior in a true Kubernetes/SONiC integration.

## Setup a New Test Pipeline to Qualify Auditd Docker Image New Versions

Auditd docker image are expected to be developed and rollout much more freuqent than the whole SONiC image. In order to qualify each auditd docker image with already qualified SONIC whole image, we need to setup a new test pipeline, and this pipeline will loop through all the production SONIC whole image versions in a specific scope, and apply the TBT (To-be-tested) auditd docker image, and run a set of audit security related testcases (not the full nightly test suite).  

The test framework is detailed in [Container Upgrade Test Plan](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/Container-Upgrade-test-plan.md).  

The SONIC whole image versions in scope depends on the rollout scope. For example:  

- Auditd container is normally loose decoupled with the SONiC whole image, the scope will be all the 202311 and later images used in production at the time of test run.  
- Telemetry container may be coupled with SONiC whole image. We assumed that all 20ABCDEF.XX telemetry image can run on any 20ABCDEF.XX SONiC image. So the version scope will be all the rollout branch (20ABCD) used in production at the time of test run.  

The version list is manually constructed and fed while triggering the pipeline. We do not plan to automate the version list constructing in the near future.  

We plan to add below new testcases for auditd security domains. However, we will not run all other testcases not directly related to auditd security domains, such as log rotation testcases. The cross testcase (like auditd brings CPU pressure and impact performance) will run in nightly test in above Section, not in this new  test pipeline.  

All the testcases covered in the new test pipeline are duplicated with the testcases in nightly test section above.  

### Test Case

- 3: file_deletion rule  
- 4: process_audit rule  
- 5: user_group_management rule  
- 6: docker_commands rule  
- 7: group_changes rule  
  - hosts_changes rule  
  - passwd_changes rule  
  - shadow_changes rule  
  - sudoers_changes rule  
  - time_changes rule  
  - auth_logs rule  
  - cron_changes rule  
  - dns_change rule  
  - docker_config rule  
  - docker_daemon rule  
  - docker_service rule  
  - docker_socket rule  
  - modules_changes rule  
  - shutdown_reboot rule  
- 8: log_changes rule  
  - bin_changes rule  
  - sbin_changes rule  
  - usr_bin_changes rule  
  - usr_sbin_changes rule  
  - docker_storage rule  

## Testcases for watchdog failure path

All the above testcases practice the happy path of a production rollout, where the watchdog  always return success result. However, watchdogs by design are to respond accurate success result on happy path or failing result for sad path. In this section, we will purposely constructing  some sad paths (with mocked components) in order to practice watchdog functionality and observe expected failure result for unexpected container rollout in bad situations.  

We plan to implement unit test or sonic-mgmt testcases. Since the failing patterns (like failing to restart service) are mostly irrelevant to HwSKU, we could just run unit test on any platform, or run sonic-mgmt testcase on KVM platform. No plan run sonic-mgmt testcase on each HwSKU.  

The sad path testcases are mainly to practice watchdog functionality and observe expected failure result for unexpected container rollout in bad situations.  

### Test Case

| # | Description | Test | Expected Result |
|---|-------------|------|-----------------|
| 1 | Host Service Functionality | Test – host auditd service restarting is working properly after pulling docker image from docker registry. | Auditd container startup script deployed the config files and try to restart the host auditd service <br><br> The host auditd service could not restart itself (mocked situation) <br><br> Auditd container watchdog could be aware of the issue, and respond to watchdog endpoint with a failure http status code |
| 2 | Hardware SKU-Specific Auditd Rules | Test - Attempt to load 64-bit rules on a 32-bit CPU system. | Rules are not validated <br><br> Watchdog endpoint returns failure http status code <br><br> Note: this testcase could only run in a 32-bit CPU test environment |