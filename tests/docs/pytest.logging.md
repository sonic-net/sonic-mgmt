# Overview

It would be much easier to troubleshoot the root cause if the failed scripts can generate appropriate log messages. We often need the log messages to be detailed enough so that we can have all the information needed for debugging. But if the log messages have too much irrelevant information, the noise will make it difficult for us to locate the root cause. The logging need to be balanced between detail and concise.

# Pytest logging
Like most automation framework, pytest supports two typical logging methods:
1. Output log messages to console.
2. Save log messages to file.

Reference: [pytest logging](https://docs.pytest.org/en/latest/logging.html)

Different configuration options can be used to control the logging level, format and destination:
* log_cli_level
* log_cli_format
* log_cli_date_format
* log_file
* log_file_level
* log_file_format
* log_file_date_format

The configuration options can be specified in the configuration INI file or supplied to the `pytest` command line. You can configure live logging or file logging according to your requirements. In this document, we will use live logging as example.

For the pytest scripts to show live logging, we can simply specify `--log-cli-level <level>` on CLI, for example:
```
pytest <scripts> <other_options> --log-cli-level debug
```

For the pytest scripts to log messages to file, we can specify arguments like `--log-file /tmp/test_log.txt --log-cli-level debug`.



The pytest scripts depend on the pytest-ansible plugin to run ansible modules on the devices in testbed. However, the pytest-ansible plugin and ansible caused some troubles with logging. If we set `--capture no` (will talk about it later) and `--log-cli-level debug`, executing a simple ansible `command` module on duthost will result in below logs:

```
DEBUG    pytest_ansible.module_dispatcher.v28:v28.py:78 [vlab-01] shell: {'_raw_params': 'pwd'}
Loading callback plugin unnamed of type old, v1.0 from /usr/local/lib/python2.7/dist-packages/pytest_ansible/module_dispatcher/v28.py
INFO     p=10040 u=johnar | :display.py:179 Loading callback plugin unnamed of type old, v1.0 from /usr/local/lib/python2.7/dist-packages/pytest_ansible/module_dispatcher/v28.py
DEBUG    pytest_ansible.module_dispatcher.v28:v28.py:127 Play({'gather_facts': 'no', 'tasks': [{'action': {'args': {'_raw_params': 'pwd'}, 'module': 'shell'}}], 'hosts': 'vlab-01', 'name': 'pytest-ansible'})
DEBUG    pytest_ansible.module_dispatcher.v28:v28.py:133 TaskQueueManager({'stdout_callback': <pytest_ansible.module_dispatcher.v28.ResultAccumulator object at 0x7f9ab67d2f50>, 'passwords': {'conn_pass': None$
 'become_pass': None}, 'variable_manager': <ansible.vars.manager.VariableManager object at 0x7f9ab8619610>, 'inventory': <ansible.inventory.manager.InventoryManager object at 0x7f9ab8619210>, 'loader': <ansib$
e.parsing.dataloader.DataLoader object at 0x7f9ab8619510>})
Loading callback plugin profile_tasks of type aggregate, v2.0 from /usr/local/lib/python2.7/dist-packages/ansible/plugins/callback/profile_tasks.py
INFO     p=10040 u=johnar | :display.py:179 Loading callback plugin profile_tasks of type aggregate, v2.0 from /usr/local/lib/python2.7/dist-packages/ansible/plugins/callback/profile_tasks.py
META: ran handlers
INFO     p=10040 u=johnar | :display.py:179 META: ran handlers
Monday 01 June 2020  09:36:33 +0000 (0:00:00.852)       0:00:07.058 ***********
INFO     p=10040 u=johnar | :display.py:179 Monday 01 June 2020  09:36:33 +0000 (0:00:00.852)       0:00:07.058 ***********
Using module file /usr/local/lib/python2.7/dist-packages/ansible/modules/commands/command.py
INFO     p=10040 u=johnar | :display.py:179 Using module file /usr/local/lib/python2.7/dist-packages/ansible/modules/commands/command.py
Pipelining is enabled.
INFO     p=10040 u=johnar | :display.py:179 Pipelining is enabled.
<10.250.0.101> ESTABLISH SSH CONNECTION FOR USER: admin
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> ESTABLISH SSH CONNECTION FOR USER: admin
<10.250.0.101> SSH: ansible.cfg set ssh_args: (-o)(ControlMaster=auto)(-o)(ControlPersist=120s)(-o)(UserKnownHostsFile=/dev/null)(-o)(StrictHostKeyChecking=no)
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: ansible.cfg set ssh_args: (-o)(ControlMaster=auto)(-o)(ControlPersist=120s)(-o)(UserKnownHostsFile=/dev/null)(-o)(StrictHostKeyChecking=no)
<10.250.0.101> SSH: ANSIBLE_HOST_KEY_CHECKING/host_key_checking disabled: (-o)(StrictHostKeyChecking=no)
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: ANSIBLE_HOST_KEY_CHECKING/host_key_checking disabled: (-o)(StrictHostKeyChecking=no)
<10.250.0.101> SSH: ANSIBLE_REMOTE_USER/remote_user/ansible_user/user/-u set: (-o)(User="admin")
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: ANSIBLE_REMOTE_USER/remote_user/ansible_user/user/-u set: (-o)(User="admin")
<10.250.0.101> SSH: ANSIBLE_TIMEOUT/timeout set: (-o)(ConnectTimeout=10)
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: ANSIBLE_TIMEOUT/timeout set: (-o)(ConnectTimeout=10)
<10.250.0.101> SSH: PlayContext set ssh_common_args: ()
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: PlayContext set ssh_common_args: ()
<10.250.0.101> SSH: PlayContext set ssh_extra_args: ()
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: PlayContext set ssh_extra_args: ()
<10.250.0.101> SSH: found only ControlPersist; added ControlPath: (-o)(ControlPath=/var/johnar/.ansible/cp/e95704e219)
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: found only ControlPersist; added ControlPath: (-o)(ControlPath=/var/johnar/.ansible/cp/e95704e219)
<10.250.0.101> SSH: EXEC sshpass -d10 ssh -vvv -o ControlMaster=auto -o ControlPersist=120s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o StrictHostKeyChecking=no -o 'User="admin"' -o ConnectT
imeout=10 -o ControlPath=/var/johnar/.ansible/cp/e95704e219 10.250.0.101 '/bin/sh -c '"'"'sudo -H -S  -p "[sudo via ansible, key=jwgphutgyvifmsnbveqtyuqzfidllhao] password:" -u root /bin/sh -c '"'"'"'"'"'"'"'"
'echo BECOME-SUCCESS-jwgphutgyvifmsnbveqtyuqzfidllhao ; /usr/bin/python'"'"'"'"'"'"'"'"' && sleep 0'"'"''
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> SSH: EXEC sshpass -d10 ssh -vvv -o ControlMaster=auto -o ControlPersist=120s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o StrictHost
KeyChecking=no -o 'User="admin"' -o ConnectTimeout=10 -o ControlPath=/var/johnar/.ansible/cp/e95704e219 10.250.0.101 '/bin/sh -c '"'"'sudo -H -S  -p "[sudo via ansible, key=jwgphutgyvifmsnbveqtyuqzfidllhao] pa
ssword:" -u root /bin/sh -c '"'"'"'"'"'"'"'"'echo BECOME-SUCCESS-jwgphutgyvifmsnbveqtyuqzfidllhao ; /usr/bin/python'"'"'"'"'"'"'"'"' && sleep 0'"'"''
Escalation succeeded
INFO     p=10040 u=johnar | :display.py:179 Escalation succeeded
<10.250.0.101> (0, '\n{"changed": true, "end": "2020-06-01 09:36:33.450915", "stdout": "/home/admin", "cmd": "pwd", "rc": 0, "start": "2020-06-01 09:36:33.442212", "stderr": "", "delta": "0:00:00.008703", "inv
ocation": {"module_args": {"creates": null, "executable": null, "_uses_shell": true, "strip_empty_ends": true, "_raw_params": "pwd", "removes": null, "argv": null, "warn": true, "chdir": null, "stdin_add_newli
ne": true, "stdin": null}}}\n', 'OpenSSH_7.2p2 Ubuntu-4ubuntu2.8, OpenSSL 1.0.2g  1 Mar 2016\r\ndebug1: Reading configuration data /var/johnar/.ssh/config\r\ndebug1: /var/johnar/.ssh/config line 1: Applying op
tions for *\r\ndebug1: Reading configuration data /etc/ssh/ssh_config\r\ndebug1: /etc/ssh/ssh_config line 19: Applying options for *\r\ndebug1: auto-mux: Trying existing master\r\ndebug2: fd 3 setting O_NONBLO
CK\r\ndebug2: mux_client_hello_exchange: master version 4\r\ndebug3: mux_client_forwards: request forwardings: 0 local, 0 remote\r\ndebug3: mux_client_request_session: entering\r\ndebug3: mux_client_request_al
ive: entering\r\ndebug3: mux_client_request_alive: done pid = 10180\r\ndebug3: mux_client_request_session: session request sent\r\ndebug1: mux_client_request_session: master session id: 2\r\ndebug3: mux_client
_read_packet: read header failed: Broken pipe\r\ndebug2: Received exit status from master 0\r\n')
INFO     p=10040 u=johnar | :display.py:179 <10.250.0.101> (0, '\n{"changed": true, "end": "2020-06-01 09:36:33.450915", "stdout": "/home/admin", "cmd": "pwd", "rc": 0, "start": "2020-06-01 09:36:33.442212", "
stderr": "", "delta": "0:00:00.008703", "invocation": {"module_args": {"creates": null, "executable": null, "_uses_shell": true, "strip_empty_ends": true, "_raw_params": "pwd", "removes": null, "argv": null, "
warn": true, "chdir": null, "stdin_add_newline": true, "stdin": null}}}\n', 'OpenSSH_7.2p2 Ubuntu-4ubuntu2.8, OpenSSL 1.0.2g  1 Mar 2016\r\ndebug1: Reading configuration data /var/johnar/.ssh/config\r\ndebug1:
 /var/johnar/.ssh/config line 1: Applying options for *\r\ndebug1: Reading configuration data /etc/ssh/ssh_config\r\ndebug1: /etc/ssh/ssh_config line 19: Applying options for *\r\ndebug1: auto-mux: Trying exis
ting master\r\ndebug2: fd 3 setting O_NONBLOCK\r\ndebug2: mux_client_hello_exchange: master version 4\r\ndebug3: mux_client_forwards: request forwardings: 0 local, 0 remote\r\ndebug3: mux_client_request_sessio
n: entering\r\ndebug3: mux_client_request_alive: entering\r\ndebug3: mux_client_request_alive: done pid = 10180\r\ndebug3: mux_client_request_session: session request sent\r\ndebug1: mux_client_request_session
: master session id: 2\r\ndebug3: mux_client_read_packet: read header failed: Broken pipe\r\ndebug2: Received exit status from master 0\r\n')
META: ran handlers
INFO     p=10040 u=johnar | :display.py:179 META: ran handlers
META: ran handlers
INFO     p=10040 u=johnar | :display.py:179 META: ran handlers
DEBUG    pytest_ansible.module_dispatcher.v28:v28.py:141 {'unreachable': {}, 'contacted': {u'vlab-01': {'stderr_lines': [], u'changed': True, u'end': u'2020-06-01 09:36:33.450915', '_ansible_no_log': False, u'
stdout': u'/home/admin', u'cmd': u'pwd', u'start': u'2020-06-01 09:36:33.442212', u'delta': u'0:00:00.008703', u'stderr': u'', u'rc': 0, u'invocation': {u'module_args': {u'warn': True, u'executable': None, u'_
uses_shell': True, u'strip_empty_ends': True, u'_raw_params': u'pwd', u'removes': None, u'argv': None, u'creates': None, u'chdir': None, u'stdin_add_newline': True, u'stdin': None}}, 'stdout_lines': [u'/home/a
dmin']}}}
```

This is too much and overwhelming, right? Among these log messages, we only care about two at debug level:
```
DEBUG    pytest_ansible.module_dispatcher.v28:v28.py:78 [vlab-01] shell: {'_raw_params': 'pwd'}
DEBUG    pytest_ansible.module_dispatcher.v28:v28.py:141 {'unreachable': {}, 'contacted': {u'vlab-01': {'stderr_lines': [], u'changed': True, u'end': u'2020-06-01 09:36:33.450915', '_ansible_no_log': False, u'
stdout': u'/home/admin', u'cmd': u'pwd', u'start': u'2020-06-01 09:36:33.442212', u'delta': u'0:00:00.008703', u'stderr': u'', u'rc': 0, u'invocation': {u'module_args': {u'warn': True, u'executable': None, u'_
uses_shell': True, u'strip_empty_ends': True, u'_raw_params': u'pwd', u'removes': None, u'argv': None, u'creates': None, u'chdir': None, u'stdin_add_newline': True, u'stdin': None}}, 'stdout_lines': [u'/home/admin']}}}
```
The first message is what ansible module was called with what argument. The second message is the ansible module result.

There are some issues in the logs.

1. The pytest-ansible plugin outputs 4 messages for running each ansible module. We only care about two of them.
2. Ansible itself output too much debug messages related with connecting to the target host. The pytest-ansible plugin calls ansible module with option `-vvvvv`. This causes ansible output the very detailed debugging information for establishing SSH connection to devices.
3. The ansible log messages are duplicated. One copy is output by logger, the other copy is directly written to stdout.

# Improvements

We've made some improvements in the framework to address these issues.

## Filter out the logs of pytest-ansible and ansible
In sonic-mgmt/tests/conftest.py, we implemented an auto used fixture `config_logging`. This fixture tries to get the logger objects of pytest-ansible and ansible and set their logging level to WARNING. Then we won't see any log messages of pytest-ansible and ansible with level lower than WARNING.

## Add code in tests/common/devices.py::AnsibleHostBase to log ansible calls
Without pytest-ansible logs, we have no information about ansible module calls. But we do wish there are log messages for what ansible module is called and what is the result. So, we added some code in the AnsibleHostBase class to generate two messages for each ansible call:
1. What and where an ansible module is called by who with what arguments.
2. What is the result of calling the ansible module.

These two messages are generated at DEBUG level.

## Disable log_path configuration in ansible/ansible.cfg
When this configuration is enabled, for the messages sent to stdout, ansible also send a copy to logger. This would cause duplicated log messages.

## Suggest to enable --capture
Pytest supports capturing all log messages sent to logger, stdout and stderr. The captured logs can be used for generating test reports. When capture is enabled, all the log messages sent to stdout and stderr will be captured and will not be output to console. In case of log-file, these log messages will not be saved to log file too. So, we suggest to have --capture enabled. Luckily, --capture is enabled by default.

## Remove the log messages captured from stdout and stderr
During testing, pytest captures all the messages sent to stdout, stderr and logger. The captured messages are stored in different sections like "stdout", "stderr" and "log". If `--show-capture` is not disabled, the for failed test cases, pytest will output all the sections of the captured logs.

The "stdout" section mainly contains ansible debug messages for establishing connection. We don't really care about them and can remove it from the report. When we do need to check these messages, wen can disable capture by adding pytest option `--capture no`. Then the messages will be output to console. Somehow content of the "stderr" section is same as the "log" section. That's why the "stderr" section can be removed too.

The code for removing these sections is added to hook function tests/conftest.py::pytest_runtest_makereport

# Logging tips

## Use logger instead of `print` in scripts

Suggest to use logger to log debug messages in test scripts. The benefits of logger against `print` is that we can easily customize format, level, destination of the log messages sent to loggers.

## Log useful information for important steps in test scripts

In test scripts, we suggest to add some log messages for important steps. The target is that in case a test failed, we can easily tell what is wrong just by inspecting the test logs.

## Set --log-cli-level=info and --log-file-level=debug
One good practice is to set --log-cli-level=info and --log-file-level=debug. We can have a big picture of the test case execution status from the log messages output to console. The more detailed messages saved to log file can be useful for analyzing the test failures.

## Enable --capture
Pytest have log capturing enabled by default. Log capturing can intercept the ansible connection debug messages sent to stdout. Without this noise, the log messages would be more easier to read. We can set `--capture no` only when we need to troubleshooting ansible connection issues.
