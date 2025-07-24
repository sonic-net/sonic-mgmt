# Testbed TACACS server

## TACACS intro
- RFC: https://www.rfc-editor.org/rfc/rfc8907.html

- HLD:
   - https://github.com/sonic-net/SONiC/blob/master/doc/aaa/TACACS%2B%20Authentication.md?plain=1
   - https://github.com/sonic-net/SONiC/blob/master/doc/aaa/TACACS%2B%20Design.md?plain=1

- TACACS protocol
   - Autehntication: Identify user
      - On SONiC device, this will check if user can login
   - Authorization: Check if user have permission
      - On SONiC device, this will check if user can run command
   - Accounting: Record what user do
      - On SONiC device, this will record user command to syslog and remote TACACS server

- TACACS related config on SONiC
   - TACACS server config
```
admin@vlab-01:~$ show tacacs
TACPLUS global auth_type login      <== TACACS packet authentication method
TACPLUS global timeout 5 (default)  <== TACACS server timeout in second
TACPLUS global passkey testing123   <== TACACS passkey, used for encrypt TACACS packet

TACPLUS_SERVER address 10.250.0.102 <== TACACS server address
               priority 1           <== TACACS server priority, will use TACACS server with bigger value first.
               tcp_port 49          <== TACACS server port
```

   - AAA config
```
admin@vlab-01:~$ show aaa
AAA authentication login tacacs+               <== How to verify user login, default/local means check local account, tacacs+ means check with remote TACACS server
AAA authentication failthrough False (default) <== Reject user login when authentication failed
AAA authorization login tacacs+                <== How to check user have permission to run every command, tacacs+ means every command will verify with remote TACACS server, local means will verify with linux permission control
AAA accounting login tacacs+,local             <== How to record user command history, tacacs+ means send to remote TACACS server, local means write to syslog
```

## Testbed TACACS server setup
On testbed, there will be 2 TACACS server running on PTF host:
- TACACS server for dailywork and none TACACS test cases.
   - Bind to TCP port 49
   - Auto restart by /root/tacacs_daily_daemon
```
root@0ce3f7bbb316:~# ps -auxww | grep tacacs_daily_daemon
root         488  0.0  0.0   2388   464 ?        S    Jul01   0:00 /bin/sh /root/tacacs_daily_daemon

root@0ce3f7bbb316:~# ps -auxww | grep "/usr/sbin/tac_plus .* -p 49"
root         502  0.0  0.0   5600  1880 ?        S    Jul01   0:00 /usr/sbin/tac_plus -d 88 -l /var/log/tac_plus_daily.log -C /etc/tac_plus_daily.conf -p 49 -G
```

- TACACS server for TACACS test cases.
   - Bind to TCP port 59
   - Only start when TACACS test case running, will stop after TACACS test finished.
```
root@0ce3f7bbb316:~# ps -auxww | grep "/usr/sbin/tac_plus .* -p 59"
root        3303  8.3  0.0   5600   224 ?        S    05:08   0:00 /usr/sbin/tac_plus -d 2058 -l /var/log/tac_plus.log -C /etc/tacacs+/tac_plus.conf -p 59
```

- The reason of having 2 TACACS server are:
1. All test case may running in parallel on multiple DUTs.
2. TACACS test case need change TACACS config and start/stop TACACS server, which will conflict with none TACACS test cases.
3. TACACS server for dailywork need auto restart and allow all RW command, which conflict with TACACS test case.

### How PTF host TACACS server for dailywork deployed
- TACACS server deployed when add-topo, in ansible/roles/vm_set/tasks/add_topo.yml:
```
  - name: Start tacacs+ daily daemon
    include_tasks: start_tacacs_daily_daemon.yml
```

- Deploy step defined here ansible/roles/vm_set/tasks/start_tacacs_daily_daemon.yml
   - For TACACS server passkey, please check "Include tacacs_passkey" step
```
  1. Try use tacacs_passkey defined in /group_vars/{{ inventory }}/{{ inventory }}.yml first, if not defined, try next step
  2. use default tacacs_passkey defined in group_vars/lab/lab.yml
```

   - For DUT login account, please check "Include duthost user name" step
```
  1. If secret_group_vars['str']['ansible_ssh_user'] defined, the DUT user name is the value of secret_group_vars['str']['ansible_ssh_user']
  2. If secret_group_vars['str']['ansible_ssh_user'] not defined, the DUT user name is the value of sonicadmin_user variable defined in group_vars/lab/secrets.yml
```

   - For DUT login password, please check "Include duthost password" step
```
  1. If secret_group_vars['str']['ansible_ssh_user'] defined, the DUT user name is the value of secret_group_vars['str']['ansible_ssh_user']
  2. If secret_group_vars['str']['ansible_ssh_user'] not defined, the DUT user name is the value of sonicadmin_user variable defined in group_vars/lab/secrets.yml
```

### How PTF host TACACS server for TACACS test case deployed
- TACACS server for TACACS test case pre-installed in ptf host docker image.
   - PTF host will run 2 TACACS server, for different, please check "Testbed TACACS server setup" section.

- The check_tacacs fixture will setup TACACS server before TACACS test case, and shutdown TACACS server after TACACS test case finish:
   - check_tacacs defined here: tests/tacacs/conftest.py
   - check_tacacs will invoke setup_tacacs_server method render and start TACACS server.
   - TACACS server config file render by template: tests/tacacs/tac_plus.conf.j2
   - The username and password are defined in this file: tests/tacacs/tacacs_creds.yaml


## DUT host TACACS config

### How DUT host TACACS server for dailywork setup
- TACACS server and AAA config deployed by ansible/config_sonic_basedon_testbed.yml
   - Following code will assign PTF IP address as TACACS server IP address when generate minigraph.xml
```
  - name: Enable PTF tacacs server by default
    set_fact:
        use_ptf_tacacs_server: true
        tacacs_enabled_by_default: true
    when: use_ptf_tacacs_server is not defined

  - debug: msg="use_ptf_tacacs_server {{ use_ptf_tacacs_server }}"

  - block:
      - name: saved original minigraph file in SONiC DUT(ignore errors when file does not exist)
        shell: mv /etc/sonic/minigraph.xml /etc/sonic/minigraph.xml.orig
        become: true
        ignore_errors: true

      - name: Update TACACS server address to PTF IP
        set_fact:
            tacacs_servers: ["{{ testbed_facts['ptf_ip'] }}"]
        when: use_ptf_tacacs_server is defined and use_ptf_tacacs_server|bool == true

      - debug: msg="tacacs_servers {{ tacacs_servers }}"
```

   - Following code will change DUT host AAA config to enable TACACS AAA feature, because per-command AAA feature does not exist on older release, so this step will ignore all error:
```
      - name: Configure TACACS with PTF TACACS server
        become: true
        shell: "{{ tacacs_config_cmd }}"
        loop:
          - config tacacs authtype login
          - config aaa authorization tacacs+
          - config aaa accounting "tacacs+ local"
        loop_control:
          loop_var: tacacs_config_cmd
        ignore_errors: true
        when: use_ptf_tacacs_server is defined and use_ptf_tacacs_server|bool == true
```

   - On DUT host, user can check TACACS related config with following command:
```
admin@vlab-01:~$ show aaa
AAA authentication login tacacs+
AAA authentication failthrough False (default)
AAA authorization login tacacs+,local
AAA accounting login tacacs+,local

admin@vlab-01:~$ show tacacs
TACPLUS global auth_type login
TACPLUS global timeout 5 (default)
TACPLUS global passkey testing123

TACPLUS_SERVER address 10.250.0.102
               priority 1
               tcp_port 49
```

### How DUT host TACACS server for TACACS test case setup
- This TACACS server been setup by setup_tacacs_client method: tests/tacacs/utils.py
- When TACACS test case finish, restore_tacacs_servers will restore the dut host TACACS config to use the TACACS server for dailywork.

## Debug testbed TACACS server

- How to stop testbed TACACS server:
   - I can't login DUT host, user can stop testbed TACACS server and login with local account.

   - Find PID of /root/tacacs_daily_daemon with following command, in this case PID is 488
```
root@0ce3f7bbb316:~# ps -auxww | grep tacacs_daily_daemon
root         488  0.0  0.0   2388   464 ?        S    Jul01   0:00 /bin/sh /root/tacacs_daily_daemon
```

   - Stop /root/tacacs_daily_daemon with kill command and PID
```
root@0ce3f7bbb316:~# kill -9 488
```

   - Find PID of tac_plus server with following command, in this case PID is 502
```
root@0ce3f7bbb316:~# ps -auxww | grep "/usr/sbin/tac_plus .* -p 49"
root         502  0.0  0.0   5600  1880 ?        S    Jul01   0:00 /usr/sbin/tac_plus -d 88 -l /var/log/tac_plus_daily.log -C /etc/tac_plus_daily.conf -p 49 -G
```

   - Stop tac_plus with kill command and PID
```
root@0ce3f7bbb316:~# kill -9 502
```

- How to start testbed TACACS server:
   - If tacacs_daily_daemon not running, start it with following command:
```
root@0ce3f7bbb316:~# /bin/sh /root/tacacs_daily_daemon &
[1] 3865
root@0ce3f7bbb316:~# starting tac_plus for daily work
```
   - After tacacs_daily_daemon started, it will monitor tac_plus server bind to port 49, if not running will auto restart tac_plus.

- How to find TACACS log
   - testbed TACACS server log is saved in /var/log/tac_plus_daily.log

- How to find TACACS config
   - testbed TACACS server log is saved in /etc/tac_plus_daily.conf
   - for the config file format, please check: https://shrubbery.net/tac_plus/
