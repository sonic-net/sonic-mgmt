### Scope
This document provides a high level description of the memory utilization verification design and instructions on using the "memory_utilization" fixture in SONiC testing.

### Overview
During testing, the memory usage of the DUT can vary due to different configurations, environment setups, and test steps. To ensure the safe use of memory resources, it is necessary to check the memory usage after the test to confirm that it has not exceeded the high memory usage threshold and that no memory leaks have occurred.

The purpose of the current feature is to verify that memory resources do not increase during test runs and do not exceed the high memory usage threshold.

### Module Design
Newly introduced a plugin "memory_utilization" and config files.

#### Config files
Config files, including both common file and platform dependence file.
- **memory_utilization_common.json**: Common configurations for memory utilization.
  - The file is in JSON format and is defined in the public branch.
  - It includes "COMMON" key which holds all publicly defined common memory items.
- **memory_utilization_dependence.json**: Dependency configruations for memory utilization, currently supporting special configurations for specific HwSku devices.
  - The dependency file is also in JSON format and is used in internal branch.
  - It also includes a 'COMMON' key which holds all internal common memory items. If an internal memory item has the same name as an item in the public common configuration file, it will overwrite the public common item.
  - The dependency file also could includes a "HWSKU" key for all hwsku related memory items. If the hwsku memory item is same as a common one, it will overwrite it.
  - This dependency file should be left empty in the public branch, with special configurations added in internal branch.

Memory utilization config files include memory items which need to check.
Each memory item include "name", "cmd", "memory_params" and "memory_check".
- **name**:          The name of the memory check item.
- **cmd**:           The shell command is run on the DUT to collect memory information.
- **memory_params**: The items and thresholds for memory usage, defined as a Dict type in the configuration JSON file. It could be modified in the test case.
- **memory_check**:  The function used to parse the output of the shell command takes two input parameters: cmd's output string and memory_params. It returns the parsered memory inforamtion, which will be compared with "memory_params" to check for memory threshold.

#### Workflow
1. Collect memory information based on memory utilization config files before running a test case.
    - Execute the "cmd" and use the "memory_check" function to collect the memory information before running the test case.
2. Collect memory information based on memory utilization config files after the test case is completed.
    - Execute the "cmd" and use the "memory_check" function to collect the memory information after running the test case.
3. Compare the memory information from before and after the test run.
    - Compare the collected memory information with the thresholds in "memory_params".
4. Raise an alarm if there is any memory leak or if the memory usage exceeds the high memory threshold based on the memory utilization config files.
    ```
    >       pytest.fail(message)
    E       Failed: [ALARM]: monit:memory_usage memory usage 77.8 exceeds high threshold 70.0
    ```


### Memory Utilization usage example

Below is a description of the possible uses for the "memory_utilization" fixture/module.

##### memory_utilization fixture
In the root conftest there is an implemented "memory_utilization" pytest fixture that starts automatically for all test cases.
The main flow of the fixture is as follows:
- memory_utilization collects memory information before the test case starts.
- memory_utilization collects memory information after the test case finishes.
- memory_utilization compares DUT memory usage and displays the results.
- if memory_utilization finds any exceeded thresholds for high memory usage or memory increase, it will display the result and pytest will generate an 'error'.

#### To skip memory_utilization for:

memory_utilization is enabled by default, if you want to skip the memory_utilization, please follow below steps
- For all test cases - use pytest command line option ```--disable_memory_utilization```
- Per test case: mark test case with ```@pytest.mark.disable_memory_utilization``` decorator. Example is shown below.
    ```python
    pytestmark = [
        pytest.mark.disable_memory_utilization
    ]
    ```

#### Example of memory items configuration in json file
Current we support the "monit", "free", "docker" and "free" memory items. "monit" is already defined in common file, we can also define "top", "free" or "docker" in internal branch with below example.
The value in the following examples are for demonstration purposes only and are not actual values.
Please adjust the corrrsponding values according to your specific platform.

##### "monit"
"monit" uses the command "sudo monit status" to get the memory item's information.
"monit" has three configurations in the example below, the first in the common file, the second in the dependency common configuration, and the third in the hwsku configuration. Therefore, the configuration from the hwsku should be use.
The threshold for high memory is 80%, and for an increase is 5%.
The function "parse_monit_status_output" parses the output of the command "sudo monit status" and returns the memory information 'monit':{'memory_usage':41.2}.
The Memory utilization fixture uses the function "parse_monit_status_output" to parse the output of "sudo monit status" before and after the test case. It then compares the value with the threshold. If the value exceeds the threshold, an 'error' will be raised.


###### "monit" configuration in memory_utilization_common.json
```json
  "COMMON": [
    {
      "name": "monit",
      "cmd": "sudo monit status",
      "memory_params": {
        "memory_usage": {
          "memory_increase_threshold": 5,
          "memory_high_threshold": 70
        }
      },
      "memory_check": "parse_monit_status_output"
    }
  ]
```
###### "monit" configuration in memory_utilization_dependence.json
```json
  "HWSKU" : {
    "Arista-7050QX": ["Arista-7050-QX-32S", "Arista-7050QX32S-Q32"]
  },
  "COMMON": [
    {
      "name": "monit",
      "cmd": "sudo monit status",
      "memory_params": {
        "memory_usage": {
          "memory_increase_threshold": 5,
          "memory_high_threshold": 60
        }
      },
      "memory_check": "parse_monit_status_output"
    }
  ],
  "Arista-7050QX": [
    {
      "name": "monit",
      "cmd": "sudo monit status",
      "memory_params": {
        "memory_usage": {
          "memory_increase_threshold": 5,
          "memory_high_threshold": 80
        }
      },
      "memory_check": "parse_monit_status_output"
    }
  ]
```

###### "sudo monit status" output
```shell
System 'sonic'
  status                       Running
  monitoring status            Monitored
  monitoring mode              active
  on reboot                    start
  load average                 [1.44] [1.10] [1.04]
  cpu                          22.7%us 3.3%sy 0.0%wa
  memory usage                 3.2 GB [41.2%]
  swap usage                   0 B [0.0%]
  uptime                       4d 3h 55m
  boot time                    Thu, 11 Jul 2024 06:41:46
  data collected               Mon, 15 Jul 2024 10:36:45
```
###### "parse_monit_status_output" return value
```shell
  'monit': {
    'memory_usage': 41.2
  }
```

##### "free"
"free" uses the command "free -m" to get the memory item's information.
The threshold for high memory is 1500, and for an increase is 100.
The function "parse_free_output" parses the output of the command "free -m" and returns the memory information 'free':{'used':2533}.
The Memory utilization fixture uses the function "parse_free_output" to parse the output of "free -m" before and after the test case. It then compares the value with the threshold. If the value exceeds the threshold, an 'error' will be raised.

###### "free" configuration
```json
    {
      "name": "free",
      "cmd": "free -m",
      "memory_params": {
        "used": {
          "memory_increase_threshold": 100,
          "memory_high_threshold": 3000
        }
      },
      "memory_check": "parse_free_output"
    }
```
###### "free -m" output
```shell
               total        used        free      shared  buff/cache   available
Mem:            3897        2533         256         183        1108         956
Swap:              0           0           0
```
###### "parse_free_output" return value
```shell
  'free': {
    'used': 2533
  }
```

##### "docker"
"docker" uses the command "docker stats --no-stream" to get the memory item's information.
30The memory_params could have several sub memory items, the example below is "snmp", "pmon" and other dockers.
The "snmp" threshold for high memory is 30, and for an increase is 3.
The function "parse_docker_stats_output" parses the output of the command "docker stats --no-stream" and returns the memory information {'snmp': '2.07', 'pmon': '5.64', 'lldp': '1.74', 'gnmi': '3.46', 'radv': '1.02', 'syncd': '13.16', 'teamd': '1.67', 'bgp': '8.98', 'swss': '3.75', 'acms': '2.22', 'database': '3.54'}
The Memory utilization fixture uses the function "parse_docker_stats_output" to parse the output of "docker stats --no-stream" before and after the test case. It then compares the value with the threshold. If the value exceeds the threshold, an 'error' will be raised.

###### "docker" configuration
```json
    {
      "name": "docker",
      "cmd": "docker stats --no-stream",
      "memory_params": {
        "snmp": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "pmon": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "lldp": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "gnmi": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "radv": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "syncd": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "bgp": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "teamd": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "swss": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "acms": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        },
        "database": {
          "memory_increase_threshold": 3,
          "memory_high_threshold": 30
        }
      },
      "memory_check": "parse_docker_stats_output"
    }
```

###### "docker stats --no-stream" output
```shell
CONTAINER ID   NAME       CPU %     MEM USAGE / LIMIT     MEM %     NET I/O   BLOCK I/O         PIDS
52958334481e   snmp       5.27%     80.8MiB / 3.807GiB    2.07%     0B / 0B   4.76MB / 180kB    10
5acbd9b57da7   pmon       2.51%     220MiB / 3.807GiB     5.64%     0B / 0B   11.6MB / 123kB    19
dc281fd005f8   lldp       0.36%     67.84MiB / 3.807GiB   1.74%     0B / 0B   5.9MB / 98.3kB    13
9f7c67031b80   gnmi       2.05%     134.7MiB / 3.807GiB   3.46%     0B / 0B   22.8MB / 823kB    28
e5b96437643b   radv       0.42%     39.84MiB / 3.807GiB   1.02%     0B / 0B   713kB / 65.5kB    8
48de97a88314   syncd      16.26%    513.2MiB / 3.807GiB   13.16%    0B / 0B   273MB / 778kB     48
26a72f50a90a   teamd      1.38%     65.09MiB / 3.807GiB   1.67%     0B / 0B   1.4MB / 90.1kB    22
2995cc0130a7   bgp        16.07%    350.2MiB / 3.807GiB   8.98%     0B / 0B   20.2MB / 537MB    27
45c759cb9770   swss       0.66%     146.2MiB / 3.807GiB   3.75%     0B / 0B   27.2MB / 209kB    41
91903b37d1cd   acms       0.35%     86.38MiB / 3.807GiB   2.22%     0B / 0B   266kB / 1.06MB    11
5ffa57081cb8   database   35.64%    138.1MiB / 3.807GiB   3.54%     0B / 0B   50.2MB / 73.7kB   13
```
###### "parse_docker_stats_output" return value
```shell
  'docker': {
    'snmp': '2.07',
    'pmon': '5.64',
    'lldp': '1.74',
    'gnmi': '3.46',
    'radv': '1.02',
    'syncd': '13.16',
    'teamd': '1.67',
    'bgp': '8.98',
    'swss': '3.75',
    'acms': '2.22',
    'database': '3.54'
  }
```


##### "top"
"top" uses the command "top -b -n 1" to get the memory item's information.
The memory_params could have several sub memory items, the example below is "bgpd" and "zebra".
The "bgpd" threshold for high memory is 200000, and for an increase is 10000.
The "zebra" threshold for high memory is 200000, and for an increase is 10000.
The function "parse_top_output" parses the output of the command "top -b -n 1" and returns the memory information 'top':{'zebra':67780,'bgpd':197416}.
The Memory utilization fixture uses the function "parse_top_output" to parse the output of "top -b -n 1" before and after the test case. It then compares the value with the threshold. If the value exceeds the threshold, an 'error' will be raised.

###### "json" configuration
```json
    {
      "name": "top",
      "cmd": "top -b -n 1",
      "memory_params": {
        "bgpd": {
          "memory_increase_threshold": 10000,
          "memory_high_threshold": 200000
        },
        "zebra": {
          "memory_increase_threshold": 10000,
          "memory_high_threshold": 200000
        }
      },
      "memory_check": "parse_top_output"
    }
```

###### "top -b -n 1" output
```shell
top - 03:01:19 up 4 days, 11 min,  0 users,  load average: 1.56, 1.38, 1.16
Tasks: 252 total,   2 running, 246 sleeping,   0 stopped,   4 zombie
%Cpu(s): 23.5 us,  8.6 sy,  0.0 ni, 66.7 id,  0.0 wa,  0.0 hi,  1.2 si,  0.0 st
MiB Mem :   3897.9 total,    254.8 free,   2534.7 used,   1108.4 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used.    954.9 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
   1063 message+  20   0  125476  73676   8184 R  35.3   1.8   2254:29 redis-s+
   6205 root      20   0   60392  41044  17348 S  29.4   1.0 553:32.09 python3
2049149 root      20   0   11276   4116   3504 R  17.6   0.1   0:00.05 top
   2808 root      20   0 2701756 639364 283328 S  11.8  16.0   1041:03 syncd
   2529 root      20   0   95860  11568  10196 S   5.9   0.3  36:50.14 tlm_tea+
   2536 root      20   0   19208   3824   2476 S   5.9   0.1   5:08.00 teamd
   5588 root      20   0  129120  32012  15944 S   5.9   0.8  19:47.47 python3
   5730 root      20   0 1417896  78608  28512 S   5.9   2.0  54:33.37 telemet+
   6082 root      20   0   38956  31736  10536 S   5.9   0.8   3:07.13 supervi+
   6193 root      20   0  282292  48244  17000 S   5.9   1.2  90:43.80 python3
      1 root      20   0  166628  13728  10192 S   0.0   0.3  10:58.80 systemd
      2 root      20   0       0      0      0 S   0.0   0.0   0:00.12 kthreadd
      3 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_gp
      4 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_par+
      6 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+
      8 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 mm_perc+
      9 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tas+
     10 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tas+
     11 root      20   0       0      0      0 S   0.0   0.0   0:26.79 ksoftir+
     12 root      20   0       0      0      0 I   0.0   0.0  15:09.90 rcu_sch+
     13 root      rt   0       0      0      0 S   0.0   0.0   0:02.01 migrati+
     15 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/0
     16 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/1
     17 root      rt   0       0      0      0 S   0.0   0.0   0:02.30 migrati+
     18 root      20   0       0      0      0 S   0.0   0.0   0:26.84 ksoftir+
     20 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+
     21 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/2
     22 root      rt   0       0      0      0 S   0.0   0.0   0:02.20 migrati+
     23 root      20   0       0      0      0 S   0.0   0.0   0:24.26 ksoftir+
     25 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+
     26 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/3
     27 root      rt   0       0      0      0 S   0.0   0.0   0:03.03 migrati+
     28 root      20   0       0      0      0 S   0.0   0.0   0:25.04 ksoftir+
     30 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+
     33 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kdevtmp+
     34 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 netns
     35 root      20   0       0      0      0 S   0.0   0.0   0:00.07 kauditd
     36 root      20   0       0      0      0 S   0.0   0.0   0:00.23 khungta+
     37 root      20   0       0      0      0 S   0.0   0.0   0:00.00 oom_rea+
     38 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 writeba+
     39 root      20   0       0      0      0 S   0.0   0.0   0:17.86 kcompac+
     40 root      25   5       0      0      0 S   0.0   0.0   0:00.00 ksmd
     41 root      39  19       0      0      0 S   0.0   0.0   0:14.38 khugepa+
     60 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kintegr+
     61 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kblockd
     62 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 blkcg_p+
     63 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 edac-po+
     64 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 devfreq+
     66 root       0 -20       0      0      0 I   0.0   0.0   0:04.09 kworker+
     67 root      20   0       0      0      0 S   0.0   0.0   0:00.59 kswapd0
     68 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kthrotld
     69 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/24-+
     70 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/25-+
     71 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/26-+
     72 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/27-+
     73 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/28-+
     75 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 acpi_th+
     76 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 ipv6_ad+
     85 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kstrp
     88 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 zswap-s+
     89 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker+
    111 root       0 -20       0      0      0 I   0.0   0.0   0:04.06 kworker+
    141 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 ata_sff
    142 root      20   0       0      0      0 S   0.0   0.0   0:00.00 scsi_eh+
    143 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 scsi_tm+
    144 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 sdhci
    145 root      20   0       0      0      0 S   0.0   0.0   0:00.00 scsi_eh+
    146 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 scsi_tm+
    147 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/16-+
    151 root       0 -20       0      0      0 I   0.0   0.0   0:04.33 kworker+
    168 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 nvme-wq
    169 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 nvme-re+
    170 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 nvme-de+
    184 root      20   0       0      0      0 S   0.0   0.0   0:00.00 scsi_eh+
    185 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 scsi_tm+
    186 root      20   0       0      0      0 S   0.0   0.0   0:19.38 usb-sto+
    187 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 uas
    191 root       0 -20       0      0      0 I   0.0   0.0   0:04.10 kworker+
    263 root      20   0       0      0      0 S   0.0   0.0   0:11.26 jbd2/sd+
    264 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 ext4-rs+
    278 root       0 -20       0      0      0 S   0.0   0.0   0:08.12 loop0
    360 root      20   0   48024  17748  14244 S   0.0   0.4   0:13.98 systemd+
    361 root      20   0   22932   7344   5764 S   0.0   0.2   0:01.14 systemd+
    412 root      16  -4   91408   3132   2200 S   0.0   0.1   0:00.53 auditd
    417 root      16  -4    7244   5104   4432 S   0.0   0.1   0:00.08 audisp-+
    479 root      20   0    8180   6796   1752 S   0.0   0.2   0:13.09 haveged
    494 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 cryptd
    495 root      20   0    7372   2968   2708 S   0.0   0.1   0:01.75 cron
    496 message+  20   0    7988   4416   3848 S   0.0   0.1   0:08.29 dbus-da+
    523 root      20   0   11152   5320   4376 S   0.0   0.1   0:00.13 smartd
    532 root      20   0   14552   9028   8048 S   0.0   0.2   0:04.42 systemd+
    534 root      20   0 1579288  65448  33076 S   0.0   1.6  16:40.26 contain+
    629 root      20   0   84096   3416   2388 S   0.0   0.1   3:46.33 monit
    650 root      20   0 1836628 100396  44680 S   0.0   2.5  41:36.89 dockerd
    654 root      20   0    6472   1732   1624 S   0.0   0.0   0:00.00 agetty
    655 root      20   0    6104   1976   1864 S   0.0   0.0   0:00.00 agetty
    658 root      20   0   14368   8700   7500 S   0.0   0.2   0:00.34 sshd
    780 root      20   0  720760  17092   6500 S   0.0   0.4   2:13.22 contain+
    801 root      20   0   32148  28064  10316 S   0.0   0.7   2:47.49 supervi+
    859 root      20   0   37176  27352  10344 S   0.0   0.7   0:43.02 arista
   1062 root      20   0  125080  27668  15768 S   0.0   0.7  18:21.61 python3
   1152 root      20   0   12040   6920   6128 S   0.0   0.2   0:00.01 databas+
   1157 root      20   0   12304   7200   6240 S   0.0   0.2   0:00.02 databas+
   1160 root      20   0 1254740  33820  16584 S   0.0   0.8   0:17.96 docker
   1202 root      20   0  222220   6212   3664 S   0.0   0.2   0:00.06 rsyslogd
   1240 root      20   0  236476  61884  20724 S   0.0   1.6  12:58.16 healthd
   1311 root      20   0  720504  17896   6312 S   0.0   0.4   2:13.54 contain+
   1333 root      20   0   36256  32032  10276 S   0.0   0.8   3:13.31 supervi+
   1339 root      20   0  386980  48952   8248 S   0.0   1.2   0:59.09 healthd
   1344 root      20   0  175300  52568  10300 S   0.0   1.3   0:34.17 healthd
   1347 root      20   0  180060  52160  11056 S   0.0   1.3   0:01.20 healthd
   1350 root      20   0  170468  47420   7020 S   0.0   1.2   0:53.54 healthd
   1411 admin     20   0   12172   6484   5720 S   0.0   0.2   0:00.02 acms.sh
   1412 root      20   0  121940  27460  15048 S   0.0   0.7   0:40.33 caclmgrd
   1416 root      20   0   46296  25168  14756 S   0.0   0.6   8:52.39 procdoc+
   1422 admin     20   0   69388  42444  18400 S   0.0   1.1   0:00.95 python3
   1730 root      20   0  129144  31712  15616 S   0.0   0.8  19:57.12 python3
   1732 root      20   0   44784  29552  15108 S   0.0   0.7   0:00.47 start.py
   1734 root      20   0   45820  29696  14840 S   0.0   0.7   0:00.49 CA_cert+
   1735 root      20   0   44572  27912  13496 S   0.0   0.7   0:01.74 cert_co+
   1869 root      20   0  222220   4188   3684 S   0.0   0.1   0:00.81 rsyslogd
   1960 root      20   0  720760  16332   6500 S   0.0   0.4   2:11.96 contain+
   1981 root      20   0   36224  32124  10320 S   0.0   0.8   6:54.24 supervi+
   2051 root      20   0  292104   5940   3028 S   0.0   0.1   0:07.35 rsyslogd
   2088 root      20   0   12304   7180   6200 S   0.0   0.2   0:00.03 swss.sh
   2272 root      20   0  720504  17260   6500 S   0.0   0.4   2:15.91 contain+
   2299 root      20   0  720504  17048   6500 S   0.0   0.4   2:13.86 contain+
   2307 root      20   0   36292  32128  10340 S   0.0   0.8   2:59.93 supervi+
   2332 root      20   0  720760  18280   6500 S   0.0   0.5   2:15.46 contain+
   2346 root      20   0   36292  32076  10268 S   0.0   0.8   3:23.37 supervi+
   2361 root      20   0   35612  31380  10236 S   0.0   0.8   4:19.78 supervi+
   2398 root      20   0   12172   7128   6212 S   0.0   0.2   0:00.02 syncd.sh
   2403 root      20   0   12172   6656   5888 S   0.0   0.2   0:00.02 syncd.sh
   2408 root      20   0   69388  42304  18268 S   0.0   1.1   0:00.94 python3
   2411 admin     20   0   12172   6288   5520 S   0.0   0.2   0:00.02 teamd.sh
   2421 admin     20   0   12172   6452   5684 S   0.0   0.2   0:00.02 teamd.sh
   2423 admin     20   0   69388  42348  18312 S   0.0   1.1   0:00.93 python3
   2430 admin     20   0   12040   6572   5804 S   0.0   0.2   0:00.02 bgp.sh
   2436 admin     20   0   12172   6440   5672 S   0.0   0.2   0:00.02 bgp.sh
   2439 admin     20   0   69388  42252  18216 S   0.0   1.1   0:00.93 python3
   2443 root      20   0  125104  27596  15668 S   0.0   0.7  18:41.56 python3
   2488 root      20   0  222220   6160   3660 S   0.0   0.2   0:04.46 rsyslogd
   2493 root      20   0  129144  31796  15700 S   0.0   0.8  18:19.70 python3
   2500 root      20   0  129144  32524  15628 S   0.0   0.8  20:00.72 python3
   2503 root      20   0   92180  11028   9824 S   0.0   0.3   0:30.90 portsyn+
   2520 root      20   0  222220   4216   3716 S   0.0   0.1   0:00.84 rsyslogd
   2524 root      20   0  222220   6348   3716 S   0.0   0.2   3:18.10 rsyslogd
   2528 root      20   0   92608  11256   9776 S   0.0   0.3   0:35.48 teammgrd
   2571 root      20   0   19212   3804   2444 S   0.0   0.1   4:55.60 teamd
   2580 root      20   0   19212   3828   2480 S   0.0   0.1   5:02.54 teamd
   2600 root      20   0   19216   3908   2560 S   0.0   0.1   4:56.09 teamd
   2602 root      20   0  620592  87972  22340 S   0.0   2.2  16:54.01 orchage+
   2611 root      20   0   19212   3800   2444 S   0.0   0.1   5:04.60 teamd
   2621 root      20   0   19212   3884   2532 S   0.0   0.1   4:56.33 teamd
   2632 root      20   0   87704   1540   1372 S   0.0   0.0   0:00.02 dsserve
   2633 root      20   0   92992  11580   9716 S   0.0   0.3   0:35.32 teamsyn+
   2643 root      20   0   19212   3832   2484 S   0.0   0.1   5:10.30 teamd
   2655 root      20   0   19212   3912   2564 S   0.0   0.1   5:27.09 teamd
   2664 root      20   0  720760  18556   6436 S   0.0   0.5   2:14.23 contain+
   2691 root      20   0   36224  32148  10320 S   0.0   0.8   2:37.63 supervi+
   2709 admin     20   0   12040   7024   6232 S   0.0   0.2   0:00.02 radv.sh
   2718 admin     20   0   12172   6640   5872 S   0.0   0.2   0:00.02 radv.sh
   2725 admin     20   0   69388  42464  18424 S   0.0   1.1   0:00.94 python3
   2742 root      20   0  293620  42828  18256 S   0.0   1.1   0:00.93 python3
   2755 root      20   0   92336  10048   8928 S   0.0   0.3   0:31.47 coppmgrd
   2777 root      20   0  125104  27796  15796 S   0.0   0.7  20:01.54 python3
   2813 root      20   0  222220   4224   3720 S   0.0   0.1   0:00.23 rsyslogd
   2826 300       20   0  665588  67780   6916 S   0.0   1.7   0:23.12 zebra
   2864 300       20   0   44084  13616   5320 S   0.0   0.3   0:07.68 staticd
   2882 root      20   0  125080  27604  15700 S   0.0   0.7  20:04.30 python3
   2895 ntp       20   0   74488   3648   2912 S   0.0   0.1   0:43.96 ntpd
   2907 root      20   0   92172   9892   8768 S   0.0   0.2   0:16.61 neighsy+
   2908 root      20   0   92336  11124   9904 S   0.0   0.3   0:31.36 vlanmgrd
   2909 root      20   0   92496  11268   9936 S   0.0   0.3   0:32.85 intfmgrd
   2910 root      20   0   92308  11128   9864 S   0.0   0.3   0:31.84 portmgrd
   2911 root      20   0   92544  11068   9768 S   0.0   0.3   0:34.04 bufferm+
   2914 root      20   0   92328  11044   9772 S   0.0   0.3   0:31.67 vrfmgrd
   2916 root      20   0   92216   9988   8868 S   0.0   0.3   0:31.45 nbrmgrd
   2917 root      20   0   92360  11112   9876 S   0.0   0.3   0:31.86 vxlanmg+
   2920 root      20   0   92108  10136   9016 S   0.0   0.3   0:15.75 fdbsyncd
   2924 root      20   0   92308  11024   9812 S   0.0   0.3   0:32.53 tunnelm+
   3034 root      20   0  222220   4208   3708 S   0.0   0.1   0:00.06 rsyslogd
   3327 root      20   0   50524  30004  15580 S   0.0   0.8   0:47.96 featured
   3328 root      20   0   61100  40044  16576 S   0.0   1.0   0:31.69 hostcfgd
   3331 root      20   0    5472   3020   2772 S   0.0   0.1   0:00.02 rasdaem+
   4346 300       20   0  498388 197416   8156 S   0.0   4.9   3:00.32 bgpd
   4351 root      20   0  123448  33264  16476 S   0.0   0.8   0:40.03 bgpcfgd
   4359 root      20   0   37472  22380  15156 S   0.0   0.6   2:10.32 bgpmon
   4361 root      20   0   93460  11936   9548 S   0.0   0.3   0:18.78 fpmsyncd
   4377 root      20   0   37664  22160  14580 S   0.0   0.6   0:35.31 staticr+
   5413 root      20   0   32180  19580  10260 S   0.0   0.5   0:00.29 python3
   5465 root      20   0  720760  17684   6372 S   0.0   0.4   3:19.35 contain+
   5486 root      20   0   36284  32056  10232 S   0.0   0.8   3:03.55 supervi+
   5499 admin     20   0   12040   6984   6192 S   0.0   0.2   0:00.02 gnmi.sh
   5501 admin     20   0   12172   6396   5632 S   0.0   0.2   0:00.02 gnmi.sh
   5503 admin     20   0   69388  42216  18168 S   0.0   1.1   0:00.87 python3
   5591 root      20   0  222220   6212   3688 S   0.0   0.2   0:00.07 rsyslogd
   5614 root      20   0  720760  16616   6372 S   0.0   0.4   2:08.40 contain+
   5640 root      20   0   36224  32148  10328 S   0.0   0.8   3:28.26 supervi+
   5668 admin     20   0   12040   6440   5676 S   0.0   0.2   0:00.01 lldp.sh
   5671 admin     20   0   12172   6540   5772 S   0.0   0.2   0:00.02 lldp.sh
   5673 admin     20   0   69388  42228  18176 S   0.0   1.1   0:00.89 python3
   5738 root      20   0 1418152  73376  28400 S   0.0   1.8  54:30.22 telemet+
   5877 root      20   0  125104  27600  15608 S   0.0   0.7  19:59.83 python3
   5884 root      20   0  721016  16468   6308 S   0.0   0.4   2:19.75 contain+
   5915 root      20   0   36232  32132  10336 S   0.0   0.8   4:06.02 supervi+
   5938 admin     20   0   12172   6568   5808 S   0.0   0.2   0:00.02 pmon.sh
   5940 admin     20   0   69388  42344  18304 S   0.0   1.1   0:00.88 python3
   5963 root      20   0  222220   4128   3624 S   0.0   0.1   0:00.08 rsyslogd
   6035 tcpdump   20   0   20252   8844   7644 S   0.0   0.2   0:00.31 lldpd
   6037 tcpdump   20   0   20384   3720   2388 S   0.0   0.1   4:04.87 lldpd
   6061 root      20   0  720760  17832   6500 S   0.0   0.4   3:15.76 contain+
   6089 root      20   0  115064  28844  14628 S   0.0   0.7  32:49.56 python3
   6098 root      20   0   12120   7108   6324 S   0.0   0.2   0:00.02 snmp.sh
   6100 root      20   0   12252   7096   6304 S   0.0   0.2   0:00.02 snmp.sh
   6103 root      20   0   69468  42572  18512 S   0.0   1.1   0:00.89 python3
   6128 root      20   0   42324  25320  15492 S   0.0   0.6   0:04.51 python3
   6164 root      20   0  125104  27568  15636 S   0.0   0.7  18:36.36 python3
   6166 root      20   0  132408  33104  15988 S   0.0   0.8  19:49.98 python3
   6176 root      20   0  222224   4016   3516 S   0.0   0.1   0:01.39 rsyslogd
   6180 root      20   0  222220   8280   3712 S   0.0   0.2   0:00.18 rsyslogd
   6188 tcpdump   20   0   26616  15068   9736 S   0.0   0.4   6:39.60 snmpd
   6191 root      20   0   52408  35208  16700 S   0.0   0.9   0:36.22 python3
   6194 root      20   0   59796  42796  16824 S   0.0   1.1  26:20.79 python3
   6195 root      20   0   60552  43180  16556 S   0.0   1.1   0:02.77 python3
   6197 root      20   0   61708  44256  16576 S   0.0   1.1   5:20.56 python3
   6198 root      20   0   72120  55252  16952 S   0.0   1.4   1:32.29 pcied
   6204 root      20   0   55332   1140      0 S   0.0   0.0   0:22.51 sensord
   6206 root      20   0   61708  33988   6308 S   0.0   0.9   3:52.65 python3
 110653 root      20   0    4160   3392   2896 S   0.0   0.1   0:00.06 bash
2002226 root      20   0       0      0      0 I   0.0   0.0   0:01.10 kworker+
2016391 root      20   0       0      0      0 I   0.0   0.0   0:00.40 kworker+
2026996 root      20   0       0      0      0 I   0.0   0.0   0:00.44 kworker+
2030519 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker+
2034114 root      20   0       0      0      0 I   0.0   0.0   0:00.24 kworker+
2036072 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker+
2036243 root      20   0       0      0      0 I   0.0   0.0   0:00.06 kworker+
2041185 root      20   0       0      0      0 I   0.0   0.0   0:00.17 kworker+
2044722 root      20   0       0      0      0 I   0.0   0.0   0:00.10 kworker+
2044751 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker+
2047210 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker+
2048525 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker+
2048528 root      20   0   14852   9136   7744 S   0.0   0.2   0:00.22 sshd
2048534 admin     20   0   15308   6584   4672 S   0.0   0.2   0:00.18 sshd
2048690 root      20   0       0      0      0 Z   0.0   0.0   0:01.06 python3
2048691 root      20   0       0      0      0 Z   0.0   0.0   0:00.19 memory_+
2048692 root      20   0       0      0      0 Z   0.0   0.0   0:00.94 python3
2048693 root      20   0       0      0      0 Z   0.0   0.0   0:00.95 python3
2049145 admin     20   0    2480    512    448 S   0.0   0.0   0:00.02 sh
2049146 root      20   0   15008   8240   7260 S   0.0   0.2   0:00.03 sudo
2049147 root      20   0    2480    516    448 S   0.0   0.0   0:00.00 sh
2049148 root      20   0   33600  23920  11384 S   0.0   0.6   0:00.43 python
```

###### "parse_top_output" return value
```shell
  'top': {
    'zebra': 67780,
    'bgpd': 197416
  }
```

#### Example Use Cases for memory items

##### Define a memory item globally
- We can define a global memory item in "memory_utilization_common.json" which is usually used in public branch. This memory item will apply to all test cases.
- If we prefer not to define it in the public branch, we can alternatively define it in "memory_utilization_dependence.json" which is usually used in the internal branch. This memory item will also apply to all test cases.
- If a memory item is defined with the same name in both "memory_utilization_common.json" and "memory_utilization_dependence.json" under their "COMMON" sections, the definition in the "memory_utilization_dependence.json" will take priority.



  ```python
  # define in "memory_utilization_common.json"
    "COMMON": [
      {
        "name": "monit",
        "cmd": "sudo monit status",
        "memory_params": {
          "memory_usage": {
            "memory_increase_threshold": 5,
            "memory_high_threshold": 70
          }
        },
        "memory_check": "parse_monit_status_output"
      }
    ]
  ```

  ```python
  # define in memory_utilization_dependence.json
  # "memory_high_threshold" overwrited to 60
    "COMMON": [
      {
        "name": "monit",
        "cmd": "sudo monit status",
        "memory_params": {
          "memory_usage": {
            "memory_increase_threshold": 5,
            "memory_high_threshold": 60
          }
        },
        "memory_check": "parse_monit_status_output"
      }
    ]
  ```


##### Define a memory item per HWSKU
We can define a memory item per HwSku in "memory_utilization_dependence.json".
- First, define a dict named "HWSKU" to manage all HwSku collections.
- Second, specify each HwSku collections. use the collection name as the key and a list of HwSku names included in that HwSku collection as the value.
- Finally, define the memory items for each HwSku collection, the configuration will take priority.

  ```python
  # memory_utilization_dependence.json
    "HWSKU" : {
      "Arista-7050QX": ["Arista-7050-QX-32S", "Arista-7050QX32S-Q32"]
    },
    "COMMON": [
      {
        "name": "monit",
        "cmd": "sudo monit status",
        "memory_params": {
          "memory_usage": {
            "memory_increase_threshold": 5,
            "memory_high_threshold": 60
          }
        },
        "memory_check": "parse_monit_status_output"
      }
    ],
    # the "memory_high_threshold" value would be overwrite to "80" for HwSku "Arista-7050-QX-32S", "Arista-7050QX32S-Q32"
    "Arista-7050QX": [
      {
        "name": "monit",
        "cmd": "sudo monit status",
        "memory_params": {
          "memory_usage": {
            "memory_increase_threshold": 5,
            "memory_high_threshold": 80
          }
        },
        "memory_check": "parse_monit_status_output"
      }
    ]
  ```


##### Define a memory item per test case
We can modify the threshold of existing memory items within the test case, but we cannot change the cmd and function of the memory items.
However, we can add new memory items within the test case by using memory_utilization fixture and then registering them.

This functionality has not been verified yet, the following examples are provided for reference only.
Updates will be made once the verification process is complete.

  ```python
  # memory item config per test case
  per_test_case_config = [
    # exist memory item
    {
        "name": "monit",
        "cmd": "sudo monit status",
        "memory_params": {
            "memory_usage": {
            "memory_increase_threshold": 10,
            "memory_high_threshold": 90
            }
        },
        "memory_check": "parse_monit_status_output"
    },
    # new memory item per test case
    {
        "name": "memory_item_per_test_case",
        "cmd": "cmd per test case",
        "memory_params": {
            "used": {
            "memory_increase_threshold": 100,
            "memory_high_threshold": 1500
            }
        },
        "memory_check": "parse_output_per_test_case"
    }
  ]

  # use the fixture memory_utilization
  def test_case_example(duthosts, enum_frontend_dut_hostname, memory_utilization):
    ...
    for memory_item in per_test_case_config:
      is_exist = False
      # for exist memory item
      for i, exist_commands in enumerate(memory_monitor.commands):
          exist_name, exist_cmd, exist_memory_params, exist_memory_check = exist_commands
          if memory_item["name"] == exist_name:
              memory_monitor.commands[i] = (
                  exist_name,
                  exist_cmd,
                  memory_item["memory_params"],
                  exist_memory_check
              )
              is_exist = True
              break
      # if memory item not exist, register a new memory item.
      if not is_exist:
          memory_monitor.register_command(memory_item["name"], memory_item["cmd"], memory_item["memory_params"], memory_item["memory_check"])
          output = memory_monitor.execute_command(memory_item["cmd"])

          initial_memory_value[memory_item["name"]] = memory_monitor.run_command_parser_function(memory_item["name"], output)
  ```
