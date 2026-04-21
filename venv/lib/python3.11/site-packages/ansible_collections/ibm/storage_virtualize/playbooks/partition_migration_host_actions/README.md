# Ansible playbook suite automates host-side actions
## Objective
    This Ansible playbook suite automates host-side actions for migrating storage partitions from one IBM FlashSystem to another.

## Prerequisites
  - Controller Requirements:
    - IBM Storage Virtualize Ansible Collection plugins v2.7.4 or above must be installed.
    - The Ansible controller machine must have Python 3.10 or higher.

  - Target Host Requirements:
    - All remote hosts must have Python 3.8 or higher.
    - Windows Hosts:
      - Must have either `sshpass` or the `winRM` utility installed.
      - SSH must be set up between the Windows host and the Ansible controller.
      - Playbooks use PowerShell commands, which require Administrator privileges.
    - Linux Hosts:
      - Must have `rescan-scsi-bus.sh` (`scsitools`)
      - Multipath utilities installed and configured.
      - Playbooks use rescan-scsi-bus.sh, which requires root privileges.

## Playbook Overview
    These playbooks monitor and respond to partition migration events by performing appropriate host actions (it fixes the supported events).
 > **[Note]**: The script uses `rescan-scsi-bus.sh`, which may impact I/O for other volumes mapped to the same host.
    Supported Events
  - `host_rescan_requested`
  - `commit_or_rollback`

## Important Files
 1. `main.yml`
  - The primary playbook to be executed:
    ansible-playbook main.yml -i inventory.ini

    Functionality:
    - Continuously looks for active partition migrations.
    - Based on the detected event, it triggers the required playbooks for fixing that particular event.
    - Supports only Linux and Windows hosts by default, with a provision to extend to other Operating Systems types.

    Workflow:
    - Detects migration events and identifies corresponding hosts using `host_identification.yml`.
    - On `host_rescan_requested`:
      - Triggers `rescan_multiple_devices.yml` to rescan devices on the identified hosts.
      - Retries up to 5 times if rescan fails.
    - On `commit_or_rollback`:
      - Triggers `verify_multiple_devices.yml` to validate path count.
      - Compares active paths per node with `min_active_path` set by the user.

    commit_or_rollback event will be skipped in case any of the following condination are met or set by user:
    - Deployment type set to 1 (localhost) by user, with multiple hosts mapped to the partition.
    - Number of detected hosts on FlashSystem doesn't match the inventory.
    - Partition includes hosts with unsupported operating system.
    - No host is mapped to the migrating partition.


 2. `inventory.ini`

    Defines hosts and FlashSystems with their access credentials.
    - application_server: List of host mapped to flashsystems
    - flash_systems: List of flash systems that the user wants to monitor for migration

    [application_server]
    linux1 ansible_host=x.x.x.x ansible_user=root ansible_ssh_pass=password ansible_connection=ssh
    windows1 ansible_host=x.x.x.x ansible_user=Administrator ansible_ssh_pass=password ansible_connection=ssh ansible_shell_type=cmd

    [flash_systems]
    fs1 ansible_host=x.x.x.x ansible_user=superuser ansible_password=password
    fs2 ansible_host=x.x.x.x ansible_user=superuser ansible_password=password

 3. `vars.yml`
    Holds user-defined parameters for customizing the playbook behavior.

    | Parameter            | Description                                                                           |
    | -------------------- | ------------------------------------------------------------------------------------- |
    | `min_active_path`    | Minimum required paths from node to host. Use `0` to skip commit validation           |
    | `hosts_name`         | Host group name from `inventory.ini` (e.g., `application_server` or `localhost`)      |
    | `deployment_type`    | `1`: Localhost; `2`: Ansible Tower                                                    |
    | `io_stability_time`  | Wait time to ensure I/O stability                                                     |
    | `inventory_file`     | Path to the inventory file                                                            |
    | `logpath`            | Path to store log files                                                               |
    | `temp_file_location` | Temporary files location during script execution                                      |


## Ansible Logging
    To enable logging, export the following environment variables:

    export ANSIBLE_LOG_PATH=/var/log/ansible.log

## Adding support for new operating system:
  To add support for new operating system, user need to do add block in following files similar to Linux and Windows block:
  - host_identification.yml
    - Currently, the playbook supports only Linux and Windows.
    - To add support for new operating system User needs to provide FC WWPNs in following format:
    ```
        fc_host_wwpns_upper: [
        "10000090FAA0B824",
        "10000090FAA0B825"
        ]
    ```

  - rescan_multiple_devices.yml
    - Currently, the playbook supports only Linux and Windows hosts.
    - User needs to provide rescan CLI path or rescan method for the specific operating system that user wants to add

  - verify_multipath_devices.yml
    - Currently, the playbook supports only Linux.
    - To add support for new operating system User need to provide output to process in following format:
    ```
      {
        "data": [
            {
                "active_paths_on_tgt": {
                    "dm-0": {
                        "node1": {
                            "active_no_paths": 2,
                            "inactive_no_paths": 0
                        },
                        "node2": {
                            "active_no_paths": 2,
                            "inactive_no_paths": 0
                        },
                        "uuid": "(36005076810da8186b80000000000006e)"
                    },
                    "dm-1": {
                        "node1": {
                            "active_no_paths": 2,
                            "inactive_no_paths": 0
                        },
                        "node2": {
                            "active_no_paths": 2,
                            "inactive_no_paths": 0
                        },
                        "uuid": "(36005076810da8186b80000000000006f)"
                    },
                    "inventory_name": "linux1"
                },
                "non_compliant_devices": []
            }
        ]
      }
    ```

**Authors:**  
- Prateek Mandge (prateekmandge@ibm.com)
- Sumit Kumar Gupta (sumit.gupta16@ibm.com) 