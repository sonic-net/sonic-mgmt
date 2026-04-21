oVirt Disaster Recovery
=========

The `disaster_recovery` role responsible to manage the disaster recovery scenarios in oVirt.

Role Variables
--------------

| Name                           | Default value                    |                                                                                                                                                                                                                                                                                                                   |
|--------------------------------|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| dr_ignore_error_clean          | `False`                          | Specify whether to ignore errors on clean engine setup.<br/>This is mainly being used to avoid failures when trying to move a storage domain to maintenance/detach it.                                                                                                                                            |
| dr_ignore_error_recover        | `True`                           | Specify whether to ignore errors on recover.                                                                                                                                                                                                                                                                      |
| dr_partial_import              | `True`                           | Specify whether to use the partial import flag on VM/Template register.<br/>If `True`, VMs and Templates will be registered without any missing disks, if `False` VMs/Templates will fail to be registered in case some of their disks will be missing from any of the storage domains.                           |
| dr_target_host                 | `secondary`                      | Specify the default target host to be used in the ansible play.<br/> This host indicates the target site which the recover process will be done.                                                                                                                                                                  |
| dr_source_map                  | `primary`                        | Specify the default source map to be used in the play.<br/> The source map indicates the key which is used to get the target value for each attribute which we want to register with the VM/Template.                                                                                                             |
| dr_reset_mac_pool              | `True`                           | If `True`, then once a VM will be registered, it will automatically reset the mac pool, if configured in the VM.                                                                                                                                                                                                  |
| dr_cleanup_retries_maintenance | `3`                              | Specify the number of retries of moving a storage domain to maintenance VM as part of a fail back scenario.                                                                                                                                                                                                       |
| dr_cleanup_delay_maintenance   | `120`                            | Specify the number of seconds between each retry as part of a fail back scenario.                                                                                                                                                                                                                                 |
| dr_clean_orphaned_vms          | `True`                           | Specify whether to remove any VMs which have no disks from the setup as part of cleanup.                                                                                                                                                                                                                          |
| dr_clean_orphaned_disks        | `True`                           | Specify whether to remove lun disks from the setup as part of engine setup.                                                                                                                                                                                                                                       |
| dr_running_vms		               | `/tmp/ovirt_dr_running_vm_list`	 | Specify the file path which is used to contain the data of the running VMs in the secondary setup before the failback process run on the primary setup after the secondary site cleanup was finished. Note that the `/tmp` folder is being used as default so the file will not be available after system reboot. |

Example Playbook
----------------

```yaml
---
- name: Setup oVirt environment
  hosts: localhost
  connection: local
  vars_files:
     - ovirt_passwords.yml
     - disaster_recovery_vars.yml
  roles:
    - disaster_recovery
  collections:
    - ovirt.ovirt
```

Generate var file mapping [demo](https://youtu.be/s1-Hq_Mk1w8)
<br/>
Fail over scenario [demo](https://youtu.be/mEOgH-Tk09c)

Scripts
-------
The ovirt-dr script should provide the user a more convenient way to run
disaster recovery actions as a way to avoid using ansible playbooks directly.
There are four actions which the user can execute:
- `generate`	Generate the mapping var file based on the primary and secondary setup, to be used for failover and failback
- `validate`	Validate the var file mapping which is used for failover and failback
- `failover`	Start a failover process to the target setup
- `failback`	Start a failback process from the target setup to the source setup

Each of those actions are using a configuration file whose default location is `disaster_recovery/files/dr.conf`<br/>
The configuration file's location can be changed using `--conf-file` flag in the `ovirt-dr` script.<br/>
Log file and log level can be configured as well through the `ovirt-dr` script using the flags `--log-file` and `--log-level`


Example Script
--------------
For mapping file generation (from the `./roles/disaster_recovery/files/` directory):
```console
$ ./ovirt-dr generate --log-file=ovirt-dr.log --log-level=DEBUG
```
For mapping file validation:
```console
$ ./ovirt-dr validate
```
For fail-over operation:
```console
$ ./ovirt-dr failover
```
For fail-back operation:
```console
$ ./ovirt-dr failback
```
