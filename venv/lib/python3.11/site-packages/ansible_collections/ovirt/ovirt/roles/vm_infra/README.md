oVirt Virtual Machine Infrastructure
====================================

The `vm_infra` role manages the virtual machine infrastructure in oVirt.
This role also creates inventory of created virtual machines it defines if
`wait_for_ip` is set to `true` and state of virtual machine is `running`.
All defined virtual machines are part of `ovirt_vm` inventory group.
Role also creates `ovirt_tag_{tag_name}` groups if there are any
tags assigned to a virtual machine and places all virtual machines with that tag
to that inventory group.

Consider the following variable structure:

```yaml
vms:
  - name: myvm1
    tag: mytag1
    profile: myprofile

  - name: myvm2
    tag: mytag2
    profile: myprofile
```

The role will create inventory group `ovirt_vm` with both of the virtual
machines - `myvm1` and `myvm2`. The role also creates inventory group `ovirt_tag_mytag1`
with virtual machine `myvm1` and inventory group `ovirt_tag_mytag2` with virtual
machine `myvm2`.

Limitations
-----------

 * Does not support Ansible Check Mode (Dry Run).

Role Variables
--------------

| Name                           | Default value |                                              |
|--------------------------------|---------------|----------------------------------------------|
| vms                            | UNDEF         | List of dictionaries with virtual machine specifications.   |
| affinity_groups                | UNDEF         | List of dictionaries with affinity groups specifications.   |
| wait_for_ip                    | false         | If true, the playbook should wait for the virtual machine IP reported by the guest agent.  |
| wait_for_ip_version            | v4            | Specify which IP version should be wait for. Either v4 or v6.  |
| wait_for_ip_range              | 0.0.0.0/0     | Specify CIDR of virutal machine IP which should be reported. Works only for IPv4.   |
| debug_vm_create                | false         | If true, logs the tasks of the virtual machine being created. The log can contain passwords. |
| vm_infra_create_single_timeout | 180           | Time in seconds to wait for VM to be created and started (if state is running). |
| vm_infra_create_poll_interval  | 15            | Polling interval. Time in seconds to wait between check of state of VM.  |
| vm_infra_create_all_timeout    | vm_infra_create_single_timeout * (vms.length) | Total time to wait for all VMs to be created/started. |
| vm_infra_wait_for_ip_retries   | 5             | Number of retries to check if VM is reporting it's IP address. |
| vm_infra_wait_for_ip_delay     | 5             | Polling interval of IP address. Time in seconds to wait between check if VM reports IP address. |


The `vms` and `profile` variables can contain following attributes, note that if you define same variable in both the value in `vms` has precendence:

| Name               | Default value         |                                            |
|--------------------|-----------------------|--------------------------------------------|
| name               | UNDEF                 | Name of the virtual machine to create.     |
| tag                | UNDEF                 | Name of the tag to assign to the virtual machine. Only administrator users can use this attribute.  |
| cloud_init         | UNDEF                 | Dictionary with values for Unix-like Virtual Machine initialization using cloud init. See below <i>cloud_init</i> section for more detailed description. |
| cloud_init_nics    | UNDEF                 | List of dictionaries representing network interafaces to be setup by cloud init. See below <i>cloud_init_nics</i> section for more detailed description. |
| sysprep            | UNDEF                 | Dictionary with values for Windows Virtual Machine initialization using sysprep. See below <i>sysprep</i> section for more detailed description. |
| profile            | UNDEF                 | Dictionary specifying the virtual machine hardware. See the table below.  |
| state              | present               | Should the Virtual Machine be stopped, present or running. Takes precedence before state value in profile. |
| nics               | UNDEF                 | List of dictionaries specifying the NICs of the virtual machine. See below for more detailed description.   |
| cluster            | UNDEF                 | Name of the cluster where the virtual machine will be created. |
| clone              | No                    | If yes then the disks of the created virtual machine will be cloned and independent of the template.  This parameter is used only when state is running or present and VM didn't exist before.  |
| template           | Blank                 | Name of template that the virtual machine should be based on.   |
| template_version   | UNDEF                 | Version number of the template to be used for VM. By default the latest available version of the template is used.   |
| boot_disk_name     | UNDEF                 | Renames the bootable disk after the VM is created. Useful when creating VMs from templates |
| boot_disk_use_vm_name_prefix | true        | Use the name of the virtual machine as prefix when renaming the VM boot disk. The resulting boot disk name would be <i>{{vm_name}}_{{boot_disk_name}}</i>|
| boot_disk_size     | UNDEF                 | Resizes the bootable disk after the VM is created. A suffix that complies to the IEC 60027-2 standard (for example 10GiB, 1024MiB) can be used. |
| memory             | UNDEF                 | Amount of virtual machine memory.               |
| memory_max         | UNDEF                 | Upper bound of virtual machine memory up to which memory hot-plug can be performed. |
| memory_guaranteed  | UNDEF                 | Amount of minimal guaranteed memory of the Virtual Machine. Prefix uses IEC 60027-2 standard (for example 1GiB, 1024MiB). <i>memory_guaranteed</i> parameter can't be lower than <i>memory</i> parameter. |
| cores              | UNDEF                 | Number of CPU cores used by the the virtual machine.          |
| sockets            | UNDEF                 | Number of virtual CPUs sockets of the Virtual Machine.  |
| cpu_shares         | UNDEF                 | Set a CPU shares for this Virtual Machine. |
| cpu_threads        | UNDEF                 | Set a CPU threads for this Virtual Machine. |
| disks              | UNDEF                 | List of dictionaries specifying the additional virtual machine disks. See below for more detailed description. |
| nics               | UNDEF                 | List of dictionaries specifying the NICs of the virtual machine. See below for more detailed description.   |
| custom_properties  | UNDEF                 | Properties sent to VDSM to configure various hooks.<br/> Custom properties is a list of dictionary which can have following values: <br/><i>name</i> - Name of the custom property. For example: hugepages, vhost, sap_agent, etc.<br/><i>regexp</i> - Regular expression to set for custom property.<br/><i>value</i> - Value to set for custom property. |
| high_availability  | UNDEF                 | Whether or not the node should be set highly available. |
| high_availability_priority | UNDEF                 | Indicates the priority of the virtual machine inside the run and migration queues. Virtual machines with higher priorities will be started and migrated before virtual machines with lower priorities. The value is an integer between 0 and 100. The higher the value, the higher the priority. If no value is passed, default value is set by oVirt/RHV engine. |
| io_threads         | UNDEF                 | Number of IO threads used by virtual machine. 0 means IO threading disabled. |
| description        | UNDEF                 | Description of the Virtual Machine. |
| operating_system   | UNDEF                 | Operating system of the Virtual Machine. For example: rhel_7x64 |
| type               | UNDEF                 | Type of the Virtual Machine. Possible values: desktop, server or high_performance |
| graphical_console  | UNDEF                 | Assign graphical console to the virtual machine.<br/>Graphical console is a dictionary which can have following values:<br/><i>headless_mode</i> - If true disable the graphics console for this virtual machine.<br/><i>protocol</i> - 'VNC', 'Spice' or both. |
| storage_domain     | UNDEF                 | Name of the storage domain where all virtual machine disks should be created. Considered only when template is provided.|
| state              | present               | Should the Virtual Machine be stopped, present or running.|
| ssh_key            | UNDEF                 | SSH key to be deployed to the virtual machine. This is parameter is keep for backward compatibility and has precendece before <i>authorized_ssh_keys</i> in <i>cloud_init</i> dictionary. |
| domain             | UNDEF                 | The domain of the virtual machine. This is parameter is keep for backward compatibility and has precendece before <i>host_name</i> in <i>cloud_init</i> or <i>sysprep</i> dictionary.|
| lease              | UNDEF                 | Name of the storage domain this virtual machine lease reside on. |
| root_password      | UNDEF                 | The root password of the virtual machine. This is parameter is keep for backward compatibility and has precendece before <i>root_password</i> in <i>cloud_init</i> or <i>sysprep</i> dictionary.|
| host               | UNDEF                 | If you need to set cpu_mode as host_passthrough, you need to use this param to define host to use along with placement_policy set to pinned. |
| cpu_mode           | UNDEF                 | CPU mode of the virtual machine. It can be some of the following: host_passthrough, host_model or custom. |
| placement_policy   | UNDEF                 | The configuration of the virtual machine's placement policy. |
| boot_devices       | UNDEF                 | List of boot devices which should be used to boot. Valid entries are `cdrom`, `hd`, `network`. |
| serial_console     | UNDEF                 | True enable VirtIO serial console, False to disable it. By default is chosen by oVirt/RHV engine. |
| serial_policy      | UNDEF                 | Specify a serial number policy for the Virtual Machine. Following options are supported. <br/><i>vm</i> - Sets the Virtual Machine's UUID as its serial number. <br/><i>host</i> - Sets the host's UUID as the Virtual Machine's serial number. <br/><i>custom</i> - Allows you to specify a custom serial number in serial_policy_value. |
| serial_policy_value | UNDEF                 | Allows you to specify a custom serial number. This parameter is used only when <i>serial_policy</i> is custom. |
| comment | UNDEF                             | Comment of the virtual Machine. |

The item in `disks` list of `profile` dictionary can contain following attributes:

| Name               | Default value  |                                              |
|--------------------|----------------|----------------------------------------------|
| size               | UNDEF          | The size of the additional disk. |
| name               | UNDEF          | The name of the additional disk.  |
| id               | UNDEF          | Id of the disk. If you pass id of the disk and name the disk will be looked up by id and will update name of the disk if it differs from the name passed in name parameter. |
| storage_domain     | UNDEF          | The name of storage domain where disk should be created. |
| interface          | UNDEF          | The interface of the disk. |
| name_prefix        | True           | If true the name of the vm will be used as prefix of disk name. If false only the name of disk will be used as disk name - could be useful when creating vm from template with custom disk size. |
| format             | UNDEF          | Specify format of the disk.  <ul><li>cow - If set, the disk will by created as sparse disk, so space will be allocated for the volume as needed. This format is also known as thin provisioned disks</li><li>raw - If set, disk space will be allocated right away. This format is also known as preallocated disks.</li></ul> |
| bootable           | UNDEF          | True if the disk should be bootable. |
| activate           | UNDEF          | True if the disk should be activated |

The item in `nics` list of `profile` dictionary can contain following attributes:

| Name               | Default value  |                                              |
|--------------------|----------------|----------------------------------------------|
| name               | UNDEF          | The name of the network interface.           |
| interface          | UNDEF          | Type of the network interface.               |
| mac_address        | UNDEF          | Custom MAC address of the network interface, by default it's obtained from MAC pool. |
| network            | UNDEF          | Logical network which the VM network interface should use. If network is not specified, then Empty network is used. |
| profile            | UNDEF          | Virtual network interface profile to be attached to VM network interface. |

The `affinity_groups` list can contain following attributes:

| Name               | Default value       |                                              |
|--------------------|---------------------|----------------------------------------------|
| cluster            | UNDEF (Required)    |  Name of the cluster of the affinity group.  |
| description        | UNDEF               |  Human readable description.                 |
| host_enforcing     | false               |  <ul><li>true - VM cannot start on host if it does not satisfy the `host_rule`.</li><li>false - VM will follow `host_rule` with soft enforcement.</li></ul>|
| host_rule          | UNDEF               |  <ul><li>positive - VM's in this group must run on this host.</li> <li>negative - VM's in this group may not run on this host</li></ul> |
| hosts              | UNDEF               |  List of host names assigned to this group.  |
| name               | UNDEF (Required)    |  Name of affinity group.                     |
| state              | UNDEF               |  Whether group should be present or absent.  |
| vm_enforcing       | false               |  <ul><li>true - VM cannot start if it cannot satisfy the `vm_rule`.</li><li>false - VM will follow `vm_rule` with soft enforcement.</li></ul> |
| vm_rule            | UNDEF               |  <ul><li>positive - all vms in this group try to run on the same host.</li><li>negative - all vms in this group try to run on separate hosts.</li><li>disabled - this affinity group does not take effect.</li></ul> |
| vms                | UNDEF               |  List of VM's to be assigned to this affinity group. |
| wait               | true                |  If true, the module will wait for the desired state. |

The `affinity_labels` list can contain following attributes:

| Name               | Default value       |                                              |
|--------------------|---------------------|----------------------------------------------|
| cluster            | UNDEF (Required)    |  Name of the cluster of the affinity label group.  |
| hosts              | UNDEF               |  List of host names assigned to this label.  |
| name               | UNDEF (Required)    |  Name of affinity label.                     |
| state              | UNDEF               |  Whether label should be present or absent.  |
| vms                | UNDEF               |  List of VM's to be assigned to this affinity label. |

The `cloud_init` dictionary can contain following attributes:

| Name                | Description                                          |
|---------------------|------------------------------------------------------|
| host_name           | Hostname to be set to Virtual Machine when deployed. |
| timezone            | Timezone to be set to Virtual Machine when deployed. |
| user_name           | Username to be used to set password to Virtual Machine when deployed. |
| root_password       | Password to be set for user specified by user_name parameter. By default it's set for root user. |
| authorized_ssh_keys | Use this SSH keys to login to Virtual Machine. |
| regenerate_ssh_keys | If True SSH keys will be regenerated on Virtual Machine. |
| custom_script       | Cloud-init script which will be executed on Virtual Machine when deployed. This is appended to the end of the cloud-init script generated by any other options. |
| dns_servers         | DNS servers to be configured on Virtual Machine. |
| dns_search          | DNS search domains to be configured on Virtual Machine. |
| nic_boot_protocol   | Set boot protocol of the network interface of Virtual Machine. Can be one of none, dhcp or static. |
| nic_ip_address      | If boot protocol is static, set this IP address to network interface of Virtual Machine. |
| nic_netmask         | If boot protocol is static, set this netmask to network interface of Virtual Machine. |
| nic_gateway         | If boot protocol is static, set this gateway to network interface of Virtual Machine. |
| nic_name            | Set name to network interface of Virtual Machine. |
| nic_on_boot         | If True network interface will be set to start on boot. |

The `sysprep` dictionary can contain following attributes:

| Name                | Description                                          |
|---------------------|------------------------------------------------------|
| host_name           | Hostname to be set to Virtual Machine when deployed. |
| active_directory_ou | Active Directory Organizational Unit, to be used for login of user. |
| org_name            | Organization name to be set to Windows Virtual Machine. |
| user_name           | Username to be used for set password to Windows Virtual Machine. |
| root_password       | Password to be set for user specified by user_name parameter. By default it's set for root user. |
| windows_license_key | License key to be set to Windows Virtual Machine. |
| input_locale        | Input localization of the Windows Virtual Machine. |
| system_locale       | System localization of the Windows Virtual Machine. |
| ui_language         | UI language of the Windows Virtual Machine. |
| domain              | Domain to be set to Windows Virtual Machine. |
| timezone            | Timezone to be set to Windows Virtual Machine. |

The `cloud_init_nics` List of dictionaries representing network interafaces to be setup by cloud init. This option is used, when user needs to setup more network interfaces via cloud init.
If one network interface is enough, user should use cloud_init nic_* parameters. cloud_init nic_* parameters are merged with cloud_init_nics parameters. Dictionary can contain following values.

| Name                | Description                                          |
|---------------------|------------------------------------------------------|
| nic_boot_protocol   | Set boot protocol of the network interface of Virtual Machine. Can be one of none, dhcp or static. |
| nic_ip_address      | If boot protocol is static, set this IP address to network interface of Virtual Machine. |
| nic_netmask         | If boot protocol is static, set this netmask to network interface of Virtual Machine. |
| nic_gateway         | If boot protocol is static, set this gateway to network interface of Virtual Machine. |
| nic_name            | Set name to network interface of Virtual Machine. |
| nic_on_boot         | If True network interface will be set to start on boot. |

Example Playbook
----------------

```yaml
---
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars_files:
    # Contains encrypted `engine_password` varibale using ansible-vault
    - passwords.yml

  vars:
    engine_fqdn: ovirt-engine.example.com
    engine_user: admin@internal
    engine_cafile: /etc/pki/ovirt-engine/ca.pem

    httpd_vm:
      cluster: production
      domain: example.com
      template: rhel7
      memory: 2GiB
      cores: 2
      ssh_key: ssh-rsa AAA...LGx user@fqdn
      disks:
        - size: 10GiB
          name: data
          storage_domain: mynfsstorage
          interface: virtio

    db_vm:
      cluster: production
      domain: example.com
      template: rhel7
      memory: 4GiB
      cores: 1
      ssh_key: ssh-rsa AAA...LGx user@fqdn
      disks:
        - size: 50GiB
          name: data
          storage_domain: mynfsstorage
          interface: virtio
      nics:
        - name: ovirtmgmt
          network: ovirtmgmt
          profile: ovirtmgmt

    vms:
      - name: postgresql-vm-0
        tag: postgresql_vm
        profile: "{{ db_vm }}"
      - name: postgresql-vm-1
        tag: postgresql_vm
        profile: "{{ db_vm }}"
      - name: apache-vm
        tag: httpd_vm
        profile: "{{ httpd_vm }}"

    affinity_groups:
      - name: db-ag
        cluster: production
        vm_enforcing: true
        vm_rule: negative
        vms:
          - postgresql-vm-0
          - postgresql-vm-1

  roles:
    - vm_infra
  collections:
    - ovirt.ovirt
```

The example below shows how to use inventory created by `vm_infra` role in follow-up play.

```yaml
---
- name: Deploy apache VM
  hosts: localhost
  connection: local
  gather_facts: false

  vars_files:
    # Contains encrypted `engine_password` varibale using ansible-vault
    - passwords.yml

  vars:
    wait_for_ip: true

    httpd_vm:
      cluster: production
      state: running
      domain: example.com
      template: rhel7
      memory: 2GiB
      cores: 2
      ssh_key: ssh-rsa AAA...LGx user@fqdn
      disks:
        - size: 10GiB
          name: data
          storage_domain: mynfsstorage
          interface: virtio

    vms:
      - name: apache-vm
        tag: apache
        profile: "{{ httpd_vm }}"

  roles:
    - vm_infra
  collections:
    - ovirt.ovirt

- name: Deploy apache on VM
  hosts: ovirt_tag_apache

  vars_files:
    - apache_vars.yml

  roles:
    - geerlingguy.apache
```

[![asciicast](https://asciinema.org/a/111662.png)](https://asciinema.org/a/111662)
