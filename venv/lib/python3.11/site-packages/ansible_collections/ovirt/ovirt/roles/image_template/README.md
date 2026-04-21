oVirt Image Template
====================

The `image_template` role creates a template from external image. Currently the disk can be an image in Glance external provider or QCOW2 image.

Requirements
------------

 * oVirt has to be 4.1 or higher and [ovirt-imageio] must be installed and running.
 * CA certificate of oVirt engine. The path to CA certificate must be specified in the `ovirt_ca` variable.
 * file

Limitations
-----------

 * We don not support Ansible Check Mode (Dry Run), because this role is using few modules(command module),
   which do not support it. Once all modules used by this role will support it, we will support it.

Role Variables
--------------

| Name               | Default value         |                            |
|--------------------|-----------------------|----------------------------|
| qcow_url           | UNDEF (mandatory if glance is not used)                | The URL of the QCOW2 image. You can specify local file with prefix 'file://'. |
| qcow_url_client_cert | UNDEF               | Path to client certificate if needed for retrieving QCOW from authenticated site. |
| qcow_url_client_key | UNDEF                | Path to client key if needed for retrieving QCOW from authenticated site. |
| image_path         | /tmp/                 | Path where the QCOW2 image will be downloaded to. If directory the base name of the URL on the remote server will be used. |
| image_checksum     | UNDEF                 | If a checksum is defined, the digest of the destination file will be calculated after it is downloaded to ensure its integrity and verify that the transfer completed successfully. Format: <algorithm>:<checksum>, e.g. checksum="sha256:D98291AC[...]B6DC7B97". |
| image_cache_download | true                | When set to false will delete image_path at the start and end of execution |
| template_cluster   | Default               | Name of the cluster where template must be created. |
| template_io_threads| UNDEF                 | Number of IO threads used by template. 0 means IO threading disabled.  (Added in ansible 2.7)|
| template_name      | mytemplate            | Name of the template. |
| template_memory    | 2GiB                  | Amount of memory assigned to the template. |
| template_memory_guaranteed    | UNDEF      | Amount of minimal guaranteed memory of the Virtual Machine |
| template_memory_max    | UNDEF             | Upper bound of virtual machine memory up to which memory hot-plug can be performed. |
| template_cpu       | 1                     | Number of CPUs assigned to the template.  |
| template_disk_storage | UNDEF              | Name of the data storage domain where the disk must be created. If not specified, the data storage domain is selected automatically. |
| template_disks     | []                 | List of dictionaries specifying the additional template disks. See below for more detailed description.  |
| template_disk_size | 10GiB                 | The size of the template disk.  |
| template_disk_name | UNDEF                 | The name of template disk.  |
| template_disk_format | UNDEF               | Format of the template disk.  |
| template_disk_interface | virtio           | Interface of the template disk.  (Choices: virtio, ide, virtio_scsi)  |
| template_seal      | true                  | 'Sealing' erases all machine-specific configurations from a filesystem. Not supported on Windows. Set this to 'false' for Windows.  |
| template_timeout   | 600                   | Amount of time to wait for the template to be created/imported. |
| template_type      | UNDEF                 | The type of the template: desktop, server or high_performance (for qcow2 based templates only) |
| template_nics      | {name: nic1, profile_name: ovirtmgmt, interface: virtio} | List of dictionaries that specify the NICs of template. |
| template_operating_system | UNDEF | Operating system of the template like: other, rhel_7x64, debian_7, see others in ovirt_template module. |
| template_bios_type | UNDEF | Set bios type, necessary for some operating systems and secure boot. If no value is passed, default value is set from cluster. |
| glance_image_provider        | UNDEF (mandatory if qcow_url is not used)            | Name of the glance image provider.                    |
| glance_image            | UNDEF (mandatory if qcow_url is not used)               | This parameter specifies the name of disk in glance provider to be imported as template. |
| template_prerequisites_tasks | UNDEF | Works only with qcow image. Specify a path to Ansible tasks file, which should be executed on virtual machine before creating a template from it. Note that qcow image must contain guest agent which reports IP address. |

The `template_disks` List of dictionaries can contain following attributes:

| Name               | Default value  |                                              |
|--------------------|----------------|----------------------------------------------|
| name               | UNDEF (Required)          | The name of the additional disk. |
| size               | UNDEF (Required)          | The size of the additional disk. |
| storage_domain     | UNDEF          | The name of storage domain where disk should be created. If no value is passed, value is set by <i>template_disk_storage</i>. |
| interface          | UNDEF          | The interface of the disk.  If no value is passed, value is set by <i>template_disk_interface</i>. |
| format             | UNDEF          | Specify format of the disk. If no value is passed, value is set by <i>template_disk_format</i>. <ul><li>cow - If set, the disk will by created as sparse disk, so space will be allocated for the volume as needed. This format is also known as thin provisioned disks</li><li>raw - If set, disk space will be allocated right away. This format is also known as preallocated disks.</li></ul> |
| bootable           | UNDEF          | True if the disk should be bootable. |

Example Playbook
----------------

```yaml
---
- name: Create a template from qcow
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    engine_fqdn: ovirt-engine.example.com
    engine_user: admin@internal
    engine_password: 123456
    engine_cafile: /etc/pki/ovirt-engine/ca.pem

    qcow_url: https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2
    #qcow_url: file:///tmp/CentOS-7-x86_64-GenericCloud.qcow2
    template_cluster: production
    template_name: centos7_template
    template_memory: 4GiB
    template_cpu: 2
    template_disk_size: 10GiB
    template_disk_storage: mydata

  roles:
    - image_template
  collections:
    - ovirt.ovirt


- name: Create a template from a disk stored in glance
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    engine_fqdn: ovirt-engine.example.com
    engine_user: admin@internal
    engine_password: 123456
    engine_cafile: /etc/pki/ovirt-engine/ca.pem

    glance_image_provider: qe-infra-glance
    glance_image: rhel7.4_ovirt4.2_guest_disk
    template_cluster: production
    template_name: centos7_template
    template_memory: 4GiB
    template_cpu: 2
    template_disk_size: 10GiB
    template_disk_storage: mydata

  roles:
    - image_template
  collections:
    - ovirt.ovirt

- name: Create a template from qcow2.xz
  hosts: localhost
  connection: local
  gather_facts: false
  pre_tasks:
    - name: Download qcow2.xz file
      get_url:
        url: "https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud.qcow2.xz"
        dest: /tmp
      register: downloaded_file

    - name: Extract downloaded QCOW image
      command: "unxz --keep --force {{ downloaded_file.dest }}"

    - name: Set qcow_url to extracted file
      set_fact:
        qcow_url: "file://{{ (downloaded_file.dest | splitext)[0] }}"
  vars:
    engine_fqdn: ovirt-engine.example.com
    engine_user: admin@internal
    engine_password: 123456
    engine_cafile: /etc/pki/ovirt-engine/ca.pem

    template_cluster: production
    template_name: centos7_template
    template_memory: 4GiB
    template_cpu: 2
    template_disk_size: 10GiB
    template_disk_storage: mydata

  roles:
    - image_template
  collections:
    - ovirt.ovirt
```

[![asciicast](https://asciinema.org/a/111478.png)](https://asciinema.org/a/111478)

[ovirt-imageio]: http://www.ovirt.org/develop/release-management/features/storage/image-upload/
