oVirt Hosts
===========

The `hosts` role is used to set up oVirt hosts.

Role Variables
--------------

The `hosts` list can contain the following parameters:

| Name          | Default value    | Description                           |
|---------------|------------------|---------------------------------------|
| name          | UNDEF (Required) | Name of the host.                      |
| state         | present          | Specifies whether the host is `present` or `absent`.  |
| address       | UNDEF (Required) | IP address or FQDN of the host.   |
| password      | UNDEF            | The host's root password. Required if <i>public_key</i> is false. |
| public_key    | UNDEF            | If <i>true</i> the public key should be used to authenticate to host. |
| cluster       | UNDEF (Required) | The cluster that the host must connect to.    |
| timeout       | 1200             | Maximum wait time for the host to be in an UP state.  |
| poll_interval | 20               | Polling interval to check the host status. |
| hosted_engine | UNDEF            | Specifies whether to 'deploy' or 'undeploy' hosted-engine to node. |
| reboot_after_installation | UNDEF | If true reboot host after successful installation. |
| reboot_after_upgrade | UNDEF | If true reboot host after successful upgrade. |

Example Playbook
----------------

```yaml
- name: oVirt infra
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    hosts:
      - name: myhost
        address: 1.2.3.4
        cluster: production
        password: 123456

  roles:
    - ovirt.ovirt.infra.roles.hosts
```
