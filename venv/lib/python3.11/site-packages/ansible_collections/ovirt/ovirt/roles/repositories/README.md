oVirt Repositories
==================

The `repositories` role is used to set the repositories required for
oVirt engine or host installation. By default it copies content of
/etc/yum.repos.d/ to /tmp/repo-backup-{{timestamp}}, so it's easy to undo that operation.

Role Variables
--------------

| Name                                       | Default value         |  Description                              |
|--------------------------------------------|-----------------------|-------------------------------------------|
| ovirt_repositories_ovirt_release_rpm       | UNDEF                 | URL of oVirt release package, which contains required repositories configuration. |
| ovirt_repositories_ovirt_release_rpm_gpg   | https://plain.resources.ovirt.org/pub/keys/RPM-GPG-ovirt-v2 | Address of the rpm GPG key. |
| ovirt_repositories_disable_gpg_check       | False                 | Disable the GPG check for <i>ovirt_repositories_ovirt_release_rpm</i>. by default is False unless 'master.rpm' in <i>ovirt_repositories_ovirt_release_rpm</i>. |
| ovirt_repositories_use_subscription_manager| False                 | If true it will use repos from subscription manager and the value of <i>ovirt_repositories_ovirt_release_rpm</i> will be ignored. |
| ovirt_repositories_ovirt_version           | 4.4                   | oVirt release version (Supported versions [4.1, 4.2, 4.3, 4.4]). Will be used to enable the required repositories and enable modules. |
| ovirt_repositories_target_host             | engine                | Type of the target machine, which should be one of [engine, host, rhvh, host_ppc]. This parameter takes effect only in case <i>ovirt_repositories_use_subscription_manager</i> is set to True. If incorrect version or target is specified no repositories are enabled. The host_ppc is available only on 4.4. |
| ovirt_repositories_rh_username             | UNDEF                 | Username to use for subscription manager. |
| ovirt_repositories_rh_password             | UNDEF                 | Password to use for subscription manager. |
| ovirt_repositories_pool_ids                | UNDEF                 | List of pools ids to subscribe to. |
| ovirt_repositories_pools                   | UNDEF                 | Specify a list of subscription pool names. Use <i>ovirt_repositories_pool_ids</i> instead if possible, as it is much faster. |
| ovirt_repositories_subscription_manager_repos| []                  | List of repositories to enable by subscription-manager. By default we have list of repositories for each {{ovirt_repositories_target_host}}_{{ovirt_repositories_ovirt_version}} in vars folder. |
| ovirt_repositories_repos_backup            | True                  | When set to `False`, original repositories won't be backed up. |
| ovirt_repositories_repos_backup_path       | /tmp/repo-backup-{{timestamp}} | Directory to backup the original repositories configuration |
| ovirt_repositories_force_register          | False                 | Bool to register the system even if it is already registered. |
| ovirt_repositories_rhsm_server_hostname    | UNDEF                 | Hostname of the RHSM server. By default it's used from rhsm configuration. |
| ovirt_repositories_clear                   | False                 | If True all repositories will be unregistered before registering new ones. |
| ovirt_repositories_org                     | UNDEF                 | The org will be used for subscription manager. The `ovirt_repositories_org` and `ovirt_repositories_activationkey` will be used over `ovirt_repositories_pool_ids`. |
| ovirt_repositories_activationkey           | UNDEF                 | The activation key will be used for the subscription manager. |
| ovirt_repositories_ca_rpm_url              | UNDEF                 | The URL for Satellite rpm will set up host certificates. |
| ovirt_repositories_ca_rpm_validate_certs   | UNDEF                 | If `False` it will ignore all SSL certificates for the `ovirt_repositories_ca_rpm_url`. |
| ovirt_repositories_ca_rpm_disable_gpg_check| UNDEF                 | If `True` it will ignore all GPG check for the `ovirt_repositories_ca_rpm_url`. |
| ovirt_repositories_rhsm_environment        | UNDEF                 | The Satellite environment to specify libraries. |


Example Playbook
----------------

```yaml
---
- name: Setup repositories using oVirt release package
  hosts: localhost
  vars_files:
    # Contains encrypted `username` and `password` variables using ansible-vault
    - passwords.yml
  vars:
    ovirt_repositories_ovirt_release_rpm: http://resources.ovirt.org/pub/yum-repo/ovirt-master-release.rpm

  roles:
    - repositories
  collections:
    - ovirt.ovirt
```

```yaml
- name: Setup repositories using Subscription Manager
  hosts: localhost

  vars:
    ovirt_repositories_use_subscription_manager: True
    ovirt_repositories_force_register: True
    ovirt_repositories_rh_username: "{{ ovirt_repositories_rh_username }}"
    ovirt_repositories_rh_password: "{{ ovirt_repositories_rh_password }}"
    # The following pool IDs are not valid and should be replaced.
    ovirt_repositories_pool_ids:
      - 0123456789abcdef0123456789abcdef
      - 1123456789abcdef0123456789abcdef

  roles:
    - repositories
  collections:
    - ovirt.ovirt
```

```yaml
- name: Setup repositories using Subscription Manager pool name
  hosts: localhost

  vars:
    ovirt_repositories_use_subscription_manager: True
    ovirt_repositories_force_register: True
    ovirt_repositories_rh_username: "{{ ovirt_repositories_rh_username }}"
    ovirt_repositories_rh_password: "{{ ovirt_repositories_rh_password }}"
    ovirt_repositories_pools:
      - "Red Hat Cloud Infrastructure, Premium (2-sockets)"

  roles:
    - repositories
  collections:
    - ovirt.ovirt
```

```yaml
- name: Setup repositories using Subscription Manager with Satellite using username and password
  hosts: localhost

  vars:
    ovirt_repositories_use_subscription_manager: true
    ovirt_repositories_ca_rpm_url: https://example.com/pub/katello-ca-consumer-latest.noarch.rpm
    ovirt_repositories_ca_rpm_validate_certs: false
    ovirt_repositories_ca_rpm_disable_gpg_check: true
    ovirt_repositories_target_host: engine
    ovirt_repositories_rhsm_environment: Library
    ovirt_repositories_rh_password: "{{ ovirt_repositories_rh_password }}"
    ovirt_repositories_rh_username: "{{ ovirt_repositories_rh_username }}"
    ovirt_repositories_pool_ids:
      - 8aa508b87f922c3b017f97a785a40068

  roles:
    - repositories
  collections:
    - ovirt.ovirt
```

```yaml
- name: Setup repositories using Subscription Manager with Satellite using org and activationkey
  hosts: localhost
  vars:
    ovirt_repositories_use_subscription_manager: true
    ovirt_repositories_org: "4fc82b1a-7d80-44cf-8ef6-affd8c6daa4f"
    ovirt_repositories_activationkey: "RHV_CDN_Host"
    ovirt_repositories_ca_rpm_url: https://example.com/pub/katello-ca-consumer-latest.noarch.rpm
    ovirt_repositories_ca_rpm_validate_certs: false
    ovirt_repositories_ca_rpm_disable_gpg_check: true
    ovirt_repositories_target_host: engine

  roles:
    - repositories
  collections:
    - ovirt.ovirt
```
