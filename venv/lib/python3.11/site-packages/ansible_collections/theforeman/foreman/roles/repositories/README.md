theforeman.foreman.repositories
===============================

This role defines Products and Custom Repositories and enables Red Hat Repositories.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

- `foreman_products`: List of products to manage.
  Each product is represented as a dictionary and can include `repository_sets` which represent Red Hat Repositories and should be used when the product name matches an existing Red Hat Product.
  Each element of `repository_sets` must have a `name` and should specify the `basearch` and/or `releasever` only when multiple versions are available for that Product.
  All repository sets for a Red Hat Product can be enabled by omitting `repository_sets` and instead specifying that the Product has `all_repositories: true`. When using this option it is also necessary to specify a list of repository `label`s for the Product (e.g. rhel-7-server-rpms). Be wary that this option can result in enabling a large number of unused repositories that, if added to sync plans, can greatly increase sync times and rapidly fill disk space.
  Custom (i.e. non Red Hat) Products can also be defined, with associated `repositories` which represent custom repositories, and are required to have a `name`, `url`, and `content_type`; they may require additional fields and can take any parameter supported by [theforeman.foreman.repository](https://theforeman.github.io/foreman-ansible-modules/develop/plugins/repository_module.html).
  The `organization` field can be specified for a product and repositories. The `organization` field defaults to `foreman_organization` variable for a product and defaults to the `organization` field of the product for repositories.
  A variety of examples are demonstrated in the data structure below:

```yaml
foreman_products:
  - name: Red Hat Enterprise Linux Server
    repository_sets:
      - name: Red Hat Enterprise Linux 7 Server (RPMs)
        basearch: x86_64
        releasever: 7Server
      - name: Red Hat Enterprise Linux 6 Server (RPMs)
        basearch: x86_64
        releasever: 6Server
      - name: Red Hat Enterprise Linux 7 Server - Extras (RPMs)
        basearch: x86_64
      - name: Red Hat Enterprise Linux 7 Server - Optional (RPMs)
        basearch: x86_64
        releasever: 7Server
  - name: Red Hat Software Collections (for RHEL Server)
    repository_sets:
      - name: Red Hat Software Collections RPMs for Red Hat Enterprise Linux 7 Server
        basearch: x86_64
        releasever: 7Server
      - name: Red Hat Software Collections RPMs for Red Hat Enterprise Linux 6 Server
        basearch: x86_64
        releasever: 6Server
  - name: Red Hat Enterprise Linux for x86_64
    repository_sets:
      - name: Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
        releasever: 8
      - name: Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
        releasever: 8
  - name: Red Hat Software Collections (for RHEL Server)
    all_repositories: true
    labels:
      - rhel-server-rhscl-7-rpms
  - name: CentOS Stream 8
    repositories:
      - name: BaseOS x86_64
        content_type: yum
        url: http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/
      - name: AppStream x86_64
        content_type: yum
        url: http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/
  - name: Debian 10
    repositories:
      - name: Debian 10 main
        content_type: deb
        url: http://deb.debian.org/debian
        deb_components: main
        deb_architectures: amd64
        deb_releases: buster
  - name: Foreman Client
    repositories:
      - name: Foreman Client Debian 10
        url: https://apt.atix.de/debian
        content_type: deb
        deb_components: main
        deb_architectures: amd64
        deb_releases: stable
      - name: Foreman Client CentOS 7
        url: https://yum.theforeman.org/client/latest/el7/x86_64/
        content_type: yum
```

Example Playbooks
-----------------

This example enables several Red Hat Repositories. There are a few important points to note about the structure of the data in the example:
- RHEL 8 repos have a different product name than previous RHEL versions.
- The RHEL 8 product already contains the `basearch` so it should not be specified on the RHEL 8 `repository_sets`, and the naming convention for `releasever` changed with RHEL 8 since system purpose removes the need for separate distributions like `Server` and `Workstation`.
- The optional and extras repositories do not have point releases so `releasever` should be omitted.
- The second Product is explicitly specified for "Other Organization" and thereby overwrites the default value of `foreman_organization`.

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.repositories
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_products:
          - name: Red Hat Enterprise Linux Server
            repository_sets:
              - name: Red Hat Enterprise Linux 7 Server (RPMs)
                basearch: x86_64
                releasever: 7Server
              - name: Red Hat Enterprise Linux 6 Server (RPMs)
                basearch: x86_64
                releasever: 6Server
              - name: Red Hat Enterprise Linux 7 Server - Extras (RPMs)
                basearch: x86_64
              - name: Red Hat Enterprise Linux 7 Server - Optional (RPMs)
                basearch: x86_64
                releasever: 7Server
          - name: Red Hat Enterprise Linux for x86_64
            organization: "Other Organization"
            repository_sets:
              - name: Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
                releasever: 8
              - name: Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
                releasever: 8
```
