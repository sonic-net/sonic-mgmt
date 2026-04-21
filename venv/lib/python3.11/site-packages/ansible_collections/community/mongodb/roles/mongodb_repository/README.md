mongodb_repository
==================

Configures a repository for MongoDB on Debian and RedHat based platforms.

Role Variables
--------------

* mongodb_version: Version of MongoDB. Default "4.4".
* debian_packages: Packages needed on Debian systems for this role.


Defaults
----------

The following two dictionaries provide configuration details for the MongoDB repositories. Most users should not need to change these.

debian:
  apt_key_url: Apt Key Url.
  apt_repository_repo: Apr repository string.
redhat:
  rpm_key_key: Rpm Key Url.
  yum_baseurl: Yum repository base url.
  yum_gpgkey: Yum repository gpg key.
  yum_gpgcheck: Enable or disable gpg check. Boolean.
  yum_description: Yum Repository Description.

Example Playbook
----------------

Set mongodb_version to 4.0.

```yaml
    - hosts: servers
      roles:
         - { role: mongodb_repository, mongodb_version: "4.0" }
```

License
-------

BSD

Author Information
------------------

Rhys Campbell (https://github.com/rhysmeister)
