Ansible Role: ProxySQL
======================

This role installs, and configures ProxySQL.

Requirements
------------

None

Role Variables
--------------

As with all roles designed in Data Platforms, the interface to variables in this role should only be via the role defaults, and it shouldn't be necessary to override the role vars.

A full list of defaults and their values can be found in the `defaults/main.yml`.

Dependencies
------------

None

Example Playbook
----------------

```
    - hosts: servers
      tasks:
        - import_role:
            name: role_mysql_proxysql
          tags:
            - proxysql
```

License
-------

BSD

Author Information
------------------

Ben Mildren
