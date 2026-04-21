mongodb_auth
============

This role to enables auth on MongoDB servers, adds the first admin user, and adds a list of other users.
If your mongo instance requires ssl or an alternative auth_mechanism, please use
[`module_defaults`](https://docs.ansible.com/ansible/latest/user_guide/playbooks_module_defaults.html)
to provide the default auth details for `community.mongodb.mongodb_user` (these defaults are ignored
when adding the initial admin user with the localhost exception).

By default this role checks and creates a file at `/root/mongodb_admin.success` to provide idempotent creation of the first admin user.

- If running this on a MongoDB server that already has an admin user (ie when using this role to audit
an alternate install method), you must touch the file or you will get an error when this role tries to add the admin user again.
- When setting up a fresh MongoDB installation on a system previously configured with this role, remember to delete this file. 

Role Variables
--------------

* `mongod_host`: The domain or ip to use to communicate with mongod. Default localhost.
* `mongod_port`: The port used by the mongod process. Default 27017.
* `mongod_package`: The mongod package to install. Default mongodb-org-server.
* `authorization`: Enable authorization. Default enabled.
* `mongodb_admin_db`: MongoDB admin database (for adding users). Default admin.
* `mongodb_admin_user`: MongoDB admin username. Default admin.
* `mongodb_admin_pwd`: MongoDB admin password. Defaults to value of mongodb_admin_default_pwd.
* `mongodb_admin_default_pwd`: MongoDB admin password (for parent roles to override without overriding user's password). Default admin.
* `mongodb_users`: List of additional users to add. Each user dict should include fields: db, user, pwd, state (default: "present"), roles (default: "readWrite").
* `mongodb_force_update_password`: Whether or not to force a password update for any users in mongodb_users. Setting this to yes will result in 'changed' on every run, even if the password is the same. Setting this to no only adds a password when creating the user.
* `mongodb_create_for_localhost_exception`: Path of the file checked before creating the first admin user. If present, it is skipped. If absent, admin is added and the file is created afterwards. Default `/root/mongodb_admin.success`.

IMPORTANT NOTE: It is expected that mongodb_admin_user & mongodb_admin_pwd values be overridden in your own file protected by Ansible Vault. Any production environments should protect these values. For more information see [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html)

Dependencies
------------

mongodb_repository

Example Playbook
----------------

Install MongoDB preparing hosts for a Replicaset

```yaml
    - hosts: servers
      roles:
         - { role: "community.mongodb.mongodb_repository" }
         - { role: "community.mongodb.mongodb_mongod" }

      tasks:

        - name: Initialise MongoDB Replicaset rs0
          community.mongodb.mongodb_replicaset:
            login_database: "admin"
            login_host: localhost
            replica_set: "rs0"
            members:
              - "mongodb1"
              - "mongodb2"
              - "mongodb3"
          when: ansible_hostname == "mongodb1"
          register: repl

        - name: Ensure replicaset has reached a converged state
          community.mongodb.mongodb_status:
            replica_set: "rs0"
            poll: 10
            interval: 10
          when: repl.changed == True

        - name: Import mongodb_auth role
          include_role:
            name: mongodb_auth
          vars:
            mongod_host: "127.0.0.1"
            mongodb_admin_pwd: "f00b@r"
          when: ansible_hostname == "mongodb1"
```

License
-------

BSD

Author Information
------------------

Jacob Floyd (https://github.com/cognifloyd)
