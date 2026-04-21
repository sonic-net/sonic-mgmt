theforeman.foreman.content_view_publish
=======================================

Publish a list of Content Views.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

### Required

- `foreman_content_views`: List of Content Views to publish. It can be either a list of Content View names or a list of dictionaries with the parameters as accepted by the `content_view_version` module or the `content_views` role.

### Optional  

- `foreman_content_view_publish_async`: Asynchronous mode lets you control how long-running tasks execute. See the [Ansible documentation](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_async.html#asynchronous-playbook-tasks) for details.
- `foreman_content_view_publish_poll`: For asynchronous tasks, this is how often to check back on the status of those tasks.
  
Example Playbook
----------------

### List of Content View names

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_view_publish
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_content_views:
          - RHEL 7 View
          - RHEL 8 View
```

### List of dictionaries as accepted by the `content_view_version` module

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_view_publish
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_content_views:
          - content_view: RHEL 7 View
            description: "daily publish of RHEL 7 View"
          - content_view: RHEL 8 View
            description: "daily publish of RHEL 8 View"
```

### List of dictionaries as accepted by the `content_views` role

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_view_publish
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_content_views:
          - name: RHEL7
            repositories:
              - name: Red Hat Enterprise Linux 7 Server RPMs x86_64 7Server
                product: 'Red Hat Enterprise Linux Server'
              - name: Red Hat Enterprise Linux 7 Server - Extras RPMs x86_64
                product: 'Red Hat Enterprise Linux Server'
              - name: Red Hat Satellite Tools 6.8 (for RHEL 7 Server) (RPMs)
                product: 'Red Hat Enterprise Linux Server'
          - name: BearApp
            organization: "ACME"
            repositories:
              - name: MyApps
                product: ACME
            filters:
              - name: "bear app"
                filter_state: "present"
                filter_type: "rpm"
                rule_name: "bear"
          - name: BearAppServer
            components:
              - content_view: RHEL7
                latest: true
              - content_view: BearApp
                latest: true
```
