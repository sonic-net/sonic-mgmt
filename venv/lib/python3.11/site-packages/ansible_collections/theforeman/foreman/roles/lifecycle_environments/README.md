theforeman.foreman.lifecycle_environments
=========================================

This role creates and manages Lifecycle Environments.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_lifecycle_environments`. Each `lifecycle_environment` requires the following fields:

- `name`: The name of the lifecycle environment.
- `prior`: The name of the previous lifecycle environment to attach to in
  sequence. For the first lifecycle environment in a new path, set the prior
  lifecycle environment to Library. The order of definition matters, ensure that
  the environments are listed in the order the path would exist. It can't be
  changed after the lifecycle environment has been created.

The following fields are required for a lifecycle environment but have defaults which make them optional for this role:

- `organization`: Organization to create the lifecycle environment for. Defaults to `foreman_organization` variable.

The following fields are optional and will be omitted by default:

- `description`: Description of the lifecycle environment
- `label`: A permanent label for identifying the lifecycle environment to tools
  such as subscription-manager. This is created by the server if omitted. It
  can't be changed after the lifecycle environment has been created.

Example Playbooks
-----------------

Create a lifecycle environment path with three environments: Library -> Dev -> Test -> Prod

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.lifecycle_environments
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_lifecycle_environments:
          - name: "Dev"
            prior: "Library"
          - name: "Test"
            prior: "Dev"
          - name: "Prod"
            prior: "Test"
```

Create two lifecycle environment paths: Library -> Dev -> Test -> Prod and Library -> QA -> Stage -> Prod

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.lifecycle_environments
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_lifecycle_environments:
          - name: "Dev"
            prior: "Library"
          - name: "Test"
            prior: "Dev"
          - name: "Prod"
            prior: "Test"

          - name: "QA"
            prior: "Library"
            organization: ACME
          - name: "Stage"
            prior: "QA"
            organization: ACME
          - name: "Prod"
            prior: "Stage"
            organization: ACME
```
