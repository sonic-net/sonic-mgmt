theforeman.foreman.content_views
================================

This role creates and manages Content Views.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_content_views`. Each Content View requires the following fields:

- `name` - the name of the content view

The following fields are required for a content view but have defaults which make them optional for this role:

- `organization`: Organization to create the content view for. Defaults to `foreman_organization` variable.

Each content view also requires either a list of repositories or components (for a composite content view):
- `repositories` - List of repositories to add to the content view. Each repository requires the following fields:
  - `name` - The name of the repository
  - `product` - The product which the repository belongs to
- `components` - List of content views to add to the composite content view. Each component requires the following fields:
  - `content_view` - The name of the content view
  - `content_view_version` - The version of the content view to add, *or*
  - `latest` - If `true`, the latest version of the content view will be used

Additionally you can pass any other parameters accepted by the `content_view` module.

This role also allows you to create Content View Filters and add them to the Content View by passing a list of `filters`:

- `filters` - List of filters to create and add to the content view. Each filter needs the following fields:
  - `name` - Name of the content view filter
  - `filter_type` - Content view filter type. The available types are `rpm`, `package_group`, `erratum`, or `docker`

Additionally you can pass any other parameters accepted by the `content_view_filter` module.

Example Playbooks
-----------------

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.content_views
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
            organization: ACME
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
