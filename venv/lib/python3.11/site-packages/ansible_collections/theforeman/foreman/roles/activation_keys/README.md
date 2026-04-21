theforeman.foreman.activation_keys
==================================

This role creates and manages Activation Keys.

Role Variables
--------------

This role supports the [Common Role Variables](https://github.com/theforeman/foreman-ansible-modules/blob/develop/README.md#common-role-variables).

The main data structure for this role is the list of `foreman_activation_keys`. Each `activation_key` requires the following fields:

- `name`: The name of the activation key.

The following fields are required for an activation key but have defaults which make them optional for this role:

- `organization`: Organization to create the activation key for. Defaults to `foreman_organization` variable.
- `lifecycle_environment`: Lifecycle Environment to assign to hosts registered with this activation key. Defaults to "Library".
- `content_view`: Content View to assign to hosts registered with this activation key. Defaults to "Default Organization View".

The following fields are optional in the sense that the server will use default values when they are omitted:

- `auto_attach`: Auto Attach behavior for the activation key. When true, it will attempt to attach a minimum of subscriptions (from the subset of assigned subscriptions on the activation key; selects from all subscriptions in the organization if none are assigned) to cover any present products on the host. When false, it will attempt to attach all subscriptions assigned on the activation key to the host at registration time. server defaults to true.
- `unlimited_hosts`: Allow an unlimited number of hosts to register with the activation key when true. When false, the `max_hosts` parameter which sets a numerical limit on the number of hosts that can be registered becomes required. server defaults to true.

The following fields are optional and will be omitted by default:

- `description`: Description of the activation key. Helpful for other users to find which activation key to use.
- `host_collections`: List of Host Collections to associate with the activation key.
- `subscriptions`: List of Subscriptions to associate with the activation key. Each Subscription is required to have one of `name`, `pool_id`, or `upstream_pool_id`. Of these, only the `pool_id` is guaranteed to be unique. `upstream_pool_id` only exists for subscriptions imported from a 3rd party organization (e.g. on a Red Hat Subscription Manifest). When uniqueness is not an issue, `name` or `upstream_pool_id` can be easier to work with since the `pool_id` does not get determined until the subscription is imported or created and therefore may not yet be determined when you are writing playbooks.
- `content_overrides`: List of Content Overrides for the activation key. Each Content Override is required to have a `label` which refers to a repository and `override` which refers to one of the states enabled, disabled, or default.
For Red Hat products the `label` is the repository label, e.g. `rhel-7-server-rpms`.
For custom products it's in the format `<organization_label>_<product_label>_<repository_label>`, e.g. `ExampleOrg_ExampleCustomProduct_ExampleRepository`.
- `release_version`: Release Version to set when registering hosts with the activation key.
- `service_level`: Service Level to set when registering hosts with the activation key. Premium, Standard, or Self-Support. This will limit Subscriptions available to hosts to those matching this service level.
- `purpose_usage`: System Purpose Usage to set when registering hosts with the activation key. Production, Development/Test, Disaster Recovery. When left unset this will not set System Purpose Usage on registering hosts. This should only be used when it is supported by the OS of registering hosts (RHEL 8 only at the time of writing).
- `purpose_role`: System Purpose Role to set when registering hosts with the activation key. Red Hat Enterprise Linux Server, Red Hat Enterprise Linux Workstation, Red Hat Enterprise Linux Compute Node. When left unset this will not set System Purpose Role on registering hosts. This should only be used when it is supported by the OS of registering hosts (RHEL 8 only at the time of writing).
- `purpose_addons`: List of System Purpose Addons (ELS, EUS) to set on registering hosts. This should only be used when it is supported by the OS of registering hosts (RHEL 8 only at the time of writing).

A helpful behavior to keep in mind when creating activation keys is that a host can register with multiple activation keys; each activation key will attach subscriptions according to its own logic, in the order that the activation keys are listed. Host attributes like Lifecycle Environment, Content View, etc will be overwritten by later activation keys so that the last activation key listed wins. A common pattern is to first use an activation key which has auto-attach disabled and a list of subscriptions to attach for any applicable custom products, followed by a second activation key which has auto attach enabled to attach the best fitting subscription(s) for the OS and any remaining products which were not already covered, and also defines the LCE, Content View, and other host attributes as required.

Example Playbooks
-----------------

Create a basic Activation Key that uses Library LCE, Default Organization View, and performs auto-attach from the set of all available Subscriptions (i.e. auto-attach=true and no Subscriptions are assigned to the Activation Key).

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.activation_keys
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "Default Organization"
        foreman_activation_keys:
          - name: "Basic Activation Key"
            description: "Registers hosts in Library/Default Organization View and tries to attach the best fitting subscription(s) from all available in the default organization"
```

Define two Activation Keys. The first registers hosts in the "ACME" organization and attaches the Subscription for the custom product "ACME_App". The second assigns the "Test" LCE and "RHEL7_Base" Content View, and auto-attaches the best fitting subscription(s) from all which are available in the ACME Organization. Additionally the organization of the second Activation Key is explicitly specified as "Base_Test".

```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.activation_keys
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "ACME"
        foreman_activation_keys:
          - name: "ACME_App_Key"
            auto_attach: false
            subscriptions:
              - name: "ACME_App"
          - name: "ACME_RHEL7_Base_Test"
            lifecycle_environment: "Test"
            content_view: "RHEL7_Base"
            organization: "Base_Test"
            content_overrides:
              - label: rhel-7-server-rpms
                override: enabled
              - label: ExampleOrganization_ExampleCustomProduct_ExampleRepository
                override: enabled
```

Following the second example, a Host which is registered using `subscription-manager register --activationkey ACME_App_Key,ACME_RHEL7_Base_Test` will get the ACME_App subscription, Test LCE, RHEL7_Base Content View, and auto-attach any additional necessary subscriptions from ACME Organization to cover the Base OS and any other products which require an entitlement certificate.

To delete multiple activation_keys
```yaml
- hosts: localhost
  roles:
    - role: theforeman.foreman.activation_keys
      vars:
        foreman_server_url: https://foreman.example.com
        foreman_username: "admin"
        foreman_password: "changeme"
        foreman_organization: "ACME"
        foreman_activation_keys:
          - name: "ACME_App_Key"
            state: absent
          - name: "ACME_OS_Key"
            state: absent
