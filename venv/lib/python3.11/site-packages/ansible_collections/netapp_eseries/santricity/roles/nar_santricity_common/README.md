nar_santricity_common
=====================
    Discover NetApp E-Series storage systems and configures SANtricity Web Services Proxy.

    The following variables will be added to the runtime host inventory.
        current_eseries_api_url:            # Web Services REST API URL
        current_eseries_api_username:       # Web Services REST API username
        current_eseries_api_password:       # Web Services REST API password
        current_eseries_ssid:               # Arbitrary string for the proxy to represent the storage system.
        current_eseries_validate_certs:     # Indicates whether SSL certificates should be verified.
        current_eseries_api_is_proxy:       # Indicates whether Web Services REST API is running on a proxy.


Requirements
------------
    - NetApp E-Series E2800 platform or newer or NetApp E-Series SANtricity Web Services Proxy configured for older E-Series storage systems.

Tested Ansible Versions
-----------------------
    - Ansible 5.x (ansible-core 2.12)

Example Playbook
----------------
    - hosts: eseries_storage_systems
      gather_facts: false
      collection:
        - netapp_eseries.santricity
      tasks:
        - name: Configure SANtricity Web Services and discover storage systems 
          import_role:
            name: nar_santricity_common


Example Inventory Host file using discovery with proxy
------------------------------------------------------
    eseries_proxy_api_url: https://192.168.1.100:8443/devmgr/v2/
    eseries_proxy_api_password: admin_password
    eseries_subnet: 192.168.1.0/24   # This should only be defined at the group level once when utilizing Web Services Proxy and should be broad enough to include all systems being added to proxy instance.
    eseries_system_serial: 012345678901
    eseries_system_password: admin_password
    eseries_validate_certs: false
    (...)


Example Inventory Host file using discovery without proxy
---------------------------------------------------------
**Note that while eseries_management_interfaces or eseries_system_api_url are optional, including at least one of them will prevent the discovery mechanism from being used when the system can be reached from their information.
    eseries_subnet: 192.168.1.0/24
    eseries_system_serial: 012345678901
    eseries_system_password: admin_password
    eseries_validate_certs: false
    (...)


Example Inventory Host file without using discovery (Embedded Web Services)
---------------------------------------------------------------------------
    eseries_system_api_url: https://192.168.1.200:8443/devmgr/v2/
    eseries_system_password: admin_password
    eseries_validate_certs: false
    (...)


Example Inventory Host file without using discovery (Proxy Web Services - system must have already been added to the proxy)
------------------------------------------------------------------------
    eseries_proxy_ssid: storage_ssid
    eseries_proxy_api_url: https://192.168.2.200:8443/devmgr/v2/
    eseries_proxy_api_password: admin_password
    (...)


Notes
-----
Use SANtricity Web Services Proxy to avoid the need to discover the storage systems each time nar_santricity_common is executed. The first time nar_santricity_common is executed will add the storage systems the proxy so that they can be recalled without the need to search the subnet each subsequent execution.
The na_santricity_proxy_systems module is used to add storage systems to the proxy but required a complete list of desired systems since it will ensure that only the systems provided will remain on the proxy. As a result any system that is not included will be removed from the proxy.

Role Variables
--------------
    eseries_subnet:                   # Network subnet to search for the storage system specified in CIDR form. Example: 192.168.1.0/24
                                      #   Note: eseries_subnet should only be defined once at the group level when utilizing the Web Services Proxy.
    eseries_template_api_url:         # Template for the web services api url. Default: https://0.0.0.0:8443/devmgr/v2/
    eseries_prefer_embedded: false    # Overrides the default behavior of using Web Services Proxy when eseries_proxy_api_url is defined. This will only effect storage systems that have Embedded Web Services.
    eseries_validate_certs: true      # Indicates Whether SSL certificates should be verified. Used for both embedded and proxy. Choices: true, false

    # Storage system specific variables
    eseries_proxy_ssid:               # Arbitrary string for the proxy to represent the storage system. eseries_system_serial will be used when not defined.
    eseries_system_serial:            # Storage system serial number. (This is located on a label at the top-left towards the front on the device)
    eseries_system_addresses:         # Storage system management IP addresses. Only required when eseries_system_serial or eseries_system_api_url are not defined. When not specified, addresses will be populated with eseries_management_interfaces controller addresses.
    eseries_system_api_url:           # Url for the storage system's for embedded web services rest api. Example: https://192.168.10.100/devmgr/v2
    eseries_system_username: admin    # Username for the storage system's for embedded web services rest api
    eseries_system_password:          # Password for the storage system's for embedded web services rest api and when the admin password has not been set eseries_system_password will be used to set it.
    eseries_system_tags:              # Meta tags to associate with storage system when added to the proxy.

    # Storage system management interface information
        Note: eseries_management_interfaces will be used when eseries_system_serial, eseries_system_api_url, or eseries_system_addresses are not defined.
    eseries_management_interfaces:    # Subset of the eseries_management_interface variable found in the nar_santricity_management role
      controller_a:
        - address:    # Controller A port 1's IP address
        - address:    # Controller A port 2's IP address
      controller_b:
        - address:    # Controller B port 1's IP address
        - address:    # Controller B port 2's IP address

    # Web Services Proxy specific variable
        Note: eseries_proxy_* variables are required to discover storage systems prior to SANtricity OS version 11.60.2.
    eseries_proxy_api_url:                                  # Url for the storage system's for proxy web services rest api. Example: https://192.168.10.100/devmgr/v2
    eseries_proxy_api_username:                             # Username for the storage system's for proxy web services rest api (Default: admin).
    eseries_proxy_api_password:                             # Password for the storage system's for proxy web services rest api and when the admin password has
                                                            #   not been set eseries_proxy_api_password will be used to set it.
    eseries_proxy_api_old_password:                         # Previous proxy admin password. This is used to change the current admin password by setting this
                                                            #   variable to the current proxy password and eseries_proxy_api_password to the new password.
    eseries_proxy_monitor_password:                         # Proxy password for the monitor username
    eseries_proxy_security_password:                        # Proxy password for the security username
    eseries_proxy_storage_password:                         # Proxy password for the monitor username
    eseries_proxy_support_password:                         # Proxy password for the support username
    eseries_proxy_accept_certifications:                    # Force automatic acceptance of all storage system's certificate
    eseries_proxy_default_system_tags:                      # Default meta tags to associate with all storage systems
    eseries_proxy_default_password:                         # Default password to associate with all storage systems. This is overridden by eseries_system_password.
    eseries_proxy_client_certificate_common_certificates:   # List of common proxy client certificate file paths. These files will be appended to each client certificate list.
    eseries_proxy_client_certificate_certificates:          # List of proxy client certificate file paths
    eseries_proxy_server_certificate_common_certificates:   # List of common proxy server certificates. These files will be appended to each controller's server certificate list.
    eseries_proxy_server_certificate_common_passphrase:     # Common passphrase for decrypting PEM (PKCS8) private key.
    eseries_proxy_server_certificate_certificates:          # List of proxy server certificates. Leave blank to use self-signed certificate.
    eseries_proxy_server_certificate_passphrase:            # Passphrase for decrypting PEM (PKCS8) private key.

    # LDAP configuration defaults
    eseries_proxy_ldap_state:             # Whether LDAP should be configured for the proxy`
    eseries_proxy_ldap_identifier:        # The user attributes that should be considered for the group to role mapping
    eseries_proxy_ldap_user_attribute:    # Attribute used to the provided username during authentication.
    eseries_proxy_ldap_bind_username:     # User account that will be used for querying the LDAP server.
    eseries_proxy_ldap_bind_password:     # Password for the bind user account
    eseries_proxy_ldap_server:            # LDAP server URL.
    eseries_proxy_ldap_search_base:       # Search base used for find user's group membership
    eseries_proxy_ldap_role_mappings:     # Dictionary of user groups, each containing the list of access roles.
                                          #     Role choices: storage.admin - allows users full read/writes access to storage objects and operations.
                                          #                   storage.monitor - allows users read-only access to storage objects and operations.
                                          #                   storage.admin - allows users access to hardware, diagnostic information, major event logs,
                                          #                       and other critical support-related functionality, but not the sorage configuration.
                                          #                   security.admin - allows users access to authentication/authorization configuration, as
                                          #                       well as the audit log configuration, adn certification management.


License
-------
    BSD-3-Clause


Author Information
------------------
    Nathan Swartz (@ndswartz)
