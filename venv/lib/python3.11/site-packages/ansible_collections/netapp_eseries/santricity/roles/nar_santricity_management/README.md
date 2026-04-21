nar_santricity_management
=========
    Manages NetApp E-Series storage system's name, passwords, management interfaces, alerts, syslog, auditlog, asup, ldap, certificates, drive firmware and controller firmware.

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
        - name: Ensure NetApp E-Series storage system is properly configured
          import_role:
            name: nar_santricity_management

Example Storage System Inventory File (Discover storage system with proxy)
-------------------------------------
    eseries_system_serial: "012345678901"   # Be sure to quote if the serial is all numbers and begins with zero.
    eseries_system_password: admin_password
    eseries_proxy_api_url: https://192.168.1.100:8443/devmgr/v2/
    eseries_proxy_api_password: admin_password
    eseries_subnet: 192.168.1.0/24
    eseries_prefer_embedded: false    # Overrides the default behavior of using Web Services Proxy when eseries_proxy_api_url is defined. This will only effect storage systems that have Embedded Web Services.
    eseries_validate_certs: false

    eseries_system_name: my_eseries_array
    eseries_system_cache_block_size: 128
    eseries_system_cache_flush_threshold: 90
    eseries_system_autoload_balance: enabled
    eseries_system_host_connectivity_reporting: enabled
    eseries_system_default_host_type: Linux DM-MP

    eseries_management_interfaces:
      config_method: static
      subnet_mask: 255.255.255.0
      gateway: 192.168.1.1
      dns_config_method: static
      dns_address: 192.168.1.253
      dns_address_backup:  192.168.1.254
      ssh: true
      ntp_config_method: static
      ntp_address: 192.168.1.200
      ntp_address_backup: 192.168.1.201
      controller_a:
        - address: 192.168.1.100
        - address: 192.168.1.101
      controller_b:
        - address: 192.168.1.102
        - address: 192.168.1.103

    eseries_ldap_state: present
    eseries_ldap_bind_username:
    eseries_ldap_bind_password:
    eseries_ldap_server:
    eseries_ldap_search_base:
    eseries_ldap_role_mappings:
      ".*":
        - storage.admin
        - storage.monitor
        - support.admin
        - security.admin

    eseries_client_certificate_certificates:
      - /path/to/client_certificate.crt
    eseries_server_certificate:
      controller_a:
        public_certificate: "/path/to/controller_a_server_certificate_bundle.pem"
      controller_b:
        public_certificate: "/path/to/controller_b_server_certificate_bundle.pem"

    eseries_firmware_firmware: "/path/to/firmware.dlp"
    eseries_firmware_nvsram: "/path/to/nvsram.dlp"
    eseries_drive_firmware_firmware_list:
      - "/path/to/drive_firmware.dlp"

    eseries_asup_state: enabled
    eseries_asup_active: true
    eseries_asup_days: [sunday, saturday]
    eseries_asup_start: 17
    eseries_asup_end: 24
    eseries_asup_validate: false
    eseries_asup_method: email
    eseries_asup_email:
      server: smtp.example.com
      sender: noreply@example.com

    eseries_syslog_state: present
    eseries_syslog_address: 192.168.1.150
    eseries_syslog_protocol: udp
    eseries_syslog_port: 514
    eseries_alert_syslog_servers:
        - "address": 192.168.1.150
          "port": 514

Example Storage System Inventory File (Without storage system discovery)
-------------------------------------
    eseries_system_api_url: https://192.168.1.200:8443/devmgr/v2/
    eseries_system_password: admin_password
    eseries_validate_certs: false

    (...)   # Same as the previous example

Role Variables
--------------
**Note that when values are specified below, they indicate the default value.**

    # Web Services Embedded information
    eseries_subnet:                    # Network subnet to search for the storage system specified in CIDR form. Example: 192.168.1.0/24
    eseries_system_serial:             # Storage system serial number. Be sure to quote if the serial is all numbers and begins with zero. (This is located on a label at the top-left towards the front on the device)
    eseries_system_addresses:          # Storage system management IP addresses. Only required when eseries_system_serial or eseries_system_api_url are not defined. When not specified, addresses will be populated with eseries_management_interfaces controller addresses.
    eseries_system_api_url:            # Url for the storage system's for embedded web services rest api. Example: https://192.168.10.100/devmgr/v2
    eseries_system_username: admin     # Username for the storage system's for embedded web services rest api
    eseries_system_password:           # Password for the storage system's for embedded web services rest api and when the admin password has not been set eseries_system_password will be used to set it.
    eseries_system_old_password:       # Previous admin password. This is used to change the current admin password by setting this variable to the current
                                       #   password and eseries_system_password to the new password.
    eseries_proxy_ssid:                # Arbitrary string for the proxy to represent the storage system. eseries_system_serial will be used when not defined.
    eseries_template_api_url:          # Template for the web services api url. Default: https://0.0.0.0:8443/devmgr/v2/
    eseries_prefer_embedded: false     # Overrides the default behavior of using Web Services Proxy when eseries_proxy_api_url is defined. This will only effect storage systems that have Embedded Web Services.
    eseries_validate_certs: true       # Indicates Whether SSL certificates should be verified. Used for both embedded and proxy. Choices: true, false

    # Web Services Proxy information
        Note: eseries_proxy_* variables are required to discover storage systems prior to SANtricity OS version 11.60.2.
    eseries_proxy_api_url:        # Url for the storage system's for proxy web services rest api. Example: https://192.168.10.100/devmgr/v2
    eseries_proxy_api_username:   # Username for the storage system's for proxy web services rest api.
    eseries_proxy_api_password:   # Password for the storage system's for proxy web services rest api and when the admin password has not been set 
                                  #   eseries_proxy_api_password will be used to set it.

    # Global storage system information
    eseries_system_name:                           # Name of the storage system.
    eseries_system_cache_block_size:               # Cache block size
    eseries_system_cache_flush_threshold:          # Unwritten data will be flushed when exceeds this threshold
    eseries_system_autoload_balance:               # Whether automatic load balancing should be enabled. Choices: enabled, disabled
    eseries_system_host_connectivity_reporting:    # Whether host connectivity reporting should be enabled. Choices: enabled, disabled
    eseries_system_login_banner_message:           # Message that appears prior to the login.
    eseries_system_controller_shelf_id:            # Controller shelf identifier.
    eseries_system_default_host_type:              # Only required when using something other than Linux kernel 3.10 or later with DM-MP (Linux DM-MP),
                                                   #     non-clustered Windows (Windows), or the storage system default host type is incorrect. Common definitions below:
                                                   #     - AIX MPIO: The Advanced Interactive Executive (AIX) OS and the native MPIO driver
                                                   #     - AVT 4M: Silicon Graphics, Inc. (SGI) proprietary multipath driver; refer to the SGI installation documentation for more information
                                                   #     - HP-UX: The HP-UX OS with native multipath driver
                                                   #     - Linux ATTO: The Linux OS and the ATTO Technology, Inc. driver (must use ATTO FC HBAs)
                                                   #     - Linux DM-MP: The Linux OS and the native DM-MP driver
                                                   #     - Linux Pathmanager: The Linux OS and the SGI proprietary multipath driver; refer to the SGI installation documentation for more information
                                                   #     - Mac: The Mac OS and the ATTO Technology, Inc. driver
                                                   #     - ONTAP: FlexArray
                                                   #     - Solaris 11 or later: The Solaris 11 or later OS and the native MPxIO driver
                                                   #     - Solaris 10 or earlier: The Solaris 10 or earlier OS and the native MPxIO driver
                                                   #     - SVC: IBM SAN Volume Controller
                                                   #     - VMware: ESXi OS
                                                   #     - Windows: Windows Server OS and Windows MPIO with a DSM driver
                                                   #     - Windows Clustered: Clustered Windows Server OS and Windows MPIO with a DSM driver
                                                   #     - Windows ATTO: Windows OS and the ATTO Technology, Inc. driver

    # Role-based username passwords 
    eseries_system_monitor_password:     # Storage system monitor username password
    eseries_system_security_password:    # Storage system security username password
    eseries_system_storage_password:     # Storage system storage username password
    eseries_system_support_password:     # Storage system support username password

    # SSL/TLS certificate configurations
    eseries_client_certificate_common_certificates:    # List of common client certificate file paths. These files will be appended to each client certificate list.
    eseries_client_certificate_certificates:           # List of client certificate file paths
    eseries_server_certificate_common_certificates:    # List of common server certificates. These files will be appended to each controller's server certificate list.
    eseries_server_certificate_common_passphrase:      # Common passphrase for decrypting PEM (PKCS8) private key.
    eseries_server_certificate:
      controller_a:
        certificates:                                  # List of server certificates for the storage systems controller A. Leave blank to use self-signed certificate.
        passphrase:                                    # Passphrase for decrypting PEM (PKCS8) private key.
      controller_b:
        certificates:                                  # List of server certificates for the storage systems controller B. Leave blank to use self-signed certificate.
        passphrase:                                    # Passphrase for decrypting PEM (PKCS8) private key.

    # Storage management interface defaults
        Note:  eseries_management_* variables have the lowest priority and will be overwritten by those found in eseries_management_interfaces; use these to defined host group defaults.
    eseries_management_config_method:         # Default config method for all management interfaces. Choices: static, dhcp
    eseries_management_subnet_mask:           # Default subnet mask for all management interfaces
    eseries_management_gateway:          # Default gateway for all management interfaces
    eseries_management_dns_config_method:     # Default DNS config method for all management interfaces
    eseries_management_dns_address:           # Default primary DNS address for all management interfaces
    eseries_management_dns_address_backup:    # Default backup DNS address for all management interfaces
    eseries_management_ntp_config_method:     # Default NTP config method for all management interfaces
    eseries_management_ntp_address:           # Default primary NTP address for all management interfaces
    eseries_management_ntp_address_backup:    # Default backup NTP address for all management interfaces
    eseries_management_ssh:                   # Default SSH access for all management interfaces. Choices: true, false
    eseries_management_interfaces:
      config_method:             # Config method for all management interfaces. Choices: static, dhcp
      subnet_mask:               # Subnet mask for all management interfaces
      gateway_mask:              # Gateway for all management interfaces
      dns_config_method:         # DNS config method for all management interfaces
      dns_address:               # Primary DNS address for all management interfaces
      dns_address_backup:        # Backup DNS address for all management interfaces
      ntp_config_method:         # NTP config method for all management interfaces
      ntp_address:               # Primary NTP address for all management interfaces
      ntp_address_backup:        # Backup NTP address for all management interfaces
      ssh:                       # SSH access for all management interfaces. Choices: true, false
      controller_a:              # List of controller A ports
        - address:               # IPv4 address for controller A
          config_method:         # Config method for controller A. Choices: static, dhcp
          subnet_mask:           # Subnet mask for controller A
          gateway:               # Gateway for controller A
          dns_config_method:     # DNS config method for controller A
          dns_address:           # Primary DNS address for controller A
          dns_address_backup:    # Backup DNS address for controller A
          ntp_config_method:     # NTP config method for controller A
          ntp_address:           # Primary NTP address for controller A
          ntp_address_backup:    # Backup NTP address for controller A
          ssh:                   # SSH access for controller A. Choices: true, false
      controller_b:              # List of controller B ports
        - (...)                  # Same as for controller A but for controller B.

    # Alerts configuration defaults
    eseries_alerts_state:               # Whether to enable storage system alerts. Choices: enabled, disabled
    eseries_alerts_contact:             # This allows owner to specify free-form contact information such as email or phone number.
    eseries_alerts_recipients:          # List containing e-mails that should be sent notifications when alerts are issued.
    eseries_alerts_sender:              # Sender email. This does not necessarily need to be a valid e-mail.
    eseries_alerts_server:              # Fully qualified domain name, IPv4 address, or IPv6 address of the mail server.
    eseries_alerts_test: false          # When changes are made to the storage system alert configuration a test e-mail will be sent. Choices: true, false
    eseries_alert_syslog_servers:       # List of dictionaries where each dictionary contains a syslog server entry. [{"address": <syslog_address>, "port": 514}]
    eseries_alert_syslog_test: false    # When changes are made to the alerts syslog servers configuration a test message will be sent to them. Choices: true, false

    # LDAP configuration defaults
    eseries_ldap_state:             # Whether LDAP should be configured
    eseries_ldap_identifier:        # The user attributes that should be considered for the group to role mapping
    eseries_ldap_user_attribute:    # Attribute used to the provided username during authentication.
    eseries_ldap_bind_username:     # User account that will be used for querying the LDAP server.
    eseries_ldap_bind_password:     # Password for the bind user account
    eseries_ldap_server:            # LDAP server URL.
    eseries_ldap_search_base:       # Search base used for find user's group membership
    eseries_ldap_role_mappings:     # Dictionary of user groups, each containing the list of access roles.
                                    #     Role choices: storage.admin - allows users full read/writes access to storage objects and operations.
                                    #                   storage.monitor - allows users read-only access to storage objects and operations.
                                    #                   storage.admin - allows users access to hardware, diagnostic information, major event logs,
                                    #                       and other critical support-related functionality, but not the sorage configuration.
                                    #                   security.admin - allows users access to authentication/authorization configuration, as
                                    #                       well as the audit log configuration, adn certification management.

    # Drive firmware defaults
    eseries_drive_firmware_firmware_list:                 # Local path list for drive firmware.
    eseries_drive_firmware_wait_for_completion:           # Forces drive firmware upgrades to wait for all associated tasks to complete. Choices: true, false
    eseries_drive_firmware_ignore_inaccessible_drives:    # Forces drive firmware upgrades to ignore any inaccessible drives. Choices: true, false
    eseries_drive_firmware_upgrade_drives_online:         # Forces drive firmware upgrades to be performed while I/Os are accepted. Choices: true, false

    # Controller firmware defaults
    eseries_firmware_nvsram:                 # Local path for NVSRAM file.
    eseries_firmware_firmware:               # Local path for controller firmware file.
    eseries_firmware_wait_for_completion:    # Forces controller firmware upgrade to wait until upgrade has completed before continuing. Choices: true, false
    eseries_firmware_clear_mel_events:       # Forces firmware upgrade to be attempted regardless of the health check results. Choices: true, false

    # Auto-Support configuration defaults
    eseries_asup_state:              # Whether auto support (ASUP) should be enabled. Choices: enabled, disabled
    eseries_asup_active:             # Enables active monitoring which allows NetApp support personnel to request support data to resolve issues. Choices: true, false
    eseries_asup_days:               # List of days of the week. Choices: monday, tuesday, wednesday, thursday, friday, saturday, sunday
    eseries_asup_start:              # Hour of the day(s) to start ASUP bundle transmissions. Start time must be less than end time. Choices: 0-23
    eseries_asup_end:                # Hour of the day(s) to end ASUP bundle transmissions. Start time must be less than end time. Choices: 1-24
    eseries_asup_method:             # ASUP delivery method. Choices https, http, email (default: https)
    eseries_asup_routing_type:       # ASUP delivery routing type for https or http. Choices: direct, proxy, script (default: direct)
    eseries_asup_proxy:              # ASUP proxy delivery method information.
      host:                          # ASUP proxy host IP address or FQDN. When eseries_asup_routing_type==proxy this must be specified.
      port:                          # ASUP proxy host port. When eseries_asup_routing_type==proxy this must be specified.
      username:                      # ASUP proxy username.
      password:                      # ASUP proxy password.
      script:                        # ASUP proxy host script.
    eseries_asup_email:              # ASUP email delivery configuration information
      server:                        # ASUP email server
      sender:                        # ASUP email sender
      test_recipient:                # ASUP configuration mail test recipient
    eseries_maintenance_duration:    # Duration in hours (1-72) the ASUP maintenance mode will be active
    eseries_maintenance_emails:      # List of email addresses for maintenance notifications
    eseries_asup_validate:           # Verify ASUP configuration prior to applying changes

    # Audit-log configuration defaults
    eseries_auditlog_enforce_policy:    # Whether to make audit-log policy changes. Choices: true, false
    eseries_auditlog_force:             # Forces audit-log to delete log messages when fullness threshold has been exceeded. Applicable when eseries_auditlog_full_policy=preventSystemAccess. Choices: true, false
    eseries_auditlog_full_policy:       # Policy for what to do when record limit has been reached. Choices: overWrite, preventSystemAccess
    eseries_auditlog_log_level:         # Filters logs based on the specified level. Choices: all, writeOnly
    eseries_auditlog_max_records:       # Maximum number of audit-log messages retained. Choices: 100-50000.
    eseries_auditlog_threshold:         # Memory full percentage threshold that audit-log will start issuing warning messages. Choices: 60-90

    # Syslog configuration defaults
    eseries_syslog_state:         # Whether syslog servers should be added or removed from storage system. Choices: present, absent
    eseries_syslog_address:       # Syslog server IPv4 address or fully qualified hostname.
    eseries_syslog_test:          # Whether a test messages should be sent to syslog server when added to the storage system. Choices: true, false
    eseries_syslog_protocol:      # Protocol to be used when transmitting log messages to syslog server. Choices: udp, tc, tls
    eseries_syslog_port:          # Port to be used when transmitting log messages to syslog server.
    eseries_syslog_components:    # List of components log to syslog server. Choices: auditLog, (others may become available)

License
-------
    BSD-3-Clause

Author Information
------------------
    Nathan Swartz (@ndswartz)
