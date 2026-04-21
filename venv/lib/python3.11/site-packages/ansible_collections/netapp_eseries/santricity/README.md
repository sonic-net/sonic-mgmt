NetApp E-Series SANtricity Collection
=========
    The SANtricity collection consist of the latest available versions of the NetApp E-Series SANtricity modules and roles.

        This collection provides NetApp E-Series customers with a wide range of configuration options through the collection's modules. However, the real
    benefit of using the SANtricity collection is found in the host and management roles. These roles provide ready-made, policy-based orchestration for
    E-Series platforms based on predefined role variables.

        Once the physical hardware has been installed, the SANtricity roles are capable of discovering the DHCP-assigned addresses, setting initial passwords
    and management interfaces so your automation can do full deployments for you without logging directly into the devices. Yet that's just the beginning,
    the management role will also ensure alerts, ASUP, logging, LDAP, and firmware are configured as expected; and the host role will setup host interfaces,
    provision and map storage, and if your servers are defined in the inventory, correctly populate E-Series hosts and host groups automatically.


    Roles:
        - nar_santricity_common: Discover NetApp E-Series storage systems and configures SANtricity Web Services Proxy.
        - nar_santricity_host: Configure storage pools, volumes, hosts, host groups, port interfaces and snapshots.
        - nar_santricity_management: Manage storage system's name, management interfaces, alerts, syslog, auditlog, asup, ldap, certificates, drive firmware and controller firmware.

    Modules:
        - na_santricity_alerts: Manage email alert notification settings
        - na_santricity_alerts_syslog: Manage syslog servers receiving storage system alerts
        - na_santricity_asup: Manage auto-support settings
        - na_santricity_auditlog: Manage audit-log configuration
        - na_santricity_auth: Set or update the password for a storage array
        - na_santricity_client_certificate: Manage remote server certificates
        - na_santricity_server_certificate: Manage storage system certificates
        - na_santricity_discover: Discover E-Series storage systems on a subnet
        - na_santricity_drive_firmware: Manage drive firmware
        - na_santricity_facts: Retrieve facts about NetApp E-Series storage arrays
        - na_santricity_firmware: Manage firmware
        - na_santricity_global: Manage global settings configuration
        - na_santricity_host: Manage eseries hosts
        - na_santricity_hostgroup: Manage array host groups
        - na_santricity_ib_iser_interface: Manage InfiniBand iSER interfaces.
        - na_santricity_iscsi_interface: Manage iSCSI interface configuration
        - na_santricity_iscsi_target: Manage iSCSI target configuration
        - na_santricity_ldap: Manage LDAP integration to use for authentication
        - na_santricity_lun_mapping: Manage lun mappings
        - na_santricity_mgmt_interface: Manage management interface configuration
        - na_santricity_nvme_interface: Manage NVMe interfaces
        - na_santricity_proxy_drive_firmware_upload: Manage proxy drive firmware cache.
        - na_santricity_proxy_firmware_upload: Manage proxy storage system firmware cache.
        - na_santricity_proxy_systems: Manage proxy storage systems.
        - na_santricity_snapshot: Manage Snapshot groups, volumes, and rollbacks.
        - na_santricity_storage_system: Manage SANtricity web services proxy storage arrays
        - na_santricity_storagepool: Manage volume groups and disk pools
        - na_santricity_syslog: Manage syslog settings
        - na_santricity_volume: Manage storage volumes

    *** Note that the following deprecated modules will be removed in a future release.
    Deprecated Modules:
        - netapp_e_alerts: Manage email notification settings
        - netapp_e_amg: Create, remove, and update asynchronous mirror groups
        - netapp_e_amg_role: Update the role of a storage array within an Asynchronous Mirror Group (AMG)
        - netapp_e_amg_sync: Conduct synchronization actions on asynchronous mirror groups
        - netapp_e_asup: Manage auto-support settings
        - netapp_e_auditlog: Manage audit-log configuration
        - netapp_e_auth: Set or update the password for a storage array
        - netapp_e_drive_firmware: Manage drive firmware
        - netapp_e_facts: Retrieve facts about NetApp E-Series storage arrays
        - netapp_e_firmware: Manage firmware
        - netapp_e_flashcache: Manage SSD caches
        - netapp_e_global: Manage global settings configuration
        - netapp_e_hostgroup: Manage eseries hosts
        - netapp_e_host: Manage array host groups
        - netapp_e_iscsi_interface: Manage iSCSI interface configuration
        - netapp_e_iscsi_target: Manage iSCSI target configuration
        - netapp_e_ldap: Manage LDAP integration to use for authentication
        - netapp_e_lun_mapping: Create, delete, or modify lun mappings
        - netapp_e_mgmt_interface: Manage management interface configuration
        - netapp_e_snapshot_group: Manage snapshot groups
        - netapp_e_snapshot_images: Create and delete snapshot images
        - netapp_e_snapshot_volume: Manage snapshot volumes
        - netapp_e_storagepool: Manage volume groups and disk pools
        - netapp_e_storage_system: Manage Web Services Proxy manage storage arrays
        - netapp_e_syslog: Manage syslog settings
        - netapp_e_volume_copy: Create volume copy pairs
        - netapp_e_volume: Manage storage volumes (standard and thin)

Requirements
------------
    - NetApp E-Series E2800 platform or newer or NetApp E-Series SANtricity Web Services Proxy configured for older E-Series Storage arrays.
    - Python cryptography >= 2.5 package is required for na_santricity_server_certificate and nar_santricity_management role.
    - Python ipaddress and netaddr packages are required for na_santricity_discover, na_santricity_ and nar_santricity_common role.

Tested Ansible Versions
-----------------------
    - Ansible 5.x (ansible-core 2.12)

Example Playbook
----------------
    - hosts: eseries_storage_systems
      gather_facts: false
      collections:
        - netapp_eseries.santricity
      tasks:
        - name: Ensure all management related policies are enforced.
          import_role:
            name: nar_santricity_management
        - name: Ensure all host related policies are enforced.
          import_role:
            name: nar_santricity_host

Example Storage System Inventory File (Simple example without storage system discovery)
-------------------------------------
    eseries_system_api_url: https://192.168.1.200:8443/devmgr/v2/
    eseries_system_password: admin_password
    eseries_validate_certs: false

    eseries_system_name: my_eseries_array

    eseries_management_interfaces:
      config_method: static
      subnet_mask: 255.255.255.0
      gateway: 192.168.1.1
      dns_config_method: static
      dns_address: 192.168.1.253
      ntp_config_method: static
      ntp_address: 192.168.1.200
      controller_a:
        - address: 192.168.1.100
        - address: 192.168.1.101
      controller_b:
        - address: 192.168.1.102
        - address: 192.168.1.103

    eseries_initiator_protocol: fc

    # Storage pool and volume configuration
    eseries_storage_pool_configuration:
      - name: vg_01
        raid_level: raid6
        criteria_drive_count: 10
        volumes:
          - name: metadata
            host: servers
            size: 4096
      - name: vg_02
        raid_level: raid5
        criteria_drive_count: 10
        volumes:
          - name: storage_[1-3]
            host: servers
            size: 2
            size_unit: tb
            volume_metadata:  # Used by netapp_eseries.host.mount role to format and mount volumes
              format_type: xfs
              mount_opt: "noatime,nodiratime,logbufs=8,logbsize=256k,largeio,inode64,swalloc,allocsize=131072k,nobarrier,_netdev"
              mount_dir: "/data/beegfs/"

Example Storage System Inventory File (Discover storage system)
-------------------------------------
**Note that this discovery method works for SANtricity versions 11.62 or later, otherwise it will only discover the systems with unset passwords.**

    eseries_system_serial: 012345678901
    eseries_system_password: admin_password
    eseries_subnet: 192.168.1.0/24

    eseries_management_interfaces:          # (Optional) Specifying static management interfaces can be used not only to discover the storage system but also to contact when valid.
      config_method: static
      controller_a:
        - address: 192.168.1.100
      controller_b:
        - address: 192.168.1.101

    (...)   # Same as the previous examples starting with the eseries_validate_certs line

Example Storage System Inventory File (Discover storage system with proxy)
-------------------------------------
    eseries_system_serial: 012345678901
    eseries_system_password: admin_password

    eseries_proxy_api_url: https://192.168.1.100:8443/devmgr/v2/
    eseries_proxy_api_password: admin_password
    eseries_subnet: 192.168.1.0/24
    eseries_prefer_embedded: false    # Overrides the default behavior of using Web Services Proxy when eseries_proxy_api_url is defined. This will only effect
                                      #     storage systems that have Embedded Web Services.

    (...)   # Same as the previous examples starting with the eseries_validate_certs line

Example Storage System Inventory File
-------------------------------------
    eseries_system_api_url: https://192.168.1.200:8443/devmgr/v2/
    eseries_system_password: admin_password
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
      - /path/to/client_certificate.pem
    eseries_server_certificate:
      controller_a:
        certificate:
          - "/path/to/controller_a_server_certificate_bundle.pem"
      controller_b:
        passphrase: keypass
        certificate:
          - "/path/to/controller_b_server_certificate_bundle.pem"

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
    eseries_initiator_protocol: iscsi

    # Controller port definitions
    eseries_controller_iscsi_port_config_method: static
    eseries_controller_iscsi_port_subnet_mask: 255.255.255.0
    eseries_controller_iscsi_port:
      controller_a:
        - address: 192.168.2.100
        - address: 192.168.2.110
      controller_b:
        - address: 192.168.3.100
        - address: 192.168.3.110

    # Storage pool and volume configuration
    eseries_storage_pool_configuration:
      - name: pool[1-2]
        raid_level: raid6
        criteria_drive_count: 10
        volumes:
          - name: "[pool]_volume[A-C]"
            host: server_group
            size: 10
            size_unit: tb

Storage System Credentials
--------------------------
    Proxy:
        - The proxy's credentials should be defined at the group inventory level (eseries_proxy_api_url, eseries_proxy_api_password, eseries_subnet) and each storage system host inventory file should include its password (eseries_system_password) and the system's serial number (eseries_system_serial).
        - You can substitute a unique proxy storage system identifier (eseries_proxy_ssid) for the system's serial number if the system has already been added to the proxy. However, using the storage system serial number is the preferred method since it will never change and is always known to the system. If you would like to be able to reference the system from the proxy using a unique identifier of your choice then add it in addition to the system's serial number.
        - If your storage system has never been added to the Web Service Proxy, utilizing your system's serial number (eseries_system_serial) ensures that the SANtricity collection can discover it and set its initial admin password if not previously done.

    Direct:
        - Provide the storage system's serial number, password and the network subnet (eseries_system_serial, eseries_system_password, and eseries_subnet) to ensure that it will be discoverable; this information will also ensure the admin password has been set. The discovery process can be lengthy depending on the size and speed of the subnet. This can be mitigated by configuring static management interfaces (eseries_management_interfaces) otherwise each playbook execution will search for the DHCP assigned address.
        - If the storage system's Web Service Embedded API url (eseries_system_api_url) is known then it can be used in place of the system's serial number.

Snapshots
---------
    - Automate snapshot consistency groups with one or more base volumes. Consistency groups allow snapshot images to be taken consistently across multiple base volumes at a single point in time. Then use these images to either create snapshot volumes or rollback the base volumes to previous states. Snapshot volumes allow you to interact with the volumes as they were in either a read-only or read-write mode.
    - Since E-Series storage systems are block storage and are unaware of both file system and application, it important to prepare volumes for snapshots. This requires applications to complete anything necessary to place the data in a valid state and file systems to complete and sync data to storage. To help facilitate these actions, checkout the snapshot role in the netapp_eseries.host collection (https://galaxy.ansible.com/netapp_eseries/host). This snapshot role ensures mounted E-Series volumes across multiple hosts have files closed, synced cache, and are temporarily unmounted prior to taking snapshots. Want to take a point-in-time snapshot of a parallel file system? The snapshot role also ensures that volumes are also ready across multiple storage systems.

General Notes
-------------
    - The EF600/300 platforms currently do not distribute drives across their PCI bridges which can result in lower than expected performance when drives become saturated so be sure to use either eseries_storage_pool_usable_drives to specify the order the drives should be selected or the eseries_storage_pool_configuration usable_drives argument to specify which drives should be used. See details in the `Collection Variables` section. The example below will ensure the drive candidate selections for EF600/300 storage pools or volume groups are selected by alternating between the first and last twelve drives. You can also specify the tray drawers in the form <tray>:<drawer>:<slot>.
        `eseries_storage_pool_usable_drives: "99:0,99:23,99:1,99:22,99:2,99:21,99:3,99:20,99:4,99:19,99:5,99:18,99:6,99:17,99:7,99:16,99:8,99:15,99:9,99:14,99:10,99:13,99:11,99:12"`

Collection Variables
--------------------
**Note that when values are specified below, they indicate the default value.**

    eseries_subnet:                   # Network subnet to search for the storage system specified in CIDR form. Example: 192.168.1.0/24
    eseries_template_api_url:         # Template for the web services api url. Default: https://0.0.0.0:8443/devmgr/v2/
    eseries_prefer_embedded: false    # Overrides the default behavior of using Web Services Proxy when eseries_proxy_api_url is defined. This will only effect
                                      #     storage systems that have Embedded Web Services.
    eseries_validate_certs: true      # Indicates Whether SSL certificates should be verified. Used for both embedded and proxy. Choices: true, false

    # Storage system specific variables
    eseries_proxy_ssid:               # Arbitrary string for the proxy to represent the storage system. eseries_system_serial will be used when not defined.
    eseries_system_serial:            # Storage system serial number. (This is located on a label at the top-left towards the front on the device)
    eseries_system_addresses:         # Storage system management IP addresses. Only required when eseries_system_serial or eseries_system_api_url are not
                                      #     defined. When not specified, addresses will be populated with eseries_management_interfaces controller addresses.
    eseries_system_api_url:           # Url for the storage system's for embedded web services rest api. Example: https://192.168.10.100/devmgr/v2
    eseries_system_username: admin    # Username for the storage system's for embedded web services rest api
    eseries_system_password:          # Password for the storage system's for embedded web services rest api and when the admin password has not been set
                                      #     eseries_system_password will be used to set it.
    eseries_system_old_password:      # Previous admin password. This is used to change the current admin password by setting this variable to the current
                                      #   password and eseries_system_password to the new password.
    eseries_system_tags:              # Meta tags to associate with storage system when added to the proxy.

    # Web Services Proxy specific variable
        Note: eseries_proxy_* variables are required to discover storage systems prior to SANtricity OS version 11.60.2.
    eseries_proxy_api_url:                                  # Url for the storage system's for proxy web services rest api. Example: https://192.168.10.100/devmgr/v2
    eseries_proxy_api_username: admin                       # Username for the storage system's for proxy web services rest api.
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

    # Global storage system information
    eseries_system_name:                           # Name of the storage system.
    eseries_system_cache_block_size:               # Cache block size
    eseries_system_cache_flush_threshold:          # Unwritten data will be flushed when exceeds this threshold
    eseries_system_autoload_balance:               # Whether automatic load balancing should be enabled. Choices: enabled, disabled
    eseries_system_host_connectivity_reporting:    # Whether host connectivity reporting should be enabled. Choices: enabled, disabled
    eseries_system_login_banner_message:           # Message that appears prior to the login.
    eseries_system_default_host_type:              # Only required when using something other than Linux kernel 3.10 or later with DM-MP (Linux DM-MP),
                                                   #    non-clustered Windows (Windows), or the storage system default host type is incorrect.
                                                   # Common host type definitions:
                                                   #     - AIX MPIO: The Advanced Interactive Executive (AIX) OS and the native MPIO driver
                                                   #     - AVT 4M: Silicon Graphics, Inc. (SGI) proprietary multipath driver
                                                   #     - HP-UX: The HP-UX OS with native multipath driver
                                                   #     - Linux ATTO: The Linux OS and the ATTO Technology, Inc. driver (must use ATTO FC HBAs)
                                                   #     - Linux DM-MP: The Linux OS and the native DM-MP driver
                                                   #     - Linux Pathmanager: The Linux OS and the SGI proprietary multipath drive
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

    # Storage management interface defaults
        Note:  eseries_management_* variables have the lowest priority and will be overwritten by those found in eseries_management_interfaces
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
          dns_config_method:     # DNS config method for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
          dns_address:           # Primary DNS address for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
          dns_address_backup:    # Backup DNS address for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
          ntp_config_method:     # NTP config method for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
          ntp_address:           # Primary NTP address for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
          ntp_address_backup:    # Backup NTP address for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
          ssh:                   # SSH access for controller A (Note this will apply to every interface of the
                                 #   controller. To be idempotent, only define for one interface on this controller).
                                 #   Choices: true, false
      controller_b:              # List of controller B ports
        - (...)                  # Same as for controller A but for controller B.

    # Alerts configuration defaults
    eseries_alerts_state:               # Whether to enable storage system alerts. Choices: enabled, disabled
    eseries_alerts_contact:             # This allows owner to specify free-form contact information such as email or phone number.
    eseries_alerts_recipients:          # List containing e-mails that should be sent notifications when alerts are issued.
    eseries_alerts_sender:              # Sender email. This does not necessarily need to be a valid e-mail.
    eseries_alerts_server:              # Fully qualified domain name, IPv4 address, or IPv6 address of the mail server.
    eseries_alerts_test: false          # When changes are made to the storage system alert configuration a test e-mail will be sent. Choices: true, false
    eseries_alert_syslog_servers:       # List of dictionaries where each dictionary contains a syslog server entry. [{"address": <address>, "port": <port>}]
    eseries_alert_syslog_test: false    # Whether alerts syslog servers configuration test message should be sent. Choices: true, false

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

    # SSL/TLS certificate configurations - Note that both individual certificates or wildcard certificates are accepted.
    eseries_client_certificate_remove_unspecified_user_certificates:    # Whether existing user certificates should be automatically removed. (Default: True)
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
    eseries_asup_active:             # Allows NetApp support personnel to request support data to resolve issues. Choices: true, false
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
    eseries_auditlog_force:             # Forces audit-log to delete log messages when fullness threshold has been exceeded. Choices: true, false
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

    # iSCSI target discovery specifications
        Note: add the following to ansible-playbook command to update the chap secret: --extra-vars "eseries_target_chap_secret_update=True
    eseries_iscsi_target_name:                        # iSCSI target name that will be seen by the initiator
    eseries_iscsi_target_ping: True                   # Enables ICMP ping response from the configured iSCSI ports (boolean)
    eseries_iscsi_target_unnamed_discovery: True      # Whether the iSCSI target iqn should be returned when an initiator performs a discovery session.
    eseries_iscsi_target_chap_secret:                 # iSCSI chap secret. When left blank, the chap secret will be removed from the storage system.
    eseries_iscsi_target_chap_secret_update: False    # DO NOT REMOVE! Since na_santricity_iscsi_target cannot compare the chap secret with the current and
                                                      #     will always return changed=True, this flag is used to force the module to update the chap secret.
                                                      #     Leave this value False and to add the --extra-vars "eseries_target_chap_secret_update=True".

    # Controller iSCSI Interface Port Default Policy Specifications
    eseries_controller_iscsi_port_state: enabled         # Generally specifies whether a controller port definition should be applied Choices: enabled, disabled
    eseries_controller_iscsi_port_config_method: dhcp    # General port configuration method definition for both controllers. Choices: static, dhcp
    eseries_controller_iscsi_port_gateway:               # General port IPv4 gateway for both controllers.
    eseries_controller_iscsi_port_subnet_mask:           # General port IPv4 subnet mask for both controllers.
    eseries_controller_iscsi_port_mtu: 9000              # General port maximum transfer units (MTU) for both controllers. Any value greater than 1500 (bytes).
    eseries_controller_iscsi_port:
      controller_a:           # Controller A port definition. Ordered list of port definitions reading iSCSI ports left to right
        - state:            # Whether the port should be enabled. Choices: enabled, disabled
          config_method:    # Port configuration method Choices: static, dhcp
          address:          # Port IPv4 address
          gateway:          # Port IPv4 gateway
          subnet_mask:      # Port IPv4 subnet_mask
          mtu:              # Port IPv4 mtu
      controller_b:           # Controller B port definition.
        - (...)               # Same as controller A but for controller B

    # Controller InfiniBand iSER Interface Channel
    eseries_controller_ib_iser_port:
      controller_a:    # Ordered list of controller A channel address definition.
          -            # Port IPv4 address for channel 1
      controller_b:    # Ordered list of controller B channel address definition.
          - (...)      # Same as controller A but for controller B

    # Controller NVMe over InfiniBand Interface Channel
    eseries_controller_nvme_ib_port:
      controller_a:    # Ordered list of controller A channel address definition.
          -            # Port IPv4 address for channel 1
      controller_b:    # Ordered list of controller B channel address definition.
          - (...)      # Same as controller A but for controller B

    # Controller NVMe RoCE Interface Port Default Policy Specifications
    eseries_controller_nvme_roce_port_state: enabled         # Specifies whether a controller port definition should be applied. Choices: enabled, disabled
    eseries_controller_nvme_roce_port_config_method: dhcp    # Port configuration method definition for both controllers. Choices: static, dhcp
    eseries_controller_nvme_roce_port_gateway:               # Port IPv4 gateway for both controllers.
    eseries_controller_nvme_roce_port_subnet_mask:           # Port IPv4 subnet mask for both controllers.
    eseries_controller_nvme_roce_port_mtu: 4200              # Port maximum transfer units (MTU). Any value greater than 1500 (bytes).
    eseries_controller_nvme_roce_port_speed: auto            # Interface speed. Value must be a supported speed or auto to negotiate the speed with the port.
    eseries_controller_nvme_roce_port:
      controller_a:         # Controller A port definition. List containing ports definitions.
        - channel:          # Channel of the port to modify. This will be a numerical value that represents the port; typically read
                            #     left to right on the HIC.
          state:            # Whether the port should be enabled.
          config_method:    # Port configuration method Choices: static, dhcp
          address:          # Port IPv4 address
          gateway:          # Port IPv4 gateway
          subnet_mask:      # Port IPv4 subnet_mask
          mtu:              # Port IPv4 mtu
          speed:            # Port IPv4 speed
      controller_b:         # Controller B port definition.
        - (...)             # Same as controller A but for controller B

    # Storage Pool Default Policy Specifications
    eseries_storage_pool_state: present                   # Default storage pool state. Choices: present, absent
    eseries_storage_pool_raid_level: raidDiskPool         # Default volume raid level. Choices: raid0, raid1, raid5, raid6, raidDiskPool
    eseries_storage_pool_secure_pool: false               # Default for storage pool drive security. This flag will enable the security at rest feature. There
                                                          #    must be sufficient FDE or FIPS security capable drives. Choices: true, false
    eseries_storage_pool_criteria_drive_count:            # Default storage pool drive count.
    eseries_storage_pool_reserve_drive_count:             # Default reserve drive count for drive reconstruction for storage pools using dynamic disk pool and
                                                          #    the raid level must be set for raidDiskPool.
    eseries_storage_pool_criteria_min_usable_capacity:    # Default minimum required capacity for storage pools.
    eseries_storage_pool_criteria_drive_type:             # Default drive type for storage pools. Choices: hdd, ssd
    eseries_storage_pool_criteria_drive_interface_type:   # Default interface type to use when selecting drives for the storage pool.
    eseries_storage_pool_criteria_size_unit: gb           # Default unit size for all storage pool related sizing.
                                                          #    Choices: bytes, b, kb, mb, gb, tb, pb, eb, zb, yb
    eseries_storage_pool_criteria_drive_min_size:         # Default minimum drive size for storage pools.
    eseries_storage_pool_criteria_drive_max_size:         # Default maximum drive size for storage pools.
    eseries_storage_pool_criteria_drive_require_da:       # Default for whether storage pools are required to have data assurance (DA) compatible drives.
                                                          #    Choices: true, false
    eseries_storage_pool_criteria_drive_require_fde:      # Default for whether storage pools are required to have drive security compatible drives.
                                                          #    Choices: true, false
    eseries_storage_pool_remove_volumes:                  # Default policy for deleting volumes prior to removing storage pools.
    eseries_storage_pool_erase_secured_drives:            # Default policy for erasing the content drives during create and delete storage pool operations.
                                                          #    Choices: true, false
    eseries_storage_pool_ddp_critical_threshold_pct:      # Default policy for dynamic disk pool alert critical threshold.
    eseries_storage_pool_ddp_warning_threshold_pct:       # Default policy for dynamic disk pool alert warning threshold.

    # Volume Default Policy Specifications
    eseries_volume_state: present                         # Default volume state. Choices: present, absent
    eseries_volume_size_unit: gb                          # Default unit size for all volume sizing options.
                                                          #    Choices: bytes, b, kb, mb, gb, tb, pb, eb, zb, yb, pct
    eseries_volume_size:                                  # Default volume size or the presented size for thinly provisioned volumes.
    eseries_volume_data_assurance_enabled:                # Default for whether data assurance(DA) is required to be enabled.
    eseries_volume_segment_size_kb:                       # Default segment size measured in kib.
    eseries_volume_read_cache_enable:                     # Default for read caching which will cache all read requests.
    eseries_volume_read_ahead_enable:                     # Default for read ahead caching; this is good for sequential workloads to cache subsequent blocks.
    eseries_volume_write_cache_enable:                    # Default for write caching which will cache all writes.
    eseries_volume_write_cache_mirror_enable:             # Default for write cache mirroring which mirrors writes to both controller's cache.
    eseries_volume_cache_without_batteries:               # Default for allowing caching when batteries are not present.
    eseries_volume_thin_provision:                        # Default for whether volumes should be thinly provisioned.
    eseries_volume_thin_volume_repo_size:                 # Default for actually allocated space for thinly provisioned volumes.
    eseries_volume_thin_volume_max_repo_size:             # Default for the maximum allocated space allowed for thinly provisioned volumes.
    eseries_volume_thin_volume_expansion_policy:          # Default thin volume expansion policy. Choices: automatic, manual
    eseries_volume_thin_volume_growth_alert_threshold:    # Default thin volume growth alert threshold; this is the threshold for when the thin volume expansion
                                                          #    policy will be enacted. Allowable values are between and including 10% and 99%
    eseries_volume_ssd_cache_enabled:                     # Default for ssd cache which will enable the volume to use an existing SSD cache on the storage array
    eseries_volume_host:                                  # Default host for all volumes; the value can be any host from the Ansible inventory.
    eseries_volume_workload_name:                         # Default workload tag name
    eseries_volume_workload_metadata:                     # Default workload metadata
    eseries_volume_volume_metadata:                       # Default volume_metadata
    eseries_volume_owning_controller                      # Default preferred owning controller
    eseries_volume_wait_for_initialization: false         # Default for whether volume creation with wait for initialization to complete

    # Storage Pool-Volume Mapping Default Policy Specifications
    eseries_lun_mapping_state: present    # Generally specifies whether a LUN mapping should be present. This is useful when adding a default host for all
                                          #    volumes. Choices: present, absent
    eseries_lun_mapping_host:             # Default host for all volumes not specifically give a host either in common_volume_configuration or in
                                          #    eseries_storage_pool_configuration.

    # Storage Pool-Volume Default Policy Specifications
       Name schemes: Storage pool and volume names can be used to specify a naming scheme to produce a list of storage pools and volumes. Schemes are defined by
                     brackets and can be used to specify a range of lowercase letters, uppercase letters, range of single digit numbers, any top-level inventory
                     variables, and [pool] to use the current defined storage pool (volume only).
    eseries_storage_pool_configuration:
      - name:                                      # Name or name scheme (see above) for the storage pool.
        state:                                     # Specifies whether the storage pool should exist. Choices: present, absent
        raid_level                                 # Volume group raid level. Choices: raid0, raid1, raid5, raid6, raidDiskPool (Default: raidDiskPool)
        secure_pool:                               # Default for storage pool drive security. This flag will enable the security at rest feature. There must be
                                                   #    sufficient FDE or FIPS security capable drives. Choices: true, false
        criteria_drive_count:                      # Default storage pool drive count.
        criteria_volume_count:                     # Number of equally sized volumes to create. All available storage pool space will be used. The option will
                                                   #    be ignored if volumes is defined.
        criteria_reserve_free_capacity_pct         # Percent of reserve free space capacity to leave when creating the criteria_volume_count volumes.
        common_volume_host                         # Host or host group for the criteria_volume_count volumes should be mapped.
        reserve_drive_count:                       # Default reserve drive count for drive reconstruction for storage pools using dynamic disk pool and the raid
                                                   #    level must be set for raidDiskPool.
        criteria_size_unit:                        # Default unit size for all storage pool related sizing. Choices: bytes, b, kb, mb, gb, tb, pb, eb, zb, yb
        criteria_min_usable_capacity:              # Default minimum required capacity for storage pools.
        criteria_drive_type:                       # Default drive type for storage pools. Choices: hdd, ssd
        criteria_drive_interface_type              # Interface type to use when selecting drives for the storage pool.
                                                   #    Choices: scsi, fibre, sata, pata, fibre520b, sas, sas4k, nvme4k
        criteria_drive_min_size:                   # Default minimum drive size for storage pools.
        criteria_drive_max_size:                   # Default maximum drive size for storage pools.
        criteria_drive_require_da:                 # Ensures storage pools have data assurance (DA) compatible drives. Choices: true, false
        criteria_drive_require_fde:                # Ensures storage pools have drive security compatible drives. Choices: true, false
        remove_volumes:                            # Ensures volumes are deleted prior to removing storage pools.
        erase_secured_drives:                      # Ensures data is erased during create and delete storage pool operations. Choices: true, false
        common_volume_configuration:               # Any option that can be specified at the volume level can be generalized here at the storage pool level.
        volumes:                                   # List of volumes associated the storage pool.
          - state:                                 # Specifies whether the volume should exist (present, absent)
            name:                                  # (required) Name or name scheme (see above) for the volume(s) to be created in the storage pool(s)
            host:                                  # host or host group for the volume should be mapped to.
            host_type:                             # Only required when using something other than Linux kernel 3.10 or later with DM-MP (Linux DM-MP),
                                                   #    non-clustered Windows (Windows), or the storage system default host type is incorrect.
                                                   # Common host type definitions:
                                                   #    - AIX MPIO: The Advanced Interactive Executive (AIX) OS and the native MPIO driver
                                                   #    - AVT 4M: Silicon Graphics, Inc. (SGI) proprietary multipath driver
                                                   #    - HP-UX: The HP-UX OS with native multipath driver
                                                   #    - Linux ATTO: The Linux OS and the ATTO Technology, Inc. driver (must use ATTO FC HBAs)
                                                   #    - Linux DM-MP: The Linux OS and the native DM-MP driver
                                                   #    - Linux Pathmanager: The Linux OS and the SGI proprietary multipath driver
                                                   #    - Mac: The Mac OS and the ATTO Technology, Inc. driver
                                                   #    - ONTAP: FlexArray
                                                   #    - Solaris 11 or later: The Solaris 11 or later OS and the native MPxIO driver
                                                   #    - Solaris 10 or earlier: The Solaris 10 or earlier OS and the native MPxIO driver
                                                   #    - SVC: IBM SAN Volume Controller
                                                   #    - VMware: ESXi OS
                                                   #    - Windows: Windows Server OS and Windows MPIO with a DSM driver
                                                   #    - Windows Clustered: Clustered Windows Server OS and Windows MPIO with a DSM driver
                                                   #    - Windows ATTO: Windows OS and the ATTO Technology, Inc. driver
            owning_controller:                     # Specifies which controller will be the primary owner of the volume. Not specifying will allow the
                                                   #    controller to choose ownership. (Choices: A, B)
            size:                                  # Size of the volume or presented size of the thinly provisioned volume.
            size_unit:                             # Unit size for the size, thin_volume_repo_size, and thin_volume_max_repo_size
                                                   #    Choices: bytes, b, kb, mb, gb, tb, pb, eb, zb, yb, pct
            segment_size_kb:                       # Indicates the amount of data stored on a drive before moving on to the next drive in the volume group.
            thin_provision:                        # Whether volumes should be thinly provisioned.
            thin_volume_repo_size:                 # Actually allocated space for thinly provisioned volumes.
            thin_volume_max_repo_size:             # Maximum allocated space allowed for thinly provisioned volumes.
            thin_volume_expansion_policy:          # Thin volume expansion policy. Choices: automatic, manual
            thin_volume_growth_alert_threshold:    # Thin volume growth alert threshold; this is the threshold for when the thin volume expansion
                                                   #    policy will be enacted. Allowable values are between and including 10% and 99%
            ssd_cache_enabled:                     # Enables ssd cache which will enable the volume to use an existing SSD cache on the storage array.
            data_assurance_enabled:                # Enables whether data assurance(DA) is required to be enabled.
            read_cache_enable:                     # Enables read caching which will cache all read requests.
            read_ahead_enable:                     # Enables read ahead caching; this is good for sequential workloads to cache subsequent blocks.
            write_cache_enable:                    # Enables write caching which will cache all writes.
            write_cache_mirror_enable:             # Enables write cache mirroring which mirrors writes to both controller's cache.
            cache_without_batteries:               # Enable caching even without batteries.

            wait_for_initialization:               # Whether volume creation with wait for initialization to complete
            workload_name:                         # Name of the volume's workload
            workload_metadata:                     # Dictionary containing arbitrary entries normally used for defining the volume(s) workload.
            volume_metadata                        # Dictionary containing arbitrary entries used to define information about the volume itself.
                                                   #    Note: format_type, format_options, mount_dir, mount_options are used by netapp_eseries.host.mount role
                                                   #            to format and mount volumes.


    # Snapshot Consistency Group Default Policy Specifications
    eseries_snapshot_remove_unspecified:                      # Whether to remove any snapshot group or view that is not specified (Default: false).
    eseries_snapshot_groups_maximum_snapshots:                # Default maximum point-in-time snapshot images (Default: 32).
    eseries_snapshot_groups_reserve_capacity_pct:             # Default reserve capacity percentage (Default: 40)
    eseries_snapshot_groups_preferred_reserve_storage_pool:   # Preferred storage pool or volume group for the reserve capacity volume.
    eseries_snapshot_groups_reserve_capacity_full_policy:     # Default full reserve capacity policy (Default: purge). Choices: [purge, reject]
    eseries_snapshot_groups_alert_threshold_pct:              # Default reserve capacity percentage full to alert administrators (Default 75).
    eseries_snapshot_groups:
      - name:                                                 # Name of snapshot consistency group.
        maximum_snapshots:                                    # Maximum allowed snapshot point-in-time images for consistency group (Default: 32).
        reserve_capacity_pct:                                 # Reserve capacity measured as a percentage of the base volume (Default: 40). Reserve capacity can be expanded
                                                              #   and trimmed; however, the trim operation requires there be no base volume snapshots images in the group.
        reserve_capacity_full_policy:                         # Policy to implement when reserve capacity is full (Default: purge). Choices [purge, reject]
        alert_threshold_pct:                                  # Reserve capacity full alert threshold for storage system administrators (Default: 75).
        rollback_priority:                                    # Storage system priority for base volume rollback (Default: medium). Choices [lowest, low, medium, high, highest]
        volumes:                                              # Information for each volume in the consistency group.
          - volume:                                           # Base volume name
            reserve_capacity_pct:                             # Reserve capacity measured as a percentage of the base volume (Default: 40). Reserve capacity can be expanded
                                                              #   and trimmed; however, the trim operation requires there be no base volume snapshots images in the group.
            preferred_reserve_storage_pool:                   # Preferred reserve capacity storage pool or volume group. This will default to the base volume's
                                                              #   storage pool or volume group. The reserve capacity volume cannot be changed once created.
          - (...)

    # Snapshot Consistency Group View Default Policy Specifications
    eseries_snapshot_views_host:                              # Default host or host group to map all snapshot volumes.
    eseries_snapshot_views_reserve_capacity_pct:              # Default reserve capacity percentage (Default: 40)
    eseries_snapshot_views_preferred_reserve_storage_pool:    # Preferred storage pool or volume group for the reserve capacity volume.
    eseries_snapshot_views_alert_threshold_pct:               # Default reserve capacity percentage full to alert administrators (Default 75).
    eseries_snapshot_views_writable:                          # Default for whether to make snapshot volumes writable.
    eseries_snapshot_views_validate:                          # Default for whether to validate snapshot volumes after creation.
    eseries_snapshot_views:
      - volume:                                               # Consistency group's snapshot view's name.
        group_name:                                           # Snapshot consistency group's name.
        pit_name:                                             # Point-in-time snapshot images group name. (Only available when specified using Ansible na_santricity_module (via direct or role)
        pit_timestamp:                                        # Point-in-time snapshot images group timestamp. Snapshot image timestamp in the YYYY-MM-DD HH:MM:SS (AM|PM) (hours, minutes, seconds, and day-period are optional)
        host:                                                 # Host or host group to map snapshot volumes.
        writable:                                             # Whether snapshot volume of base volume images should be writable.
        validate:                                             # Whether snapshot volume should be validated which includes both a media scan and parity validation.
        reserve_capacity_pct:                                 # Percentage of base volume capacity to reserve for snapshot copy-on-writes (COW). Only used when snapshot volume is writable.
        preferred_reserve_storage_pool:                       # Preferred storage pool or volume group for the reserve capacity volume.
        alert_threshold:                                      # Reserve capacity percentage full to alert administrators
        volumes:                                              # (Optional) Select subset of volumes within the snapshot consistency group.
          - name:                                             # Name of volume within consistency group.
            host:                                             # Host or host group to map snapshot volumes.
            lun:                                              # Logical unit number (LUN) mapping for the host or host group.
            writable:                                         # Whether snapshot volume of base volume images should be writable.
            validate:                                         # Whether snapshot volume should be validated which includes both a media scan and parity validation.
            reserve_capacity_pct:                             # Percentage of base volume capacity to reserve for snapshot copy-on-writes (COW). Only used when snapshot volume is writable.
            preferred_reserve_storage_pool:                   # Preferred storage pool or volume group for the reserve capacity volume.

    # Snapshot Consistency Group Rollback Default Policy Specifications
    eseries_snapshot_rollback_priority: medium                # Default point-in-time rollback priority (Default: medium). Choices [lowest, low, medium, high, highest]
    eseries_snapshot_rollback_backup: true                    # Default whether snapshot should be taken prior to rolling back base volumes (Default: true).
    eseries_snapshot_rollbacks:
      - group_name:                                           # Snapshot consistency group's name.
        pit_name:                                             # Point-in-time snapshot images group name (Only available when specified using Ansible na_santricity_module (via direct or role)
        pit_timestamp:                                        # Point-in-time snapshot images group timestamp. Snapshot image timestamp in the YYYY-MM-DD HH:MM:SS (AM|PM) (hours, minutes, seconds, and day-period are optional)
        rollback_priority:                                    # Storage system priority for base volume rollback (Default: medium). Choices [lowest, low, medium, high, highest]
        rollback_backup:                                      # Whether to create point-in-time snapshot images of the consistency group prior to rollback.
        volumes:

    # Initiator-Target Protocol Variable Defaults
        Note that the following commands need to produce a unique list of IQNs or WWNs of the interfaces used, line separated. Overwrite as necessary.
    eseries_initiator_protocol: fc     # Storage system protocol. Choices: fc, iscsi, sas, ib_iser, ib_srp, nvme_ib, nvme_fc, nvme_roce
    eseries_initiator_command:
      fc:
        linux: "cat /sys/class/fc_host/host*/port_name | sort | uniq"
        windows: "(Get-InitiatorPort | Where-Object -P ConnectionType -EQ 'Fibre Channel' | Select-Object -Property PortAddress |
                   Format-Table -AutoSize -HideTableHeaders | Out-String).trim()"
      iscsi:
        linux: "grep -o iqn.* /etc/iscsi/initiatorname.iscsi"
        windows: "(get-initiatorPort | select-object -property nodeaddress | sort-object | get-unique | ft -autoSize | out-string -stream |
                   select-string iqn | out-string).trim()"
      sas:
        # NetApp IMT for SAS attached E-Series SAN hosts recommends adding all possible SAS addresses with the base address
        # starting at 0, and the last address ending in 3 for single port HBAs, or 7 for dual port HBAs. Since determining
        # single vs . dual port HBAs adds complexity, we always add all 8 possible permutations of the SAS address.
        linux: "cat /sys/class/sas_host/host*/device/scsi_host/*/host_sas_address | sort | uniq"
        windows: "(Get-InitiatorPort | Where-Object -P ConnectionType -EQ 'SAS' | Select-Object -Property PortAddress | Format-Table -AutoSize -HideTableHeaders | Out-String).trim()"
      ib_iser:
        linux: "grep -o iqn.* /etc/iscsi/initiatorname.iscsi"
        windows: ""   # add windows command for determining host iqn address(es)
      ib_srp:
        linux: "for fp in /sys/class/infiniband/*/ports/*/gids/*; do out=`cat $fp | tr -d :`; port=`expr substr $out 17 32`; if [ $port != 0000000000000000 ]; then echo 0x$port; fi; done | sort | uniq"
        windows: ""   # add windows command for determining host guid
      nvme_ib:
        linux: "grep -o nqn.* /etc/nvme/hostnqn"
        windows: ""   # add windows command for determining host nqn address(es)
      nvme_fc:
        linux: "grep -o nqn.* /etc/nvme/hostnqn"
        windows: ""   # add windows command for determining host nqn address(es)
      nvme_roce:
        linux: "grep -o nqn.* /etc/nvme/hostnqn"
        windows: ""   # add windows command for determining host nqn address(es)

    # Manual host definitions, Linux and Windows systems can be automatically populated based on host mappings found in eseries_storage_pool_configuration
        Note that using the automated method is preferred.
    eseries_host_force_port: true                 # Default for whether ports are to be allowed to be re-assigned (boolean)
    eseries_host_remove_unused_hostgroup: true    # Forces any unused groups to be removed
    eseries_host_object:
      - name:         # Host label as referenced by the storage array.
        state:        # Specifies whether host definition should be exist. Choices: present, absent
        ports:        # List of port definitions
          - type:     # Port protocol definition (iscsi, fc, sas, ib, nvme). Note that you should use 'iscsi' prior to SANtricity version 11.60 for IB iSER.
            label:    # Arbitrary port label
            port:     # Port initiator (iqn, wwn, etc)
        group:        # Host's host group
        host_type:    # Only required when using something other than Linux kernel 3.10 or later with DM-MP (Linux DM-MP),
                      #     non-clustered Windows (Windows), or the storage system default host type is incorrect.
                      # Common host type definitions:
                      #     - AIX MPIO: The Advanced Interactive Executive (AIX) OS and the native MPIO driver
                      #     - AVT 4M: Silicon Graphics, Inc. (SGI) proprietary multipath driver
                      #     - HP-UX: The HP-UX OS with native multipath driver
                      #     - Linux ATTO: The Linux OS and the ATTO Technology, Inc. driver (must use ATTO FC HBAs)
                      #     - Linux DM-MP: The Linux OS and the native DM-MP driver
                      #     - Linux Pathmanager: The Linux OS and the SGI proprietary multipath driver
                      #     - Mac: The Mac OS and the ATTO Technology, Inc. driver
                      #     - ONTAP: FlexArray
                      #     - Solaris 11 or later: The Solaris 11 or later OS and the native MPxIO driver
                      #     - Solaris 10 or earlier: The Solaris 10 or earlier OS and the native MPxIO driver
                      #     - SVC: IBM SAN Volume Controller
                      #     - VMware: ESXi OS
                      #     - Windows: Windows Server OS and Windows MPIO with a DSM driver
                      #     - Windows Clustered: Clustered Windows Server OS and Windows MPIO with a DSM driver
                      #     - Windows ATTO: Windows OS and the ATTO Technology, Inc. driver

Remove Inventory Configuration
------------------------------
Whether its for a testing automation or a temporary project, its helpful to be able to undo all that you configured. Just set `eseries_remove_all_configuration: True` and nar_santricity_host will remove all it configured. Be aware that this feature does not know the previous state of anything; it simply removes anything specified in the inventory.

License
-------
    BSD-3-Clause

Maintainer Information
------------------
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
    - Joe McCormick (@iamjoemccormick)
