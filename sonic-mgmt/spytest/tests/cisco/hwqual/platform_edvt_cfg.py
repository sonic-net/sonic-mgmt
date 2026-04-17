#!/usr/bin/env python3
"""
Platform EDVT Configuration Module

This module contains configuration definitions for Engineering Design Verification Testing (EDVT)
of Cisco hardware platforms running SONiC Network Operating System.

File: platform_edvt_cfg.py
Path: sonic-mgmt/spytest/tests/cisco/hwqual/platform_edvt_cfg.py

Description:
   Defines test categories, check configurations, and platform-specific settings
   for hardware qualification, unit testing, and security validation of Cisco
   8000 series network switches.

Test Categories:
   - default: Standard EDVT test suites
   - hwqual: Hardware qualification testing
   - security: Security compliance testing

Check Types:
   - systemctl_check: Platform service validation
   - idprom_check: Hardware identity verification
   - docker_check: Container service validation
   - sensor_check: Environmental monitoring (temperature, voltage, current)
   - fan_check: Cooling system validation
   - psu_check: Power supply unit validation
   - xcvr_check: Transceiver functionality
   - datapath_check: Network data path verification
   - margining_check: Voltage margin testing (vm_max, vm_min, vm_nom)
   - obfl_check: Onboard failure logging
   - traffic_check: Network traffic validation
   - security_check: Security compliance verification

Supported Platforms:
   - 8102-64H-O: 64-port 100G switch
   - 8101-32FH-O/8101-32FH-C01: 32-port 400G switch
   - 8122-64EH-O/8122-64EHF-O/HF6100-64ED: 64-port 800G switch  

Platform Configurations:
   Each platform entry contains:
   - test_type: Category of tests to run (hwqual, security)
   - asic: ASIC type and family
   - asic_count: Number of ASICs on the platform
   - fpds: Firmware component list (BIOS, Aikido, TAM, etc.)
   - fantrays: Number of fan trays
   - psus: Number of power supply units

Integration:
   This configuration is used by:
   - test_edvt_sequence.py: Main EDVT test orchestrator
   - platform validation modules: Individual test implementations
   - CI/CD pipelines: Automated hardware validation

Version History:
   v1.0 - Initial platform configurations
   v1.1 - Added voltage margining checks
   v1.2 - Enhanced security testing support
   v1.3 - Added FPDS firmware validation
   v1.4 - Thermal zone and voltage sensor integration
"""

from tests.cisco.hwqual.platform_snt_cfg import vrf_traffic_configs 

# =============================================================================
# Each check list defines specific validation items for different subsystems

"""
Platform Services Validation Check

Validates that critical platform services are running and healthy during EDVT testing.

Services Checked:
   - platform-topology.service: Hardware topology discovery and mapping
   - platform-dev-cfg.service: Platform device configuration
   - platform-obfl.service: Onboard failure logging
   - platform-fault-handler.service: Hardware fault handling
   - config-setup.service: System configuration setup
"""
systemctl_check = [
   "platform-topology.service",
   "platform-dev-cfg.service",
   "platform-obfl.service",
   "platform-fault-handler.service",
   "config-setup.service"
]

"""
Hardware Identity EEPROM Validation Check

Validates IDPROM (ID PROM) data from hardware components to verify proper
hardware identification and manufacturing information.

Components Checked:
   - baseboard: Main board EEPROM containing platform identification data
   - fantray: Fan tray EEPROM for cooling system component identification  
   - psu: Power Supply Unit EEPROM for power component identification
"""
idprom_check = [
   "baseboard",
   "fantray",
   "psu"
]

"""
Environmental Sensor Monitoring Check

Validates environmental sensors to ensure platform operates within safe
operating parameters and monitors hardware health.

Sensors Checked:
   - temperature: Thermal sensors for CPU, ASIC, and ambient monitoring
   - voltage: Power rail voltage sensors for system power validation
   - current: Current draw sensors for power consumption monitoring
"""
sensor_check = [
   "temperature",
   "voltage",
   "current"
]

sensor_warning_check = [
   "temperature_warning",
   "voltage_warning",
   "current_warning"
]

"""
Docker Container Service Validation Check

Validates that critical SONiC Docker containers are running and healthy
to ensure proper network operating system functionality.

Containers Checked:
   - database: Redis database service for system state storage
   - eventd: Event handling and logging service
   - bgp: Border Gateway Protocol routing service  
   - syncd: Switch abstraction interface daemon
   - swss: Switch state service for forwarding plane
   - teamd: Link aggregation (LAG) management service
   - pmon: Platform monitoring service for hardware health
   - lldp: Link Layer Discovery Protocol service
   - sysmgr: System manager for service orchestration
   - mgmt-framework: Management interface framework
   - dhcp_relay: DHCP relay service for network configuration
   - radv: Router advertisement daemon for IPv6
   - gnmi: gRPC Network Management Interface service
   - snmp: Simple Network Management Protocol service
"""
docker_check = [
   "database",
   "eventd",
   "bgp",
   "syncd",
   "swss",
   "teamd",
   "pmon",
   "lldp",
   "sysmgr",
   "mgmt-framework",
   "dhcp_relay",
   "radv",
   "gnmi",
   "snmp"
]

"""
Platform Hardware Data Validation Check

Validates platform hardware information and status to ensure proper
hardware detection and operational state.

Data Sources Checked:
   - summary: Platform summary information and overall system status
   - syseeprom: System EEPROM data for platform identification and specs
   - fan: Fan tray status, speeds, and operational health
   - psustatus: Power Supply Unit status and power metrics
   - firmware_status: Firmware versions and component status
"""
platform_data_check = [
   "summary",
   "syseeprom",
   "firmware_status"
]

"""
System Reboot Validation Check

Validates system reboot functionality and recovery to ensure platform
can properly restart and restore operational state.

Reboot Types Checked:
   - cold_reboot: Complete system power cycle and restart validation
"""
reboot_check = [
   "cold_reboot"
]

"""
Interface Shut/NoShut Validation Check

Validates interface shut/noshut functionality to ensure interfaces
can properly shut and restore operational state.

Parameters Checked:
   - shut_noshut: Complete multiple interface shut/noshut.
                  This param is to shut/noshut repeated 25 times.
"""
shut_noshut = [
   "shut_noshut"
]

"""
Fan System Validation Check

Validates cooling system functionality to ensure proper thermal management
and prevent hardware overheating conditions.

Fan Parameters Checked:
   - fan_status: Operational status of all fan trays and individual fans
   - fan_speed: Fan rotation speeds and RPM measurements
"""
fan_check = [
   "fan_status",
   "fan_speed"
]

"""
Power Supply Unit Validation Check

Validates power supply functionality to ensure stable power delivery
and proper electrical operation of the platform.

PSU Parameters Checked:
   - psu_status: Operational status and health of all power supply units
   - psu_voltage: Output voltage levels and power delivery metrics
"""
psu_check = [
   "psu_status",
   "psu_voltage"
]

"""
Transceiver Validation Check

Validates optical transceiver modules to ensure proper network connectivity
and interface functionality across all ports.

Transceiver Parameters Checked:
   - transceiver_status: Operational status and health of all SFP/QSFP modules
"""
xcvr_check = [
   "error_status"
]

"""
Network Data Path Validation Check

Validates network data path functionality to ensure proper packet forwarding
and interface connectivity across the switching platform.

Data Path Parameters Checked:
   - intf_status: Network interface operational status and link state
"""
datapath_check = [
   "intf_status"
]


"""
Onboard Failure Logging Validation Check

Validates OBFL (Onboard Failure Logging) functionality to ensure proper
hardware failure tracking and diagnostic data collection.

OBFL Parameters Checked:
   - onboard_failure_logging: OBFL service status and failure log accessibility
"""
obfl_check = [
   "obfl_status"
]

"""
VRF Traffic Validation Check

Validates Virtual Routing and Forwarding (VRF) functionality to ensure proper
traffic isolation and routing across multiple virtual networks.

VRF Parameters Checked:
   - vrf_traffic_validation: Verify for any traffic drop
"""
vrf_traffic_check = [
   "vrf_traffic_validation"
]

"""
VRF Traffic Start

Validates Virtual Routing and Forwarding (VRF) functionality to ensure proper
traffic isolation and routing across multiple virtual networks.

VRF Parameters Checked:
   - vrf_traffic_start: Start VRF traffic
"""
vrf_traffic_start = [
   "vrf_traffic_start"
]

"""
VRF Traffic Stop

Validates Virtual Routing and Forwarding (VRF) functionality to ensure proper
traffic isolation and routing across multiple virtual networks.

VRF Parameters Checked:
   - vrf_traffic_stop: Stop VRF traffic
"""
vrf_traffic_stop = [
   "vrf_traffic_stop"
]

"""
Voltage Margin Maximum Check

Validates platform operation at maximum voltage margins to ensure
stability under high voltage stress conditions.

Margin Parameters Checked:
   - volt_margin_max: Maximum voltage margin stress testing
"""
vm_max_check = [
   "volt_margin_max"
]

"""
Voltage Margin Minimum Check

Validates platform operation at minimum voltage margins to ensure
stability under low voltage stress conditions.

Margin Parameters Checked:
   - volt_margin_min: Minimum voltage margin stress testing
"""
vm_min_check = [
   "volt_margin_min"
]

"""
Voltage Margin Nominal Check

Validates platform operation at nominal voltage margins to establish
baseline performance and stability characteristics.

Margin Parameters Checked:
   - volt_margin_nom: Nominal voltage margin baseline testing
"""
vm_nom_check = [
   "volt_margin_nom"
]

"""
Security Compliance Validation Check

Validates security features and compliance requirements to ensure platform
meets security requirements.

Security Parameters Checked:
   - security_compliance: Security compliance verification
"""
security_data_check = [
   "security_compliance"
]


# =============================================================================
# EDVT TEST CATEGORY CONFIGURATION
# =============================================================================

"""
EDVT Test Category Configuration Dictionary

This dictionary defines the test category hierarchies and check sequences for
Engineering Design Verification Testing (EDVT) across different test types.

Test Categories:
   - hwqual: Hardware qualification testing for production readiness
   - security: Security compliance testing for certified platforms

Test Structure:
   Each test category contains test phases that group related validation checks:
   
   test_bringup:     Platform initialization and service startup validation
   test_stability:   Hardware detection and platform data validation  
   test_docker:      Container service health verification
   test_sensor:      Environmental monitoring validation
   test_fan:         Cooling system functionality verification
   test_psu:         Power supply unit validation
   test_xcvr:        Transceiver module functionality
   test_datapath:    Network data path and interface validation
   test_traffic:     VRF traffic flow and configuration validation
   test_margining:   Voltage margin stress testing (max/min/nominal)
   test_obfl:        Onboard failure logging verification
   test_security:    Security compliance and policy validation
   test_edvt_1-4:    Comprehensive multi-phase testing sequences
"""
edvt_test_category = {
  "hwqual": {
       "test_bringup": [
           {"name": "test_systemctl_check", "checks": systemctl_check}, 
           {"name": "test_idprom_check", "checks": idprom_check}, 
           {"name": "test_docker_check", "checks": docker_check}, 
       ],
       "test_stability": [
           {"name": "test_platform_data_check", "checks": platform_data_check},
           {"name": "test_sensor_check", "checks": sensor_check},
           {"name": "test_fan_check", "checks": fan_check},
           {"name": "test_psu_check", "checks": psu_check},
           {"name": "test_xcvr_check", "checks": xcvr_check},
           {"name": "test_datapath_check", "checks": datapath_check}
       ],
       "test_shut_noshut": [
           {"name": "test_datapath_check", "checks": shut_noshut},
       ],
       "test_traffic": [
           {"name": "test_vrf_traffic_check", "checks": vrf_traffic_check}, 
       ],
       "test_margining": [
           {"name": "test_vmon_max_check", "checks": vm_max_check}, 
           {"name": "test_vmon_nominal_check", "checks": vm_nom_check}, 
           {"name": "test_vmon_min_check", "checks": vm_min_check}, 
           {"name": "test_vmon_nominal_check", "checks": vm_nom_check}, 
       ],
       "test_edvt_seq_1": [
           {"name": "test_reboot_check", "checks": reboot_check}, 
           {"name": "test_systemctl_check", "checks": systemctl_check}, 
           {"name": "test_docker_check", "checks": docker_check}, 
           {"name": "test_datapath_check", "checks": datapath_check}
       ],
       "test_edvt_seq_2": [
           {"name": "test_reboot_check", "checks": reboot_check}, 
           {"name": "test_vm_max_check", "checks": vm_max_check}, 
           {"name": "test_sensor_check", "checks": sensor_check},
           {"name": "test_datapath_check", "checks": datapath_check},
           {"name": "test_vrf_traffic_check", "checks": vrf_traffic_check}, 
       ],
       "test_edvt_seq_3": [
           {"name": "test_reboot_check", "checks": reboot_check}, 
           {"name": "test_vm_min_check", "checks": vm_min_check}, 
           {"name": "test_sensor_check", "checks": sensor_check},
           {"name": "test_datapath_check", "checks": datapath_check},
           {"name": "test_vrf_traffic_check", "checks": vrf_traffic_check}, 
       ]
   },
  "security": {
       "test_bringup": [systemctl_check, idprom_check, docker_check],
       "test_stability": [platform_data_check],
       "test_docker": [docker_check],
       "test_sensor": [sensor_check],
       "test_fan": [fan_check],
       "test_psu": [psu_check],
       "test_security": [security_data_check],
       "test_xcvr": [xcvr_check],
       "test_datapath": [datapath_check],
       "test_traffic": [vrf_traffic_check],
       "test_margining": [vm_max_check, vm_nom_check, vm_min_check, vm_nom_check],
       "test_obfl": [obfl_check],
       "test_edvt_1": [reboot_check, systemctl_check, docker_check, datapath_check],
       "test_edvt_2": [reboot_check, vm_max_check, vrf_traffic_check, sensor_check],
       "test_edvt_3": [reboot_check, vm_min_check, vrf_traffic_check, sensor_check],
       "test_edvt_4": [reboot_check, vm_max_check, datapath_check, vrf_traffic_check, vm_min_check, vrf_traffic_check],
   },
}


# =============================================================================
# PLATFORM EDVT CONFIGURATION DICTIONARY
# =============================================================================

"""
Platform EDVT Configuration Dictionary

This dictionary maps platform identifiers to their specific hardware configurations
and test requirements for Engineering Design Verification Testing (EDVT).

Dictionary Structure:
   category: Reference to edvt_test_category for test execution lookup
   <platform_id>: Platform-specific configuration and hardware specifications

Platform Configuration Fields:
   test_type:     Test category from edvt_test_category (hwqual, security)
   asic:          ASIC family identifier (cisco-8000)
   asic_count:    Number of switching ASICs on the platform
   fpds:          List of firmware components for validation
   fantrays:      Number of cooling fan tray assemblies
   psus:          Number of power supply units
"""
platform_edvt_cfg = {
   "category": edvt_test_category,
   "traffic_configs": vrf_traffic_configs,

   "platforms": {
       "8102-64H-O": {
           "test_type": "hwqual",
           "asic": "cisco-8000",
           "asic_count": 1,
           "fpds": ["BIOS", "Aikido", "TAM", "IOFPGA", "SSD", "eCPLD"],
           "fantrays": 4,
           "psus": 2,
           "shut_noshut" : 10,
           "noshut_timer": 60,
           "exception_intf" : [],
           "traffic_cfg_type": "fixed_traffic"
       },
       "8101-32FH-O": {
           "test_type": "hwqual",
           "asic": "cisco-8000",
           "asic_count": 1,
           "fpds": ["BIOS", "Aikido", "TAM", "IOFPGA", "SSD", "eCPLD", "CPU_CPLD"],
           "fantrays": 6,
           "psus": 2,
           "shut_noshut" : 10,
           "noshut_timer": 60,
           "exception_intf" : [],
           "traffic_cfg_type": "fixed_traffic"
       },
       "8101-32FH-O-C01": {
           "test_type": "hwqual",
           "asic": "cisco-8000",
           "asic_count": 1,
           "fpds": ["BIOS", "Aikido", "TAM", "IOFPGA", "SSD", "eCPLD", "CPU_CPLD"],
           "fantrays": 6,
           "psus": 2,
           "shut_noshut" : 10,
           "noshut_timer": 60,
           "exception_intf" : [],
           "traffic_cfg_type": "fixed_traffic"
       },
       "8122-64EHF-O": {
           "test_type": "hwqual",
           "asic": "cisco-8000",
           "asic_count": 1,
           "fpds": ["BIOS", "Aikido", "TAM", "IOFPGA", "SSD", "pwrcpld", "iocpld0", "iocpld1"],
           "fantrays": 4,
           "psus": 2,
           "shut_noshut" : 10,
           "noshut_timer": 60,
           "exception_intf" : ["Ethernet4", "Ethernet512", "Ethernet513"],
           "traffic_cfg_type": "fixed_traffic"
       },
       "8223-64E-MO": {
           "test_type": "hwqual",
           "asic": "cisco-8000",
           "asic_count": 1,
           "fpds": ["BIOS", "Aikido", "IOFPGA", "uFPGA", "pwrcpld", "iocpld0", "iocpld1"],
           "fantrays": 4,
           "psus": 2,
           "shut_noshut" : 10,
           "noshut_timer": 60,
           "exception_intf" : ["Ethernet4"],
           "traffic_cfg_type": "fixed_traffic"
       },
       "HF6100-64ED": {
           "test_type": "security",
           "asic": "cisco-8000",
           "asic_count": 1,
           "fpds": ["BIOS", "Aikido", "TAM", "IOFPGA", "SSD", "pwrcpld", "iocpld0", "iocpld1"],
           "fantrays": 4,
           "psus": 2,
           "shut_noshut" : 10,
           "noshut_timer": 60,
           "exception_intf" : ["Ethernet4", "Ethernet512", "Ethernet513"],
           "traffic_cfg_type": "fixed_traffic"
       }
   }
}

# Helper function to get bgp route advertisement configuration for a platform
def get_platform_edvt_traffic_cfg_type(platform_id):
   """
   get platform EDVT traffic configuration

   Args:
       platform_id (str): Platform identifier (e.g., "8101-32FH-O", "HF6100-64ED")

   Returns:
       dict: platform edvt traffic configuration or None if not found
   """
   platform_cfg = platform_edvt_cfg["platforms"].get(platform_id)
   if not platform_cfg:
       return None

   traffic_cfg_type = platform_cfg.get("traffic_cfg_type")
   if not traffic_cfg_type:
       return None

   return traffic_cfg_type

# Helper function to get bgp route advertisement configuration for a platform
def get_platform_edvt_cfg(platform_id):
   """
   get platform EDVT configuration

   Args:
       platform_id (str): Platform identifier (e.g., "8101-32FH-O", "HF6100-64ED")

   Returns:
       dict: platform edvt configuration or None if not found
   """
   platform_cfg = platform_edvt_cfg["platforms"].get(platform_id)
   if not platform_cfg:
       return None

   return platform_cfg
