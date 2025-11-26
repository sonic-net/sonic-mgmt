# Common2 Directory Structure Guidelines

This document defines the standardized directory structure for `tests/common2`, which serves as the central location for all refactored common code used across SONiC test modules.

## Design Principles

1. **Domain-Based Organization**: Group modules by networking domain/feature area
2. **Flat Hierarchy**: Avoid deep nesting; prefer 2-3 levels maximum
3. **Clear Naming**: Use descriptive directory names that reflect functionality
4. **Scalability**: Structure should accommodate future common code refactoring
5. **Discoverability**: Easy navigation without excessive hierarchies

## Directory Structure

```
tests/common2/
├── DIRECTORY_STRUCTURE.md          # This file - guidelines and structure
├── README.md                       # Overview and usage instructions
├── pytest.ini                      # Local pytest configuration
├── requirements.txt                # Dependencies for common2 modules
├── __init__.py                     # Package initialization
├──
├── routing/                        # Routing protocol utilities
│   ├── __init__.py
│   ├── bgp/                        # BGP-specific utilities
│   │   ├── __init__.py
│   │   ├── bgp_route_control.py    # ExaBGP route management
│   │   └── bgp_helpers.py          # BGP test helpers
│   ├── ospf/                       # OSPF utilities (future)
│   └── static/                     # Static routing utilities (future)
├──
├── switching/                      # Layer 2 switching utilities
│   ├── __init__.py
│   ├── vlan/                       # VLAN management utilities
│   ├── fdb/                        # FDB utilities
│   └── stp/                        # STP/RSTP utilities (future)
├──
├── platform/                       # Platform-specific utilities
│   ├── __init__.py
│   ├── hardware/                   # Hardware abstraction utilities
│   ├── drivers/                    # Driver interaction utilities
│   └── thermal/                    # Thermal management utilities
├──
├── network/                        # Core networking utilities
│   ├── __init__.py
│   ├── interface/                  # Interface management
│   ├── ip/                         # IP address utilities
│   └── packet/                     # Packet manipulation utilities
├──
├── security/                       # Security-related utilities
│   ├── __init__.py
│   ├── acl/                        # ACL management utilities
│   ├── auth/                       # Authentication utilities
│   └── macsec/                     # MACsec utilities
├──
├── monitoring/                     # Monitoring and telemetry utilities
│   ├── __init__.py
│   ├── sflow/                      # sFlow utilities
│   ├── telemetry/                  # Telemetry utilities
│   └── logs/                       # Log analysis utilities
├──
├── qos/                           # QoS utilities
│   ├── __init__.py
│   ├── pfc/                       # PFC utilities
│   └── scheduler/                 # QoS scheduler utilities
├──
├── system/                        # System-level utilities
│   ├── __init__.py
│   ├── config/                    # Configuration management
│   ├── reboot/                    # System reboot utilities
│   └── health/                    # Health check utilities
├──
├── utilities/                     # Cross-cutting utilities
│   ├── __init__.py
│   ├── connection/               # Connection management
│   ├── validation/               # Data validation helpers
│   ├── templates/                # Template utilities
│   └── helpers/                  # Generic helper functions
├──
└── unit_tests/                   # Unit tests for common2 modules
    ├── __init__.py
    ├── routing/
    ├── switching/
    ├── platform/
    └── ...
```

## Module Placement Guidelines

### When to Create a New Directory

1. **Feature Domain**: When refactoring utilities for a major SONiC feature (BGP, ACL, QoS, etc.)
2. **Logical Grouping**: When you have 3+ related utility files
3. **Cross-Test Usage**: When utilities are used by multiple test modules

### Naming Conventions

- **Directories**: Use singular nouns when possible (`routing`, not `routings`)
- **Files**: Use descriptive names with underscores (`bgp_route_control.py`)
- **Modules**: Follow Python naming conventions (snake_case)

### File Organization Within Directories

- **Core Functionality**: Main utility classes and functions
- **Helpers**: Supporting functions in `*_helpers.py` files
- **Constants**: Protocol/feature constants in `*_constants.py` files
- **Exceptions**: Custom exceptions in `*_exceptions.py` files

## Migration Guidelines

### From tests/common to tests/common2

1. **Identify Domain**: Determine which domain the utility belongs to
2. **Check Dependencies**: Ensure all dependencies are documented
3. **Update Imports**: Update all import statements in test modules
4. **Add Tests**: Include unit tests for the migrated functionality
5. **Update Documentation**: Update module docstrings and README files

## Adding New Utilities

1. **Check Existing Structure**: See if it fits in an existing directory
2. **Follow Conventions**: Use established naming patterns
3. **Add Documentation**: Include comprehensive docstrings
4. **Write Tests**: Add unit tests to `unit_tests/` subdirectory
5. **Update README**: Document new utilities in appropriate README files

## Domain-to-Directory Mapping

| Test Module Domain | Common2 Directory | Examples |
|-------------------|-------------------|----------|
| tests/bgp/        | routing/bgp/      | BGP route control, neighbor management |
| tests/acl/        | security/acl/     | ACL rule management, validation |
| tests/qos/        | qos/              | PFC, scheduler configuration |
| tests/platform_tests/ | platform/     | Hardware abstraction, thermal |
| tests/pc/         | switching/        | Port channel management |
| tests/vlan/       | switching/vlan/   | VLAN configuration utilities |
| tests/route/      | routing/          | Static routing, route validation |
| tests/telemetry/  | monitoring/telemetry/ | Telemetry data collection |
| tests/sflow/      | monitoring/sflow/ | sFlow configuration |
| tests/macsec/     | security/macsec/  | MACsec key management |
