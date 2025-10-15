# File Organization Diagram

## Transceiver Test Framework File Structure

```text
ansible/files/transceiver/inventory/
├── dut_info.json                           # Core transceiver metadata
│
├── attributes/                             # Test category attribute files
│   ├── eeprom.json                         # EEPROM test attributes
│   ├── system.json                         # System test attributes
│   ├── physical_oir.json                   # Physical OIR attributes
│   ├── remote_reseat.json                  # Remote reseat attributes
│   ├── cdb_fw_upgrade.json                 # CDB FW upgrade attributes
│   ├── dom.json                            # DOM test attributes
│   ├── vdm.json                            # VDM test attributes
│   └── pm.json                             # PM test attributes
│
└── templates/                              # Validation templates (optional)
    └── deployment_templates.json           # Attribute completeness validation
```

## File Relationships

```mermaid
graph TD
    A[dut_info.json] --> B[Framework Parser]
    C[eeprom.json] --> B
    D[system.json] --> B
    E[physical_oir.json] --> B
    F[other category files...] --> B
    
    B --> H[BASE_ATTRIBUTES]
    B --> I[EEPROM_ATTRIBUTES]
    B --> J[SYSTEM_ATTRIBUTES]
    B --> K[Other Category Attributes]
    
    H --> G[port_attributes_dict]
    I --> G
    J --> G
    K --> G
    
    G --> M{Validation Templates?}
    M -->|Yes| N[Validator]
    M -->|No| L[Test Cases]
    N --> L
    O[deployment_templates.json] --> N
    
    style A fill:#e1f5fe
    style G fill:#f3e5f5
    style L fill:#e8f5e8
    style O fill:#fff3e0
```

## Key Concepts

- **dut_info.json**: Single source of truth for transceiver hardware metadata
- **Category files**: Modular test-specific attribute definitions for each type of transceiver
- **Templates**: Optional validation templates for attribute completeness checking
- **port_attributes_dict**: Final merged data structure used by test cases
- **BASE_ATTRIBUTES**: Core transceiver info parsed from dut_info.json
- **Category-specific attributes**: Merged from respective JSON files using priority hierarchy
- **Validation**: Optional post-processing step to ensure attribute completeness