# Data Flow Architecture Diagram

## Overall System Architecture

```mermaid
graph TB
    subgraph "Input Files"
        A[dut_info.json]
        B[eeprom.json]
        C[system.json] 
        D[Other category files...]
    end
    
    subgraph "Framework Processing"
        E[AttributeManager]
        F[Port Expansion Processor]
        G[Configuration Parser]
        H[Priority Resolver]
        I[Validator]
    end
    
    subgraph "Output Structure"
        J[port_attributes_dict]
        K[BASE_ATTRIBUTES]
        L[EEPROM_ATTRIBUTES]
        M[SYSTEM_ATTRIBUTES]
        N[Other Category Attributes]
    end
    
    subgraph "Validation (Optional)"
        Q[Deployment Templates]
        R[AttributeCompletenessValidator]
    end
    
    subgraph "Test Consumption"
        O[Test Cases]
        P[DUT Host Object]
    end
    
    A --> E
    B --> E
    C --> E
    D --> E
    
    E --> F
    F --> G
    G --> H
    H --> I
    
    I --> K
    I --> L
    I --> M
    I --> N
    
    K --> J
    L --> J
    M --> J
    N --> J
    
    J --> R
    Q --> R
    R --> P
    P --> O
    J --> O
    
    style A fill:#e1f5fe
    style E fill:#f3e5f5
    style J fill:#e8f5e8
    style O fill:#fff3e0
```

## Detailed Processing Flow

```mermaid
sequenceDiagram
    participant DI as dut_info.json
    participant AM as AttributeManager
    participant PP as Port Processor
    participant CP as Config Parser
    participant CF as Category Files
    participant PR as Priority Resolver
    participant PD as port_attributes_dict
    participant V as Validator
    participant TC as Test Cases
    
    TC->>AM: Initialize for DUT
    AM->>DI: Load base transceiver data
    DI-->>AM: Raw port specifications & metadata
    
    AM->>PP: Process port specifications
    PP->>PP: Expand "Ethernet4:13" → individual ports
    PP-->>AM: Individual port list
    
    AM->>CP: Parse transceiver configurations
    CP->>CP: Split "AOC-200-QSFPDD-2x100G_200G_SIDE-0xFF-0xFF"
    CP-->>AM: Parsed components
    
    AM->>PD: Create BASE_ATTRIBUTES for each port
    
    loop For each category file
        AM->>CF: Load category JSON (eeprom.json, system.json, etc.)
        CF-->>AM: Category attribute definitions
        
        loop For each port
            AM->>PR: Resolve attributes using 8-level priority
            PR->>PR: Check DUT → Vendor+PN → Deployment → Platform → Defaults
            PR-->>AM: Final attribute values
            AM->>PD: Store in CATEGORY_ATTRIBUTES
        end
    end
    
    AM->>PD: Attach to DUT host object
    
    opt Attribute Completeness Validation
        PD->>V: Validate against deployment templates
        V->>V: Compare required vs actual attributes
        V-->>PD: Validation results (pass/warn/fail)
    end
    
    PD-->>TC: Ready for test execution
```

## Data Transformation Examples

### Step 1: Port Expansion

```text
Input (dut_info.json):
{
  "dut_name_1": {
    "Ethernet4:7": {
      "vendor_name": "ACME Corp.",
      "transceiver_configuration": "AOC-100-QSFPDD-2x100G_100G_SIDE-0xFF-0xFF"
    }
  }
}

After Port Expansion:
- Ethernet4: same attributes
- Ethernet5: same attributes  
- Ethernet6: same attributes
```

### Step 2: Configuration Parsing

```text
Input: "AOC-100-QSFPDD-2x100G_100G_SIDE-0xFF-0xFF"

Parsed Components:
- cable_type: "AOC"
- speed_gbps: 100
- form_factor: "QSFPDD"
- deployment: "2x100G_100G_SIDE"
- media_lane_mask: "0xFF"
- host_lane_mask: "0xFF"
- media_lane_count: 8
- host_lane_count: 8
```

### Step 3: Attribute Merging

```text
For Ethernet4 EEPROM_ATTRIBUTES:

Priority Resolution:
1. defaults.dual_bank_supported = false
2. deployment_configurations.2x100G_100G_SIDE.dual_bank_supported = true  ← WINS
3. vendor.ACME_CORP.defaults.dual_bank_supported = false
4. No higher priority overrides found

Result: dual_bank_supported = true
```

### Step 4: Final Structure

```python
port_attributes_dict = {
    "Ethernet4": {
        "BASE_ATTRIBUTES": {
            "vendor_name": "ACME Corp.",
            "cable_type": "AOC",
            "speed_gbps": 100,
            "deployment": "2x100G_100G_SIDE",
            # ... other parsed fields
        },
        "EEPROM_ATTRIBUTES": {
            "dual_bank_supported": true,
            "vdm_supported": false,
            # ... other resolved attributes
        },
        "SYSTEM_ATTRIBUTES": {
            # ... resolved system attributes
        }
    }
    # ... other ports
}
```

## Key Benefits

1. **Separation of Concerns**: Base hardware data vs. test-specific attributes
2. **Modular Design**: Each category file is independent
3. **Flexible Overrides**: 8-level priority system handles all scenarios
4. **Efficient Grouping**: Port ranges reduce configuration overhead
5. **Deployment Patterns**: Shared attributes for similar deployments
6. **Extensible**: Easy to add new categories and attributes