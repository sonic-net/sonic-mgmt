# CDB Firmware Upgrade Flow

## Inventory Files and Firmware Staging Flow

```mermaid
flowchart TB
    subgraph inv["Inventory files"]
        direction TB
        I_DUT["dut_info/&lt;dut_hostname&gt;.json<br/>"]
        I_BIN["cdb_firmware_binaries.json<br/>"]
        I_URL["cdb_firmware_base_url.json<br/>(optional)"]
        I_ATTR_CAT["cdb_firmware_upgrade.json<br/>(category-level attributes)"]
        I_ATTR_PN["cdb_firmware_upgrade.json<br/>(per-PN attributes)"]
    end

    subgraph mode["Transport mode resolution (per session)"]
        direction TB
        Q{"cdb_firmware_base_url.json<br/>present for this inventory?"}
        DOWN["Download mode:<br/>fetch from remote server"]
        PRE["Pre-staged mode:<br/>copy binaries to destination"]
        Q -- "Yes" --> DOWN
        Q -- "No" --> PRE
    end

    subgraph stage["DUT"]
        TMP["/tmp/cmis_cdb_firmware/ + MD5 verify against manifest"]
    end

    I_URL -- "firmware_base_url" --> Q
    I_DUT -- "per-port<br/>(vendor, PN)" --> FW_LOOKUP
    I_BIN -- "fw_binary_name + md5sum" --> FW_LOOKUP["Firmware binary<br/>lookup"]
    FW_LOOKUP --> DOWN
    FW_LOOKUP --> PRE

    DOWN --> TMP
    PRE --> TMP

    style I_BIN fill:#e1f5ff
    style I_URL fill:#fff4e1
    style I_ATTR_CAT fill:#e1ffe1
    style I_ATTR_PN fill:#e1ffe1
    style I_DUT fill:#f5e1ff
    style Q fill:#fff4e1
    style TMP fill:#ffe9d6
```

## Related documents

- See [CDB Firmware Upgrade Test Plan](../cdb_fw_upgrade_test_plan.md) for detailed attributes, file formats, and test cases.