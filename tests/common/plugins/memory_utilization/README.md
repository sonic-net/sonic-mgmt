# Memory Utilization Plugin for SONiC Testing

## Table of Contents
- [Overview](#overview)
- [Plugin Design](#plugin-design)
  - [Configuration Files](#configuration-files)
  - [Memory Item Structure](#memory-item-structure)
  - [Threshold Types](#threshold-types)
  - [Behavior for Combined Thresholds](#behavior-for-combined-thresholds)
  - [Workflow](#workflow)
- [Usage Guide](#usage-guide)
  - [Enabling and Disabling](#enabling-and-disabling)
  - [Configuration Examples](#configuration-examples)
- [Supported Memory Monitors](#supported-memory-monitors)
  - [Monit Status Monitor](#monit-status-monitor)
  - [Free Memory Monitor](#free-memory-monitor)
  - [Docker Stats Monitor](#docker-stats-monitor)
  - [Top Monitor](#top-monitor)
  - [FRR Memory Monitor](#frr-memory-monitor)
- [Advanced Usage](#advanced-usage)
  - [Global Memory Items](#global-memory-items)
  - [HWSKU-Specific Memory Items](#hwsku-specific-memory-items)
  - [Test-Specific Memory Items](#test-specific-memory-items)
- [Troubleshooting](#troubleshooting)

## Overview

During testing, memory usage on the Device Under Test (DUT) can vary due to different configurations, environment setups, and test operations. To ensure safe memory resource utilization, this plugin checks memory usage before and after tests to verify that:

1. Memory usage doesn't exceed high memory thresholds
2. No memory leaks occur during test execution
3. Memory increases stay within acceptable limits

The memory utilization plugin automatically monitors memory resources and generates test failures when thresholds are exceeded.

## Plugin Design

### Memory Utilization Plugin Summary

The memory utilization plugin for SONiC testing automatically monitors memory usage on the Device Under Test (DUT) before and after each test. Its main goals are to ensure that memory usage does not exceed configured thresholds and to detect memory leaks or abnormal increases during test execution.

**Key Features:**
- **Automatic Monitoring:** Runs for all tests unless explicitly disabled.
- **Configurable Thresholds:** Uses JSON files to define memory checks, commands, and thresholds (absolute values or percentages).
- **Multiple Monitors:** Supports system memory, process memory, docker containers, and FRR daemons.
- **Flexible Scope:** Allows global, HWSKU-specific, and test-specific configuration.
- **Failure Reporting:** Fails tests with detailed messages if thresholds are exceeded.

**How It Works:**
1. **Pre-test:** Collects baseline memory usage using configured commands and parsers.
2. **Post-test:** Collects memory usage again and compares with baseline.
3. **Validation:** Checks if usage exceeds high thresholds or if increase is above allowed limits.
4. **Reporting:** Fails the test if any check fails, with clear diagnostics.

**Configuration:**
- Thresholds can be absolute values, percentages, or both (the strictest applies).
- Can be disabled globally or per-test.
- Easily extendable for new memory monitors or custom thresholds.

This plugin helps maintain system stability and quickly identifies memory-related issues during SONiC test runs.

### Configuration Files

The plugin uses two JSON configuration files:

1. **memory_utilization_common.json** - Common configurations for all platforms
   - Used in public branches
   - Contains the `COMMON` section with default memory items

2. **memory_utilization_dependence.json** - Platform-specific configurations
   - Used primarily in internal branches
   - Contains a `COMMON` section that overrides common.json if needed
   - Contains `HWSKU` section for hardware-specific thresholds

### Memory Item Structure

Each memory item in the configuration includes:

| Field | Description |
|-------|-------------|
| `name` | Identifier for the memory check item |
| `cmd` | Shell command to execute on the DUT |
| `memory_params` | Dictionary of items to monitor with their thresholds |
| `memory_check` | Function name used to parse command output |

Each `memory_params` entry can define:
- `memory_high_threshold`: Maximum acceptable value (fails if exceeded)
- `memory_increase_threshold`: Maximum acceptable increase (fails if exceeded)

### Threshold Types

Memory thresholds must be defined using the following structured formats:

1. **Absolute value threshold**:
   ```json
   "memory_high_threshold": {
     "type": "value",
     "value": 128
   }
   ```

2. **Percentage threshold**:
   ```json
   "memory_increase_threshold": {
     "type": "percentage",
     "value": "10%"
   }
   ```

3. **Combined thresholds** (when you want both types):
   ```json
   "memory_high_threshold": [
     {"type": "value", "value": 128},
     {"type": "percentage", "value": "75%"}
   ]
   ```

4. **Disabled threshold**:
   ```json
   "memory_high_threshold": null
   ```
   This explicitly disables high threshold checking for this item.

### Behavior for Combined Thresholds

When thresholds include both **value** and **percentage** types, the plugin calculates both thresholds and applies the most restrictive one (i.e., the smallest value).

For example:
- If `memory_increase_threshold` includes:
  ```json
  [
    {"type": "value", "value": 128},
    {"type": "percentage", "value": "10%"}
  ]
  ```
  and the baseline memory usage is `1000`, the plugin will calculate:
  - Absolute value threshold: `128`
  - Percentage threshold: `10% of 1000 = 100`
  - The plugin will use `100` as the threshold since it is the smaller value.

This ensures that the plugin enforces the strictest memory usage limits.

### Workflow

1. **Before Test**:
   - Executes each command in the configuration
   - Parses output using the specified function
   - Stores baseline memory values

2. **After Test**:
   - Executes the same commands again
   - Parses output to get current memory values
   - Compares with baseline and thresholds

3. **Validation**:
   - Checks if current values exceed high thresholds
   - Checks if increases exceed increase thresholds
   - Fails the test if any threshold is exceeded

## Usage Guide

### Enabling and Disabling

Memory utilization checking is enabled by default for all tests. To disable it:

1. **For all test cases**:
   - Use the command line option `--disable_memory_utilization`

2. **For specific test cases**:
   - Add the `disable_memory_utilization` marker:
   ```python
   pytestmark = [
       pytest.mark.disable_memory_utilization
   ]
   ```

## Supported Memory Monitors and Configuration Examples

### Monit Status Monitor

Monitors system memory usage via Monit.

- **Command**: `sudo monit status`
- **Parser Function**: `parse_monit_status_output`
- **Monitored Parameters**:
  - `memory_usage`: System memory utilization percentage

Example configuration:
```json
{
  "name": "monit",
  "cmd": "sudo monit status",
  "memory_params": {
    "memory_usage": {
      "memory_increase_threshold": {
        "type": "value",
        "value": 5
      },
      "memory_high_threshold": {
        "type": "value",
        "value": 75
      }
    }
  },
  "memory_check": "parse_monit_status_output"
}
```

### Free Memory Monitor

Monitors available system memory.

- **Command**: `free -m`
- **Parser Function**: `parse_free_output`
- **Monitored Parameters**:
  - `used`: Used memory in MB

Example configuration:
```json
{
  "name": "free",
  "cmd": "free -m",
  "memory_params": {
    "used": {
      "memory_increase_threshold": {
        "type": "percentage",
        "value": "10%"
      },
      "memory_high_threshold": null
    }
  },
  "memory_check": "parse_free_output"
}
```

### Docker Stats Monitor

Monitors memory usage of Docker containers.

- **Command**: `docker stats --no-stream`
- **Parser Function**: `parse_docker_stats_output`
- **Monitored Parameters**:
  - Multiple container names (snmp, pmon, lldp, etc.)
  - Each container's memory usage as a percentage

Example configuration:
```json
{
  "name": "docker",
  "cmd": "docker stats --no-stream",
  "memory_params": {
    "snmp": {
      "memory_increase_threshold": {
        "type": "value",
        "value": 2
      },
      "memory_high_threshold": {
        "type": "value",
        "value": 4
      }
    },
    "swss": {
      "memory_increase_threshold": {
        "type": "value",
        "value": 2
      },
      "memory_high_threshold": {
        "type": "value",
        "value": 8
      }
    }
  },
  "memory_check": "parse_docker_stats_output"
}
```

### Top Monitor

Monitors memory usage of specific processes.

- **Command**: `top -b -n 1`
- **Parser Function**: `parse_top_output`
- **Monitored Parameters**:
  - Process names (bgpd, zebra, etc.)
  - Each process's memory usage in MB (from RES column)

Example configuration:
```json
{
  "name": "top",
  "cmd": "top -b -n 1",
  "memory_params": {
    "bgpd": {
      "memory_increase_threshold": {
        "type": "value",
        "value": 128
      },
      "memory_high_threshold": null
    },
    "zebra": {
      "memory_increase_threshold": {
        "type": "value",
        "value": 64
      },
      "memory_high_threshold": null
    }
  },
  "memory_check": "parse_top_output"
}
```

### FRR Memory Monitor

Monitors memory usage of FRR routing daemons.

- **Commands**:
  - `vtysh -c "show memory bgp"`
  - `vtysh -c "show memory zebra"`
- **Parser Function**: `parse_frr_memory_output`
- **Monitored Parameters**:
  - `used`: Memory usage in MB

Example configuration:
```json
{
  "name": "frr_bgp",
  "cmd": "vtysh -c \"show memory bgp\"",
  "memory_params": {
    "used": {
      "memory_increase_threshold": [
        {"type": "percentage", "value": "10%"},
        {"type": "value", "value": 5}
      ],
      "memory_high_threshold": {
        "type": "value",
        "value": 128
      }
    }
  },
  "memory_check": "parse_frr_memory_output"
}
```

## Advanced Usage

### HWSKU-Specific Memory Items

To define HWSKU-specific configurations in memory_utilization_dependence.json:

1. Define the `HWSKU` section mapping collection names to specific SKUs
2. Create sections using collection names containing memory items for those SKUs

Example:
```json
{
  "HWSKU": {
    "Arista-7050QX": ["Arista-7050-QX-32S", "Arista-7050-QX32", "Arista-7050QX-32S-S4Q31", "Arista-7050QX32S-Q32"]
  },
  "Arista-7050QX": [
    {
      "name": "monit",
      "cmd": "sudo monit status",
      "memory_params": {
        "memory_usage": {
          "memory_increase_threshold": {
            "type": "value",
            "value": 5
          },
          "memory_high_threshold": {
            "type": "value",
            "value": 85
          }
        }
      },
      "memory_check": "parse_monit_status_output"
    }
  ]
}
```

In this example, specific Arista SKUs will use a higher memory_high_threshold (85 instead of 75).

### Test-Specific Memory Items

You can modify or add memory items within individual tests by:
1. Modifying thresholds of existing items
2. Registering new memory monitors

```python
def test_case_example(duthosts, enum_frontend_dut_hostname, memory_utilization):
    # Get memory monitors and values
    memory_monitors, memory_values = memory_utilization

    # Get memory monitor for the current DUT
    duthost = duthosts[enum_frontend_dut_hostname]
    memory_monitor = memory_monitors[duthost.hostname]

    # Update existing monitor thresholds or register new monitors
    # ...existing code...
```

## Troubleshooting

When a memory threshold is exceeded, the plugin will fail the test with a detailed message showing:
- The name of the memory item that triggered the failure
- The specific memory parameter that exceeded the threshold
- The current value compared to the threshold value
- Additional contextual information about memory usage

Example failure message:
```
[ALARM]: frr_bgp:used memory usage increased by 15.5, exceeds increase threshold 5%
```

Common troubleshooting steps:
1. Check if the thresholds are appropriate for your test environment
2. Verify if the memory increase is expected due to test operations
3. Analyze the DUT logs for potential memory leaks or resource issues
4. For persistent issues, consider increasing the threshold or disabling the specific check
