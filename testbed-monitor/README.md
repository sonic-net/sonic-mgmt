# Packet Drop Monitoring System

A comprehensive 24/7 testbed monitoring solution for SONiC devices that detects, analyzes, and alerts on packet drops across multiple testbed device.

## Overview

This system provides real-time monitoring of packet drops across testbed infrastructure with specialized analyzers for different drop categories:

- **Interface Drops**: RX/TX drop counters with utilization metrics, based on show int counter command
- **Drop Reasons**: Categorized drop analysis (L2/L3, ACL, MTU, etc.), based on config. version of show dropcounter count command
- **Queue Drops**: Per-queue congestion analysis, based on show queue counters command
- **Priority Group Drops**: Priority-based drop monitoring, based on pg-drop -c show command
- **NPU/ASIC Drops**: Hardware-level drop counters, based on show platform npu counters command
- **PFCWD Statistics**: Priority Flow Control Watchdog monitoring, based on show pfcwd stat command
- **Core File Detection**: System crash monitoring, based on detection on if a new core file has been added to a device

## Architecture

The system uses a modular analyzer architecture where each monitoring layer is handled by a dedicated analyzer:

```
packet_drop_monitor.py (Main Orchestrator)
├── crawler_main.py (Data Collection Engine)
├── interface_drop_analyzer.py (Interface Counter Analysis)
├── drop_reason_analyzer.py (Drop Categorization)
├── queue_counter_analyzer.py (Queue-Level Monitoring)
├── pg_drop_analyzer.py (Priority Group Analysis)
├── npu_drop_analyzer.py (NPU/ASIC Hardware Monitoring)
├── pfcwd_analyzer.py (PFCWD Statistics)
├── core_file_analyzer.py (System Health Monitoring)
└── splunk_output.py (Splunk Integration) -> Look at section towards the end called Creating a Splunk Instance for more details on how to activate Splunk output
```

## Quick Start

### Configuration Setup

Edit `testbed_info.yml` with your device information (or add a new .yml):

```yaml
all:
  command_timeout: 30
  children:
    dut_group:
      hosts:
        DEVICE-NAME-1:
          ansible_host: "10.1.1.100"
          ansible_user: "admin"
          ansible_password: "password"
        DEVICE-NAME-2:
          ansible_host: "10.1.1.101"
          ansible_user: "admin"
          ansible_password: "password"

  commands:
    - show int counter -d all
    - show dropcounter count
    - show queue counters -d all
    - pg-drop -c show
    - sudo show platform npu counters
    - show pfcwd stat

# Splunk Configuration (Optional)
splunk:
  hec_url: "https://your-splunk-server:8088"
  hec_token: "PLEASE ADD SPLUNK TOKEN HERE"
  index: "main"
  source: "packet_drop_monitor"
  sourcetype: "_json"
  verify_ssl: false
  timeout: 30
```

### Basic Usage

```bash
# Start 24/7 monitoring with default settings (alerts printed to console)
python3 packet_drop_monitor.py

# Use custom database location, by default database is stored by timestamp and in a home directory folder called packet_monitor_data
python3 packet_drop_monitor.py --db /path/to/database/

# Use custom config file, default uses example .yml in the commit, being testbed_info.yml
python3 packet_drop_monitor.py --config my_testbed.yml

# Send data to Splunk (in addition to normal console alerts)
python3 packet_drop_monitor.py --output splunk

# Abort on first error (for debugging)
python3 packet_drop_monitor.py -E
```
## 📊 Output Modes

### Database Mode (Default)
- **Storage**: Local SQLite database
- **Location**: `~/packet_monitor_data/crawler-TIMESTAMP.db`
- **Benefits**: Local storage, no external dependencies
- **Use Case**: Development, testing, standalone monitoring

### Splunk Mode
- **Storage**: Splunk HTTP Event Collector (HEC)
- **Real-time**: Live dashboard updates
- **Benefits**: Centralized logging, advanced analytics
- **Use Case**: Production monitoring, NOC dashboards

## Command Line Options

### packet_drop_monitor.py
```bash
python3 packet_drop_monitor.py [OPTIONS]

Options:
  --db PATH              Database file or directory path
  --config FILE          YAML configuration file (default: testbed_info.yml)  
  --output MODE          Output mode: db, splunk (default: db)
  -E                     Exit on first error (default: continue)
  --help                 Show help message
```
## Supported Commands

The system supports these SONiC CLI commands:

| Command | Purpose | Analyzer |
|---------|---------|----------|
| `show int counter -d all` | Interface RX/TX drops & utilization | Interface Drop Analyzer |
| `show dropcounter count` | Categorized drop reasons | Drop Reason Analyzer |
| `show queue counters -d all` | Per-queue drop statistics | Queue Counter Analyzer |
| `pg-drop -c show` | Priority group drop counters | PG Drop Analyzer |
| `sudo show platform npu counters` | NPU/ASIC hardware drops | NPU Drop Analyzer |
| `show pfcwd stat` | PFCWD statistics | PFCWD Analyzer |

### Important Notes

- **NPU Counters**: Use `sudo show platform npu counters` (no `-n asic0` option)
- **Drop Counter Setup**: System automatically configures drop counters if needed
- **Multi-ASIC**: System automatically detects and adapts to multi-ASIC devices

## Database Schema

### Main Tables
- `crawler_logs`: Raw command outputs and parsed data
- `interface_drops_history`: Interface drop tracking
- `drop_reasons_history`: Drop reason categorization
- `queue_counters_history`: Queue-level statistics
- `pg_drops_history`: Priority group drops
- `npu_drops_history`: NPU/ASIC counters
- `pfcwd_history`: PFCWD statistics
- `core_files_history`: Core file tracking

### Database Path Logic
- **None**: Creates `~/packet_monitor_data/crawler-TIMESTAMP.db`
- **Directory**: Creates timestamped file in specified directory
- **File Path**: Uses exact file specified

## Monitoring Logic

### Interface Drops
- **Tracking**: RX/TX drop counters with utilization percentages
- **Alerts**: Any increase in drop counts between monitoring cycles
- **Baseline**: Compares current run with previous run

### Drop Reasons  
- **Tracking**: L2/L3 drops, ACL drops, MTU violations, etc.
- **Alerts**: Increase in any drop reason category
- **Categories**: 29 standard SONiC drop reason types

### Queue Drops
- **Tracking**: Per-queue drop statistics across all interfaces
- **Alerts**: Queue congestion and drop increases
- **Analysis**: Identifies specific congested queues

### NPU Drops ⚠️ **Special Behavior**
- **First Run**: Shows accumulated drops since device boot (REAL DROPS)
- **Subsequent Runs**: Shows new drops since last command (REAL DROPS)
- **Counter Reset**: Counters reset after each command execution
- **No Baseline**: Every value represents actual drops that occurred

### PFCWD Statistics
- **Tracking**: Storm detection, TX/RX drops per queue
- **Alerts**: Storm conditions and drop increases
- **Status**: Active storm monitoring

## Alert Types

### Drop Increase Alerts
- Interface drops (RX/TX)
- Drop reason increases  
- Queue congestion
- Priority group drops
- NPU/ASIC drops
- PFCWD storms

### System Health Alerts
- New core files detected
- Command execution failures
- Data processing errors

## Troubleshooting

### Common Issues

#### No Data Collected
```bash
# Check device connectivity
ssh user@device-ip
# Verify config file
python3 -c "import yaml; print(yaml.safe_load(open('testbed_info.yml')))"
# Run with error abort
python3 packet_drop_monitor.py -E
```

#### Database Permissions
```bash
# Check directory permissions
ls -la ~/packet_monitor_data/
# Create directory manually
mkdir -p ~/packet_monitor_data/
```

#### Splunk Connection Issues
```bash
# Test HEC endpoint
curl -k https://splunk-server:8088/services/collector/health
# Verify token in Splunk: Settings > Data Inputs > HTTP Event Collector
```

#### NPU Command Issues
- **Error**: "Invalid option -n asic0"
- **Solution**: Use `sudo show platform npu counters` (no ASIC option)
- **Note**: System auto-detects correct NPU command format

### Debug Mode
```bash
# Enable detailed logging
python3 packet_drop_monitor.py -E --output db

# Check specific analyzer
python3 -c "
from interface_drop_analyzer import InterfaceDropAnalyzer
analyzer = InterfaceDropAnalyzer('test.db')
analyzer.process_interface_data(123456)
"
```
### Monitoring Interval
- **Default**: 60 seconds between monitoring cycles (can be configured in .yml)
- **Recommendation**: Don't go below 30 seconds (device load)
- **Large Networks**: Consider 120+ seconds for many devices


### Splunk Token
- **Never commit tokens** to version control
- For Splunk use, paste the Splunk token in the .yml, in hec_token in the Splunk section of the .yml
- For commits, use placeholder: `"PLEASE ADD SPLUNK TOKEN HERE"`
- Consider environment variables for production

### Network Access
- Monitor systems should have read-only device access
- Use management VRF/networks when possible
- Implement proper firewall rules

## Contributing

### Code Style
- Use Python 3.5+ compatible syntax (`.format()` not f-strings)
- Follow existing analyzer patterns
- Add comprehensive error handling
- Include detailed docstrings

### Adding New Analyzers
1. Create new analyzer file: `new_analyzer.py`
2. Implement required methods:
   - `process_*_data(run_id)`
   - `analyze_*_increases(run_id)`
   - `print_*_report(data)`
3. Add to main orchestrator initialization
4. Add corresponding command to YAML config

### Adding New Commands and Analyzers - Complete Workflow

#### Step 1: Add Command to Configuration
Add your new SONiC command to the `commands` list in your `.yml` configuration file:

```yaml
all:
  commands:
    - show int counter -d all
    - show dropcounter count
    - show queue counters -d all
    - pg-drop -c show
    - sudo show platform npu counters
    - show pfcwd stat
    - your-new-command here  # Add your command
```
#### Parser Step:
If the command's output does not follow the general SONiC tabular formatted output, which has a universal parser in parse_show_output function in crawler_main.py, you will need to build a custom parser in crawler_main.py, such as the custom parser for show platform npu counters (parse_npu_counters_output function).


#### Step 2: Create New Analyzer Class
Create a new analyzer file following the established pattern. Use existing analyzers as templates:
- **Pattern Reference**: `interface_drop_analyzer.py` - Complete analyzer template
- **Database Methods**: Follow the same table creation and data processing patterns
- **Required Methods**: Implement `process_*_data()`, `analyze_*_increases()`, and `print_*_report()`

#### Step 3: Integrate with Main Orchestrator
Add your analyzer to `packet_drop_monitor.py`:
- **Initialization**: Add to the `analyzers` dictionary following existing pattern
- **Processing Loop**: Add calls to process data, analyze increases, and print reports
- **Reference**: Follow the same pattern as existing analyzers in the main loop

#### Step 4: Splunk Integration via splunk_output.py, Look at section towards the end called Creating a Splunk Instance for more details on how to activate Splunk output
The system uses `splunk_output.py` for all Splunk communication. Integration happens in two places:

**A. In your analyzer's process method** - Add a `splunk_client` parameter:
```python
def process_your_data(self, run_id, splunk_client=None):
    # ... your existing processing code ...
    
    # Send data to Splunk if client available
    if splunk_client:
        data_to_send = {
            'analyzer_type': 'your_analyzer_type',
            'device_name': device_name,
            'your_metric_field': metric_value,
            'run_id': run_id
            # Add your specific fields here
        }
        splunk_client.store_drop_data(device_name, 'your_analyzer_type', data_to_send)
```

**B. In the main orchestrator** - Pass the splunk_client to your analyzer, look at interface_drop_analyzer.py for an example on what to do for Splunk integration

**Splunk Data Structure**: The `splunk_output.py` module handles:
- **HEC Event Wrapping**: Wraps your data in proper HEC format with time, index, source, sourcetype
- **Data Sanitization**: Converts datetime objects to ISO format strings for JSON compatibility
- **Predefined Field Schema**: Creates standardized `event_data` structure with fields like:
  - `event_type: "drop_counter"`, `timestamp`, `device_name`, `analyzer_type`
  - Interface fields: `interface_name`, `rx_drops`, `tx_drops`, `rx_util`, `tx_util`
  - NPU fields: `dut_name`, `asic_id`, `counter_type`, `drop_count`
  - PFCWD fields: `storm_detected`, `storm_restored`, `tx_ok`, `rx_ok`
  - And 20+ other predefined fields (see `store_drop_data` method for complete list)
  - For additional commands, add fields of the command output that user wants monitored to the event_data dictionary, similar to the other fields, and specify with a comment what command output the field belongs to
- **Connection Management**: Handles SSL, authentication, timeouts, and HTTP requests
- **Error Handling**: Catches HTTP errors, URL errors, and logs detailed error information (no retry logic)

#### Step 5: Create Splunk Dashboard
Create a new XML dashboard file for your analyzer. **Reference Template**: Use `interface_monitoring_dashboard.xml` as your starting template - it contains all the standard patterns:

- **Device Summary Panel**: Shows which devices have data
- **Metrics Over Time**: Line charts for trend analysis  
- **Top N Panels**: Tables showing highest values
- **Increment Tracking**: Logic for detecting new drops vs. total counters
- **Time Windows**: Standard time ranges (`-14d@d`, `-24h@h`)
- **Refresh Rates**: Appropriate refresh intervals for different panel types

**Dashboard Creation Process**:
1. Copy `interface_monitoring_dashboard.xml` as your template
2. Replace `analyzer_type="interface"` with your analyzer type
3. Update field names to match your data structure
4. Modify panel titles and descriptions
5. Adjust queries for your specific metrics

#### Step 6: Import Dashboard to Splunk
1. **Save Dashboard XML**: Copy your modified XML code
2. **Access Splunk Web**: Log into your Splunk instance
3. **Navigate to Dashboards**: Apps → Search and Reporting → Dashboards → Create New Dashboard → Source → Paste the XML and save the source code

#### Step 7: Dashboard Design Tips
**Reference Examples**: Study existing dashboards like `interface_monitoring_dashboard.xml` for:
- **Panel Layout**: How rows and panels are structured
- **Search Queries**: How to filter and aggregate your data using `analyzer_type` field
- **Time Ranges**: Use appropriate time windows (`-14d@d`, `-24h@h`, etc.)
- **Refresh Rates**: Balance between real-time updates and system load
- **Formatting**: Color coding, number formatting, conditional formatting

**Key Query Patterns** (replace "interface" with your analyzer_type):
- Device listing: `index=main analyzer_type="your_type" | stats latest(_time) by device_name`
- Trend analysis: `index=main analyzer_type="your_type" | timechart span=5m sum(your_metric)`
- Top devices: `index=main analyzer_type="your_type" | stats sum(your_metric) by device_name | sort - sum`

#### Step 8: Testing Your Integration
```bash
# Test your new analyzer independently
python3 your_new_analyzer.py

# Test with main system (database mode)
python3 packet_drop_monitor.py --config your_testbed.yml -E

# Test Splunk integration
python3 packet_drop_monitor.py --output splunk --config your_testbed.yml

# Verify data in Splunk
# Search: index=main analyzer_type="your_analyzer_type"
```

#### Key Integration Points with splunk_output.py

**splunk_output.py handles**:
- **Connection Management**: HEC endpoint, token authentication, SSL verification
- **Data Formatting**: Automatic timestamp addition, JSON serialization, field mapping
- **Error Handling**: Connection failures, retry logic, timeout management
- **Event Structure**: Standardized event format across all analyzers

**Your analyzer needs to**:
- Accept `splunk_client` parameter in processing methods
- Call `splunk_client.store_drop_data(device_name, analyzer_type, data_dict)`
- Structure data as a dictionary with your specific fields
- Let `splunk_output.py` handle all Splunk communication details

**Data Flow**: `Your Analyzer` → `splunk_output.py` → `Splunk HEC` → `Splunk Index` → `Dashboard`

#### Common Pitfalls to Avoid
1. **Command Parsing**: Test your parsing logic with various device outputs
2. **Database Schema**: Ensure your table schema matches your data structure
3. **Error Handling**: Add proper error handling for command failures
4. **Splunk Field Names**: Use consistent field names across events
5. **Dashboard Queries**: Test Splunk queries independently before adding to dashboard
6. **Time Zones**: Ensure timestamp consistency between system and Splunk

## Support

### Log Locations
- **Console Output**: Real-time monitoring progress
- **Database**: `~/packet_monitor_data/crawler-*.db`
- **Splunk**: Search index for events and alerts

### Common Queries

#### Database Queries
```sql
-- Recent interface drops
SELECT * FROM interface_drops_history WHERE run_id = (SELECT MAX(run_id) FROM interface_drops_history);

-- Drop reason trends  
SELECT drop_reason, SUM(drop_count) FROM drop_reasons_history GROUP BY drop_reason ORDER BY SUM(drop_count) DESC;

-- NPU drops
SELECT * FROM npu_drops_history WHERE drop_count > 0 ORDER BY drop_count DESC;
```

#### Splunk Queries
```splunk

index=main source=packet_drop_monitor analyzer_type=interface

# Drop increases
index=main source=packet_drop_monitor "drop increase"

# NPU alerts
index=main source=packet_drop_monitor analyzer_type=npu drop_count>0
```

### Creating a Splunk Instance
Create a Splunk Enterprise account. Then go to https://dev.splunk.com/enterprise/dev_license/ , and submit the needed forms. Then, wait for until the license information is sent to your email that you used for account creation. 

After you receive the license, download and install Splunk Enterprise on where you want to run the testbed monitoring scripts from (should be a Ubuntu server with root/sudo access). 

Then, Start Splunk for First Time: sudo /opt/splunk/bin/splunk start --accept-license Set an admin username and password when prompted. Wait until Splunk reports: The Splunk web interface is at http://<your-ip>:8000. Then, open your browser and visit the web interface, and login using the credentials you provided. 

Once logged in: Navigate to: Settings → Licensing Click: Add License. Upload the .lic file you received from Splunk. Confirm license is active. 

Enable the HTTP Event Collector (HEC) To send data from Python via REST API: Navigate to: Settings → Data Inputs → HTTP Event Collector, Click: New Token, and put in the information you want (and update .yml in the way you added the HEC information), as an example, look at testbed_info.yml. 

If you are unable to enter the web interface at some point (Note: This changes file ownership. It is acceptable for a personal dev setup, but do not do this on production systems): 
1. Stop Splunk (if it’s running): sudo /opt/splunk/bin/splunk stop 
2. Change ownership of all Splunk files to cisco: sudo chown -R cisco:cisco /opt/splunk 
3. Now run Splunk as cisco: /opt/splunk/bin/splunk start

Current Splunk Dashboards Made Previously: https://wiki.cisco.com/pages/viewpage.action?pageId=1558102025 (access info given there as well), in Crawler and Splunk Dashboards section of page