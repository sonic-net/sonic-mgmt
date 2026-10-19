# Console Logging Test Plan

- [Console Logging Test Plan](#console-logging-test-plan)
  - [1 Background](#1-background)
  - [2 Scope](#2-scope)
  - [3 Testbed Setup](#3-testbed-setup)
    - [3.1 Topology and DUT role](#31-topology-and-dut-role)
    - [3.2 Preconditions](#32-preconditions)
    - [3.3 CLI and CONFIG_DB](#33-cli-and-config_db)
    - [3.4 Test utilities and fixtures](#34-test-utilities-and-fixtures)
  - [4 Test Cases](#4-test-cases)
    - [4.1 Enable logging and default configuration](#41-enable-logging-and-default-configuration)
    - [4.2 Console output capture](#42-console-output-capture)
    - [4.3 Disable logging](#43-disable-logging)
    - [4.4 Custom log path and logrotate options](#44-custom-log-path-and-logrotate-options)
    - [4.5 Reject invalid logrotate options](#45-reject-invalid-logrotate-options)
    - [4.6 Reject invalid log file paths](#46-reject-invalid-log-file-paths)
    - [4.7 Reject symlink log paths](#47-reject-symlink-log-paths)
    - [4.8 Log rotation on size threshold](#48-log-rotation-on-size-threshold)
    - [4.9 Rotated backup retention count](#49-rotated-backup-retention-count)
  - [5 Automation mapping](#5-automation-mapping)
  - [6 Cleanup and recovery](#6-cleanup-and-recovery)

## 1 Background

Console logging extends the BMC **console-monitor** stack so that traffic on a configured console line can be persisted to a log file on the BMC, with **logrotate** integration. Configuration is applied through `config console logging` and stored under CONFIG_DB keys of the form `CONSOLE_PORT|{line}` (for example `CONSOLE_PORT|0`) in **CONFIG_DB**. The **console-monitor** daemon generates per-line logrotate snippets and restarts **console-monitor-proxy@{line}.service** (for example `console-monitor-proxy@0.service`) when logging settings change.

On a BMC DUT, console **line 0** is typically wired to the host CPU (`remote_device` = `SwitchCpu`). When logging is enabled on that line, the log file captures the **host CPU serial console** stream (device-to-session direction as implemented by the proxy).

For console session and monitor behavior, see [Console Monitor Test Plan](./Console-Monitor-Test-Plan.md) and the SONiC Console Monitor HLD.

## 2 Scope

This plan verifies end-to-end console logging on a **BMC SONiC** image:

- CLI enable/disable and optional `filename` / logrotate parameters
- CONFIG_DB field persistence (`logging_enabled`, `log_file`, `logrotate_size`, `logrotate_count`)
- Log file creation, capture of live console traffic, and stop-on-disable
- Generated logrotate configuration (for example `/etc/logrotate.d/console-monitor-logging-0`), including **copytruncate** so rotation does not break the proxy’s open file descriptor
- Input validation (invalid sizes, counts, paths)
- Refusal to log through a symlink path (daemon error, no writes to the symlink target)
- Size-triggered rotation and `rotate` count retention

**Out of scope:** non-BMC topologies (tests are marked `topology('bmc')` only).

## 3 Testbed Setup

### 3.1 Topology and DUT role

| Item | Requirement |
|------|-------------|
| Topology | `bmc` (BMC is the DUT under test) |
| Console lines | At least one line in `console_facts`; prefer the line whose CONFIG_DB `CONSOLE_PORT` entry has `remote_device` = `SwitchCpu` (often line `0`) |
| Host CPU | Reachable login prompt on the target console line via reverse SSH (`consutil` / console server credentials from testbed) |
| Image | `config console logging --help` present; `/usr/local/bin/console-monitor` implements `logging_enabled` handling |

Wiring (logical, line `0` as example):

```text
+--------------------------- BMC SONiC (DUT) ---------------------------+
|                                                                       |
|   console-monitor-proxy@0  ----writes---->  /var/log/console-0.log   |
|            |                                                          |
+------------|----------------------------------------------------------+
             |
             |  serial console line (SwitchCpu)
             v
+--------------------------- Switch host CPU ---------------------------+
|                         serial console / getty                          |
+-----------------------------------------------------------------------+
```

### 3.2 Preconditions

Before each test function (autouse fixtures):

1. **Feature present:** `sudo config console logging --help` succeeds; `console-monitor` script references logging support.
2. **Proxy ready:** Automation **waits** (up to ~20 s) until `console-monitor-proxy@{line}.service` reports `ActiveState=active`, including after logging config teardown from the previous test (proxy may be mid-restart).
3. **LogAnalyzer:** Tests use `@pytest.mark.disable_loganalyzer` because logging changes restart the proxy and produce expected service messages.

Before driving the host CPU console (marker tests), automation also **waits** (up to ~180 s) until `show chassis module status` lists **SWITCH-HOST** with **Oper-Status** `Online` and **Admin-Status** `up`. If SWITCH-HOST is missing from the table, the test fails immediately rather than attempting the console session.

Module-level skip applies if the feature is absent on the image.

### 3.3 CLI and CONFIG_DB

**User interface (BMC):**

```text
config console logging <line> enable
config console logging <line> disable
config console logging <line> filename <absolute_path> [--logrotate-size <size>] [--logrotate-count <count>]
```

**CONFIG_DB** (key pattern `CONSOLE_PORT|{line}`, example `CONSOLE_PORT|0`):

| Field | Description |
|-------|-------------|
| `logging_enabled` | `yes` when enabled; `no` or absent after disable |
| `log_file` | Absolute path to the active log file |
| `logrotate_size` | Size threshold (e.g. `10M`, `1k`) |
| `logrotate_count` | Number of rotated backups to retain |

**STATE_DB** (same key `CONSOLE_PORT|{line}`; written by **console-monitor-proxy**):

| Field | Description |
|-------|-------------|
| `logging_status` | `disabled` when logging is off or no log path; `active` when the log file is open; `failed` when open fails |
| `logging_error` | Present only while `logging_status` is `failed` |
| `oper_state` / `last_state_change` | Existing proxy operational fields (unchanged by logging) |

**Defaults after `enable` (no `filename`)** for line `0`:

| Setting | Default |
|---------|---------|
| `log_file` | `/var/log/console-0.log` |
| `logrotate_size` | `10M` |
| `logrotate_count` | `10` |

**Generated artifacts** (line `0` shown as example):

- Logrotate: `/etc/logrotate.d/console-monitor-logging-0`
- Proxy unit: `console-monitor-proxy@0.service`

### 3.4 Test utilities and fixtures

| Utility / fixture | Purpose |
|-------------------|---------|
| `target_line` | Console line under test (`SwitchCpu` line if present, else lowest configured line) |
| `require_proxy_running` | Autouse: waits for `console-monitor-proxy@{line}` to be `active` at the start of each test |
| `preserve_logging_config` | Snapshots and restores CONFIG_DB logging fields; removes test log files and logrotate snippet if created by the test |
| `wait_for_switch_host_online` | Waits for SWITCH-HOST `Online` / admin `up` in `show chassis module status` before console marker traffic |
| `emit_console_marker` | Calls `wait_for_switch_host_online`, then opens reverse-SSH console session, wakes getty, types a unique marker, drains echo to the log, sends Ctrl-U (no command executed on host CPU) |
| `wait_for_proxy_active` | Waits for proxy `active` after logging CLI changes (~20 s timeout) |

**Marker capture note:** Only traffic that flows through the proxied session path is logged; the test deliberately drives the **far-end echo** so the marker appears in the log without submitting a shell command on the host CPU.

## 4 Test Cases

In the tables below, `{line}` is the target console line id (same value as `target_line` in automation, often `0`).

### 4.1 Enable logging and default configuration

| Item | Detail |
|------|--------|
| **Objective** | Verify `enable` applies defaults, creates the log file, and generates a correct logrotate configuration. |
| **Test steps** | 1. `config console logging {line} disable` (clean slate).<br>2. `config console logging {line} enable`.<br>3. Confirm CONFIG_DB logging fields for that line match section 3.3 (e.g. `HGET` per field or `HGETALL` on the line’s `CONSOLE_PORT` key).<br>4. Confirm log file exists.<br>5. Read `/etc/logrotate.d/console-monitor-logging-{line}`. |
| **Expected result** | `logging_enabled=yes`, `log_file=/var/log/console-{line}.log`, `logrotate_size=10M`, `logrotate_count=10`. Log file present. Logrotate config references the log path, includes `copytruncate`, `size 10M`, and `rotate 10`. |

Example CONFIG_DB check (substitute line id for `0`):

```bash
sudo sonic-db-cli CONFIG_DB HGETALL 'CONSOLE_PORT|0'
```

### 4.2 Console output capture

| Item | Detail |
|------|--------|
| **Objective** | Verify enabled logging writes live console traffic to the log file. |
| **Test steps** | 1. Enable logging; wait for log file and active proxy.<br>2. Truncate the log file.<br>3. Emit a unique console marker via reverse SSH on line `{line}`.<br>4. `grep` the marker in the log file (poll up to ~20 s). |
| **Expected result** | Marker string appears at least once in `/var/log/console-{line}.log`. |

### 4.3 Disable logging

| Item | Detail |
|------|--------|
| **Objective** | Verify `disable` stops capture and removes the logrotate snippet. |
| **Test steps** | 1. Enable logging; truncate log; emit marker **A**; confirm **A** in log.<br>2. `config console logging {line} disable`.<br>3. Confirm `logging_enabled` is `no` or absent.<br>4. Confirm logrotate config file is removed.<br>5. Truncate log; emit marker **B**; wait briefly.<br>6. Confirm **B** is **not** in the log. |
| **Expected result** | Capture works before disable; after disable, no new markers in the log and no `/etc/logrotate.d/console-monitor-logging-{line}`. |

### 4.4 Custom log path and logrotate options

| Item | Detail |
|------|--------|
| **Objective** | Verify custom `filename`, `--logrotate-size`, and `--logrotate-count` are honored in CONFIG_DB, on disk, and in logrotate. |
| **Test steps** | 1. Enable logging.<br>2. `config console logging {line} filename /var/log/console-mgmt-{unique}.log --logrotate-size 1M --logrotate-count 3`.<br>3. Verify CONFIG_DB fields.<br>4. Wait for custom log file and regenerated logrotate config.<br>5. Emit marker; confirm it appears in the custom log path. |
| **Expected result** | `log_file`, `logrotate_size=1M`, `logrotate_count=3` in CONFIG_DB; custom file exists; logrotate contains custom path, `size 1M`, `rotate 3`; marker captured in custom file. |

### 4.5 Reject invalid logrotate options

| Item | Detail |
|------|--------|
| **Objective** | Invalid rotation options are rejected without mutating CONFIG_DB. |
| **Test steps** | 1. Enable logging; snapshot all logging CONFIG_DB fields.<br>2. For each bad option below, run `config console logging {line} filename /var/log/console-invalid.log {bad_option}` and expect non-zero exit.<br>3. Compare CONFIG_DB to snapshot. |
| **Variants** | `--logrotate-size 10X`; `--logrotate-size M`; `--logrotate-count 0`; `--logrotate-count 101` |
| **Expected result** | CLI fails for every variant; CONFIG_DB unchanged from snapshot. |

### 4.6 Reject invalid log file paths

| Item | Detail |
|------|--------|
| **Objective** | Invalid log paths are rejected; path must be absolute and must not contain whitespace or curly braces. |
| **Test steps** | 1. Enable logging; snapshot CONFIG_DB.<br>2. For each bad path, run `config console logging {line} filename '{bad_path}'` (quoted as needed); expect failure.<br>3. Compare CONFIG_DB to snapshot. |
| **Variants** | Relative path `console-relative-{id}.log`; path with space `/var/log/console bad-{id}.log`; path with braces `/var/log/console-{id}.log` with literal `{` `}` in the name |
| **Expected result** | CLI fails for every variant; CONFIG_DB unchanged. |

### 4.7 Reject symlink log paths

| Item | Detail |
|------|--------|
| **Objective** | CLI may accept a symlink path, but **console-monitor** must not write through it. |
| **Test steps** | 1. Create target file and symlink `ln -s {target} {symlink_path}`.<br>2. Enable logging; set `filename` to the symlink path.<br>3. Wait for active proxy.<br>4. Check `/var/log/syslog` for `Failed to open log file {symlink_path}`.<br>5. Emit console marker.<br>6. Read symlink target file content. |
| **Expected result** | Syslog reports open failure on the symlink path; symlink **target** remains empty (no console data written via symlink). |

### 4.8 Log rotation on size threshold

| Item | Detail |
|------|--------|
| **Objective** | Logrotate rotates only when size exceeds the configured threshold; **copytruncate** keeps the proxy writing to the same inode after rotation; logging continues after rotation. |
| **Test steps** | 1. Enable logging with `filename /var/log/console-{line}.log`, `--logrotate-size 1k`, `--logrotate-count 3`.<br>2. Clear logrotate status for the log path; truncate log; remove old `log.N` artifacts.<br>3. Append ~900 bytes; run `logrotate` on the generated config (no `-f`).<br>4. Confirm no `log.1` created.<br>5. Truncate; append ~1100 bytes; record inode of active log; run `logrotate`.<br>6. Confirm `log.1` or `log.1.gz` exists; inode of active log unchanged.<br>7. Truncate active log; emit marker; confirm marker in active log. |
| **Expected result** | No rotation below 1k; rotation at/above threshold; inode stable (copytruncate); post-rotation capture still works. |

### 4.9 Rotated backup retention count

| Item | Detail |
|------|--------|
| **Objective** | Only `rotate` numbered backups are kept when rotation is forced repeatedly. |
| **Test steps** | 1. Same logging setup as section 4.8 (`1k` / count `3`).<br>2. Clear status and rotated artifacts; truncate log.<br>3. Loop `rotate_count + 2` times: append ~1100 bytes; `logrotate -f` on generated config.<br>4. List `log.[0-9]*` backups. |
| **Expected result** | At most **3** backup files exist; no `log.4` / `log.5` (or `.gz` equivalents) when `rotate` is 3. |

### 4.10 STATE_DB logging runtime status

| Item | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Objective** | Verify **console-monitor-proxy** publishes `logging_status` (and `logging_error` on failure) to **STATE_DB** `CONSOLE_PORT                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |{line}`. |
| **Test steps** | 1. `config console logging {line} disable`; `HGETALL` ~expect `logging_status=disabled`, no `logging_error`.<br>2. `enable` logging with default `/var/log/console-{line}.log`; wait for log file and active proxy.<br>3. `HGETALL` ~expect `logging_status=active`, no `logging_error`.<br>4. `config console logging {line} filename /etc/console/test-{line}.log` (path that cannot be opened).<br>5. `HGETALL` again ~expect `logging_status=failed` and `logging_error` mentioning the path or 'No such file'.<br>6. Restore default log path; expect `logging_status=active` and cleared `logging_error`. |
| **Expected result** | Runtime status tracks open success/failure independently of CONFIG_DB; failed state surfaces operator-visible error text in STATE_DB.                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

Example:

```bash
sudo sonic-db-cli STATE_DB HGETALL 'CONSOLE_PORT|0'
```

## 5 Automation mapping

Automated tests live in `tests/console/test_console_logging.py`.

| Test plan section | Pytest test function |
|-------------|----------------------|
| 4.1 | `test_logging_enable_applies_defaults` |
| 4.2 | `test_logging_captures_console_output` |
| 4.3 | `test_logging_disable_stops_capture` |
| 4.4 | `test_logging_filename_and_logrotate_options` |
| 4.5 | `test_logging_rejects_invalid_logrotate_options` (parametrized) |
| 4.6 | `test_logging_rejects_invalid_filename` (parametrized) |
| 4.7 | `test_logging_rejects_symlink_filename` |
| 4.8 | `test_logging_rotates_when_size_exceeded` |
| 4.9 | `test_logging_rotate_count_retention` |
| 4.10 | `test_logging_state_db_logging_status` |

**Example run:**

```bash
pytest tests/console/test_console_logging.py --topology bmc -v
```

## 6 Cleanup and recovery

The `preserve_logging_config` fixture restores original CONFIG_DB logging fields, removes test-created log files, and deletes the logrotate snippet if the test created it. Tests that create rotated backups register `log.N` / `log.N.gz` paths for teardown removal.

If a test aborts mid-run, manually restore logging on the BMC:

```bash
sudo config console logging 0 disable
sudo sonic-db-cli CONFIG_DB HGETALL 'CONSOLE_PORT|0'
sudo systemctl status console-monitor-proxy@0.service
```
