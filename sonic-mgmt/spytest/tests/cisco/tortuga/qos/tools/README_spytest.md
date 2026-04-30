# Spytest Results Publisher

Tools for viewing and publishing spytest test results.

## Quick Start

**Quick local summary** (no upload):
```bash
python3 spytest_summary.py <results_dir>
python3 spytest_summary.py <results_dir> -f   # Show failures only
```

**Full publish** (XML + upload + dashboard):
```bash
python3 spytest_publish.py <results_dir> --profile <profile> --platform <platform>
```

## spytest_summary.py - Quick Local Summary

View test results locally without uploading anything.

```bash
# Full summary
python3 spytest_summary.py /path/to/gamut_full_run_4_29_image_40442

# Failures only
python3 spytest_summary.py /path/to/results -f
```

## spytest_publish.py - Full Workflow

### Full Workflow (Parse → XML → Upload → Import)

```bash
# Gamut G200 tests
python3 spytest_publish.py /path/to/gamut_full_run_4_29_image_40442 \
    --profile 202505c-Gamut --platform g200

# Tortuga G200 tests  
python3 spytest_publish.py /path/to/tortuga_run_results \
    --profile 202405c_tortuga --platform g200

# Tortuga Q200 tests
python3 spytest_publish.py /path/to/tortuga_q200_results \
    --profile 202505c_tortuga --platform q200
```

### Dry Run (Preview without making changes)

```bash
python3 spytest_publish.py /path/to/results --profile 202505c-Gamut --platform g200 --dry-run
```

### Generate XML Only (No upload/import)

```bash
python3 spytest_publish.py /path/to/results --profile 202505c-Gamut --platform g200 --xml-only -o tr.xml
```

### Skip Dashboard Import

```bash
python3 spytest_publish.py /path/to/results --profile 202505c-Gamut --platform g200 --skip-import
```

## Options

| Option | Description |
|--------|-------------|
| `--profile` | Profile name (required). See profiles below. |
| `--platform` | Platform/NPU: `g200`, `q200`, `p200`, `spectrum4` (required) |
| `--build` | Build ID. Auto-detected from directory name if not specified. |
| `--dry-run` | Preview all steps without executing |
| `--xml-only` | Generate XML locally, skip upload and import |
| `--skip-upload` | Skip uploading logs to server |
| `--skip-import` | Skip importing to dashboard |
| `-o, --output` | Output XML file path (for --xml-only) |
| `-v, --verbose` | Verbose output |

## Available Profiles

| Profile | Platform Dir | Description |
|---------|--------------|-------------|
| `202505c-Gamut` | No | Gamut testing (no platform subdirectory) |
| `gamut_bringup` | No | Gamut bringup testing |
| `202405c_tortuga` | Yes | Tortuga 202405c release |
| `202505c_tortuga` | Yes | Tortuga 202505c release |

### Directory Structure on Server

**Profiles WITH platform directory** (tortuga):
```
/home/sonic/test_logs_central/spytest_logs/202405c_tortuga/g200/<build>/run_logs_g200/
```

**Profiles WITHOUT platform directory** (gamut):
```
/home/sonic/test_logs_central/spytest_logs/202505c-Gamut/<build>/run_logs_g200/
```

## Dashboard

- **URL**: http://sonic-ucs-m6-51:5005
- **API Docs**: http://sonic-ucs-m6-51:5005/api-docs

## Server Details

- **Host**: sonic-ucs-m6-51
- **User**: sonic
- **Base Path**: `/home/sonic/test_logs_central/spytest_logs/`

## What Gets Uploaded

- All spytest result files (`results_*.txt`, `results_*.csv`)
- Techsupport tarballs (`techsupport_*.tar.gz`)
- Log directories
- Generated `tr.xml` (JUnit format)

## Examples

### Run for different platforms

```bash
# G200 Gamut
python3 spytest_publish.py /nobackup/shbhatna/weekly_runs/sonic-test/sonic-mgmt/spytest/gamut_full_run_4_29_image_40442 \
    --profile 202505c-Gamut --platform g200

# G200 Tortuga
python3 spytest_publish.py /path/to/tortuga_g200_results \
    --profile 202405c_tortuga --platform g200

# Q200 Tortuga
python3 spytest_publish.py /path/to/tortuga_q200_results \
    --profile 202405c_tortuga --platform q200
```

### Check what would happen (dry run)

```bash
python3 spytest_publish.py /path/to/results --profile 202505c-Gamut --platform g200 --dry-run
```

## Troubleshooting

### DNS/Proxy Issues
The script uses SSH to run curl on the server itself (`localhost:5005`) to bypass DNS/proxy issues.

### Build ID Detection
Build ID is auto-detected from directory names like:
- `gamut_full_run_4_29_image_40442` → build ID: `40442`
- `results_build_39990` → build ID: `39990`

Override with `--build <id>` if auto-detection fails.

## Files (Legacy)

| File | Status | Description |
|------|--------|-------------|
| `spytest_publish.py` | **USE THIS** | All-in-one: parse, XML, upload, import |
| `spytest_summary.py` | **USE THIS** | Quick local summary (no network) |
| `spytest_lib.py` | Library | Shared parsing functions (used by both scripts) |
