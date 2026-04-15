from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import importlib.util
import inspect
import pandas as pd
import re
import sys
import types

from utilities.logs import get_syslog_for_device_in_window

HIGH_SEVERITY = re.compile(r"\b(ERR|ERROR|CRIT|CRITICAL|WARN|WARNING)\b")

REPO_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_PATTERN_DIR = (
    REPO_ROOT / "ansible" / "roles" / "test" / "files" / "tools" / "loganalyzer"
)

LOGANALYZER_PLUGIN_DIR = REPO_ROOT / "tests" / "common" / "plugins" / "loganalyzer"
SYSTEM_MSG_HANDLER_FILE = LOGANALYZER_PLUGIN_DIR / "system_msg_handler.py"


def _ensure_namespace_pkg(name: str, path: Path) -> None:
    """
    Ensure `name` exists in `sys.modules` as a namespace package pointing at `path`.

    We use this to avoid importing `tests.common` normally (which executes
    `tests/common/__init__.py` and drags in heavy test dependencies). By stubbing
    the parent packages as namespace packages, we can load the loganalyzer plugin
    module directly by file path while still allowing its relative imports to resolve.
    """
    if name in sys.modules:
        return
    m = types.ModuleType(name)
    m.__path__ = [str(path)]  # type: ignore[attr-defined]
    sys.modules[name] = m


def _load_ansible_loganalyzer_via_plugin():
    """
    Load AnsibleLogAnalyzer from test plugin without importing tests.common
    to avoid heavy test dependencies in Jupyter notebooks.
    """
    print("LogAnalyzer plugin dir  :", str(LOGANALYZER_PLUGIN_DIR))
    print("system_msg_handler file :", str(SYSTEM_MSG_HANDLER_FILE))

    if not SYSTEM_MSG_HANDLER_FILE.is_file():
        raise FileNotFoundError(f"Missing file: {SYSTEM_MSG_HANDLER_FILE}")

    # Avoid importing tests/common/__init__.py (pulls extra deps)
    _ensure_namespace_pkg("tests", REPO_ROOT / "tests")
    _ensure_namespace_pkg("tests.common", REPO_ROOT / "tests" / "common")
    _ensure_namespace_pkg("tests.common.plugins", REPO_ROOT / "tests" / "common" / "plugins")
    _ensure_namespace_pkg("tests.common.plugins.loganalyzer", LOGANALYZER_PLUGIN_DIR)

    mod_name = "tests.common.plugins.loganalyzer.system_msg_handler"
    spec = importlib.util.spec_from_file_location(mod_name, str(SYSTEM_MSG_HANDLER_FILE))
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to create import spec for {SYSTEM_MSG_HANDLER_FILE}")

    module = importlib.util.module_from_spec(spec)
    module.__package__ = "tests.common.plugins.loganalyzer"
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]

    cls = getattr(module, "AnsibleLogAnalyzer", None)
    if cls is None:
        raise ImportError("AnsibleLogAnalyzer not found in system_msg_handler.py")

    print("AnsibleLogAnalyzer module:", cls.__module__)
    print("AnsibleLogAnalyzer file  :", inspect.getsourcefile(cls))
    return cls


AnsibleLogAnalyzer = _load_ansible_loganalyzer_via_plugin()


@dataclass
class SyslogScanResult:
    unexpected: pd.DataFrame
    devices_without_syslog: pd.DataFrame


def _resolve_pattern_dir(pattern_dir: Optional[str]) -> Path:
    """
    Resolve the pattern directory path for LogAnalyzer configuration.

    Args:
        pattern_dir: Optional pattern directory path. If None, uses default.

    Returns:
        Absolute Path to the pattern directory.
    """
    if pattern_dir is None:
        return DEFAULT_PATTERN_DIR
    p = Path(pattern_dir)
    return p if p.is_absolute() else (REPO_ROOT / p)


def _create_loganalyzer(pattern_dir: Optional[str]):
    """
    Create and configure an AnsibleLogAnalyzer instance with match/ignore patterns.

    Args:
        pattern_dir: Optional directory containing loganalyzer pattern files.

    Returns:
        Tuple of (loganalyzer_instance, match_regex, ignore_regex).
    """
    pattern_path = _resolve_pattern_dir(pattern_dir)
    print("LogAnalyzer pattern dir :", str(pattern_path))

    la = AnsibleLogAnalyzer(run_id="tor_pilot_exit", verbose=False, start_marker=None)

    def _load(name: str):
        path = pattern_path / name
        if not path.is_file():
            print(f"⚠️ Pattern file not found: {path}")
            return None
        # print(f"Using pattern file: {path}")
        regex, _ = la.create_msg_regex([str(path)])
        return regex

    match_re = _load("loganalyzer_common_match.txt")
    ignore_re = _load("loganalyzer_common_ignore.txt")
    return la, match_re, ignore_re


def _filter_unexpected_syslogs(df: pd.DataFrame, la, match_re, ignore_re) -> pd.DataFrame:
    """
    Filter DataFrame to keep only unexpected high-severity syslog messages.

    Args:
        df: DataFrame containing syslog messages with 'Message' column.
        la: LogAnalyzer instance for pattern matching.
        match_re: Compiled regex for matching expected patterns.
        ignore_re: Compiled regex for ignoring certain patterns.

    Returns:
        Filtered DataFrame containing only unexpected syslog entries.
    """
    if df is None or df.empty:
        return df

    if "Message" not in df.columns:
        raise KeyError(f"syslog DataFrame must contain 'Message', got: {list(df.columns)}")

    def _is_unexpected(row) -> bool:
        msg = str(row["Message"])

        # Use regex to detect high severity since query doesn't return Severity column
        high = bool(HIGH_SEVERITY.search(msg))

        if not high:
            return False

        # If no match patterns, consider all high-severity logs as unexpected
        if match_re is None:
            return True

        # Check if message matches expected patterns
        if la.line_matches(msg, match_re, ignore_re):
            return False  # Expected log, not unexpected
        else:
            return True   # Doesn't match expected patterns, so it's unexpected

    return df[df.apply(_is_unexpected, axis=1)]


def scan_unexpected_syslogs(successful_upgrades: pd.DataFrame, pattern_dir: Optional[str] = None) -> SyslogScanResult:
    """
    Scan for unexpected error/warning syslogs across multiple devices during upgrade windows.

    Args:
        successful_upgrades: DataFrame with device upgrade info (device, startTime, endTime columns).
        pattern_dir: Optional directory containing loganalyzer pattern files.

    Returns:
        SyslogScanResult containing unexpected syslogs and devices without syslog data.
    """
    la, match_re, ignore_re = _create_loganalyzer(pattern_dir)

    all_frames: List[pd.DataFrame] = []
    no_syslog_rows: List[Dict[str, object]] = []

    for _, row in successful_upgrades.iterrows():
        device = row["device"]
        start_time = row["startTime"]
        end_time = row["endTime"]

        syslog_df = get_syslog_for_device_in_window(
                device, start_time, end_time,
                message_regex=r"\b(ERR|CRIT|WARN|WARNING|kernel)\b"
            )
        if syslog_df is None or syslog_df.empty:
            no_syslog_rows.append({"device": device, "start": start_time, "end": end_time, "syslog_rows": 0})
            continue

        bad_df = _filter_unexpected_syslogs(syslog_df, la, match_re, ignore_re)
        if bad_df is None or bad_df.empty:
            # No unexpected syslogs seen for this device
            continue

        # Add time window metadata - safe to modify in place since bad_df is not used elsewhere
        bad_df["start"] = start_time
        bad_df["end"] = end_time
        all_frames.append(bad_df)

    unexpected_df = pd.concat(all_frames, ignore_index=True) if all_frames else pd.DataFrame()
    devices_without_syslog_df = pd.DataFrame(no_syslog_rows) if no_syslog_rows else pd.DataFrame(
        columns=["device", "start", "end", "syslog_rows"]
    )

    return SyslogScanResult(unexpected=unexpected_df, devices_without_syslog=devices_without_syslog_df)


def categorize_message(msg: str) -> str:
    """
    Categorize syslog messages into high-level error categories for pilot analysis.
    Format: {ERROR_LEVEL}_{SERVICE}_{ERROR_TYPE}
    """
    # Strip variable content but preserve service and error patterns
    pattern = (r'<\d+>|\d{4}-\d{2}-\d{2}T[\d:.+-]+|[A-Z0-9]+-\d{4}-\d{4}-\d{2}[A-Z]\d+|'
               r'\[\d+\]|\b\d+\b|0x[0-9a-fA-F]+|\b\d{1,3}(\.\d{1,3}){3}(:\d+)?')
    clean_msg = re.sub(pattern, ' ', msg)

    # Extract service and error level using existing regex patterns
    service_match = re.search(r'(ERR|ERROR|WARNING|WARN|CRITICAL|CRIT|INFO)\s+([^#\s]+)#', clean_msg)
    if service_match:
        error_level = service_match.group(1).replace('ERR', 'ERROR').replace('WARN', 'WARNING')
        service = service_match.group(2).upper()
    else:
        # Fallback to existing severity detection logic
        severity_match = HIGH_SEVERITY.search(clean_msg)
        error_level = (severity_match.group(1).replace('ERR', 'ERROR').replace('WARN', 'WARNING')
                       if severity_match else 'UNKNOWN')

        # Extract service from known patterns
        service_pattern = r'\b(syncd|snmp|acms|kernel|bgp|frr|orchagent|portsyncd|intfsyncd|swss|pmon)\b'
        service_candidates = re.findall(service_pattern, clean_msg, re.IGNORECASE)
        service = service_candidates[0].upper() if service_candidates else 'UNKNOWN'

        if re.search(r'\bkernel\b', clean_msg, re.IGNORECASE):
            service, error_level = 'KERNEL', 'KERNEL'

    # Add error type subcategory to provide more granular categorization
    # This helps group similar error patterns (timeouts, cert issues, etc.) for analysis
    error_type = ""
    if any(keyword in clean_msg.lower() for keyword in ['cert', 'certificate']):
        error_type = "_CERT"
    elif any(keyword in clean_msg.lower() for keyword in ['timeout', 'time out']):
        error_type = "_TIMEOUT"
    elif any(keyword in clean_msg.lower() for keyword in ['connection', 'connect']):
        error_type = "_CONNECTION"
    elif any(keyword in clean_msg.lower() for keyword in ['database', 'db']):
        error_type = "_DB"
    elif any(keyword in clean_msg.lower() for keyword in ['missing', 'not found']):
        error_type = "_MISSING"
    elif any(keyword in clean_msg.lower() for keyword in ['failed', 'fail']):
        error_type = "_FAILED"

    return f"{error_level}_{service}{error_type}"
