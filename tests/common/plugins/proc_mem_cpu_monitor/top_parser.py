# -*- coding: utf-8 -*-
"""Parse batch `top` output for per-process CPU% and MEM%."""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set

from tests.common.plugins.memory_utilization.memory_utilization import _parse_top_res_to_mib

logger = logging.getLogger(__name__)

SYSTEM_CPU_IDLE_PROCESS = "system_cpu_idle"

_TOP_CPU_SUMMARY_RE = re.compile(
    r"^\s*%Cpu\(s\):\s*"
    r"([\d.]+)\s*us,\s*"
    r"([\d.]+)\s*sy,\s*"
    r"([\d.]+)\s*ni,\s*"
    r"([\d.]+)\s*id"
    r"(?:,\s*([\d.]+)\s*wa)?"
    r"(?:,\s*([\d.]+)\s*hi)?"
    r"(?:,\s*([\d.]+)\s*si)?"
    r"(?:,\s*([\d.]+)\s*st)?",
    re.IGNORECASE,
)


def parse_top_cpu_summary(stdout: str) -> Optional[Dict[str, float]]:
    """
    Parse system-wide CPU from the ``%Cpu(s):`` header in ``top -bn1`` output.

    Returns dict with ``idle_pct``, optional ``busy_pct`` (100 - idle), and breakdown
    fields (``us_pct``, ``sy_pct``, ), or None if not found.
    """
    if not stdout:
        return None
    for line in stdout.splitlines():
        m = _TOP_CPU_SUMMARY_RE.match(line.strip())
        if not m:
            continue
        us, sy, ni, idle = (float(m.group(i)) for i in range(1, 5))
        wa = float(m.group(5)) if m.group(5) is not None else 0.0
        hi = float(m.group(6)) if m.group(6) is not None else 0.0
        si = float(m.group(7)) if m.group(7) is not None else 0.0
        st = float(m.group(8)) if m.group(8) is not None else 0.0
        idle_pct = round(idle, 2)
        return {
            "idle_pct": idle_pct,
            "busy_pct": round(100.0 - idle, 2),
            "us_pct": round(us, 2),
            "sy_pct": round(sy, 2),
            "ni_pct": round(ni, 2),
            "wa_pct": round(wa, 2),
            "hi_pct": round(hi, 2),
            "si_pct": round(si, 2),
            "st_pct": round(st, 2),
        }
    return None


def _match_process(cmd_field: str, proc_names: Set[str]) -> Optional[str]:
    """Return the proc_names entry that matches this COMMAND field (substring)."""
    for name in proc_names:
        if name in cmd_field:
            return name
    return None


def parse_top_batch(stdout: str, proc_names: List[str]) -> List[Dict[str, Any]]:
    """
    Parse `top -bn1` style output (procps-like: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND).

    Returns a list of dicts: process, cpu_pct, mem_pct (%MEM from top), mem_res_mib (RES→MiB, same as
    memory_utilization ``parse_top_output``), raw_command, pid.
    """
    if not stdout or not proc_names:
        return []

    wanted: Set[str] = set(proc_names)
    rows: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("top -") or line.startswith("Tasks:"):
            continue
        if line.startswith("PID ") or line.startswith("%Cpu"):
            continue
        if line.startswith("MiB Mem") or line.startswith("KiB Mem"):
            continue

        parts = line.split(None, 11)
        if len(parts) < 12:
            continue
        pid, _user, _pr, _ni, _virt, _res, _shr, _s, cpu_s, mem_s, _timep, cmd = parts[:12]
        if not pid.isdigit():
            continue
        try:
            cpu_pct = float(cpu_s)
            mem_pct = float(mem_s)
        except ValueError:
            continue

        matched = _match_process(cmd, wanted)
        if matched is None:
            continue
        try:
            mem_res_mib = round(float(_parse_top_res_to_mib(_res)), 2)
        except (ValueError, TypeError):
            mem_res_mib = None
        rows.append(
            {
                "process": matched,
                "cpu_pct": round(cpu_pct, 2),
                "mem_pct": round(mem_pct, 2),
                "mem_res_mib": mem_res_mib,
                "raw_command": cmd,
                "pid": int(pid),
            }
        )
    return rows


def parse_top_host_all(stdout: str) -> List[Dict[str, Any]]:
    """
    Parse every process row from procps-style ``top -bn1`` on the host (no name filter).

    Each row uses ``process`` = the first token basename of COMMAND (no PID suffix). If the same
    basename appears more than once in one snapshot (different PIDs), the row with larger
    ``mem_res_mib`` is kept. ``pid`` is stored on each row for debugging.
    """
    if not stdout:
        return []
    rows: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("top -") or line.startswith("Tasks:"):
            continue
        if line.startswith("PID ") or line.startswith("%Cpu"):
            continue
        if line.startswith("MiB Mem") or line.startswith("KiB Mem"):
            continue

        parts = line.split(None, 11)
        if len(parts) < 12:
            continue
        pid, _user, _pr, _ni, _virt, _res, _shr, _s, cpu_s, mem_s, _timep, cmd = parts[:12]
        if not pid.isdigit():
            continue
        try:
            cpu_pct = float(cpu_s)
            mem_pct = float(mem_s)
        except ValueError:
            continue

        cmd0 = cmd.strip().split(None, 1)[0] if cmd.strip() else "?"
        base = os.path.basename(cmd0) or "unknown"
        try:
            mem_res_mib = round(float(_parse_top_res_to_mib(_res)), 2)
        except (ValueError, TypeError):
            mem_res_mib = None
        rows.append(
            {
                "process": base,
                "cpu_pct": round(cpu_pct, 2),
                "mem_pct": round(mem_pct, 2),
                "mem_res_mib": mem_res_mib,
                "raw_command": cmd,
                "pid": int(pid),
            }
        )
    merged: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        name = row["process"]
        prev = merged.get(name)
        pr = row.get("mem_res_mib")
        pv = float(pr) if pr is not None else -1.0
        if prev is None:
            merged[name] = row
            continue
        pprev = prev.get("mem_res_mib")
        pv_prev = float(pprev) if pprev is not None else -1.0
        if pv > pv_prev:
            merged[name] = row
    return list(merged.values())


def parse_top_batch_loose(stdout: str, proc_names: List[str]) -> List[Dict[str, Any]]:
    """
    Fallback: scan each line for wanted process names and try to extract floats (best-effort).
    """
    if not stdout or not proc_names:
        return []
    wanted: Set[str] = set(proc_names)
    rows: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        matched = None
        for name in wanted:
            if name in line:
                matched = name
                break
        if matched is None:
            continue
        nums = re.findall(r"\d+\.\d+|\d+", line)
        floats: List[float] = []
        for n in nums:
            try:
                floats.append(float(n))
            except ValueError:
                continue
        if len(floats) < 2:
            continue
        if len(floats) >= 3:
            cpu_pct, mem_pct = floats[-3], floats[-2]
        else:
            cpu_pct, mem_pct = floats[-2], floats[-1]
        rows.append(
            {
                "process": matched,
                "cpu_pct": round(cpu_pct, 2),
                "mem_pct": round(mem_pct, 2),
                "raw_command": line,
                "pid": None,
            }
        )
    return rows


def parse_top(stdout: str, proc_names: List[str]) -> List[Dict[str, Any]]:
    """Try strict procps parse; if nothing matched, try loose parser."""
    strict = parse_top_batch(stdout, proc_names)
    if strict:
        return strict
    loose = parse_top_batch_loose(stdout, proc_names)
    if loose:
        logger.debug("top parse used loose fallback (proc_names=%s)", proc_names)
    return loose


def parse_free_m_used(stdout: str) -> Optional[Dict[str, float]]:
    """
    Parse ``free -m`` output for the ``Mem:`` row (same layout as ``memory_utilization``).

    Returns dict with keys: ``used_mib``, ``total_mib``, ``used_pct`` (100 * used / total), or None.
    """
    if not stdout:
        return None
    headers: List[str] = []
    mem_parts: List[int] = []
    for line in stdout.split("\n"):
        line_st = line.strip()
        if not line_st:
            continue
        if line_st.startswith("Mem:"):
            try:
                mem_parts = [int(x) for x in line_st.split()[1:]]
            except ValueError:
                return None
        elif line_st.startswith("total") and "used" in line_st:
            headers = [h.lower() for h in line_st.split()]

    if not headers or not mem_parts or len(headers) != len(mem_parts):
        return None
    mem_info = {headers[i]: mem_parts[i] for i in range(len(mem_parts))}
    used = float(mem_info.get("used", 0))
    total = float(mem_info.get("total", 0))
    used_pct = round(100.0 * used / total, 2) if total else 0.0
    return {"used_mib": used, "total_mib": total, "used_pct": used_pct}
