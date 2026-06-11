# -*- coding: utf-8 -*-
"""Periodic process CPU/memory sampling via `top` on DUT(s)."""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import threading
import time
from contextlib import contextmanager
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import pytest

from tests.common.plugins.proc_mem_cpu_monitor.constants import MEM_LEAK_EVENT
from tests.common.plugins.proc_mem_cpu_monitor.tcmalloc_parser import parse_tcmalloc_stats
from tests.common.plugins.proc_mem_cpu_monitor.top_parser import parse_free_m_used, parse_top, parse_top_host_all

logger = logging.getLogger(__name__)

# ``output_basename_style`` / ``basename_style`` for PNG/JSON/CSV stems (see README).
OUTPUT_BASENAME_STYLES = ("full", "short_node", "dut_ts_hash")

# Host logical CPU count (first DUT in ``start()`` probe order); same pipeline as manual SONiC check.
_NUM_CORES_CMD = "sh -c 'cat /proc/cpuinfo | grep processor | wc -l'"

_DEVICES_BASE_LOGGER = logging.getLogger("tests.common.devices.base")


@contextmanager
def _suppress_devices_base_debug():
    """Raise ``tests.common.devices.base`` to INFO for this block (skip large Ansible DEBUG dumps)."""
    log = _DEVICES_BASE_LOGGER
    previous = log.level
    log.setLevel(logging.INFO)
    try:
        yield
    finally:
        log.setLevel(previous)


def _first_free_total_mib_from_samples(samples: List[Dict[str, Any]]) -> Optional[float]:
    """First ``mem_total_mib`` from a ``free_used`` sample (full run), for plot reference."""
    for s in samples:
        if s.get("kind") != "sample":
            continue
        if s.get("process") == "free_used" and s.get("mem_total_mib") is not None:
            return float(s["mem_total_mib"])
    return None


def _memory_ordered_basenames(rows: List[Dict[str, Any]]) -> List[str]:
    """Unique process basenames ordered by RSS (``mem_res_mib``) desc, then ``%MEM`` desc."""

    def sort_key(r: Dict[str, Any]) -> Tuple[float, float, str]:
        mb = r.get("mem_res_mib")
        v = float(mb) if mb is not None else -1.0
        mp = float(r["mem_pct"]) if r.get("mem_pct") is not None else 0.0
        return (-v, -mp, r["process"])

    rows_sorted = sorted(rows, key=sort_key)
    out: List[str] = []
    seen: Set[str] = set()
    for r in rows_sorted:
        p = r["process"]
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def _host_top_capture_names(rows: List[Dict[str, Any]], proc_list: List[str], top_n: int) -> Set[str]:
    """
    Per host ``top`` snapshot: which process basenames to store.

    * ``proc_list`` empty: the ``top_n`` processes with highest RSS (``mem_res_mib``).
    * Else: every process matching a user substring, plus enough highest-RSS processes so that
      together with the user set we cover ``top_n`` memory leaders minus overlap
      (user processes that already sit in the top-``top_n`` RSS set reduce how many extras are added).
    """
    ordered = _memory_ordered_basenames(rows)
    if not ordered:
        return set()
    top_set = set(ordered[: max(0, top_n)])
    user: Set[str] = set()
    if proc_list:
        for r in rows:
            if any(u in r["process"] for u in proc_list):
                user.add(r["process"])
    overlap = len(top_set & user)
    need_extra = max(0, top_n - overlap)
    extras: List[str] = []
    for p in ordered:
        if p in user:
            continue
        if need_extra <= 0:
            break
        extras.append(p)
        need_extra -= 1
    return user.union(extras)


def _rank_host_jumpers(host_samples: List[Dict[str, Any]], n: int) -> List[str]:
    """
    Rank host ``top`` samples by combined CPU% and %MEM swing (max - min) over the run.
    Returns up to ``n`` process names (host ``top`` basename keys).
    """
    by_proc: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for s in host_samples:
        by_proc[s["process"]].append(s)
    scores: List[Tuple[str, float]] = []
    for proc_key, series in by_proc.items():
        if len(series) < 2:
            continue
        cpus = [float(s["cpu_pct"]) for s in series if s.get("cpu_pct") is not None]
        mems = [float(s["mem_pct"]) for s in series if s.get("mem_pct") is not None]
        if len(cpus) < 2 or len(mems) < 2:
            continue
        cpu_j = max(cpus) - min(cpus)
        mem_j = max(mems) - min(mems)
        scores.append((proc_key, cpu_j + mem_j))
    scores.sort(key=lambda x: -x[1])
    return [x[0] for x in scores[: max(0, n)]]


def effective_adaptive_plot_processes(
    samples: List[Dict[str, Any]],
    interest: List[str],
    jumper_top_n: int = 5,
) -> Optional[List[str]]:
    """
    Legacy helper for non-``host_top_all`` adaptive chart subsetting.

    When ``interest`` is empty, returns every distinct host ``top`` process name in ``samples``.
    When ``interest`` is non-empty, ranks by CPU+%MEM swing and unions with interest matches
    (used only if ``host_top_all_procs`` is false but adaptive plotting is forced on).
    """
    host_s = [
        s
        for s in samples
        if s.get("kind") == "sample"
        and s.get("probe_transport") == "top"
        and s.get("scope") == "host"
    ]
    if not host_s:
        return None

    if not interest:
        return sorted({s["process"] for s in host_s})

    top_jumpers = _rank_host_jumpers(host_s, jumper_top_n)
    interest_matched = {
        s["process"]
        for s in host_s
        if interest and any(u in s["process"] for u in interest)
    }

    if not top_jumpers:
        return sorted(interest_matched) if interest_matched else None

    def in_interest(pk: str) -> bool:
        return bool(interest) and any(u in pk for u in interest)

    all_top_in_user = all(in_interest(p) for p in top_jumpers)

    if all_top_in_user:
        return sorted(interest_matched) if interest_matched else sorted(top_jumpers)
    return sorted(interest_matched | set(top_jumpers))


def _first_sample_ts_str(samples: List[Dict[str, Any]], compact: bool = False) -> str:
    tw = samples[0]["t_wall"]
    if isinstance(tw, str):
        tw = datetime.fromisoformat(tw.replace("Z", "+00:00"))
    if tw.tzinfo is None:
        tw = tw.replace(tzinfo=timezone.utc)
    if compact:
        return tw.strftime("%Y%m%d_%H%M%S")
    return tw.strftime("%Y%m%dT%H%M%SZ")


def _stem_filename(
    request: Any,
    samples: List[Dict[str, Any]],
    style: str,
) -> str:
    """
    Build basename (no directory, no extension) for plot/export files.

    ``style``:
        * ``full`` — sanitized full ``nodeid`` + DUT + timestamp (legacy, can be long).
        * ``short_node`` — pytest ``node.name`` (function + params, no file path) + DUT + timestamp.
        * ``dut_ts_hash`` — DUT + compact timestamp + 10-char hex of full ``nodeid`` (short, unique).
    """
    if style not in OUTPUT_BASENAME_STYLES:
        raise ValueError(
            "output_basename_style must be one of {}, got {!r}".format(OUTPUT_BASENAME_STYLES, style)
        )
    dut = _safe_name(samples[0]["dut"])
    nodeid = request.node.nodeid
    if style == "dut_ts_hash":
        ts = _first_sample_ts_str(samples, compact=True)
        h = hashlib.sha256(nodeid.encode("utf-8")).hexdigest()[:10]
        return "{}__{}__{}".format(dut, ts, h)
    ts = _first_sample_ts_str(samples, compact=False)
    if style == "short_node":
        mid = _safe_name(request.node.name)[:96]
        return "{}__{}__{}".format(mid, dut, ts)
    mid = _safe_name(nodeid)
    return "{}__{}__{}".format(mid, dut, ts)


def _normalize_duts(duts: Any) -> List[Any]:
    if duts is None:
        return []
    if hasattr(duts, "nodes"):
        return list(duts.nodes)
    if hasattr(duts, "hostname"):
        return [duts]
    return list(duts)


def _top_cmd_host() -> str:
    return "top -bn1"


def _top_cmd_docker(duthost: Any, asic: Any, docker_service: str) -> str:
    inner = "top -bn1"
    if duthost.sonichost.is_multi_asic:
        return asic.get_docker_cmd(inner, docker_service)
    docker_name = asic.get_docker_name(docker_service)
    return "sudo docker exec {} {}".format(docker_name, inner)


def _tcmalloc_cmd_docker(duthost: Any, asic: Any, docker_service: str) -> str:
    inner = 'vtysh -c "show tcmalloc stats"'
    if duthost.sonichost.is_multi_asic:
        return asic.get_docker_cmd(inner, docker_service)
    docker_name = asic.get_docker_name(docker_service)
    return "sudo docker exec {} {}".format(docker_name, inner)


@dataclass
class MemCpuMonitorResult:
    samples: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    top_raw_log_path: Optional[str] = None
    tcmalloc_raw_log_path: Optional[str] = None


class ProcMemCpuMonitor(object):
    """
    Controller for optional CPU/MEM sampling. Use via ``mem_cpu_monitor`` fixture.

    Typical usage::

        mem_cpu_monitor.start(duthost, ["bgpd", "zebra"], interval=2.0, include_host_free=True)
        mem_cpu_monitor.snapshot(event="Traffic_start")
        mem_cpu_monitor.snapshot(event=MEM_LEAK_EVENT, threshold="10%")
        result = mem_cpu_monitor.stop()
        mem_cpu_monitor.plot(result, proc_subset=["bgpd"])
    """

    def _should_set_mem_baseline(self, process: str) -> bool:
        if not self._host_top_all_procs:
            return True
        if not self._proc_list:
            return True
        return any(u in process for u in self._proc_list)

    def __init__(self, request):
        self.request = request
        self._lock = threading.RLock()
        # Serialize duthost.command(): sampler thread vs snapshot(MEM_LEAK_EVENT) / same Ansible SSH.
        self._dut_ssh_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._samples: List[Dict[str, Any]] = []
        self._events: List[Dict[str, Any]] = []
        self._seq = 0
        self._baseline_mem: Dict[Tuple[str, str, str], float] = {}
        self._targets: List[Tuple[Any, str, str, str]] = []
        self._proc_list: List[str] = []
        self._interval = 1.0
        self._last_result: Optional[MemCpuMonitorResult] = None
        self._thread_exc: Optional[Exception] = None
        self._stopped: bool = False
        self._host_top_all_procs: bool = False
        self._jumper_top_n: int = 5
        self._capture_raw_stdout: bool = False
        self._raw_log_path: Optional[str] = None
        self._top_raw_log_path: Optional[str] = None
        self._include_tcmalloc_stats: bool = False
        self._tcmalloc_raw_log_path: Optional[str] = None
        self._output_basename_style: str = "full"
        self._host_top_num_cores: Optional[int] = None

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _append_event(self, name: str, extra: Optional[Dict[str, Any]] = None) -> None:
        # Serialize with sampler thread: it calls _next_seq() under self._lock in _poll_tick().
        with self._lock:
            now = datetime.now(timezone.utc)
            mono = time.monotonic()
            ev = {
                "kind": "event",
                "event": name,
                "t_wall": now,
                "t_mono": mono,
                "seq": self._next_seq(),
            }
            if extra:
                ev.update(extra)
            self._events.append(ev)

    def _append_raw_log(self, hostname: str, scope: str, kind: str, cmd: str, stdout: str) -> None:
        if not self._capture_raw_stdout or not self._raw_log_path:
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        block = "\n===== {} hostname={} scope={} kind={}\nCMD: {}\n-----\n{}\n".format(
            ts, hostname, scope, kind, cmd, stdout or ""
        )
        with self._lock:
            with open(self._raw_log_path, "a", encoding="utf-8") as fh:
                fh.write(block)

    def _append_top_raw_log(self, hostname: str, scope: str, kind: str, cmd: str, stdout: str) -> None:
        """Append full ``top`` stdout (host or docker) to the dedicated top-raw log file."""
        if kind not in ("top", "top_all") or not self._top_raw_log_path:
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        block = "\n===== {} hostname={} scope={} kind={}\nCMD: {}\n-----\n{}\n".format(
            ts, hostname, scope, kind, cmd, stdout or ""
        )
        with self._lock:
            with open(self._top_raw_log_path, "a", encoding="utf-8") as fh:
                fh.write(block)

    def _append_tcmalloc_raw_log(self, hostname: str, scope: str, kind: str, cmd: str, stdout: str) -> None:
        """Append full ``show tcmalloc stats`` stdout to the dedicated tcmalloc raw log file."""
        if kind != "tcmalloc" or not self._tcmalloc_raw_log_path:
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        block = "\n===== {} hostname={} scope={} kind={}\nCMD: {}\n-----\n{}\n".format(
            ts, hostname, scope, kind, cmd, stdout or ""
        )
        with self._lock:
            with open(self._tcmalloc_raw_log_path, "a", encoding="utf-8") as fh:
                fh.write(block)

    def _dut_command_raw(self, duthost: Any, cmd: str, hostname: str, scope: str, kind: str) -> str:
        with self._dut_ssh_lock:
            try:
                with _suppress_devices_base_debug():
                    out = duthost.command(cmd, module_ignore_errors=True)
            except Exception as ex:  # noqa: BLE001 — DUT command failures should not kill sampler
                logger.warning("mem_cpu_monitor command failed: %s", ex)
                err = "<exception: {}>\n".format(ex)
                self._append_raw_log(hostname, scope, kind, cmd, err)
                self._append_top_raw_log(hostname, scope, kind, cmd, err)
                self._append_tcmalloc_raw_log(hostname, scope, kind, cmd, err)
                return ""
            stdout = (out or {}).get("stdout") or ""
            self._append_raw_log(hostname, scope, kind, cmd, stdout)
            self._append_top_raw_log(hostname, scope, kind, cmd, stdout)
            self._append_tcmalloc_raw_log(hostname, scope, kind, cmd, stdout)
            return stdout

    def _probe_host_num_cores_once(self) -> None:
        """Set ``_host_top_num_cores`` from ``/proc/cpuinfo`` on the first DUT (per ``_targets`` order)."""
        if self._host_top_num_cores is not None or not self._targets:
            return
        seen: Set[str] = set()
        for duthost, _scope, _cmd, _kind in self._targets:
            hn = getattr(duthost, "hostname", None) or str(duthost)
            if hn in seen:
                continue
            seen.add(hn)
            try:
                with self._dut_ssh_lock:
                    with _suppress_devices_base_debug():
                        out = duthost.command(_NUM_CORES_CMD, module_ignore_errors=True)
            except Exception as ex:  # noqa: BLE001
                logger.debug("mem_cpu_monitor num_cores probe failed: %s", ex)
                continue
            stdout = (out or {}).get("stdout") or ""
            for line in stdout.splitlines():
                chunk = line.strip().split()
                if not chunk:
                    continue
                try:
                    n = int(chunk[0])
                except ValueError:
                    continue
                if n > 0:
                    self._host_top_num_cores = n
                    return

    def _poll_tick(self) -> None:
        proc_list = self._proc_list
        for duthost, scope, cmd, kind in self._targets:
            try:
                hostname = duthost.hostname
                stdout = self._dut_command_raw(duthost, cmd, hostname, scope, kind)
                now = datetime.now(timezone.utc)
                mono = time.monotonic()
                if kind == "free":
                    data = parse_free_m_used(stdout)
                    if not data:
                        continue
                    with self._lock:
                        rec = {
                            "kind": "sample",
                            "dut": hostname,
                            "scope": scope,
                            "process": "free_used",
                            "cpu_pct": None,
                            "mem_pct": data["used_pct"],
                            "mem_mib_used": data["used_mib"],
                            "mem_total_mib": data.get("total_mib"),
                            "mem_res_mib": round(data["used_mib"], 2),
                            "mem_unit": "%",
                            "probe_transport": "free",
                            "t_wall": now,
                            "t_mono": mono,
                            "seq": self._next_seq(),
                        }
                        self._samples.append(rec)
                        key = (hostname, scope, "free_used")
                        if key not in self._baseline_mem:
                            self._baseline_mem[key] = data["used_pct"]
                    continue

                if kind == "tcmalloc":
                    rows = parse_tcmalloc_stats(stdout)
                    with self._lock:
                        for row in rows:
                            heap_b = row["heap_size_bytes"]
                            free_b = row["pageheap_free_bytes"]
                            rec = {
                                "kind": "sample",
                                "dut": hostname,
                                "scope": scope,
                                "process": row["process"],
                                "cpu_pct": None,
                                "mem_pct": None,
                                "mem_res_mib": round(heap_b / (1024.0 * 1024.0), 2),
                                "mem_unit": "bytes",
                                "probe_transport": "tcmalloc",
                                "tcmalloc_heap_size_bytes": heap_b,
                                "tcmalloc_pageheap_free_bytes": free_b,
                                "t_wall": now,
                                "t_mono": mono,
                                "seq": self._next_seq(),
                            }
                            self._samples.append(rec)
                    continue

                if kind == "top_all":
                    rows = parse_top_host_all(stdout)
                    cap = _host_top_capture_names(rows, proc_list, self._jumper_top_n)
                    rows = [r for r in rows if r["process"] in cap]
                else:
                    rows = parse_top(stdout, proc_list)
                with self._lock:
                    for row in rows:
                        rec = {
                            "kind": "sample",
                            "dut": hostname,
                            "scope": scope,
                            "process": row["process"],
                            "cpu_pct": row["cpu_pct"],
                            "mem_pct": row["mem_pct"],
                            "mem_res_mib": row.get("mem_res_mib"),
                            "mem_unit": "%",
                            "probe_transport": "top",
                            "pid": row.get("pid"),
                            "t_wall": now,
                            "t_mono": mono,
                            "seq": self._next_seq(),
                        }
                        self._samples.append(rec)
                        key = (hostname, scope, row["process"])
                        if key not in self._baseline_mem and self._should_set_mem_baseline(row["process"]):
                            self._baseline_mem[key] = row["mem_pct"]
            except Exception as ex:  # noqa: BLE001 — one bad target must not stop the sampler
                hn = getattr(duthost, "hostname", None) or str(duthost)
                logger.warning(
                    "mem_cpu_monitor: poll_tick failed for hostname=%s scope=%s kind=%s; "
                    "skipping this target for this interval: %s",
                    hn,
                    scope,
                    kind,
                    ex,
                    exc_info=True,
                )

    def _loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                with self._lock:
                    if not self._running:
                        break
                self._poll_tick()
                self._stop_event.wait(self._interval)
        except Exception as ex:  # noqa: BLE001 — surface sampler failures on stop(), not BaseException
            logger.exception("mem_cpu_monitor sampler thread died")
            self._thread_exc = ex

    def start(
        self,
        duts: Any,
        proc_list: List[str],
        interval: float = 1.0,
        docker_service: str = "bgp",
        include_host_top: bool = False,
        include_host_free: bool = False,
        asics: Optional[str] = None,
        host_top_all_procs: bool = False,
        skip_docker_top: Optional[bool] = None,
        jumper_top_n: int = 5,
        capture_raw_stdout: bool = False,
        raw_log_path: Optional[str] = None,
        top_raw_log_path: Optional[str] = None,
        include_tcmalloc_stats: bool = False,
        tcmalloc_raw_log_path: Optional[str] = None,
        output_basename_style: str = "full",
    ) -> None:
        """
        Begin background sampling.

        Args:
            duts: One ``MultiAsicSonicHost`` or a ``DutHosts`` / iterable of DUTs.
            proc_list: Substrings matched against process COMMAND (filtered ``top``) or against
                host process basenames when using ``host_top_all_procs``. Also used for
                adaptive plot/export (interest list) and optional mem-leak baselines on host rows.
            interval: seconds between completed poll rounds (default ``1.0``). The first round runs
                immediately after ``start()``; the sampler thread then sleeps ``interval`` between rounds.
            docker_service: SONiC feature name for per-ASIC docker (default ``bgp``).
            include_host_top: if True, sample host ``top`` filtered by ``proc_list`` (ignored if
                ``host_top_all_procs`` is True — host ``top`` is then full-process only).
            include_host_free: if True, also run host ``free -m`` and record ``free_used``.
            asics: ``\"frontend\"`` (default) or ``\"all\"``.
            host_top_all_procs: if True, run **host** ``top -bn1`` once per DUT per tick and record
                **every** process (``process`` = command basename; ``pid`` stored separately). No docker ``top`` unless
                ``skip_docker_top`` is False. Plot/export default to an **adaptive** subset: top
                ``jumper_top_n`` host processes by CPU+%MEM swing vs ``proc_list`` (see README).
            skip_docker_top: if None and ``host_top_all_procs`` is True, docker ``top`` targets are
                omitted; if None and ``host_top_all_procs`` is False, docker tops are included as
                today. Set explicitly to override.
            jumper_top_n: host-only rank size: number of **highest-RSS** processes to merge with the
                user ``proc_list`` for **host-wide** ``top`` capture (see README), and swing rank size
                for legacy adaptive plotting when ``host_top_all_procs`` is false.
            capture_raw_stdout: if True, append full stdout of every DUT command (``top``, ``free``, etc.)
                to ``raw_log_path`` (default under pytest ``tmp_path``).
            raw_log_path: destination log file; default ``<tmp_path>/mem_cpu_monitor_raw_commands.log``.
            top_raw_log_path: optional path for **``top``-only** raw stdout (host and docker ``top`` probes).
                Default ``<tmp_path>/mem_cpu_monitor_top_raw.log`` when any ``top`` target is configured;
                omitted when the run only probes ``free`` (no ``top``). The path is logged from
                ``stop()`` / ``plot()`` / ``export_samples()`` and included in JSON as ``top_raw_log``.
            include_tcmalloc_stats: if True, run ``docker exec <bgp> vtysh -c "show tcmalloc stats"`` each
                tick (per ASIC when docker probes are configured) and store ``generic.heap_size`` /
                ``tcmalloc.pageheap_free_bytes`` per FRR daemon. Raw CLI output goes to
                ``tcmalloc_raw_log_path`` (separate from ``top_raw_log`` / ``raw_log_path``).
            tcmalloc_raw_log_path: optional path for tcmalloc-only raw stdout. Default
                ``<tmp_path>/mem_cpu_monitor_tcmalloc_raw.log`` when ``include_tcmalloc_stats`` is True.
            output_basename_style: how to build PNG/JSON/CSV basename — ``full`` (default, long
                ``nodeid``), ``short_node`` (``node.name`` only), or ``dut_ts_hash`` (DUT + time + hash).
        """
        if output_basename_style not in OUTPUT_BASENAME_STYLES:
            raise ValueError(
                "output_basename_style must be one of {}, got {!r}".format(
                    OUTPUT_BASENAME_STYLES, output_basename_style
                )
            )
        with self._lock:
            if self._running:
                raise RuntimeError("mem_cpu_monitor.start() called while already running")
            dut_list = _normalize_duts(duts)
            if not dut_list:
                raise ValueError("mem_cpu_monitor.start() needs at least one DUT")
            if (
                not proc_list
                and not include_host_free
                and not host_top_all_procs
                and not include_tcmalloc_stats
            ):
                raise ValueError(
                    "mem_cpu_monitor.start() needs proc_list and/or include_host_free=True "
                    "and/or host_top_all_procs=True and/or include_tcmalloc_stats=True"
                )

            skip_eff = skip_docker_top
            if skip_eff is None:
                skip_eff = bool(host_top_all_procs)

            self._proc_list = list(proc_list) if proc_list else []
            self._interval = float(interval)
            self._host_top_all_procs = bool(host_top_all_procs)
            self._jumper_top_n = int(jumper_top_n)
            self._capture_raw_stdout = bool(capture_raw_stdout)
            self._include_tcmalloc_stats = bool(include_tcmalloc_stats)
            self._output_basename_style = output_basename_style
            self._raw_log_path = None
            if self._capture_raw_stdout:
                log_dir = self._resolve_out_dir(None)
                os.makedirs(log_dir, exist_ok=True)
                self._raw_log_path = raw_log_path or os.path.join(log_dir, "mem_cpu_monitor_raw_commands.log")
                with open(self._raw_log_path, "w", encoding="utf-8") as fh:
                    fh.write("# mem_cpu_monitor: raw DUT stdout for each command invocation\n")
            self._targets = []
            self._top_raw_log_path = None
            self._tcmalloc_raw_log_path = None
            use_asics = asics or "frontend"

            for duthost in dut_list:
                if host_top_all_procs:
                    self._targets.append((duthost, "host", _top_cmd_host(), "top_all"))
                elif include_host_top:
                    self._targets.append((duthost, "host", _top_cmd_host(), "top"))

                if not skip_eff:
                    if use_asics == "all":
                        asic_iter = list(duthost.asics)
                    else:
                        asic_iter = list(getattr(duthost, "frontend_asics", None) or []) or [duthost.asics[0]]

                    for asic in asic_iter:
                        scope = "docker:{}:{}".format(docker_service, asic.asic_index)
                        cmd = _top_cmd_docker(duthost, asic, docker_service)
                        self._targets.append((duthost, scope, cmd, "top"))

                if include_host_free:
                    self._targets.append((duthost, "host:free", "free -m", "free"))

                if self._include_tcmalloc_stats:
                    if use_asics == "all":
                        tcmalloc_asics = list(duthost.asics)
                    else:
                        tcmalloc_asics = list(getattr(duthost, "frontend_asics", None) or []) or [duthost.asics[0]]
                    for asic in tcmalloc_asics:
                        scope = "docker:{}:{}".format(docker_service, asic.asic_index)
                        cmd = _tcmalloc_cmd_docker(duthost, asic, docker_service)
                        self._targets.append((duthost, scope, cmd, "tcmalloc"))

            if not self._targets:
                raise ValueError("mem_cpu_monitor.start(): no probe targets configured")

            if any(k in ("top", "top_all") for _d, _s, _c, k in self._targets):
                log_dir = self._resolve_out_dir(None)
                os.makedirs(log_dir, exist_ok=True)
                self._top_raw_log_path = top_raw_log_path or os.path.join(
                    log_dir, "mem_cpu_monitor_top_raw.log"
                )
                with open(self._top_raw_log_path, "w", encoding="utf-8") as fh:
                    fh.write("# mem_cpu_monitor: raw stdout from every host/docker `top` probe\n")

            if self._include_tcmalloc_stats:
                log_dir = self._resolve_out_dir(None)
                os.makedirs(log_dir, exist_ok=True)
                self._tcmalloc_raw_log_path = tcmalloc_raw_log_path or os.path.join(
                    log_dir, "mem_cpu_monitor_tcmalloc_raw.log"
                )
                with open(self._tcmalloc_raw_log_path, "w", encoding="utf-8") as fh:
                    fh.write(
                        "# mem_cpu_monitor: raw stdout from every "
                        "`docker exec <bgp> vtysh -c \"show tcmalloc stats\"` probe\n"
                    )

            self._host_top_num_cores = None
            self._probe_host_num_cores_once()

            self._running = True
            self._stop_event.clear()
            self._thread_exc = None
            self._samples.clear()
            self._events.clear()
            self._seq = 0
            self._baseline_mem.clear()
            self._last_result = None
            self._stopped = False
            self._append_event(
                "start",
                {
                    "proc_list": list(proc_list),
                    "interval": self._interval,
                    "include_host_free": include_host_free,
                    "host_top_all_procs": host_top_all_procs,
                    "skip_docker_top": skip_eff,
                    "jumper_top_n": self._jumper_top_n,
                    "raw_log_path": self._raw_log_path,
                    "top_raw_log_path": self._top_raw_log_path,
                    "include_tcmalloc_stats": self._include_tcmalloc_stats,
                    "tcmalloc_raw_log_path": self._tcmalloc_raw_log_path,
                    "output_basename_style": output_basename_style,
                    "num_cores": self._host_top_num_cores,
                },
            )
            self._poll_tick()
            self._thread = threading.Thread(target=self._loop, name="mem_cpu_monitor", daemon=True)
            self._thread.start()

    def snapshot(self, event: Optional[str] = None, threshold: Optional[str] = None, strict: bool = True) -> None:
        """
        Record a timeline event. If ``event == MEM_LEAK_EVENT`` (``\"mem_leak\"``) and ``threshold`` is set,
        run an immediate memory check vs the first-seen baseline per (dut, scope, process).
        """
        name = event or "snapshot"
        extra: Dict[str, Any] = {}
        if threshold is not None and name == MEM_LEAK_EVENT:
            failures, skipped = self._run_mem_leak_compare(threshold)
            extra["mem_leak_failures"] = failures
            if skipped:
                extra["mem_leak_skipped"] = True
            if failures and strict:
                pytest.fail("mem_leak check failed:\n" + "\n".join(failures))
        self._append_event(name, extra if extra else None)

    def _parse_threshold_relative(self, threshold: str) -> float:
        t = threshold.strip()
        if t.endswith("%"):
            return float(t[:-1].strip()) / 100.0
        return float(t) / 100.0

    def _run_mem_leak_compare(self, threshold: str) -> Tuple[List[str], bool]:
        """Return (failure_messages, skipped_due_to_no_baseline)."""
        with self._lock:
            if not self._baseline_mem:
                logger.warning("mem_leak check skipped: no baseline samples yet")
                return [], True

        rel = self._parse_threshold_relative(threshold)
        current: Dict[Tuple[str, str, str], float] = {}
        proc_list = self._proc_list
        for duthost, scope, cmd, kind in self._targets:
            stdout = self._dut_command_raw(duthost, cmd, duthost.hostname, scope, kind)
            hostname = duthost.hostname
            if kind == "free":
                data = parse_free_m_used(stdout)
                if data:
                    current[(hostname, scope, "free_used")] = data["used_pct"]
                continue
            if kind == "top_all":
                rows = parse_top_host_all(stdout)
                cap = _host_top_capture_names(rows, proc_list, self._jumper_top_n)
                rows = [r for r in rows if r["process"] in cap]
            else:
                rows = parse_top(stdout, proc_list)
            for row in rows:
                key = (hostname, scope, row["process"])
                current[key] = row["mem_pct"]

        failures: List[str] = []
        with self._lock:
            for key, base in self._baseline_mem.items():
                if key not in current:
                    failures.append("{} missing in current snapshot".format(key))
                    continue
                cur = current[key]
                low, high = base * (1.0 - rel), base * (1.0 + rel)
                if cur < low or cur > high:
                    failures.append(
                        "{} baseline={:.2f}% current={:.2f}% allowed=[{:.2f}%, {:.2f}%]".format(
                            key, base, cur, low, high
                        )
                    )
        return failures, False

    def stop(self) -> MemCpuMonitorResult:
        """Stop sampler and return sorted timeline."""
        with self._lock:
            if self._stopped:
                return self._last_result or MemCpuMonitorResult()

        with self._lock:
            if self._running:
                self._running = False
            self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=30.0)
            self._thread = None
        self._append_event("stop")

        with self._lock:
            merged = list(self._samples) + list(self._events)
            merged.sort(key=lambda r: (r["t_mono"], r["seq"]))
            result = MemCpuMonitorResult(
                samples=list(self._samples),
                events=list(self._events),
                timeline=merged,
                top_raw_log_path=self._top_raw_log_path,
                tcmalloc_raw_log_path=self._tcmalloc_raw_log_path,
            )
            self._last_result = result
            self._stopped = True
            if self._thread_exc is not None:
                exc = self._thread_exc
                self._thread_exc = None
                logger.error("mem_cpu_monitor thread had failed: %s", exc)
            if self._top_raw_log_path:
                logger.info("mem_cpu_monitor.stop() top raw stdout log: %s", self._top_raw_log_path)
            if self._tcmalloc_raw_log_path:
                logger.info("mem_cpu_monitor.stop() tcmalloc raw stdout log: %s", self._tcmalloc_raw_log_path)
            return result

    def _resolve_out_dir(self, out_dir: Optional[str]) -> str:
        if out_dir is None:
            try:
                return str(self.request.getfixturevalue("tmp_path"))
            except Exception:  # noqa: BLE001
                return "."
        return out_dir

    @staticmethod
    def _filter_samples_for_plot(res: MemCpuMonitorResult, proc_subset: Optional[List[str]]) -> List[Dict[str, Any]]:
        samples = [
            s for s in res.samples
            if s.get("probe_transport") not in ("tcmalloc",)
        ]
        if proc_subset:
            samples = [s for s in samples if s["process"] in proc_subset]
        return samples

    @staticmethod
    def _tcmalloc_samples_for_plot(res: MemCpuMonitorResult) -> List[Dict[str, Any]]:
        return [s for s in res.samples if s.get("probe_transport") == "tcmalloc"]

    def _output_stem(self, out_dir: str, samples: List[Dict[str, Any]], basename_style: Optional[str] = None) -> str:
        style = basename_style or self._output_basename_style
        base = _stem_filename(self.request, samples, style)
        return os.path.join(out_dir, base)

    def _resolve_plot_proc_subset(
        self,
        res: MemCpuMonitorResult,
        proc_subset: Optional[List[str]],
        auto_host_jumper_subset: Optional[bool],
    ) -> Optional[List[str]]:
        """
        If ``proc_subset`` is set, use it. Otherwise when ``auto_host_jumper_subset`` (default: follow
        ``host_top_all_procs`` from ``start()``) is True and ``host_top_all_procs`` is set: chart every
        host process that was **stored** (already filtered to user list ∪ top RSS at capture time),
        plus matching docker ``top`` rows and ``free_used`` when present. Legacy jump-based subsetting
        applies only if adaptive is on without ``host_top_all_procs`` (unusual).
        """
        if proc_subset is not None:
            return proc_subset
        use_adaptive = self._host_top_all_procs if auto_host_jumper_subset is None else bool(auto_host_jumper_subset)
        if not use_adaptive:
            return None
        if self._host_top_all_procs:
            keys: Set[str] = set()
            for s in res.samples:
                if s.get("kind") != "sample" or s.get("probe_transport") != "top":
                    continue
                if s.get("scope") == "host":
                    keys.add(s["process"])
                elif self._proc_list and s.get("scope") != "host":
                    proc = s.get("process")
                    if proc and any(u in proc for u in self._proc_list):
                        keys.add(proc)
            if any(s.get("process") == "free_used" for s in res.samples):
                keys.add("free_used")
            return sorted(keys) if keys else None
        eff = effective_adaptive_plot_processes(res.samples, self._proc_list, self._jumper_top_n)
        keys = set(eff) if eff else set()
        if self._proc_list:
            for s in res.samples:
                if s.get("kind") != "sample" or s.get("probe_transport") != "top":
                    continue
                if s.get("scope") == "host":
                    continue
                proc = s.get("process")
                if proc and any(u in proc for u in self._proc_list):
                    keys.add(proc)
        if any(s.get("process") == "free_used" for s in res.samples):
            keys.add("free_used")
        return sorted(keys) if keys else None

    def plot(
        self,
        result: Optional[MemCpuMonitorResult] = None,
        proc_subset: Optional[List[str]] = None,
        out_dir: Optional[str] = None,
        auto_host_jumper_subset: Optional[bool] = None,
        basename_style: Optional[str] = None,
    ) -> Optional[str]:
        """
        Write a PNG with three rows: CPU %, top ``%MEM`` / host ``free`` %, and RSS or host used (MiB)
        vs ``t_wall`` if matplotlib is installed.

        When ``start(..., host_top_all_procs=True)`` and ``proc_subset`` is omitted, the default is
        to chart all **stored** host processes (capture already applied RSS ranking ∪ user list); pass
        ``auto_host_jumper_subset=False`` to chart every stored sample series (same for non-adaptive).

        ``basename_style`` overrides ``output_basename_style`` from ``start()`` for this file only
        (``full`` / ``short_node`` / ``dut_ts_hash``); see README.

        Returns path written, or None if skipped.
        """
        try:
            import matplotlib.dates as mdates
            import matplotlib.pyplot as plt
            from matplotlib.ticker import AutoMinorLocator
        except ImportError:
            logger.info("matplotlib not available; mem_cpu_monitor.plot() skipped")
            if self._top_raw_log_path:
                logger.info("mem_cpu_monitor.plot() top raw stdout log: %s", self._top_raw_log_path)
            if self._tcmalloc_raw_log_path:
                logger.info("mem_cpu_monitor.plot() tcmalloc raw stdout log: %s", self._tcmalloc_raw_log_path)
            return None

        res = result or self._last_result
        if res is None or not res.samples:
            logger.info("mem_cpu_monitor.plot(): no samples to plot")
            if self._top_raw_log_path:
                logger.info("mem_cpu_monitor.plot() top raw stdout log: %s", self._top_raw_log_path)
            if self._tcmalloc_raw_log_path:
                logger.info("mem_cpu_monitor.plot() tcmalloc raw stdout log: %s", self._tcmalloc_raw_log_path)
            return None

        resolved = self._resolve_plot_proc_subset(res, proc_subset, auto_host_jumper_subset)
        if resolved is not None:
            logger.info("mem_cpu_monitor.plot() proc subset: %s", resolved)
        samples = self._filter_samples_for_plot(res, resolved)
        tcmalloc_samples = self._tcmalloc_samples_for_plot(res)
        if not samples and not tcmalloc_samples:
            if self._top_raw_log_path:
                logger.info("mem_cpu_monitor.plot() top raw stdout log: %s", self._top_raw_log_path)
            if self._tcmalloc_raw_log_path:
                logger.info("mem_cpu_monitor.plot() tcmalloc raw stdout log: %s", self._tcmalloc_raw_log_path)
            return None

        out_dir = self._resolve_out_dir(out_dir)
        os.makedirs(out_dir, exist_ok=True)
        plot_samples = samples if samples else tcmalloc_samples
        path = self._output_stem(out_dir, plot_samples, basename_style) + ".png"

        by_proc: Dict[str, List[Tuple[datetime, float, float, Optional[float]]]] = defaultdict(list)
        for s in samples:
            tw = s["t_wall"]
            if isinstance(tw, str):
                tw = datetime.fromisoformat(tw.replace("Z", "+00:00"))
            if tw.tzinfo is None:
                tw = tw.replace(tzinfo=timezone.utc)
            cpu_val = float(s["cpu_pct"]) if s.get("cpu_pct") is not None else 0.0
            mib = s.get("mem_res_mib")
            if mib is None and s.get("mem_mib_used") is not None:
                mib = float(s["mem_mib_used"])
            by_proc[s["process"]].append((tw, cpu_val, float(s["mem_pct"]), mib))

        by_tcmalloc_heap: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        by_tcmalloc_free: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        for s in tcmalloc_samples:
            tw = s["t_wall"]
            if isinstance(tw, str):
                tw = datetime.fromisoformat(tw.replace("Z", "+00:00"))
            if tw.tzinfo is None:
                tw = tw.replace(tzinfo=timezone.utc)
            heap_b = s.get("tcmalloc_heap_size_bytes")
            free_b = s.get("tcmalloc_pageheap_free_bytes")
            proc = s["process"]
            if heap_b is not None:
                by_tcmalloc_heap[proc].append((tw, float(heap_b) / (1024.0 * 1024.0)))
            if free_b is not None:
                by_tcmalloc_free[proc].append((tw, float(free_b) / (1024.0 * 1024.0)))

        n_rows = 5 if tcmalloc_samples else 3
        fig, axes = plt.subplots(n_rows, 1, figsize=(11, 4 + 2.5 * n_rows), sharex=True)
        if n_rows == 3:
            ax_cpu, ax_mem_pct, ax_mem_mib = axes
            ax_tcm_heap = ax_tcm_free = None
        else:
            ax_cpu, ax_mem_pct, ax_mem_mib, ax_tcm_heap, ax_tcm_free = axes

        for proc, series in by_proc.items():
            series.sort(key=lambda x: x[0])
            xs = [x[0] for x in series]
            ax_cpu.plot(xs, [x[1] for x in series], marker="o", markersize=2, label=proc)
            ax_mem_pct.plot(xs, [x[2] for x in series], marker="o", markersize=2, label=proc)
            xs_m = [x[0] for x in series if x[3] is not None]
            ys_m = [x[3] for x in series if x[3] is not None]
            if xs_m:
                ax_mem_mib.plot(xs_m, ys_m, marker="o", markersize=2, label=proc)

        if ax_tcm_heap is not None and ax_tcm_free is not None:
            for proc, series in by_tcmalloc_heap.items():
                series.sort(key=lambda x: x[0])
                xs = [x[0] for x in series]
                ax_tcm_heap.plot(xs, [x[1] for x in series], marker="o", markersize=2, label=proc)
            for proc, series in by_tcmalloc_free.items():
                series.sort(key=lambda x: x[0])
                xs = [x[0] for x in series]
                ax_tcm_free.plot(xs, [x[1] for x in series], marker="o", markersize=2, label=proc)

        plot_axes = list(axes) if hasattr(axes, "__iter__") else [axes]
        for ev in res.events:
            if ev.get("kind") != "event":
                continue
            tw = ev["t_wall"]
            if isinstance(tw, str):
                tw = datetime.fromisoformat(tw.replace("Z", "+00:00"))
            if tw.tzinfo is None:
                tw = tw.replace(tzinfo=timezone.utc)
            label = ev.get("event", "event")
            for ax in plot_axes:
                ax.axvline(tw, color="red", linestyle="--", alpha=0.35)
                ymax = ax.get_ylim()[1]
                ax.text(
                    tw,
                    ymax,
                    label,
                    rotation=90,
                    va="top",
                    ha="right",
                    fontsize=7,
                    color="darkred",
                    clip_on=False,
                )

        ax_cpu.set_ylabel("CPU %")
        ax_cpu.set_title(self.request.node.nodeid, fontsize=7)

        ax_mem_pct.set_ylabel("MEM % (top %MEM / free %total)")

        ax_mem_mib.set_ylabel("MiB (top RES / free used)")
        if n_rows == 3:
            ax_mem_mib.set_xlabel("Time (UTC)")
        else:
            ax_tcm_heap.set_ylabel("tcmalloc heap (MiB)")
            ax_tcm_free.set_ylabel("tcmalloc pageheap free (MiB)")
            ax_tcm_free.set_xlabel("Time (UTC)")

        dt_fmt = mdates.DateFormatter("%H:%M:%S")
        for ax in plot_axes:
            ax.yaxis.set_minor_locator(AutoMinorLocator(1))
            ax.grid(True, which="major", alpha=0.3)
            ax.grid(True, which="minor", alpha=0.15, linestyle=":", linewidth=0.6)
            ax.xaxis.set_major_formatter(dt_fmt)
            ax.tick_params(axis="x", labelbottom=True, labelrotation=22, labelsize=8)

        top_margin = 0.94
        legend_proc_count = max(len(by_proc), len(by_tcmalloc_heap), len(by_tcmalloc_free), 1)
        ncol = min(8, max(1, legend_proc_count))
        legend_kw = {
            "loc": "upper center",
            "bbox_to_anchor": (0.5, -0.32),
            "ncol": ncol,
            "fontsize": 7,
            "frameon": True,
        }
        if by_proc:
            ax_cpu.legend(**legend_kw)
            ax_mem_pct.legend(**legend_kw)
            ax_mem_mib.legend(**legend_kw)
        if ax_tcm_heap is not None and by_tcmalloc_heap:
            ax_tcm_heap.legend(**legend_kw)
        if ax_tcm_free is not None and by_tcmalloc_free:
            ax_tcm_free.legend(**legend_kw)
        fig.subplots_adjust(hspace=0.85, bottom=0.12, top=top_margin)
        fig.savefig(path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        logger.info("mem_cpu_monitor.plot() wrote %s", path)
        if self._top_raw_log_path:
            logger.info("mem_cpu_monitor.plot() top raw stdout log: %s", self._top_raw_log_path)
        if self._tcmalloc_raw_log_path:
            logger.info("mem_cpu_monitor.plot() tcmalloc raw stdout log: %s", self._tcmalloc_raw_log_path)
        return path

    def export_samples(
        self,
        result: Optional[MemCpuMonitorResult] = None,
        proc_subset: Optional[List[str]] = None,
        out_dir: Optional[str] = None,
        formats: Union[Tuple[str, ...], List[str]] = ("json", "csv"),
        auto_host_jumper_subset: Optional[bool] = None,
        basename_style: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Write the same filtered samples as ``plot()`` to JSON and/or CSV (plus serialized ``events`` in JSON).

        CSV rows include ``plot_cpu_pct``, ``plot_mem_pct``, and ``plot_mem_mib`` matching the chart series.
        Uses the same ``proc_subset`` / adaptive rules as ``plot()``. ``basename_style`` matches ``plot()``.
        """
        res = result or self._last_result
        if res is None or not res.samples:
            logger.info("mem_cpu_monitor.export_samples(): no samples")
            if self._top_raw_log_path:
                logger.info("mem_cpu_monitor.export_samples() top raw stdout log: %s", self._top_raw_log_path)
            return {}

        resolved = self._resolve_plot_proc_subset(res, proc_subset, auto_host_jumper_subset)
        samples = self._filter_samples_for_plot(res, resolved)
        tcmalloc_samples = self._tcmalloc_samples_for_plot(res)
        export_samples = samples + tcmalloc_samples
        if not export_samples:
            if self._top_raw_log_path:
                logger.info("mem_cpu_monitor.export_samples() top raw stdout log: %s", self._top_raw_log_path)
            if self._tcmalloc_raw_log_path:
                logger.info(
                    "mem_cpu_monitor.export_samples() tcmalloc raw stdout log: %s",
                    self._tcmalloc_raw_log_path,
                )
            return {}

        out_dir = self._resolve_out_dir(out_dir)
        os.makedirs(out_dir, exist_ok=True)
        stem = self._output_stem(out_dir, export_samples, basename_style)
        style_used = basename_style or self._output_basename_style
        fmt_set = {str(f).lower() for f in formats}
        written: Dict[str, str] = {}

        if "json" in fmt_set:
            path = stem + ".json"
            payload = {
                "nodeid": self.request.node.nodeid,
                "node_name": self.request.node.name,
                "output_basename_style": style_used,
                "export_file_basename": os.path.basename(stem),
                "proc_subset": proc_subset,
                "plot_proc_subset_resolved": resolved,
                "raw_command_log": self._raw_log_path,
                "top_raw_log": self._top_raw_log_path,
                "tcmalloc_raw_log": self._tcmalloc_raw_log_path,
                "samples": [_build_export_sample_row(s) for s in export_samples],
                "events": [_serialize_event(e) for e in res.events],
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            written["json"] = path
            logger.info("mem_cpu_monitor.export_samples() wrote %s", path)

        if "csv" in fmt_set:
            path = stem + ".csv"
            rows = [_build_export_sample_row(s) for s in export_samples]
            fieldnames_set = set()
            for row in rows:
                fieldnames_set.update(row.keys())
            fieldnames = sorted(fieldnames_set)
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
            written["csv"] = path
            logger.info("mem_cpu_monitor.export_samples() wrote %s", path)

        if self._top_raw_log_path:
            written["top_raw_log"] = self._top_raw_log_path
            logger.info("mem_cpu_monitor.export_samples() top raw stdout log: %s", self._top_raw_log_path)
        if self._tcmalloc_raw_log_path:
            written["tcmalloc_raw_log"] = self._tcmalloc_raw_log_path
            logger.info(
                "mem_cpu_monitor.export_samples() tcmalloc raw stdout log: %s",
                self._tcmalloc_raw_log_path,
            )

        return written

    def teardown(self) -> None:
        """Fixture cleanup: stop sampler if still running."""
        if self._running or (self._thread and self._thread.is_alive()):
            try:
                self.stop()
            except Exception:  # noqa: BLE001
                logger.debug("mem_cpu_monitor teardown stop", exc_info=True)


def _safe_name(s: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", s)[:160]


def _serialize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(ev)
    tw = out.get("t_wall")
    if hasattr(tw, "isoformat"):
        out["t_wall"] = tw.isoformat()
    if "t_mono" in out and out["t_mono"] is not None:
        out["t_mono"] = float(out["t_mono"])
    return out


def _build_export_sample_row(s: Dict[str, Any]) -> Dict[str, Any]:
    """Same numeric fields used for matplotlib panels (CPU, %MEM, MiB, tcmalloc)."""
    mib = s.get("mem_res_mib")
    if mib is None and s.get("mem_mib_used") is not None:
        mib = float(s["mem_mib_used"])
    tw = s.get("t_wall")
    tw_out = tw.isoformat() if hasattr(tw, "isoformat") else str(tw)
    heap_b = s.get("tcmalloc_heap_size_bytes")
    free_b = s.get("tcmalloc_pageheap_free_bytes")
    row = {
        "seq": s.get("seq"),
        "t_wall": tw_out,
        "t_mono": float(s["t_mono"]) if s.get("t_mono") is not None else None,
        "dut": s.get("dut"),
        "scope": s.get("scope"),
        "process": s.get("process"),
        "pid": s.get("pid"),
        "cpu_pct": s.get("cpu_pct"),
        "mem_pct": s.get("mem_pct"),
        "mem_res_mib": s.get("mem_res_mib"),
        "mem_mib_used": s.get("mem_mib_used"),
        "mem_total_mib": s.get("mem_total_mib"),
        "plot_cpu_pct": float(s["cpu_pct"]) if s.get("cpu_pct") is not None else 0.0,
        "plot_mem_pct": float(s["mem_pct"]) if s.get("mem_pct") is not None else None,
        "plot_mem_mib": mib,
        "mem_unit": s.get("mem_unit"),
        "probe_transport": s.get("probe_transport"),
        "kind": s.get("kind"),
        "tcmalloc_heap_size_bytes": heap_b,
        "tcmalloc_pageheap_free_bytes": free_b,
    }
    if heap_b is not None:
        row["plot_tcmalloc_heap_mib"] = float(heap_b) / (1024.0 * 1024.0)
    if free_b is not None:
        row["plot_tcmalloc_pageheap_free_mib"] = float(free_b) / (1024.0 * 1024.0)
    return row
