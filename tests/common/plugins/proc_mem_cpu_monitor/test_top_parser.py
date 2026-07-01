# -*- coding: utf-8 -*-
import pytest
from tests.common.plugins.proc_mem_cpu_monitor.controller import (
    _host_top_capture_names,
    effective_adaptive_plot_processes,
)
from tests.common.plugins.proc_mem_cpu_monitor.top_parser import (
    parse_free_m_used,
    parse_top,
    parse_top_batch,
    parse_top_host_all,
)

pytestmark = [
    pytest.mark.topology('t0', 't1', 'any')
]


PROCPS_TOP = """
top - 14:32:10 up 1 day,  2 users,  load average: 0.10, 0.12, 0.09
Tasks: 200 total,   1 running, 199 sleeping,   0 stopped,   0 zombie
%Cpu(s):  1.0 us,  0.5 sy,  0.0 ni, 98.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :  32000.0 total,  28000.0 free,   2000.0 used,   2000.0 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used.  30000.0 avail Mem

    PID USER      PR  NI    VIRT    RES  SHR S  %CPU %MEM     TIME+ COMMAND
   1001 root      20   0  500000  80000  12000 S   5.5  2.5   1:00.12 bgpd
   1002 root      20   0  400000  60000  10000 S   1.2  1.1   0:10.00 zebra
"""


def test_parse_top_batch_bgpd_zebra():
    rows = parse_top_batch(PROCPS_TOP, ["bgpd", "zebra"])
    by = {r["process"]: r for r in rows}
    assert "bgpd" in by and "zebra" in by
    assert by["bgpd"]["cpu_pct"] == 5.5
    assert by["bgpd"]["mem_pct"] == 2.5
    assert by["bgpd"]["mem_res_mib"] == round(80000 / 1024.0, 2)
    assert by["zebra"]["pid"] == 1002


def test_parse_top_empty():
    assert parse_top("", ["bgpd"]) == []


def test_parse_top_strict_only():
    blob = "no columns here bgpd"
    assert parse_top_batch(blob, ["bgpd"]) == []


def test_parse_top_host_all_keys_and_rows():
    rows = parse_top_host_all(PROCPS_TOP)
    by_name = {r["process"]: r for r in rows}
    assert "bgpd" in by_name and "zebra" in by_name
    assert by_name["bgpd"]["pid"] == 1001
    assert by_name["zebra"]["pid"] == 1002
    assert by_name["bgpd"]["cpu_pct"] == 5.5


PROCPS_DUP = PROCPS_TOP + "   2001 root      20   0  100000  20000  5000 S   0.1  0.3   0:00.01 bgpd\n"


def test_parse_top_host_all_dedupes_same_basename_by_res():
    rows = parse_top_host_all(PROCPS_DUP)
    bgpds = [r for r in rows if r["process"] == "bgpd"]
    assert len(bgpds) == 1
    assert bgpds[0]["pid"] == 1001
    assert bgpds[0]["mem_res_mib"] == round(80000 / 1024.0, 2)


def _sample(process, cpu, mem, scope="host"):
    return {
        "kind": "sample",
        "probe_transport": "top",
        "scope": scope,
        "process": process,
        "cpu_pct": cpu,
        "mem_pct": mem,
    }


def test_effective_adaptive_all_jumpers_in_interest():
    samples = []
    for t in range(4):
        samples.append(_sample("bgpd", 1.0 + t * 0.1, 2.0))
        samples.append(_sample("zebra", 0.5, 1.0))
    out = effective_adaptive_plot_processes(samples, ["bgpd", "zebra"], jumper_top_n=5)
    assert out is not None
    assert set(out) == {"bgpd", "zebra"}


def _host_row(process: str, mem_res_mib: float, mem_pct: float = 0.0) -> dict:
    return {"process": process, "mem_res_mib": mem_res_mib, "mem_pct": mem_pct}


def test_host_top_capture_names_empty_proc_list_top_n():
    rows = [
        _host_row("p1", 100),
        _host_row("p2", 90),
        _host_row("p3", 80),
        _host_row("p4", 70),
        _host_row("p5", 60),
        _host_row("p6", 50),
    ]
    assert _host_top_capture_names(rows, [], 5) == {"p1", "p2", "p3", "p4", "p5"}


def test_host_top_capture_names_user_plus_fillers_one_overlap():
    # Top-5 by RSS: t1..t5; user wants a (low RSS) and b (inside top-5).
    rows = [
        _host_row("t1", 100),
        _host_row("t2", 90),
        _host_row("b", 80),
        _host_row("t3", 70),
        _host_row("t4", 60),
        _host_row("t5", 50),
        _host_row("a", 5),
    ]
    cap = _host_top_capture_names(rows, ["a", "b"], 5)
    assert cap == {"a", "b", "t1", "t2", "t3", "t4"}


def test_host_top_capture_names_user_plus_fillers_two_overlap():
    # Top-5: t1, a, c, t2, t3 — user {a,b,c} overlaps two; add three more RSS leaders not in user.
    rows = [
        _host_row("t1", 100),
        _host_row("a", 99),
        _host_row("c", 98),
        _host_row("t2", 97),
        _host_row("t3", 96),
        _host_row("b", 10),
        _host_row("t4", 95),
        _host_row("t5", 94),
    ]
    cap = _host_top_capture_names(rows, ["a", "b", "c"], 5)
    assert cap == {"a", "b", "c", "t1", "t2", "t3"}


def test_effective_adaptive_adds_outside_jumper():
    samples = []
    for t in range(4):
        samples.append(_sample("bgpd", 1.0, 2.0))
        samples.append(_sample("syncd", 0.1, 1.0 + t * 5.0))
    out = effective_adaptive_plot_processes(samples, ["bgpd"], jumper_top_n=5)
    assert out is not None
    assert "syncd" in out
    assert "bgpd" in out


FREE_M_OUT = """
              total        used        free      shared  buff/cache   available
Mem:          32000       10200       12000         100        9700       21000
Swap:             0           0           0
"""


def test_parse_free_m_used():
    d = parse_free_m_used(FREE_M_OUT)
    assert d is not None
    assert d["used_mib"] == 10200
    assert d["total_mib"] == 32000
    assert abs(d["used_pct"] - (100.0 * 10200 / 32000)) < 0.02
    assert parse_top("", ["bgpd"]) == []
