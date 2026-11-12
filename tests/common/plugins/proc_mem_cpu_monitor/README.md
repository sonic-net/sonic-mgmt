# proc_mem_cpu_monitor

Optional pytest plugin for **periodic process CPU and memory sampling** on SONiC DUTs using batch `top` (`top -bn1`), with **timeline events**, optional **memory drift check** vs the first reading, and optional **plots** (matplotlib).

This package is **separate** from the autouse [`memory_utilization`](../memory_utilization/) plugin.

## Registration and default (disabled)

The plugin is registered in the repo root [`tests/conftest.py`](../../conftest.py) `pytest_plugins` tuple so the **`mem_cpu_monitor`** fixture is always available.

**The fixture is a no-op unless you explicitly enable it** (no background `top` sampling, no DUT commands):

- **Whole session:** `pytest --enable_proc_mem_cpu_monitor ...`
- **Selected tests:** `@pytest.mark.enable_proc_mem_cpu_monitor` on the test (or module/class via `pytestmark`).

If you load this package only from a **local** `pytest_plugins` (without root registration), the same opt-in rules apply once the plugin is loaded.

## Logging (`--log-cli-level DEBUG`)

Periodic probes call `duthost.command()` (via `tests.common.devices.base`). At **DEBUG**, that layer can log full Ansible args and JSON results on every call, which is very noisy at short **`interval`** values.

While each probe runs, this plugin **temporarily sets** the logger **`tests.common.devices.base`** to **INFO** and restores the previous level afterward, so **DEBUG** on the rest of the test (and other loggers) is unchanged. Other code that runs **in parallel** on the same process could still see that windowusually negligible under normal serial pytest use.

## Fixture API (`mem_cpu_monitor`)

```python
import pytest
from tests.common.plugins.proc_mem_cpu_monitor import MEM_LEAK_EVENT

@pytest.mark.enable_proc_mem_cpu_monitor
def test_example(duthosts, mem_cpu_monitor, enum_rand_one_frontend_hostname):
    dut = duthosts[enum_rand_one_frontend_hostname]
    mem_cpu_monitor.start(
        dut, ["bgpd", "zebra"], interval=2.0,
        host_top_all_procs=True, include_host_free=True, capture_raw_stdout=True,
    )
    mem_cpu_monitor.snapshot(event="Route_Withdrawal")
    mem_cpu_monitor.snapshot(event=MEM_LEAK_EVENT, threshold="10%")
    res = mem_cpu_monitor.stop()
    mem_cpu_monitor.plot(res, out_dir="/tmp")
    mem_cpu_monitor.export_samples(res, out_dir="/tmp")
```

### `start(duts, proc_list, interval=1.0, docker_service="bgp", include_host_top=False, include_host_free=False, asics="frontend", host_top_all_procs=False, skip_docker_top=None, jumper_top_n=5, capture_raw_stdout=False, raw_log_path=None, top_raw_log_path=None, output_basename_style="full")`

- **duts**: one `MultiAsicSonicHost` or `DutHosts` / iterable of DUTs.
- **interval**: seconds between **completed poll rounds** (one round runs every configured probe: host `top`, per-ASIC docker `top` if enabled, `free -m` if enabled, for each DUT in order). **Default `1.0`** if you omit **`interval`**. After `start()`, the **first** round runs immediately; the sampler thread then waits **`interval`** before starting the **next** round (so smaller values give denser samples and more DUT load).
- **proc_list**: substrings for **interest** processes: matched against `COMMAND` on **filtered** `top`, or against the **basename** of the first token of COMMAND on **host-wide** `top`. With **`host_top_all_procs=True`**, stored host rows per tick are **not** every process: see **`jumper_top_n`** below. Mem-leak baselines on host-wide rows apply to every stored process when **`proc_list`** is empty, and only to substring matches when **`proc_list`** is non-empty.
- **docker_service**: per-ASIC container name stem (default `bgp` ? `bgp0`,  on multi-ASIC).
- **include_host_top**: host `top` filtered by `proc_list` (ignored if **`host_top_all_procs=True`**  then a single full-process host `top` is used instead).
- **include_host_free**: host `free -m` each interval; sample **process** `free_used` (see below).
- **asics**: `"frontend"` (default) or `"all"`.
- **host_top_all_procs**: if **True**, run **host** `top -bn1` only (per DUT); **`parse_top_host_all`** yields one row per basename (largest **RES** wins if duplicated); **`process`** is the command **basename**; **`pid`** is on each row. **Only a subset of those rows is stored each tick** (see **`jumper_top_n`**): the global top **`jumper_top_n`** processes by **RSS** (`mem_res_mib`, tie-break **`%MEM`**), **or** if **`proc_list`** is non-empty, the **union** of all substring matches plus enough additional highest-RSS processes so that user matches that already sit in the global top-**N** RSS set reduce how many extras are added (see examples in **Adaptive plot / export**). By default **docker** `top` targets are **skipped** (`skip_docker_top` defaults to **True** when this is set). Set **`skip_docker_top=False`** to keep per-ASIC docker `top` as well.
- **skip_docker_top**: explicit override; **`None`** means skip docker tops iff **`host_top_all_procs`** is True.
- **jumper_top_n** (default **5**): with **`host_top_all_procs=True`**, this **N** controls **which host processes are stored** each tick: top-**N** by RSS, merged with **`proc_list`** matches as described under **`host_top_all_procs`**. It is also the swing-rank size for **`effective_adaptive_plot_processes`** when adaptive plotting runs **without** host-wide mode (legacy).
- **capture_raw_stdout**: if **True**, append every probes full stdout to **`raw_log_path`** (default `mem_cpu_monitor_raw_commands.log` under pytest **`tmp_path`**), including **`mem_leak`** re-checks.
- **raw_log_path**: optional absolute path for the raw log file.
- **top_raw_log_path**: optional absolute path for the **dedicated `top`-only** raw stdout log (host and docker `top` probes, including **`mem_leak`** re-parses). Default **`mem_cpu_monitor_top_raw.log`** under pytest **`tmp_path`** whenever the sampler includes a `top` target; omitted if the run only probes **`free`** (no `top`). **`stop()`**, **`plot()`**, and **`export_samples()`** log this path; JSON export includes **`top_raw_log`**; **`export_samples()`** also returns **`"top_raw_log"`** in the written-paths dict.
- **output_basename_style**: `full`, `short_node`, or `dut_ts_hash`  controls PNG/JSON/CSV filenames; see **Output basename** below.

### Host-wide `process` names and `top` truncation

`top` limits the COMMAND column width; long argv0 strings appear truncated (e.g. `redis-s+`). That comes from **`top`**, not this plugin. Inspect the **automatic `top` raw log** (`mem_cpu_monitor_top_raw.log` under **`tmp_path`** by default) for full **`top`** output each tick, or use the optional **raw command log** when **`capture_raw_stdout=True`** to capture **`top`**, **`free`**, and every other probe in one file.

### `free_used` sample (host RAM)

When **`include_host_free=True`**, each tick runs **`free -m`** on the DUT. One synthetic sample is stored with **`process="free_used"`**:

- **`mem_mib_used`** / **`plot_mem_mib`**: **used** RAM in MiB from the `Mem:` line (same as the **`used`** column in `free -m`).
- **`mem_total_mib`**: total RAM (MiB) from `free -m` when available.
- **`mem_pct`**: **100 × used / total** (percent of physical RAM in use).

So **`free_used`** is **system-wide used memory**, not a single process; it is included on the same charts as the MiB / % panels for correlation with process RSS.

### Adaptive plot / export (host-wide mode)

**Capture (storage)** when **`host_top_all_procs=True`**: let **N** = **`jumper_top_n`** (default 5). Each tick, after parsing full host `top`, only these basenames are appended as samples:

- **`proc_list` empty or omitted**: the **N** processes with highest **RSS** (`mem_res_mib`, then **`%MEM`**).
- **`proc_list` non-empty**: every process whose basename contains a user substring, **plus** the **N - k** highest-RSS processes among the rest, where **k** is how many of the global top-**N** RSS processes are already covered by those user matches.

Examples (N = 5): user **`["a","b"]`** and **b** is in the global top-5 by RSS ? stored set is **{a, b}** plus the **four** next-highest RSS processes outside **{a,b}**. User **`["a","b","c"]`** with **a** and **c** in the global top-5 ? stored set is **{a,b,c}** plus **three** more highest-RSS fillers. Empty **`proc_list`** ? top **5** by RSS only.

**Charts / export** when **`host_top_all_procs=True`** and **`proc_subset`** is omitted and **`auto_host_jumper_subset`** is not **`False`**: the default is to plot **every stored** host `top` series (already filtered as above), **`free_used`** if sampled, and docker `top` rows matching **`proc_list`** when docker probes are enabled.

Pass **`auto_host_jumper_subset=False`** to **`plot`/`export_samples`** to chart **all** stored series (same set in host-wide mode when capture already narrowed rows). JSON export includes **`plot_proc_subset_resolved`**, **`raw_command_log`** (path or `null` when `capture_raw_stdout` was off), and **`top_raw_log`** (path or `null` when no `top` probes).

### `snapshot(event=None, threshold=None, strict=True)`

- Records **event** on the timeline (default label `snapshot`).
- If `event == MEM_LEAK_EVENT` (`"mem_leak"`) **and** `threshold` is set (e.g. `"10%"`), runs an immediate `top` parse and checks each process **memory %** is within **±threshold** of the **first** reading seen after `start()` (relative band). On failure and `strict=True`, calls `pytest.fail`.

### `stop()`

Stops the background sampler and returns `MemCpuMonitorResult` (`samples`, `events`, `timeline` sorted by time, and **`top_raw_log_path`** when a `top` raw file was created). Logs the **`top` raw log** path at **INFO** when present (same style as **`plot()`** / **`export_samples()`** path logs).

### Output basename (PNG / JSON / CSV file names)

Long parametrized **`nodeid`** strings produce long paths. Set on **`start(..., output_basename_style=...)`** (default **`full`**) or override per call on **`plot(..., basename_style=...)`** / **`export_samples(..., basename_style=...)`**.

| Style | Pattern (concept) | When to use |
| ----- | ----------------- | ----------- |
| **`full`** | `sanitized_nodeid__dut__YYYYmmddTHHMMSSZ` | Default; unambiguous, can be very long. |
| **`short_node`** | `sanitized_node.name__dut__YYYYmmddTHHMMSSZ` | Drops file path; keeps function + param marks (usually much shorter). |
| **`dut_ts_hash`** | `dut__YYYYmmdd_HHMMSS__<10 hex>` | Shortest; DUT + time + SHA-256 prefix of full **`nodeid`**. Map back via JSON fields **`nodeid`** / **`node_name`**. |

Other ideas (not built-in): pass a **`pytest` custom property** or env var in your job to build your own stem and copy/rename artifacts after **`export_samples`**; or archive with **`zipfile`** so internal names can stay long.

### `plot(..., basename_style=None)`

Writes a PNG with **four** rows when matplotlib is installed and host `top` (or other process) samples exist: **system CPU idle %** (from host `top -bn1` `%Cpu(s):` `id`), **per-process CPU %**, **%MEM** (from `top` and host-% for `free_used`), and **MiB** (`top` **RES** / `free` **used** MiB). Optional **tcmalloc** rows append when enabled. (Optional **Reference** text for **`total_mem`** / **`num_cores`** on the figure is **commented out** in ``plot()`` for now; probes at **`start()`** still populate **`num_cores`** in the timeline event **extra**.) Snapshot **event** names are drawn at each vertical marker on **all** panels. Returns the path or `None`. Logs the **`top` raw stdout** file path at **INFO** when a `top` raw log exists (including when plotting is skipped but raw log was captured).

System CPU idle % requires host `top` (`include_host_top=True` or `host_top_all_procs=True`); it is parsed from the same `top -bn1` stdout as per-process rows (no extra DUT command).

The output basename follows **`output_basename_style`** from **`start()`**, unless **`basename_style`** is set for this call. Companion **JSON/CSV** should use the same style (set on **`start`** or pass **`basename_style`** to **`export_samples`** too).

**`auto_host_jumper_subset`**: **`None`** follows **`host_top_all_procs`** from **`start()`**; **`False`** plots every series.

### `export_samples(..., basename_style=None)`

Writes the **same filtered samples** as `plot()` to JSON and/or CSV. JSON includes **`nodeid`**, **`node_name`**, **`output_basename_style`**, **`export_file_basename`** (stem without extension), serialized **events**, **`plot_proc_subset_resolved`**, **`raw_command_log`**, **`top_raw_log`**. CSV columns include `plot_cpu_pct`, `plot_mem_pct`, `plot_mem_mib`, and `plot_system_cpu_idle_pct` when host `top` summary samples exist. Returns a dict with paths for each written format (e.g. **`json`**, **`csv`**) plus **`top_raw_log`** when a `top` raw file exists. Logs each written path and the **`top` raw log** path at **INFO** when applicable.

## Imports

```python
from tests.common.plugins.proc_mem_cpu_monitor import MEM_LEAK_EVENT, ProcMemCpuMonitor
```

## Alternate controller (`show event cpu`)

The default ``controller.py`` (and the ``mem_cpu_monitor`` fixture from ``__init__.py``) does **not** implement FRR **``show event cpu``** periodic sampling.

A full-featured copy that still supports ``include_event_cpu_stats`` / ``event_cpu_raw_log_path`` / ``probe_transport == "event_cpu"`` samples lives beside it as **`event_cpu.controller.py`**. Because the filename contains a **dot**, it is **not** a normal importable dotted module; load it with ``importlib.util.spec_from_file_location`` if needed, or rename it in a fork (e.g. ``event_cpu_controller.py``) for plain ``import``.

## Limitations (v1)

- **Probe transport** is `top` in host and/or per-ASIC BGP docker only; `vtysh_shell` templates from the design doc are not implemented yet.
- Parser targets **procps-style** `top`; a loose fallback exists for odd formats.
- **Chassis / multi-linecard**: pass the DUT(s) you need explicitly to `start()` (e.g. iterate `duthosts.nodes` in the test).
