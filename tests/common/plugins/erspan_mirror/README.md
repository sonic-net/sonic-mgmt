# ERSPAN Mirror Plugin

## Overview

Automatically creates ERSPAN mirror sessions on the DUT and starts a tcpdump
capture on the corresponding PTF monitor port for the duration of each test.
On teardown the ERSPAN encapsulation (60B Eth+IPv4+GRE+ERSPAN-II) is stripped
with `editcap -C 60`, the stripped pcap is fetched to the local host
(`/tmp/<test>_<dut>_<port>_stripped.pcap`) and attached to the Allure report,
and the mirror session is removed. The raw pcap is left on the PTF.

This lets tests get a packet capture of what the DUT actually sent / received
on a dataplane port without wiring `mirror_session` and `tcpdump` into every
test body.

## How to use

To enable the plugin for a run, pass the CLI flag:

```
pytest ... --enable-dpc-mirroring
```

By default the plugin mirrors **every NPU<->DPU midplane (DPC) port on
every DUT**, enumerated directly from each DUT's `platform.json`
(`DPUS` -> `dpu*` -> `interface`). On non-smartswitch DUTs (no `DPUS`
section) the plugin is a no-op. This default works for both single-DUT
(DASH) and multi-DUT (HA) smartswitch tests, so packages do not need to
override anything to get full DPC coverage:

* Single DUT with 4 DPUs -> 4 sessions per test (`<test>_1` .. `<test>_4`,
  `dst=2.2.2.1` .. `2.2.2.4`).
* HA setup with 2 DUTs x 4 DPUs -> 8 sessions per test (`<test>_1` ..
  `<test>_8`, `dst=2.2.2.1` .. `2.2.2.8`).

Mirroring all DPC ports means the capture set does not depend on
`--dpu-pattern` ordering or on which DPUs a particular test happens to
exercise.

> Note: the pytest node name is sanitized for use in the pcap path and session
> name -- every run of characters outside `[A-Za-z0-9_.-]` (spaces, brackets
> from parameterization, etc.) is collapsed to a single `_`. ERSPAN session
> names are additionally capped at the first 20 characters of the sanitized
> name, followed by `_<n>`, so long parameterized test names will share a
> session-name prefix.

If `--enable-dpc-mirroring` is not passed, or if `erspan_mirror_targets`
returns an empty list, the plugin is a no-op.
