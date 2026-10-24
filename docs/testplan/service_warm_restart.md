# Standalone BGP service warm restart and upgrade

`platform_tests/test_service_warm_restart.py` uses the existing `AdvancedReboot`
fixture and PTF `advanced-reboot.ReloadTest`. Explicit BGP selection enables
single-ASIC T0, T1, M0 and MX testbeds:

```bash
./run_tests.sh -n <testbed> -d <dut> -c platform_tests/test_service_warm_restart.py \
  -e "--warm-restart-service=bgp"
```

To test an image-changing upgrade, add an HTTP(S) Docker archive URL:

```bash
./run_tests.sh -n <testbed> -d <dut> -c platform_tests/test_service_warm_restart.py \
  -e "--warm-restart-service=bgp --new_docker_image=https://images.example/build/docker-fpm-frr.gz"
```

The existing directory-URL form of `--new_docker_image` remains supported; the
fixture appends `<running-image-name>.gz` while preserving URL query parameters.
With no image URL, the operation is a same-image restart, not an upgrade. Failed
downloads, invalid/wrong-service archives, and archives containing the current
image fail before disruption rather than falling back to a restart. After an
upgrade, the running container must have a different full image ID, and its
architecture, OS, runtime configuration and ordered rootfs-layer fingerprints
must match the archive. This works with both classic and containerd image stores,
which can expose different types of image ID. Raw image configuration is not
included in the result report.

## Prerequisites and coverage

- The running image must already enable BGP GR with `preserve-fw-state`, and the
  configured IPv4/IPv6 peers must have established sessions with negotiated GR.
  Installing these settings only in the target image is too late.
- Use a fully connected PTF testbed with reachable EOS or SONiC neighbor VMs.
  Each peer must provide a route to the DUT's IPv4 and IPv6 loopbacks through
  the DUT. Peer checks support physical routed interfaces and LAGs.
- VLAN-backed testbeds retain the existing simulated-host traffic. Their remote
  destination is selected from installed BGP routes. VLAN-less testbeds use two
  learned destinations with disjoint physical/LAG egress-port sets; the source
  addresses also have learned return paths. No artificial VLAN is configured.
- Packet capture and traffic in both directions must be ready before the
  service operation. BGP-only testing does not wait for teamd shutdown or the
  full-switch warmboot-finalizer. It uses captured packet sequences on physical
  devices and VS, not the coarse KVM reachability threshold.

## Results and cleanup

The default BGP forwarding-disruption limit is zero seconds; the existing
`--reboot_limit` option can explicitly select a different limit. The packet
measurement covers **IPv4 traffic**. Both address families are covered by BGP
session recovery, sampled peer-loopback next hops, and APPL_DB route comparison.

Success requires a new warm-restore attempt reaching `reconciled`, recovery of
the original BGP peers, and the original APPL_DB route prefixes and paired next
hops/interfaces. Matching route counts alone is insufficient. Peer samples,
image identities, recovery results, and packet-loss measurements are included
in the service report. Logs and packet captures are fetched through the existing
framework, including on failures.

The original BGP warm-enable field is restored, including an originally absent
field. Unique staged archives are removed during fixture finalization. The
existing default `--stay_in_target_image=True` leaves the upgraded image running.
Selecting `--stay_in_target_image=False` retains the existing rollback behavior,
which includes a **cold switch reboot** after restoring the original image tag;
rollback is outside the measured service-warm interval.

Without `--warm-restart-service=bgp`, the original T0 service-selection rules
remain in effect, and non-T0 runs skip. Existing Mellanox/NVIDIA exclusions are
unchanged. This extension does not qualify multi-ASIC devices, IPv6 packet loss,
route-mutation SAD cases, or whole-switch warm reboot. Unit tests do not replace
VS and hardware qualification or establish zero packet loss on a platform.
