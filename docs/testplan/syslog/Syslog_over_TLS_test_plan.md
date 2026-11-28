# Feature Name
SonicMgmt Testcases for Syslog over TLS
# High Level Design Document
#### Rev 1.0
[SONiC Remote Syslog over TLS HLD](https://github.com/sonic-net/SONiC/pull/2600)

# Table of Contents
  * [List of Tables](#list-of-tables)
  * [Revision](#revision)
  * [About this Manual](#about-this-manual)
  * [Scope](#scope)
  * [Testing Strategy for Syslog over TLS feature](#testing-strategy-for-syslog-over-tls-feature)
  * [Test cases](#test-cases)
    * [TC1: Validate mTLS delivery from SONIC DUT](#tc1-validate-mtls-delivery-from-sonic-dut)
    * [TC2: Validate CA-only delivery from SONIC DUT](#tc2-validate-ca-only-delivery-from-sonic-dut)
    * [TC3: Validate permitted peers in TLS handshake](#tc3-validate-permitted-peers-in-tls-handshake)
    * [TC4: Validate fail-closed behaviour on server authentication failure](#tc4-validate-fail-closed-behaviour-on-server-authentication-failure)
    * [TC5: Validate fail-closed behaviour when collector requires a client certificate](#tc5-validate-fail-closed-behaviour-when-collector-requires-a-client-certificate)
    * [TC6: Validate fail-closed behaviour when the TLS profile is not usable](#tc6-validate-fail-closed-behaviour-when-the-tls-profile-is-not-usable)
    * [TC7: Validate late arrival and removal of trust material](#tc7-validate-late-arrival-and-removal-of-trust-material)
    * [TC8: Validate certificate rotation without CONFIG_DB change](#tc8-validate-certificate-rotation-without-config_db-change)
    * [TC9: Validate multi-server isolation and mixed transport](#tc9-validate-multi-server-isolation-and-mixed-transport)
    * [TC10: Validate persistence across config reload](#tc10-validate-persistence-across-config-reload)
    * [TC11: Validate persistence across reboot](#tc11-validate-persistence-across-reboot)
    * [TC12: Validate persistence across service restarts](#tc12-validate-persistence-across-service-restarts)
    * [TC13: Validate source address on a TLS server](#tc13-validate-source-address-on-a-tls-server)
  * [References](#references)
  * [Abbreviations](#abbreviations)
  * [Revision](#revision)


# List of Tables
[Table 1: Abbreviations](#table-1-abbreviations)

[Table 2: Collector addressing](#table-2-collector-addressing)

[Table 3: Collector roles](#table-3-collector-roles)

# Revision
| Rev |     Date    |       Author               | Change Description                |
|:---:|:-----------:|:--------------------------:|-----------------------------------|
| 0.1 | 09/11/2026  |     rjojupom               | Initial version in sonic-mgmt testplan format |
| 0.2 | 09/11/2026  |     rjojupom               | Capture plaintext on configured TLS ports; restore collectors before TC9 isolation; save config before TC11 reboot |

# About this Manual
This document describes the approach that can be taken for adding support for Syslog over TLS (RFC 5425) feature testing as part of sonic-mgmt test suite.

# Scope
This document describes the high level details of SONiC management test-cases for remote syslog over TLS.

The cases here cover only what needs a real DUT (`rsyslog-config` + host rsyslog TLS stream driver) talking to a real TLS collector:

- Encrypted delivery with server authentication by permitted peer name; mutual TLS and CA-only profiles
- Fail-closed behaviour: a TLS server that cannot be authenticated or fully configured delivers nothing and never falls back to cleartext
- Trust material changes while running: late arrival, removal, rotation
- Multi-server isolation and persistence across `config reload` / reboot / service restarts

**Out of scope:** CLI argument validation, rendered `rsyslog.conf` content and host-service file publishing (unit tested in sonic-utilities, sonic-config-engine and sonic-host-services); UDP/TCP behaviour, filters, severity and rate limit (existing syslog plans); OpenConfig and gNMI; SONiC as a syslog receiver; certificate-fingerprint peer authorisation (not implemented).

# Testing Strategy for Syslog over TLS feature:
Existing `t0` topology (or any topology with a PTF host) will be used for developing the Syslog over TLS test suite. SONIC DUT ports used for management/data reachability to the collector are connected to PTF. The PTF host runs the TLS collectors; it is not used as a packet-test dataplane for this feature.

Following mechanisms will be used in the test script implementation

- SONIC DUT will be configured using the available Click CLIs for syslog:
  `config syslog add <ip> --protocol tls --tls-profile-id <id> --tls-permitted-peers <name[,name...]>`
- Verification of operational data will be performed by fetching STATE_DB `SYSLOG_SERVER|<ip>` (`applied_transport_security`, `failure_reason`) and by `show syslog` / `show syslog tls-state`
- PTF will be used to run TLS collectors that accept RFC 5425 octet-counted frames, optionally require a client certificate, and record the peer certificate they saw
- PTF packet capture will be used to assert that a TLS-configured destination never receives plaintext syslog: not on UDP/514 or TCP/514, and not on the configured TLS port (6514 or 6515)

Every TLS case shares these assertions:

- No cleartext: capture to the TLS server's address shows no plaintext syslog on UDP/514, TCP/514, or the configured TLS port. Encrypted TLS records on that port are expected; unencrypted syslog frames on that port fail the case
- Marker on the collector within 30 s; STATE_DB updated within 60 s of the change

Trust material is generated per test session with ECDSA P-256 and SHA-256 (lab CA, a second CA, a certificate per collector role, a client certificate, plus negative sets). Profiles are installed under the DUT SSL profile directory that rsyslog consumes:

```text
/etc/sonic/ssl-certs/<profile_id>/ca-bundle.pem   # required
/etc/sonic/ssl-certs/<profile_id>/cert.pem         # optional, only together with key
/etc/sonic/ssl-certs/<profile_id>/key.pem
```

| Profile kind | Files | Meaning |
|--------------|-------|---------|
| mTLS | CA + cert + key | Server authenticated and the DUT presents a client identity |
| CA-only | CA | Server authenticated only; no client certificate is sent |
| Not ready | no CA, or only one of cert/key | Server skipped; `failure_reason=NO_CERTIFICATE` |

Suggested location for the pytest suite: `tests/syslog/test_syslog_tls.py`, reusing `syslog_utils.py` and `backup_and_restore_config_db_on_duts`. Topology marker: `any`. All cases run on sim and hardware except TC11 (hardware only). Negative handshake cases make rsyslog log TLS errors on purpose; add loganalyzer ignore patterns for those cases rather than disabling loganalyzer globally.

Expected limitations (not failures): rsyslog 8.2504 matches wildcard permitted peers against the certificate CN only, never SAN; `failure_reason` reflects file presence and the restart result, not certificate validity or delivery; source address is not applied to TCP/TLS connections (`omfwd` `Address` is UDP only), so TC13 is `xfail` until that is fixed.

### Table 2: Collector addressing

| VRF | Collector IPv4 | DUT IPv4 | Collector IPv6 | DUT IPv6 |
|-----|----------------|----------|----------------|----------|
| `default` | `100.100.100.1` | `100.100.100.2/24` | `2222::1111` | `2222::1112/64` |
| `Vrf-data` | `200.200.200.1` | `200.200.200.2/24` | `2221::1111` | `2221::1112/64` |

Static neighbours and routes on the PTF host so the DUT can reach each collector per VRF.

### Table 3: Collector roles

| Role | Bind | Behaviour |
|------|------|-----------|
| A-srv | `:6514` | Presents `collector-a.lab.example`; does not require a client certificate |
| A-mtls | `:6514` | As A-srv, but requires a client certificate signed by the lab CA and records its subject |
| B | `:6515` | Presents `collector-b.lab.example` signed by a second CA (CA-B) |
| C | UDP `:514` | Cleartext baseline for the mixed-transport case |
| X-wrong / X-expired / X-future / X-name | `:6514` | Server certificate from an alien CA / expired / not yet valid / name not in the permitted list |

Only one of A-srv / A-mtls listens at a time on a given address.

# Test cases:
The test cases here are to validate the basic functionality of Syslog over TLS feature.

## TC1: Validate mTLS delivery from SONIC DUT
1)	Install an mTLS profile `lab` on SONIC DUT (CA + client cert + key). Start collector A-mtls on PTF.
2)	On SONIC DUT add a TLS syslog server with `--protocol tls --tls-profile-id lab --tls-permitted-peers collector-a.lab.example`.
3)	Send a `logger` marker from SONIC DUT.
4)	On PTF verify the marker arrives, the capture shows TLS (no plaintext payload), and the collector parsed octet-counted frames.
5)	Verify A-mtls recorded the DUT client subject.
6)	Verify STATE_DB `SYSLOG_SERVER|<ip>` has `applied_transport_security=true` and `failure_reason=NONE`.
7)	Delete the syslog server on SONIC DUT and verify delivery stops.
8)	Repeat steps 1-7 for IPv4 / IPv6 collector addresses and for default VRF / `Vrf-data`.

## TC2: Validate CA-only delivery from SONIC DUT
1)	Install a CA-only profile on SONIC DUT (CA bundle, no client cert/key). Start collector A-srv on PTF.
2)	On SONIC DUT add a TLS syslog server using that profile and permitted peer `collector-a.lab.example`.
3)	Send a `logger` marker from SONIC DUT.
4)	On PTF verify the marker arrives and the collector saw no client certificate.
5)	Verify STATE_DB `applied_transport_security=true`.

## TC3: Validate permitted peers in TLS handshake
1)	From PTF run collector A-srv. On SONIC DUT add a TLS server with permitted peers `other.lab.example,collector-a.lab.example`.
2)	Send a marker and verify delivery succeeds.
3)	Reconfigure permitted peers to only `other.lab.example`.
4)	Verify the handshake is refused and nothing is delivered; capture shows no cleartext.
5)	Reconfigure permitted peers to wildcard `*.lab.example` and present a CN-only collector certificate.
6)	Verify delivery succeeds.
7)	Present a SAN-only collector certificate with the same wildcard peers.
8)	Verify there is no delivery (rsyslog 8.2504 matches wildcards on CN only).

## TC4: Validate fail-closed behaviour on server authentication failure
1)	On SONIC DUT enable a TLS syslog server with a valid profile and permitted peer `collector-a.lab.example`.
2)	From PTF start collector X-wrong (server certificate from an alien CA) and send a marker from SONIC DUT.
3)	Verify the handshake fails, nothing is delivered, and the capture shows no plaintext syslog on UDP/514, TCP/514, or the configured TLS port.
4)	Repeat steps 2-3 with X-name (name not permitted), X-expired and X-future.
5)	Verify the DUT log shows the TLS stream-driver error. STATE_DB may stay `applied=true` because `failure_reason` is not a delivery probe.

## TC5: Validate fail-closed behaviour when collector requires a client certificate
1)	Install a CA-only profile on SONIC DUT. Start collector A-mtls on PTF.
2)	On SONIC DUT add a TLS syslog server using that profile.
3)	Send a marker from SONIC DUT.
4)	Verify the handshake fails on the collector, nothing is delivered, and there is no cleartext fallback.

## TC6: Validate fail-closed behaviour when the TLS profile is not usable
1)	On SONIC DUT add a TLS syslog server that references a profile with `cert` and no `key`.
2)	Verify the server is skipped, no traffic is sent, and STATE_DB shows `applied_transport_security=false` with `failure_reason=NO_CERTIFICATE`.
3)	Repeat with `key` and no `cert`; with `cert`+`key` and no CA; with a profile id that has no profile at all; and with `transport_security=true` written alone with no profile id (`NO_PROFILE` for the last case).
4)	Verify a half client identity is not silently treated as CA-only, and that there is no cleartext fallback.

## TC7: Validate late arrival and removal of trust material
1)	On SONIC DUT add the TLS syslog server first, with no profile files present.
2)	Verify STATE_DB shows `NO_CERTIFICATE` and nothing is delivered.
3)	Install the profile on SONIC DUT after the server is configured.
4)	Verify within 60 s delivery starts and `applied_transport_security=true`.
5)	Remove the profile.
6)	Verify delivery stops, STATE_DB returns to `NO_CERTIFICATE`, and there is no cleartext.

## TC8: Validate certificate rotation without CONFIG_DB change
1)	On SONIC DUT configure a working TLS syslog server and confirm delivery.
2)	Replace the collector certificate on PTF (same CA) and update the DUT CA/profile files as needed without changing CONFIG_DB.
3)	Verify sessions re-establish and delivery resumes within 60 s.
4)	Rotate the CA and collector certificate together; verify delivery resumes without a CONFIG_DB change.
5)	Replace the client certificate (mTLS); verify delivery resumes and the collector records the new client subject.
6)	Drop `cert`/`key` from an mTLS profile (downgrade to CA-only); verify the DUT sends no client certificate and delivery continues against collector A-srv.

## TC9: Validate multi-server isolation and mixed transport
1)	On SONIC DUT add server 1: TLS to collector A on profile `lab`.
2)	Add server 2: TLS to collector B on profile `labb` (CA-B).
3)	Add server 3: UDP to collector C.
4)	Send a unique marker from SONIC DUT and verify each collector sees only its own transport and its own CA.
5)	Swap collectors between the two TLS servers and verify both TLS servers fail closed.
6)	Restore the original collector assignments and confirm server 1, server 2, and server 3 deliver again.
7)	Break server 2's profile. Verify server 1 and server 3 still deliver, server 2 gets nothing, and there is no cleartext for server 2.
8)	Delete server 1 and verify server 3 is not affected.

## TC10: Validate persistence across config reload
1)	On SONIC DUT configure at least two TLS syslog servers and confirm delivery.
2)	Run `config save` then `config reload`.
3)	Verify profiles are still present, delivery is restored, and STATE_DB is republished (`applied_transport_security=true`, `failure_reason=NONE`).

## TC11: Validate persistence across reboot
1)	On a hardware DUT configure two TLS syslog servers and confirm delivery.
2)	Run `config save -y` so the running CONFIG_DB is written to the saved configuration that a cold boot loads.
3)	Perform a cold reboot.
4)	Verify profiles are repopulated, delivery resumes after neighbours return, and there is no cleartext at any point during boot.

## TC12: Validate persistence across service restarts
1)	On SONIC DUT configure a working TLS syslog server and confirm delivery.
2)	Run `systemctl restart rsyslog`. Verify sessions re-establish, delivery resumes, and there is no cleartext gap.
3)	Run `systemctl restart hostcfgd`. Verify the same.
4)	Run `systemctl restart rsyslog-config` twice with unchanged config. Verify delivery continues and the second run does not restart rsyslog.

## TC13: Validate source address on a TLS server
1)	On SONIC DUT add a TLS syslog server with per-server `--source 100.100.100.2`.
2)	On PTF verify the collector sees the configured source address.
3)	Remove the per-server source and configure global `config syslog source-interface <intf>`.
4)	Verify the collector sees the configured source address.
5)	This case is expected fail (`xfail`) until rsyslog `omfwd` honours `Address` for TCP/TLS (today it applies to UDP only). Remove the `xfail` when fixed.

# References
- [SONiC Remote Syslog over TLS HLD](https://github.com/sonic-net/SONiC/pull/2600)
- [SONiC Syslog Design](https://github.com/sonic-net/SONiC/blob/master/doc/syslog/syslog-design.md)
- [RFC 5425 - Transport Layer Security (TLS) Transport Mapping for Syslog](https://datatracker.ietf.org/doc/html/rfc5425)
- [Syslog Source IP test plan](./Syslog_Source_IP_test_plan.md)
- [Syslog Protocol Filter / Trap Severity test plan](./Syslog_Protocol_Filter_TrapSeverityLevel_test_plan.md)

# Abbreviations
### Table 1: Abbreviations
| Term | Meaning |
|:-----|:--------|
| SONiC | Software for Open Networking in the Cloud |
| DUT | Device Under Test |
| PTF | Packet Test Framework |
| TLS | Transport Layer Security |
| mTLS | Mutual TLS |
| CA | Certificate Authority |
| PEM | Privacy-Enhanced Mail encoding for X.509 keys/certs |
| CONFIG_DB | Redis configuration database |
| STATE_DB | Redis operational state database |
| omfwd | rsyslog forwarding module (UDP/TCP/TLS) |
| RFC 5425 | TLS transport mapping for syslog |
