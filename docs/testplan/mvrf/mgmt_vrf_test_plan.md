# Management VRF functional test plan

## Scope

This plan describes the tests in `tests/mvrf/test_mgmtvrf.py`: management
access, service settings, invalid commands, VRF isolation, RADIUS login and
reboot recovery. The module has 25 test methods, expanding to 29 cases.

## Test setup and roles

| Role | Use in the tests |
| --- | --- |
| SONiC DUT | The selected switch whose Management VRF and services are tested. |
| Test controller | Runs pytest, connects to the DUT and checks SNMP and SSH access. |
| PTF host | Provides HTTP, NTP when needed, RADIUS, and packet checks. |

The module is marked `topology("any")`. The two access/isolation cases need
existing IPv4 management and front-panel paths between the DUT and PTF. They
use Paramiko and Scapy with SNMP support on the PTF.

RADIUS login cases need an on-link IPv4 management path without NAT,
FreeRADIUS 3.x with its required modules and Paramiko on the PTF, and one-to-one
RADIUS user mapping on the DUT. Cases can skip when suitable endpoints or a
supported RADIUS setup are unavailable. Working local login and SNMP credentials
are required.

## Tests and expected results

### Connectivity, services and reboot — 9 cases

| Test | Check and expected result |
| --- | --- |
| `TestMvrfInbound::test_ping` | The controller reaches the DUT using Ansible. |
| `TestMvrfInbound::test_snmp_fact` | An SNMP query returns the DUT system description. |
| `TestMvrfOutbound::test_ping` | The DUT pings the PTF through Management VRF. |
| `TestMvrfOutbound::test_curl` | An HTTP request through Management VRF returns the expected PTF response. |
| `TestServices::test_ntp` | A fresh NTP client synchronizes; the normal daemon is restored afterward. |
| `TestServices::test_service_acl` | A temporary access rule blocks a new SSH connection; access returns after rollback. |
| `TestReboot::test_warmboot`, `test_reboot`, `test_fastboot` | Each reboot type is followed by checks of Management VRF, services, controller access, outbound ping and SNMP. |

### Configuration and invalid commands — 13 cases

These methods belong to `TestMvrfRegressionGaps`.

| Test method | Check and expected result |
| --- | --- |
| `test_vrf_transition_and_rollback` | Enable and disable Management VRF. Database, generated interface file and Linux state agree; management addresses and routes remain. |
| `test_snmp_saved_rendered_running_and_reply` | Saved listeners, generated SNMP settings, the running listener and a real reply agree. |
| `test_snmp_invalid_vrf_preserves_configuration` | Reject a nonexistent VRF without changing saved listeners or the SNMP file. |
| `test_snmp_listener_churn_recovers` | Delete and add the listener three times, respecting service restart limits, then confirm SNMP replies. |
| `test_ntp_saved_show_and_explicit_iburst` | The saved and displayed NTP VRF agree. Explicit `iburst` is saved and appears in the daemon file. |
| `test_show_ntp_uses_saved_vrf` | Verbose status-command traces use the saved NTP VRF. |
| `test_ntp_rejects_invalid_server_without_changes` — 4 cases | Reject `0.0.0.0`, `::`, `224.0.0.1` and `ff02::1` without changing NTP settings or its generated file. |
| `test_aaa_migration_preserves_attributes` — 2 cases | TACACS+ and RADIUS server VRF settings follow enable/disable changes; other server fields remain unchanged. |
| `test_forbidden_front_panel_binding_preserves_ip` | Reject a front-panel interface binding to Management VRF without changing its IP or interface state. |

The TACACS+ case checks saved server settings. The NTP status case checks command
traces; time synchronization is checked separately by `TestServices::test_ntp`.

### Access and isolation — 2 cases

These methods belong to `TestMvrfDualPath`.

| Test method | Check and expected result |
| --- | --- |
| `test_snmp_and_ssh_in_both_vrfs` | Real SNMP replies and authenticated SSH work through management and default/front-panel paths. |
| `test_no_forwarding_between_mgmt_and_default` | Confirm both packet receivers work, then check that marked UDP probes do not cross between the two VRFs. |

### RADIUS — 5 cases

These methods belong to `TestMvrfRadius`.

| Test method | Check and expected result |
| --- | --- |
| `test_radius_login_across_vrf_transitions` | Fresh RADIUS SSH logins work before and after Management VRF changes, without re-adding the server. |
| `test_radius_request_uses_management_nas_ip` | The RADIUS request carries the DUT management IPv4 address as NAS-IP-Address. |
| `test_radius_cisco_avpair_privilege` | Cisco-AVPair and standard privilege replies give matching user groups at levels 1 and 15. |
| `test_radius_delete_removes_only_its_pam_file` | Deleting one server removes its entry and PAM file while preserving the other server. |
| `test_radius_client_message_authenticator_support` | Installed RADIUS PAM modules include the `require_message_authenticator` option. This checks installed module contents. |

## Execution and cleanup

Run sequentially on an isolated testbed: the suite changes management settings
and reboots the DUT. Fixtures back up running and saved configuration, restore
settings at teardown, and check configuration, service and interface recovery.
Cleanup also checks for new or changed DUT core dumps.
