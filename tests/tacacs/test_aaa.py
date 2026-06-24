"""
test_aaa.py -- Aggregator entry point for all AAA test cases.

Running ``pytest tests/tacacs/test_aaa.py`` collects every test from the
sub-modules so the full suite can be executed with a single invocation.

File layout
-----------
test_aaa_preflight.py       TC_H01 – TC_H08  (pre-flight health checks)  ← runs first
test_aaa_config.py          TC_001 – TC_005  (core auth / authz)
test_aaa_accounting.py      TC_006 – TC_007  (accounting login + command)
                            TC_017 – TC_018  (wildcard encoding, dual accounting)
test_aaa_authentication.py  TC_008 – TC_016  (failover / resilience / negative)

Execution order
---------------
pytest collects tests in the order they are imported here.  The pre-flight
health checks (TC_H01 – TC_H08) are imported first so they always run before
any functional test.  If any health check fails the problem is environmental
(services down, misconfigured server, network issue) rather than a code bug.
"""

# ---------------------------------------------------------------------------
# TC_H01 – TC_H08  Pre-flight health checks  (test_aaa_preflight.py)
# ---------------------------------------------------------------------------
from tests.tacacs.test_aaa_preflight import (         # noqa: F401
    test_h01_sonic_services_running,
    test_h02_tacacs_server_reachable,
    test_h03_tacacs_config_on_dut,
    test_h04_aaa_authentication_mode,
    test_h05_aaa_authorization_mode,
    test_h06_aaa_accounting_mode,
    test_h07_tacacs_daemon_running_on_ptf,
    test_h08_end_to_end_smoke_login,
)

# ---------------------------------------------------------------------------
# TC_001 – TC_005  (test_aaa_config.py)
# ---------------------------------------------------------------------------
from tests.tacacs.test_aaa_config import (            # noqa: F401
    test_valid_ssh_authentication,
    test_invalid_credentials_rejected,
    test_local_fallback_when_server_unreachable,
    test_ro_user_blocked_from_write_commands,
    test_rw_user_read_write_commands,
)

# ---------------------------------------------------------------------------
# TC_006 – TC_007, TC_017 – TC_018  (test_aaa_accounting.py)
# ---------------------------------------------------------------------------
from tests.tacacs.test_aaa_accounting import (        # noqa: F401
    test_accounting_records_login_events,
    test_accounting_records_command_execution,
    test_wildcard_encoding_sent_to_server,
    test_dual_accounting_tacacs_and_local,
)

# ---------------------------------------------------------------------------
# TC_008 – TC_016  (test_aaa_authentication.py)
# ---------------------------------------------------------------------------
from tests.tacacs.test_aaa_authentication import (    # noqa: F401
    test_failover_primary_down_secondary_takes_over,
    test_wrong_passkey_rejected,
    test_server_timeout_no_hang,
    test_jit_user_created_on_login,
    test_disable_tacacs_reverts_to_local,
    test_tacacs_config_persists_after_reload,
    test_tacacs_source_ip,
    test_concurrent_ro_rw_sessions,
    test_local_user_blocked_tacacs_only,
)
