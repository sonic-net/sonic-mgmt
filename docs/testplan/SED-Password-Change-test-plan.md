# SED Password Change Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| SONiC SED (Self-Encrypting Drive) | [sonic-net/SONiC#2171](https://github.com/sonic-net/SONiC/pull/2171) |

## 1. Overview

Self-Encrypting Drive (SED) password management allows operators to set and reset the password used to unlock SED-enabled storage on the switch. The password controls locking ranges and access to the encrypted disk.

The SED password change feature on SONiC provides:

- Setting a new SED password via CLI
- Resetting the SED password to a platform default
- Persistence of the password in TPM (tests assert consistency across at least two persistent TPM handles used as primary and secondary “banks”)
- Recovery after the primary bank is deliberately out of sync (cold reboot; platform is expected to reconcile so the correct SED password is reflected again in both banks)

The sonic-mgmt tests under `tests/sed_password_change/` validate CLI change and reset, password verification against the drive, length validation, TPM persistence checks, and reboot recovery. A **vendor abstraction** (`SED_Change_Password_General` plus per-vendor subclasses) supplies TPM handle identifiers, password length limits, and any TPM authorization needed for seal/unseal. Tests run only when the module fixture selects a vendor implementation for the DUT; otherwise the run is skipped.

## 2. Requirements

### 2.1 Feature functionality (as exercised by tests)

1. Change SED password to a user-defined value within vendor-defined min/max length
2. Reset SED password to platform default
3. Persist the SED password such that both primary and secondary TPM banks (vendor-defined persistent handles) match after a successful change
4. After primary-bank corruption and cold reboot, primary and secondary banks again hold the same correct SED password (recovery behavior asserted by the test)

### 2.2 CLI (as used in automation)

1. **Change password:** `sudo config sed change-password`
2. **Reset to default:** `sudo config sed reset-password & wait` (automation waits for completion via the shell)

Success/failure for change-password is inferred from whether the command output contains `error` (case-insensitive), matching the current test helper behavior.

### 2.3 Error handling / preconditions

#### 2.3.1 CLI / validation

1. Password length below vendor minimum → change-password treated as failure by tests
2. Password length above vendor maximum → change-password treated as failure by tests

#### 2.3.2 Platform / environment

1. No suitable SED device or locking not enabled → feature check skips (see §3.3)
2. Required TPM persistent handles for primary and secondary banks not present → skip

## 3. Scope

Tests verify CLI change and reset, that the password works with the SED (via `sedutil-cli` in the shared base helper), and that TPM banks match expectations including after recovery reboot. Vendor-specific items are TPM handle IDs, min/max length, TPM policy/password arguments for `tpm2_*` if required, and any extra feature gating (e.g. stricter disk checks) implemented by overriding base methods.

### 3.1 Scale / performance

No scale or performance tests; functional correctness and recovery only.

### 3.2 CLI structure (conceptual)

```
config
└── sed
    ├── change-password
    └── reset-password
```

Examples:

```bash
1.sudo config sed change-password
New SED passdowrd: MyNewSEDPassword123
Reapeat for confirmation: MyNewSEDPassword123
2.sudo config sed reset-password
```

### 3.3 Code layout and common interface

| **Area** | **Location** |
|----------|----------------|
| Base vendor API and shared SED/TPM steps | `tests/common/helpers/sed_password_helper.py` — class `SED_Change_Password_General` |
| Test cases | `tests/sed_password_change/test_sed_password.py` |
| Module autouse setup/teardown | `tests/sed_password_change/conftest.py` |

**Base class** (`SED_Change_Password_General`) provides:

- **Disk:** `get_disk_name(duthost)` — discovers device from `sudo sedutil-cli --scan` (`/dev/...` parsing)
- **Verify password on disk:** `verify_sed_pass_works(duthost, password)` — `sedutil-cli --listLockingRanges`
- **CLI wrappers:** `change_sed_pass_via_cli`, `reset_sed_pass_via_cli` (reset then runs `verify_default_pass`)
- **Password generation:** `generate_pass_with_len(min_len, max_len, exclude_passwords=...)`
- **Feature gate:** `verify_sed_pass_change_feature_enabled(duthost)` — `sedutil-cli --query` must show `LockingEnabled = Y`; `tpm2_getcap handles-persistent` must list both `get_primary_sed_tpm_bank()` and `get_secondary_sed_tpm_bank()` return values
- **TPM read/write helpers:** `get_sed_pass_from_tpm_bank(duthost, tpm_bank, tpm_auth_pass=None)`, `set_sed_pass_in_tpm_bank(...)` — use `tpm2_unseal` / `tpm2_create` + evict/load flow; vendors may override to supply TPM authorization
- **Consistency checks:** `verify_pass_saved(duthost, expected_pass)` — unseals primary and secondary banks and asserts both match `expected_pass`
- **After reset:** `verify_default_pass(duthost, localhost)` — obtains the platform default secret from the TPM handle the subclass defines for that purpose, confirms `verify_pass_saved` and `verify_sed_pass_works`; on failure may cold reboot then raise (recovery attempt)

**Vendor subclass must implement** (base raises skip/TODO if missing):

- `get_primary_sed_tpm_bank()`, `get_secondary_sed_tpm_bank()`
- `get_min_and_max_pass_len(duthost)`

**Vendor subclass must align with base expectations for reset validation:**

- Expose whichever persistent TPM handle (or equivalent) holds the expected default SED password after `reset-password`, so `verify_default_pass` can read and validate it (the base implementation expects a subclass-defined handle used for that read path)

**Optional overrides:** e.g. `verify_sed_pass_change_feature_enabled`, `get_sed_pass_from_tpm_bank`, `set_sed_pass_in_tpm_bank` for extra preconditions or TPM auth.

**Test selection:** Module-scoped fixture `vendor_sed_class` returns an instance of the vendor class for the DUT or skips if no implementation is registered for that device.

### 3.4 Topology and marks

- `pytest.mark.topology('any')`
- `pytest.mark.disable_loganalyzer` (reboots and disruptive operations)

## 4. Test cases

| **No.** | **Test Case** | **Test Purpose** |
|---------|---------------|------------------|
| 1 | `test_change_sed_password` | Set a new password via CLI; confirm it works with `verify_sed_pass_works`; confirm primary and secondary TPM banks hold the same password via `verify_pass_saved`. |
| 2 | `test_set_default_pass` | Set a random valid password and verify; reset via CLI; verify default works and differs from the random password; `verify_pass_saved` for the default. |
| 3 | `test_password_length_negative` | Attempt change-password with length > max and < min; expect helper-reported failure (`change_sed_pass_via_cli` with `expect_success=False`). |
| 4 | `test_reboot_recovery_password` | Set new password and `verify_pass_saved`; overwrite **primary** bank only with a wrong password and confirm readback; **cold reboot** (`safe_reboot=False`); then `verify_pass_saved` for the original password. |

### Module fixture behavior (`conftest.py`)

Autouse, module-scoped fixture (depends on `vendor_sed_class`):

1. Before all tests: `verify_sed_pass_change_feature_enabled`, then `reset_sed_pass_via_cli`
2. After all tests: `reset_sed_pass_via_cli` again

### Test case steps (aligned with code)

#### 4.1 `test_change_sed_password`

1. `get_min_and_max_pass_len` → `generate_pass_with_len` within range
2. `change_sed_pass_via_cli`
3. `verify_sed_pass_works`
4. `verify_pass_saved`

#### 4.2 `test_set_default_pass`

1. Generate random valid password; `change_sed_pass_via_cli`; `verify_sed_pass_works`
2. `reset_sed_pass_via_cli` → returns validated default password string
3. Assert `verify_sed_pass_works` for default and default ≠ random password
4. `verify_pass_saved` for default

#### 4.3 `test_password_length_negative`

1. `get_min_and_max_pass_len`
2. Long password: length in `(max+1 .. max+30]` (random upper slack); `change_sed_pass_via_cli(..., expect_success=False)`; assert failure
3. Short password: length in `[max(1, min−offset) .. min−1]` with bounded offset; same failure assertion

#### 4.4 `test_reboot_recovery_password`

1. New password; `change_sed_pass_via_cli`; `verify_pass_saved`
2. `set_sed_pass_in_tpm_bank` on **primary** handle only with wrong password; `get_sed_pass_from_tpm_bank` on primary confirms wrong value
3. `reboot(..., reboot_type='cold', safe_reboot=False)`
4. `verify_pass_saved` for the original password
