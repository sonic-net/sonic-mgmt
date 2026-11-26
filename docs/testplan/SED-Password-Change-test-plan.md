# SED Password Change Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| SONiC SED (Self-Encrypting Drive) | [sonic-net/SONiC#2171](https://github.com/sonic-net/SONiC/pull/2171) |
| SED password change HLD | [change_sed_password_hld.md](https://github.com/sonic-net/SONiC/blob/master/doc/sed/change_sed_password_hld.md) |

## 1. Overview

Self-Encrypting Drive (SED) password management allows operators to set and reset the password used to unlock SED-enabled storage on the switch. The password controls locking ranges and access to the encrypted disk.

The SED password change feature on SONiC provides:

- Setting a new SED password via CLI
- Resetting the SED password to a platform default
- Persistence of the password in two TPM persistent handles, bank A (primary) and bank B (secondary)
- Recovery at boot by `sed-pw-tpm-recovery.service`: when one bank does not unlock the disk, the service copies the other bank into it

The sonic-mgmt tests under `tests/sed_password_change/` validate CLI change and reset, password verification against the drive, length validation, TPM persistence checks, the recovery service, and reboot recovery. A **vendor abstraction** (`SED_Change_Password_General` plus per-vendor subclasses) supplies the vendor-specific parts. Tests run only when the module fixture selects a vendor implementation for the DUT; otherwise the run is skipped.

## 2. Prerequisites

The tests change the disk password and corrupt a TPM bank on purpose. Run them only on a DUT that meets all of the following:

1. NVIDIA DUT with an Opal SED NVMe disk, where `sedutil-cli --query <disk>` shows `LockingEnabled = Y`
2. TPM persistent handles `0x81010001` (bank A), `0x81010002` (bank B) and `0x81010003` (default password) are defined
3. `/etc/sonic/sed_config.conf` holds `tpm_bank_a` and `tpm_bank_b`
4. The pre-boot component (PBA) tries bank B when bank A does not unlock the disk. The HLD places this component outside SONiC. Without it, `test_reboot_recovery_password` leaves a DUT that does not boot.

### 2.1 Recovering a DUT after a failed run

- **The DUT keeps a test password.** Banks A and B still hold the same test password, so the DUT boots. Run `sudo config sed reset-password` to go back to the default password.
- **Bank A was left with a wrong password.** Run `sudo systemctl start sed-pw-tpm-recovery.service`. It copies bank B into bank A when bank B unlocks the disk. Then run `sudo config sed reset-password`.
- **The DUT does not boot.** The pre-boot component could not unlock the disk with either bank. Recovery needs the platform procedure of the pre-boot component, which is outside SONiC.

## 3. Requirements

### 3.1 Feature functionality

| **ID** | **Requirement** | **HLD section** |
|--------|-----------------|-----------------|
| R1 | Change the SED password to a value within the platform minimal and maximal length | §7.3 |
| R2 | Reset the SED password to the platform default | §7.4 |
| R3 | After a change or a reset, banks A and B hold the same password and it unlocks the disk | §7.3, §7.4 |
| R4 | A changed password survives a reboot and still unlocks the disk | §4, §7.5 |
| R5 | At boot, `sed-pw-tpm-recovery.service` repairs a bank that does not unlock the disk | §5, §7.2, §7.5 |
| R6 | A password with an invalid length is rejected, and the current password stays in place | §7.3 |

### 3.2 CLI (as used in automation)

1. **Change password:** `sudo config sed change-password`. The CLI prompts twice and hides the input. The automation waits for each prompt before it sends the password, and treats the change as successful only when the CLI prints `SED password change process completed successfully`.
2. **Reset to default:** `sudo config sed reset-password`

```
config
└── sed
    ├── change-password
    └── reset-password
```

Examples:

```bash
admin@sonic:~$ sudo config sed change-password
New SED password:
Repeat for confirmation:
Handling SED password change started...
SED password change process completed successfully
admin@sonic:~$ sudo config sed reset-password
Handling SED password reset started...
SED password reset process completed successfully
```

### 3.3 Platform / environment checks

1. No SED NVMe disk, or `LockingEnabled` is not `Y` → skip
2. TPM banks A, B or the default bank not present → skip

## 4. Scope

### 4.1 Code layout and common interface

| **Area** | **Location** |
|----------|----------------|
| Base vendor API, shared SED/TPM steps, NVIDIA implementation | `tests/common/helpers/sed_password_helper.py` — classes `SED_Change_Password_General`, `SED_Change_Password_Mellanox` |
| Test cases | `tests/sed_password_change/test_sed_password.py` |
| Vendor fixture, module autouse setup/teardown | `tests/sed_password_change/conftest.py` |

**Base class** (`SED_Change_Password_General`) provides:

- **TPM banks:** `get_primary_sed_tpm_bank(duthost)`, `get_secondary_sed_tpm_bank(duthost)` — read from `/etc/sonic/sed_config.conf`, the same file the platform scripts use
- **Length limits:** `get_min_and_max_pass_len(duthost)` — read from `chassis.get_sed_mgmt()` on the DUT
- **Disk:** `get_disk_name(duthost)` — discovers the device from `sudo sedutil-cli --scan`
- **Verify password on disk:** `verify_sed_pass_works(duthost, password)` — `sedutil-cli --listLockingRanges`
- **CLI wrappers:** `change_sed_pass_via_cli`, `reset_sed_pass_via_cli` (reset then runs `verify_default_pass`)
- **Default password check:** `verify_default_pass(duthost)` — one DUT-side script reads the default password, compares it with banks A and B, and runs `sedutil-cli --listLockingRanges`. Only the exit status comes back, so the default password never reaches the test host, the logs or the report. On a mismatch it starts `sed-pw-tpm-recovery.service` and fails.
- **TPM read/write helpers:** `get_sed_pass_from_tpm_bank`, `set_sed_pass_in_tpm_bank` — use the TPM auth and unseal flow of `/usr/local/bin/sed_pw_utils.sh`. A bank write creates and loads the new object first, then evicts and persists in the same DUT-side command.
- **Consistency checks:** `is_pass_saved(duthost, expected_pass)` returns whether both banks hold the password; `verify_pass_saved` asserts it

**Vendor subclass must implement:** `get_default_sed_pass_cmd()` — a DUT-side command that prints the default password. The NVIDIA implementation unseals TPM handle `0x81010003`.

**Test selection:** Module-scoped fixture `vendor_sed_class` returns an instance of the vendor class for the DUT or skips if no implementation is registered for that device.

### 4.2 Topology and marks

- `pytest.mark.topology('any')`
- `pytest.mark.disable_loganalyzer` only on `test_reboot_recovery_password`. `test_password_length_negative` keeps the log analyzer and ignores the expected length error.

### 4.3 Out of scope

- Platforms without SED management (`chassis.get_sed_mgmt()` is `None`), where the CLI prints `Error: SED management not supported on this platform`
- A password change interrupted between the bank A and bank B writes
- A missing or malformed `/etc/sonic/sed_config.conf`

## 5. Test cases

### Module setup and teardown (`conftest.py`)

1. Before all tests: `verify_sed_pass_change_feature_enabled`, then `reset_sed_pass_via_cli`
2. After all tests: `reset_sed_pass_via_cli` again

| **No.** | **Test Case** | **Requirements** |
|---------|---------------|------------------|
| 5.1 | `test_change_sed_password[min/max/random]` | R1, R3 |
| 5.2 | `test_set_default_pass` | R2, R3 |
| 5.3 | `test_password_length_negative` | R6 |
| 5.4 | `test_reboot_recovery_password` | R4, R5 |
| 5.5 | `test_recovery_service_configured` | R5 |

### 5.1 `test_change_sed_password`

- **Setup:** The default password is set (module setup).
- **Procedure:**
  1. Generate a password with the minimal length, the maximal length, or a random valid length (one parameter per run).
  2. `change_sed_pass_via_cli`.
- **Expected:** The password unlocks the disk (`verify_sed_pass_works`), and both banks hold it (`verify_pass_saved`).
- **Teardown:** Module teardown resets to default.

### 5.2 `test_set_default_pass`

- **Setup:** Set a random valid password and verify it unlocks the disk.
- **Procedure:** `reset_sed_pass_via_cli`.
- **Expected:** `verify_default_pass` passes on the DUT, and the random password no longer unlocks the disk.
- **Teardown:** None. The default password is set.

### 5.3 `test_password_length_negative`

- **Setup:** The default password is set (module setup).
- **Procedure:** Try `change_sed_pass_via_cli` with a password of `max_len + 1` characters, then with `min_len - 1` characters.
- **Expected:** For each attempt, the CLI does not report success, syslog has `SED password length is not valid: <len>.`, and `verify_default_pass` passes.
- **Teardown:** None.

### 5.4 `test_reboot_recovery_password`

- **Setup:** Set a new password and `verify_pass_saved`.
- **Procedure:**
  1. `set_sed_pass_in_tpm_bank` writes a wrong password to bank A only; reading bank A returns the wrong value.
  2. Cold reboot with `safe_reboot=True`.
- **Expected:** `sed-pw-tpm-recovery.service` ran in this boot with `Result=success` and logged `Stored PW from Bank 2 to Bank 1 succeed`. Both banks hold the new password, and it still unlocks the disk.
- **Teardown:** If the test fails before the reboot, bank A is restored from the bank B value. Module teardown resets to default.

### 5.5 `test_recovery_service_configured`

- **Setup:** None.
- **Procedure:** Read the unit state and the TPM handles.
- **Expected:** `sed-pw-tpm-recovery.service` is enabled, and the banks in `/etc/sonic/sed_config.conf` are defined TPM handles.
- **Teardown:** None.
