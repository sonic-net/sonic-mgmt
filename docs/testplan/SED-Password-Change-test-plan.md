# SED Password Change Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| SONiC SED (Self-Encrypting Drive) | [https://github.com/sonic-net/SONiC/pull/2171 / Mellanox-vendor-specific https://github.com/sonic-net/SONiC/pull/2171] |


## 1. Overview

Self-Encrypting Drive (SED) password management allows operators to set and reset the password used to unlock SED-enabled storage (e.g., NVMe disks) on the switch. The password is used to control locking ranges and access to the encrypted disk.

The SED password change feature on SONiC provides:
- Setting a new SED password via CLI
- Resetting the SED password to a platform default
- Persistence of the password across reboots (mechanism is vendor-defined)
- Recovery behavior when primary password storage is corrupted (mechanism is vendor-defined)

The sonic-mgmt SED password change tests validate that password change and reset work correctly, that length validation is enforced, and that persistence and recovery behave as expected. The test framework is designed for **multiple vendors**: common behavior is defined in a shared helper, and vendor-specific logic (disk discovery, password storage, default password handling, min/max length) is implemented per vendor. Each vendor provides its own implementation; tests run only when a vendor implementation is available for the DUT and are skipped otherwise.

## 2. Requirements

### 2.1 The SED password change feature supports the following functionality:

1. Change SED password to a user-defined value within vendor-defined min/max length
2. Reset SED password to platform default
3. Persist the current SED password (mechanism and storage are vendor-defined)
4. Recovery when primary password storage is corrupted (mechanism is vendor-defined, e.g. restore from secondary storage after reboot)

### 2.2 This feature supports the following commands:

1. **config**: set or reset SED password
   - `config sed change-password -p '<password>'`: set new SED password
   - `config sed reset-password`: reset SED password to default (blocking operation; automation must wait for completion)

### 2.3 This feature provides error handling for the following situations:

#### 2.3.1 Frontend
1. Password length below vendor minimum → command fails with error
2. Password length above vendor maximum → command fails with error

#### 2.3.2 Backend / Platform
1. No SED-enabled disk present → feature checks skip or fail appropriately
2. Locking not enabled on disk → skip or fail
3. Required password storage (vendor-defined) not configured → skip or fail

## 3. Scope

The tests verify that SED password can be changed and reset via CLI, that the password works with the SED (e.g., via vendor-chosen tools), and that persistence and recovery work as designed. All vendor-specific behavior (disk path, password storage, default password source, min/max length) is abstracted behind a vendor class. Adding a new vendor means implementing that class and registering it in the test fixture; no change to test case steps is required.

### 3.1 Scale / Performance

No scale or performance tests; focus is functional correctness and recovery.

### 3.2 CLI commands

#### 3.2.1 Config

```
config
|--- sed
      |--- change-password -p <password>
      |--- reset-password
```

Examples:

Set a new SED password:
```bash
sudo config sed change-password -p 'MyNewSEDPassword123'
```

Reset SED password to default (blocking; wait for completion in automation):
```bash
sudo config sed reset-password
```

### 3.3 Multi-vendor design

- **Common interface**: `tests/common/helpers/sed_password_helper.py` defines `SED_Change_Password_General`, a base class with methods that each vendor must implement or override:
  - `get_disk_name(duthost)` – SED device path (vendor-defined discovery)
  - `verify_sed_pass_works(duthost, password)` – verify password works (e.g. via vendor-chosen SED tool)
  - `change_sed_pass_via_cli`, `reset_sed_pass_via_cli` – CLI wrappers (base implementation may be reused)
  - `verify_default_pass`, `get_min_and_max_pass_len`, `verify_pass_saved`, `verify_sed_pass_change_feature_enabled` – must be implemented per vendor (storage, default source, length limits, feature checks)
- **Vendor implementations**: Each vendor provides a subclass of `SED_Change_Password_General` in a vendor-specific module. The subclass implements the above methods according to that platform’s disk discovery, password storage, default password, and length rules.
- **Test selection**: The test module uses a `vendor_sed_class` fixture that, based on DUT type (e.g. platform/HWSKU), returns the appropriate vendor class instance. If no implementation exists for the DUT, the fixture skips with a message that SED password change is not supported for this vendor. Adding support for a new vendor is done by implementing the interface and updating the fixture to return that class for the corresponding DUT type.

### 3.4 Supported topology

Tests are topology-agnostic (`pytest.mark.topology('any')`). They run on a single DUT per HWSKU; the vendor fixture selects the implementation for that DUT or skips when unsupported.

## 4. Test cases

| **No.** | **Test Case** | **Test Purpose** |
|---------|---------------|------------------|
| 1 | test_change_sed_password | Verify setting a new SED password via CLI, that the password works (vendor verification), and that it is stored in vendor-defined primary and secondary storage. |
| 2 | test_set_default_pass | Verify resetting SED password to default via CLI and that the default password works and is persisted. |
| 3 | test_password_length_negative | Verify that passwords below vendor minimum or above vendor maximum length are rejected by the CLI. |
| 4 | test_reboot_recovery_password | Verify that when primary password storage is corrupted with a wrong password, after reboot the system recovers to the previously set SED password (using vendor-defined recovery). |

### Notes (multi-vendor only)

1. **Vendor fixture**: The test module uses a `vendor_sed_class` fixture that returns the vendor-specific implementation for the DUT. Vendors without an implementation cause the fixture to skip. Adding a new vendor requires implementing the common interface and wiring the fixture to return that implementation for the corresponding DUT type.
2. **Vendor abstraction**: Test steps are written in terms of “password storage”, “primary/secondary”, “min/max length”, and “recovery”. Each vendor maps these to its own mechanisms (e.g. TPM banks, NV, or other secure storage). The same test cases apply to all vendors; only the implementation class differs.
3. **Module-level cleanup**: A module-scoped autouse fixture resets the SED password to default before and after all tests, and verifies that the SED password change feature is enabled for the DUT (via the vendor’s `verify_sed_pass_change_feature_enabled`) before running tests.
4. **Loganalyzer**: Tests are run with `pytest.mark.disable_loganalyzer` due to reboot and disruptive operations.

### Test case #1 – test_change_sed_password

1. Obtain vendor min/max password length and generate a new password within range.
2. Set the new SED password via CLI: `config sed change-password -p '<password>'`.
3. Verify the password works using the vendor’s verification method.
4. Verify that the password is stored in vendor-defined primary and secondary storage.

### Test case #2 – test_set_default_pass

1. Set a random valid SED password via `config sed change-password` and verify it works.
2. Reset the SED password to default via `config sed reset-password` and wait for completion.
3. Verify the default password works (vendor verification) and that it differs from the previous random password.
4. Verify the default password is stored correctly in vendor-defined primary and secondary storage.

### Test case #3 – test_password_length_negative

1. Obtain vendor min and max password length.
2. Generate a password longer than the maximum length; attempt to set it via CLI and verify the command fails.
3. Generate a password shorter than the minimum length; attempt to set it via CLI and verify the command fails.

### Test case #4 – test_reboot_recovery_password

1. Set a new valid SED password and verify it is stored in vendor-defined primary and secondary storage.
2. Corrupt the primary storage by writing a different (wrong) password into it; verify the primary storage contains the wrong password.
3. Perform a cold reboot (recovery behavior is vendor-defined).
4. After reboot, verify that both primary and secondary storage contain the original (correct) SED password (vendor-defined recovery).
