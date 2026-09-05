# SONiC Secure Boot Test Plan

## Table of Contents

- [Introduction](#introduction)
- [Scope](#scope)
- [Secure Boot Chain of Trust](#secure-boot-chain-of-trust)
- [Test Environment](#test-environment)
- [Automation Strategy](#automation-strategy)
- [Test Cases](#test-cases)
  - [Boot Chain](#boot-chain)
  - [DB Enrollment and Pruning](#db-enrollment-and-pruning)
  - [SBAT Bundle Selection](#sbat-bundle-selection)
  - [Provisioning Pipeline](#provisioning-pipeline)
  - [Build Validation](#build-validation)

## Introduction

UEFI Secure Boot protects the SONiC boot process by establishing a chain of
trust from firmware to the operating system. The firmware validates shim,
shim validates GRUB and MokManager, GRUB validates the Linux kernel, and the
kernel validates loadable kernel modules. Only components signed by a trusted
key may execute.

This test plan validates the SONiC Secure Boot implementation across image
build, image installation, key enrollment and pruning, SBAT-based bootloader
bundle selection, firmware provisioning, boot-time verification, and runtime
kernel-module enforcement.

## Scope

The test plan covers:

1. Verification of signed and unsigned boot components.
2. Detection of boot components modified after signing.
3. Enrollment, retention, deduplication, authorization, and pruning of UEFI DB
   certificates.
4. Selection of complete shim, GRUB, and MokManager bundles using SBAT levels.
5. Initial PK, KEK, and DB provisioning and idempotent pipeline behavior.
6. Development Secure Boot image builds and invalid signing configurations.
7. Signed-kernel warm reboot and kernel-module enforcement required by the
   Secure Boot HLD.
8. Prevention of private-key leakage into build outputs.

The tests do not validate vendor-specific hardware root-of-trust
implementations or production signing-server APIs. Those flows remain the
responsibility of each platform vendor.

## Secure Boot Chain of Trust

The expected verification sequence is:

1. UEFI firmware verifies `shimx64.efi` against a certificate in the firmware
   DB.
2. shim verifies `grubx64.efi` and invokes `mmx64.efi` only when MokManager is
   trusted.
3. GRUB verifies the SONiC kernel.
4. The kernel verifies loadable kernel modules using the certificate embedded
   at build time.
5. Secure warm reboot verifies the replacement kernel through `kexec`.

The signing hierarchy uses a Platform Key (PK), Key Exchange Key (KEK), and
signature database keys (DB). PK authorizes KEK management, KEK authorizes DB
management, and DB certificates authorize boot components.

## Test Environment

### Hardware

- Initial tests run on a KVM testbed configured with UEFI Secure Boot.
- Physical-platform validation uses a Secure Boot-capable UEFI device. Initial
  provisioning tests require an Arista 7280 unless support is extended to
  additional platforms.
- Serial or equivalent recovery-console access for tests that intentionally
  prevent the DUT from booting.

### Images and Keys

- A known-good signed SONiC image.
- Images A, B, and C signed by distinct trusted DB keys.
- Images containing unsigned, tampered, expired-certificate, and
  untrusted-certificate variants.
- Valid PK, KEK, DB, and remove-all-DB authenticated update files.
- Invalid, malformed, expired, unauthorized, and incomplete authenticated
  update files.
- Complete shim, GRUB, and MokManager bundles with older, equal, newer, and
  invalid `.sbatlevel` values.

### General Preconditions

- Record the current firmware Secure Boot state and enrolled keys before each
  test.
- Preserve a known-good image and a recovery procedure.
- Capture the serial console, installer output, firmware key state, kernel log,
  and `mokutil --sb-state` output.
- Restore the original image, boot order, keys, and Secure Boot state after
  each destructive test.

## Automation Strategy

Runtime tests should be implemented under `tests/platform_tests/secure_boot/`.
Build-only tests belong in the sonic-buildimage CI because they require image
construction and inspection rather than a deployed SONiC testbed.

The runtime suite must:

- Detect unsupported platforms and skip them with a clear reason.
- Require recovery-console support before executing an expected-boot-failure
  scenario.
- Treat a missing signed, unsigned, or tampered image artifact as a setup
  failure rather than a passing skip in scheduled qualification runs.
- Collect firmware variables, `/host/db-auth/`, ESP file hashes, installer
  logs, console logs, `dmesg`, and the active/default image before cleanup.
- Restore a bootable image and the original firmware state even when a test
  fails.
- Run destructive scenarios serially on one DUT.

## Test Cases

### Boot Chain

| ID | Test | Prerequisites | Procedure | Expected Result |
| --- | --- | --- | --- | --- |
| SB-BOOT-001 | Tampered GRUB | Secure Boot enabled; PK, KEK, and DB installed; recovery console available | Install an image containing a GRUB binary modified after signing. Verify the binary was copied to `/mnt/esp/EFI/SONiC-OS`, then reboot. | Firmware loads shim, but shim rejects GRUB. The DUT does not complete boot. |
| SB-BOOT-002 | Unsigned GRUB | Secure Boot enabled; PK, KEK, and DB installed; recovery console available | Install an image containing unsigned `grubx64.efi`. Verify the binary was copied to `/mnt/esp/EFI/SONiC-OS`, then reboot. | Firmware loads shim, but shim rejects GRUB. The DUT does not complete boot. |
| SB-BOOT-003 | Tampered shim | Secure Boot enabled; PK, KEK, and DB installed; recovery console available | Install an image containing a shim binary modified after signing. Verify the binary was copied to `/mnt/esp/EFI/SONiC-OS`, then reboot. | Firmware rejects shim. The DUT does not complete boot. |
| SB-BOOT-004 | Unsigned shim | Secure Boot enabled; PK, KEK, and DB installed; recovery console available | Install an image containing unsigned `shimx64.efi`. Verify the binary was copied to `/mnt/esp/EFI/SONiC-OS`, then reboot. | Firmware rejects shim. The DUT does not complete boot. |
| SB-BOOT-005 | Unsigned MokManager | Secure Boot enabled; trusted shim and GRUB; unsigned MokManager installed | Verify that normal boot succeeds, then explicitly invoke MokManager through a MOK operation. | Normal boot succeeds. shim rejects MokManager when it is invoked. |
| SB-BOOT-006 | Tampered kernel | Secure Boot enabled; trusted shim and GRUB; recovery console available | Install an image containing a kernel modified after signing, then reboot. | GRUB rejects the kernel. The DUT does not complete boot. |
| SB-BOOT-007 | Unsigned kernel | Secure Boot enabled; trusted shim and GRUB; recovery console available | Install an image containing an unsigned kernel, then reboot. | GRUB rejects the kernel. The DUT does not complete boot. |
| SB-BOOT-008 | Unsigned kernel module | Secure Boot enabled and booted with a trusted kernel | Attempt to load an unsigned module using `modprobe` or `insmod`. | The kernel rejects the module load and records the rejection in the kernel log. |
| SB-BOOT-009 | Components signed by an untrusted DB key | Secure Boot enabled; signing certificate absent from DB; recovery console available | Test otherwise valid shim, GRUB, MokManager, kernel, and kernel-module artifacts signed by the untrusted key. | Each component is rejected at its corresponding verification stage, equivalent to an unsigned component. |

### DB Enrollment and Pruning

| ID | Test | Prerequisites | Procedure | Expected Result |
| --- | --- | --- | --- | --- |
| SB-DB-001 | First DB certificate in Setup Mode | Secure Boot disabled; no PK, KEK, or DB enrolled; image contains `DB.auth` | Install the signed image and reboot. | One firmware DB certificate and one `/host/db-auth/DB-*.auth` file exist. Boot succeeds, and `mokutil --sb-state` reports Secure Boot disabled. |
| SB-DB-002 | Second DB certificate | Secure Boot enabled; PK and KEK installed; image A and its signer installed | Install image B signed by a new DB certificate while retaining image A. | Firmware contains both required DB certificates and `/host/db-auth/` contains two unique `DB-*.auth` files. Both images boot and Secure Boot remains enabled. |
| SB-DB-003 | Third DB certificate and stale signer removal | Secure Boot enabled; images A and B installed; valid `remove-all-db.auth`; installation removes A and retains B | Install image C signed by a third DB certificate. | Firmware DB retains only the signers required by B and C. Images B and C boot, and signer A is removed. |
| SB-DB-004 | Reinstall identical DB certificate | Certificate already enrolled and matching `DB-<hash>.auth` exists | Reinstall an image using the same `DB.auth`. | No duplicate firmware entry or `DB-<hash>.auth` file is created. |
| SB-DB-005 | Unauthorized `DB.auth` | Secure Boot enabled; image DB update signed by an unknown KEK | Install the image. | Firmware rejects enrollment and installation terminates with an explicit error. |
| SB-DB-006 | Expired DB certificate | Image is signed with an expired but otherwise valid DB certificate and contains its authorized update | Install the image and reboot. | Installation and boot behavior match the platform's authenticated-variable policy. The observed behavior is recorded; the current expected behavior is successful installation and boot. |
| SB-DB-007 | `remove-all-db.auth` absent | Secure Boot enabled; existing DB certificates; remove-all file absent | Install another signed image. | Pruning is skipped and existing firmware DB entries remain unchanged. |
| SB-DB-008 | Invalid `remove-all-db.auth` | Secure Boot enabled; malformed file or file signed by the wrong KEK | Run an installation that invokes DB pruning. | Pruning fails safely, existing DB entries remain unchanged, and every retained image still boots. |
| SB-DB-009 | Preserve signer used by an older image | Installed images use different DB signers; valid remove-all file exists | Install another image without deleting the older images. | Signers required by every retained image remain enrolled. |
| SB-DB-010 | Remove last unused signer | No retained image uses one enrolled signer; valid remove-all file exists | Install a new image and remove the final image that uses the old signer. | The unused signer is removed and all retained images boot. |

### SBAT Bundle Selection

The shim, GRUB, and MokManager files form one atomic bundle. A test passes only
when all three files are selected from the same expected bundle.

| ID | Test | Prerequisites | Procedure | Expected Result |
| --- | --- | --- | --- | --- |
| SB-SBAT-001 | Upgrade with Secure Boot enabled | Secure Boot enabled; incoming shim has a newer `.sbatlevel` timestamp | Install the incoming image. | The complete incoming shim, GRUB, and MokManager bundle replaces the installed bundle. Reboot succeeds. |
| SB-SBAT-002 | Upgrade with Secure Boot disabled | Secure Boot disabled; incoming shim has a newer `.sbatlevel` timestamp | Install the incoming image. | The complete incoming bundle replaces the installed bundle. Reboot succeeds. |
| SB-SBAT-003 | Downgrade with Secure Boot enabled | Secure Boot enabled; installed shim has a newer `.sbatlevel` timestamp | Install an image containing an older shim bundle. | The complete newer installed bundle is preserved. Reboot succeeds. |
| SB-SBAT-004 | Downgrade with Secure Boot disabled | Secure Boot disabled; installed shim has a newer `.sbatlevel` timestamp | Install an image containing an older shim bundle. | The complete newer installed bundle is preserved. Reboot succeeds. |
| SB-SBAT-005 | Equal SBAT level | Installed and incoming shims have equal `.sbatlevel` timestamps; bundles have identifiable hashes | Install the incoming image. | The complete incoming bundle replaces the installed bundle. |
| SB-SBAT-006 | Invalid incoming shim SBAT | Complete installed bundle; incoming shim has malformed or missing `.sbatlevel` | Install the incoming image. | Comparison fails and the complete installed bundle is replaced by the complete incoming bundle. |
| SB-SBAT-007 | Invalid installed shim SBAT | Installed shim is unreadable; incoming bundle is valid | Install the incoming image. | The complete incoming bundle replaces the installed bundle. |
| SB-SBAT-008 | Python unavailable during comparison | Complete installed bundle; comparison environment has no `python3` | Install an image with a different bundle. | Comparison falls back safely and the complete incoming bundle replaces the installed bundle. |

### Provisioning Pipeline

| ID | Test | Prerequisites | Procedure | Expected Result |
| --- | --- | --- | --- | --- |
| SB-PIPE-001 | Initial PK, KEK, and DB provisioning | Arista 7280 in Setup Mode; no PK, KEK, or DB; signed image configured | Run the firmware-upgrade pipeline. | KEK is enrolled before PK, DB is enrolled during image installation, Secure Boot is enabled, and reboot succeeds. |
| SB-PIPE-002 | Existing Microsoft PK | Microsoft PK already enrolled | Run the provisioning pipeline. | PK and KEK provisioning is skipped and existing keys remain unchanged. |
| SB-PIPE-003 | Existing foreign PK | Non-Microsoft PK already enrolled | Run the provisioning pipeline. | Pipeline aborts with the foreign-PK error and does not overwrite any key. |
| SB-PIPE-004 | KEK enrollment failure | Setup Mode; invalid or rejected `KEK.auth`; valid `PK.auth` | Run the provisioning pipeline. | KEK enrollment fails, PK enrollment is not attempted, and Secure Boot remains disabled. |
| SB-PIPE-005 | PK enrollment failure | Valid KEK; rejected or invalid `PK.auth` | Run the provisioning pipeline. | KEK remains enrolled, PK enrollment fails, and the DUT remains in Setup Mode. |
| SB-PIPE-006 | Missing PK and KEK bundle | Secure Boot certificate bundle absent from the server | Run the provisioning pipeline. | Upgrade continues on a best-effort basis; no PK or KEK files are staged or enrolled. |
| SB-PIPE-007 | Archive missing one key | Archive contains only PK or only KEK | Run the provisioning pipeline. | The entire key set is rejected and no partial enrollment occurs. |
| SB-PIPE-008 | Idempotent rerun | DUT was provisioned successfully by an earlier run | Run the same pipeline again. | No duplicate keys are added, trusted state remains unchanged, and reboot succeeds. |
| SB-PIPE-009 | Unsupported platform | DUT is not an Arista 7280 | Run the provisioning pipeline. | Automatic PK and KEK staging and enrollment are skipped. |

### Build Validation

Unless otherwise stated, build tests use:

```text
SECURE_UPGRADE_MODE=dev
SECURE_UPGRADE_DEV_SIGNING_KEY=/data/sonic-buildimage/keys/DB.key
SECURE_UPGRADE_SIGNING_CERT=/data/sonic-buildimage/keys/DB.crt
SECURE_BOOT_DB_CERT=/data/sonic-buildimage/keys/DB.auth
```

| ID | Test | Prerequisites | Procedure | Expected Result |
| --- | --- | --- | --- | --- |
| SB-BUILD-001 | Successful development build | Valid matching `DB.key`, `DB.crt`, and `DB.auth`; all required paths configured | Build the target SONiC installer image with the complete Secure Boot environment. | Build succeeds. shim, GRUB, MokManager, kernel, and kernel modules are signed, and `DB.auth` is included in the image. |
| SB-BUILD-002 | Private key and certificate mismatch | Private key A and unrelated certificate B | Configure the build with key A and certificate B, then build. | Signing or signature verification fails and the build does not succeed. |
| SB-BUILD-003 | Missing development private key | `SECURE_UPGRADE_DEV_SIGNING_KEY` references a nonexistent file | Build the image. | Build fails with a clear missing-private-key error. |
| SB-BUILD-004 | Missing signing certificate | `SECURE_UPGRADE_SIGNING_CERT` references a nonexistent file | Build the image. | Build fails with a clear missing-certificate error. |
| SB-BUILD-005 | Invalid private-key format | Private-key path contains malformed or unsupported key data | Build the image. | Signing fails and the build fails. |
| SB-BUILD-006 | Invalid certificate format | Signing-certificate path contains malformed or non-X.509 data | Build the image. | Signing or signature verification fails and the build fails. |
| SB-BUILD-007 | Expired signing certificate | Expired `DB.crt` and matching private key | Build the image. | Certificate validity is rejected and the build fails. |
| SB-BUILD-008 | Certificate not yet valid | `DB.crt` has a future `notBefore` value and a matching private key | Build the image. | Certificate validity is rejected and the build fails. |
| SB-BUILD-009 | Wrong kernel CA certificate | EFI files and modules signed by certificate A; kernel CA path references certificate B | Build and boot the image, then load a module signed by A. | The mismatch is detected during build, or the running kernel rejects the module signed by A. |
| SB-BUILD-010 | Missing kernel CA file | Kernel CA path references a nonexistent file | Build the kernel and image. | Kernel or image build fails with a clear missing-CA-file error. |
| SB-BUILD-011 | Missing `DB.auth` | `SECURE_BOOT_DB_CERT` references a nonexistent file | Build the image. | Build fails with an error stating that `SECURE_BOOT_DB_CERT` is configured but missing. |
| SB-BUILD-012 | Invalid `DB.auth` contents | `SECURE_BOOT_DB_CERT` references malformed data or a text file | Build and install the image. | Build succeeds because the file is copied without structural validation; installation reports DB enrollment failure. |
| SB-BUILD-013 | `DB.auth` signed by wrong KEK | Valid DB update authorized by a KEK not enrolled on the target DUT | Build and install the image. | Build succeeds, but firmware rejects DB enrollment during installation. |
| SB-BUILD-014 | `SECURE_BOOT_DB_CERT` unset | Development signing key and certificate are valid; DB variable is empty | Build and inspect the installer payload, then install it. | A signed image is built without `boot/DB.auth`; installation emits a clear warning about the missing DB update. |
| SB-BUILD-015 | `no_sign` mode with DB variable set | `SECURE_UPGRADE_MODE=no_sign`; DB variable references `DB.auth` | Build and inspect the boot payload. | Secure Boot signing is skipped and `DB.auth` is not embedded. |
| SB-BUILD-016 | No private-key leakage | Successful build using `DB.key` | Search the installer payload, filesystem, packages, logs, and generated artifacts for the private-key bytes and configured path. | The private key is absent from every output artifact and its path is not exposed in logs. |
