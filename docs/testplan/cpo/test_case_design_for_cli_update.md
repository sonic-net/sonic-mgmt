# Test Case Design — cpoutil CLI for CPO with Software Control

> **Source HLD (Community PR)**: [`SONiC PR #2498`](https://github.com/sonic-net/SONiC/pull/2498/files)

---

## 1. Background and Scope

The QG plan for CPO Utils commands under CPO Baseline limits October 2026 verification to:

- DOM field coverage through `cpoutil`.
- Migration from `sfputil read-eeprom` to `cpoutil read-eeprom` on SimX and ASIC.

**Follow-up**: Integrate community sonic-mgmt tests for the remaining `show/config/read-eeprom/write-eeprom` commands across interface/OE/ELS, assess coverage, and fill gaps.

**Out of scope**: STATE_DB-based `show interface transceiver` CPO support is planned with `cposhow` script. The previous transceiver EEPROM, status, and error-status cases are not part of the current coverage.

---

## 2. Current Automated Coverage

The source plan describes `test_cpo_cli_update.py` as containing **3 test functions / 4 pytest items**: TC-2a runs separately for OE and ELS. All automated tests are read-only.

**Common pre-conditions**:

- CPO platform with SW control enabled, on SimX or ASIC.
- Select a target CPO interface as `<port>`.
- Every command in the automated cases below must succeed (`rc == 0`).

### TC-1: DOM output in text and JSON formats

**Steps**:

```bash
cpoutil show interface dom <port>
cpoutil show interface dom <port> --json
```

**Expected results**:

- Both commands return `rc == 0`.
- Output indicates module presence and contains no read errors.
- Both formats contain the required OE/ELS fields listed below; JSON output is parseable.
- Validation covers field presence and format, **not value correctness**.

**DOM field coverage**:

| Component | Required fields | Platform coverage |
| --- | --- | --- |
| OE | CMIS temperature, supply voltage, RX/TX power | SimX and ASIC |
| OE | Platform-specific laser temperature and its alarm/warning thresholds | SimX and ASIC |
| ELS | Temperature, voltage, current | SimX and ASIC |
| ELS | Per-laser bias current, optical power, and voltage | SimX and ASIC |
| ELS | Temperature, Vcc, TxPower, and TxBias alarm/warning thresholds | SimX and ASIC |
| ELS | Control mode; per-laser bias-current and optical-power setpoints | SimX and ASIC |
| ELS | Power consumption; per-laser MPD, TEC voltage, health, and TEC health | ASIC only; these field checks are skipped on SimX |

### TC-2a: Full EEPROM dump for OE and ELS

Run as two separate pytest items, one for each endpoint.

**Steps**:

```bash
cpoutil read-eeprom interface <port> --oe
cpoutil read-eeprom interface <port> --els
```

**Expected results**:

- Each command returns `rc == 0`.
- Output contains the EEPROM hexdump header and parseable bytes.
- Parsed offsets include `0x00` and `0x7f`, covering the lower page.

### TC-2b: Ranged EEPROM read for OE

**Steps**:

```bash
# Full OE dump used as the identifier-byte reference
cpoutil read-eeprom interface <port> --oe
# Read 16 bytes starting at offset 0
cpoutil read-eeprom interface <port> --oe -n 0 -o 0 -s 16
```

**Expected results**:

- Both commands return `rc == 0`.
- The ranged output contains exactly offsets 0–15.
- Identifier byte 0 matches the corresponding byte in the full OE dump.

**Coverage limits**: Other live bytes are not compared against the full dump; ELS ranged reads are not covered.

---

## 3. One-Time Manual Tests Only

In joint mode, configuring OE or ELS separately is not supported. Perform each check once manually; these cases are **not** part of the automated pytest suite.

| Case | Command | Expected result |
| --- | --- | --- |
| Manual-1: OE configuration | `cpoutil config oe` | Reports “unimplemented” in joint mode. |
| Manual-2: ELS configuration | `cpoutil config els` | Reports “unimplemented” in joint mode. |
