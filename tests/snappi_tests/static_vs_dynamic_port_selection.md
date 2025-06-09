# Static and Dynamic Port Selection for Snappi
-----------------------------------------------

Snappi tests support two modes of port selection:

- **Static Port Selection**
- **Dynamic Port Selection**

These tests are typically executed across three test subtypes:

- **Single line card, single ASIC.**
- **Single line card, multiple ASICs.**
- **Multiple line cards.**

---

## Static Port Selection

Static port selection is the existing method used for assigning ports. It relies on the `tests/snappi_tests/variables.override.yml` file to define the ports.

A dictionary maps each test subtype to its corresponding Tx and Rx ports. The test framework uses these mappings as parameterized variables and iterates through each subtype.

**Dictionary format:**

```yaml
<test-subtype>:
  tx-ports: [list of ports]
  rx-ports: [list of ports]
```

Users can customize or extend subtypes as needed by modifying the `variables.py` file.

**Advantages:**

- Full control over which subtypes and ports are used.
- Easy to define and reuse specific configurations.

**Disadvantages:**

- Not portable across different setups, hence requires manual updates to `variables.py` for each new environment.
- Cannot easily handle setups with interfaces of varying speeds unless subtypes are explicitly defined for each speed.

---

## Dynamic Port Selection

Dynamic port selection is new feature that automatically determines available ports based on the testbed configuration. It uses metadata stored in:

```
tests/metadata/snappi_tests/<testbed>.json
```

This file includes information about available ports, their speeds, and associated ASICs. During test execution, `test_pretest.py` generates subtypes dynamically based on interface speeds and three subtypes defined above. For each combination, it assigns appropriate ports.

Example:
```
./run_tests.sh -n vms-snappi-sonic-multidut -c snappi_tests/pfcwd/test_pfcwd_a2a_with_snappi.py -i ../ansible/veos -e "--topology multidut-tgen,any --enable-snappi-dynamic-ports"

```

**Dictionary format:**

```
{
  "<test-subtype>_<interface-speed>": [list of ports]
}
```

**Advantages:**

- Automatically adapts to different setups and interface speeds.
- No manual configuration required.

**Disadvantages:**

- No fine-grained control over which subtypes or ports are selected.
- Dynamic subtypes cannot be customized.

---

## Port Selection Logic

The test framework chooses between static and dynamic port selection based on the following logic:

1. *Static Selection* is used if the testbed name, subtype, and ports are defined in `tests/snappi_tests/variables.override.yml`.
2. *Dynamic Selection* is used if the above file does not contain the required configuration.
3. Users can *force dynamic selection* by passing the `--enable-snappi-dynamic-ports` flag to `pytest`, even if static configuration is present.
---
