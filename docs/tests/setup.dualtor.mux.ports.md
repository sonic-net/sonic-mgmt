# Dual-ToR Mux Port Setup

## Purpose
The purpose of this document is to introduce the new Dual-ToR mux port setup infrastructure, describe how it works, and how to use it for test users.

## Introduction
As Dual-ToR shares the same test scope as T0, the T0 features need to be tested on Dual-ToR. Nowadays, the T0 test suite is growing faster but many new sonic-mgmt T0 test cases **DO NOT** take the difference of Dual-ToR into account. The unawareness of Dual-ToR leads to test failures, and most of the test failures are due to the DUT is not correctly selected with expected mux status:
- For active-standby Dual-ToR, the selected DUT is the standby side and cannot receive any upstream traffic.
- For active-active Dual-ToR, the upstream packet is ECMPed to both ToRs, the selected DUT might not be able to receive expected upstream packet.
- The test case has test steps which are Dual-ToR failure scenarios (link down, bgp down, etc.) and leads to unnecessary mux port toggle and unexpected I/O forwarding path change.

And the test contributor always finds it difficult to use the current Dual-ToR mux port setup fixtures:
- No uniform API.
The mux port setup fixtures are defined across multiple Python modules with no uniform naming convention.
- No self-acting mux port setup support.
If the test selects a DUT as the target test device, the test case needs to explicitly include the correct mux port setup fixture to ensure the mux port status to be expected, which places a burden to test writer to figure out the correct fixture import path/test function definition.

To address the issues listed above, a new Dual-ToR mux port setup infrastructure is introduced to provide a uniform and self-acting mux port setup API to reduce the burden to onboard T0 test cases onto Dual-ToR testbed.

## Requirement

* Provide uniform API to support the mux port setup functionalities provided by existing active-standby mux toggle and active-active mux setup fixtures.
* Support setup the mux ports on the DUT selected by the test case automatically.

## Design
A new global autouse fixture `setup_dualtor_mux_ports` is introduced to provide the mux port setup functionalities, it has the following key features:
- Use Pytest markers to customize test case mux port setup behaviors.
- Backward compatible with current mux port toggle/setup fixtures.

Current available mux port toggle/setup fixtures:
[1] `toggle_all_simulator_ports_to_upper_tor`
[2] `toggle_all_simulator_ports_to_lower_tor`
[3] `toggle_all_simulator_ports_to_rand_selected_tor`
[4] `toggle_all_simulator_ports_to_rand_unselected_tor`
[5] `toggle_all_simulator_ports_to_rand_selected_tor_m`
[6] `toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_frontend_host_m`
[7] `toggle_all_simulator_ports_to_enum_rand_one_per_hwsku_host_m`
[8] `toggle_all_aa_ports_to_lower_tor`
[9] `toggle_all_aa_ports_to_rand_selected_tor`
[10] `toggle_all_aa_ports_to_rand_unselected_tor`
[11] `setup_standby_ports_on_rand_selected_tor`
[12] `setup_standby_ports_on_rand_unselected_tor`
[13] `setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m`
[14] `setup_standby_ports_on_non_enum_rand_one_per_hwsku_host_m`
[15] `setup_standby_ports_on_rand_unselected_tor_unconditionally`
[16] `setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m_unconditionally`

The following Pytest markers are added to replace above fixtures:

|marker|description|note|
|-|-|-|
|`pytest.mark.dualtor_active_standby_toggle_to_enum_tor`|[active-standby] Toggle mux ports to the enum DUT|N/A|
|`pytest.mark.dualtor_active_standby_toggle_to_enum_tor_manual_mode`|[active-standby] Toggle mux ports to the enum DUT and set mux config to manual|This is to deprecate fixture [6] and [7]|
|`pytest.mark.dualtor_active_standby_toggle_to_upper_tor`|[active-standby] Toggle mux ports to the upper DUT|This is to deprecate fixture [1]|
|`pytest.mark.dualtor_active_standby_toggle_to_upper_tor_manual_mode`|[active-standby] Toggle mux ports to the upper DUT and set mux config to manual|N/A|
|`pytest.mark.dualtor_active_standby_toggle_to_lower_tor`|[active-standby] Toggle mux ports to the lower DUT|This is to deprecate fixture [2]|
|`pytest.mark.dualtor_active_standby_toggle_to_lower_tor_manual_mode`|[active-standby] Toggle mux ports to the lower DUT and set mux config to manual|N/A|
|`pytest.mark.dualtor_active_standby_toggle_to_random_tor`|[active-standby] Toggle mux ports to the random DUT|This is to deprecate fixture [3]|
|`pytest.mark.dualtor_active_standby_toggle_to_random_tor_manual_mode`|[active-standby] Toggle mux ports to the random DUT and set mux config to manual|This is to deprecate fixture [5]|
|`pytest.mark.dualtor_active_standby_toggle_to_random_unselected_tor`|[active-standby] Toggle mux ports to the random-unselected DUT|This is to deprecate fixture [4]|
|`pytest.mark.dualtor_active_standby_toggle_to_random_unselected_tor_manual_mode`|[active-standby] Toggle mux ports to the random-unselected DUT and set mux config to manual|N/A|
|`pytest.mark.dualtor_active_active_setup_standby_on_enum_tor`|[active-active] Setup mux mode standby on the enum DUT|N/A|
|`pytest.mark.dualtor_active_active_setup_standby_on_enum_tor_manual_mode`|[active-active] Setup mux mode standby on the enum ToR and config both ToRs manual|This is to deprecate fixture [13], [14] and [16]|
|`pytest.mark.dualtor_active_active_setup_standby_on_upper_tor`|[active-active] Setup mux mode standby on the upper ToR|This is to deprecate fixture [8]|
|`pytest.mark.dualtor_active_active_setup_standby_on_upper_tor_manual_mode`|[active-active] Setup mux mode standby on the upper ToR and config both ToRs manual|N/A|
|`pytest.mark.dualtor_active_active_setup_standby_on_lower_tor`|[active-active] Setup mux mode standby on the lower ToR|N/A|
|`pytest.mark.dualtor_active_active_setup_standby_on_lower_tor_manual_mode`|[active-active] Setup mux mode standby on the lower ToR and config both ToRs manual|N/A|
|`pytest.mark.dualtor_active_active_setup_standby_on_random_tor`|[active-active] Setup mux mode standby on the random ToR|This is to deprecate fixture [10] and [11]|
|`pytest.mark.dualtor_active_active_setup_standby_on_random_tor_manual_mode`|[active-active] Setup mux mode standby on the random ToR and config both ToRs manual|N/A|
|`pytest.mark.dualtor_active_active_setup_standby_on_random_unselected_tor`|[active-active] Setup mux mode standby on the random-unselected ToR|This is to deprecate fixture [9] and [12]|
|`pytest.mark.dualtor_active_active_setup_standby_on_random_unselected_tor_manual_mode`|[active-active] Setup mux mode standby on the random-unselected ToR and config both ToRs manual|This is to deprecate fixture [15]|

In addition, for active-standby Dual-ToR, `setup_dualtor_mux_ports` also reads the test function argument list to detect the DUT used by the test function and setup the mux ports accordingly:
- If the test function uses fixture `duthost` to access DUT, `setup_dualtor_mux_ports` will toggle the mux ports to `duthost`.
- If the test function uses fixture `rand_selected_dut` to access DUT, `setup_dualtor_mux_ports` will toggle the mux ports to `rand_selected_dut`

```python
def test_XXX(duthost):
    # All mux ports on duthost should be active
    pass

def test_YYY(rand_selected_dut)
    # All mux ports on rand_selected_dut should be active
    pass
```

## Example
Please refer to the API unit test `tests/dualtor_mgmt/test_dualtor_setup_mux_ports.py` that gives a comprehensive demonstration on each marker behavior.

## Q & A

### Q: Will the existing mux port toggle/setup fixtures be removed in the future?
No, all the existing mux port toggle/setup fixtures are marked with deprecation warnings and there is no plan to use the new markers for existing test cases. For new cases, it is recommended to use this new markers.
