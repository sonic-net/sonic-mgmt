# transceiver_attribute_infra_test.py is a self-contained selftest script
# (run via `python transceiver_attribute_infra_test.py`), not a pytest module.
# Exclude it from pytest collection so its `test_*` functions are not picked up
# by the transceiver test suite runs.
collect_ignore = ["transceiver_attribute_infra_test.py"]
