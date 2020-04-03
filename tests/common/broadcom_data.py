def is_broadcom_device(dut):
    return dut.get_asic_type() == "broadcom"
