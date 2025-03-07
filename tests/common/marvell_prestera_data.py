def is_marvell_prestera_device(dut):
    return dut.facts["asic_type"] == "marvell-prestera"
