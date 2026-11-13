def is_broadcom_device(dut):
    return dut.facts["asic_type"] == "broadcom"


def is_broadcom_dnx_device(dut):
    return dut.facts.get("platform_asic") == "broadcom-dnx"


# Q3D (Jericho3) is one of several broadcom-dnx ASICs; get_asic_name() reads the PCI ID off the DUT.
def is_broadcom_q3d_device(dut):
    return is_broadcom_dnx_device(dut) and dut.get_asic_name() == "q3d"


LOSSY_ONLY_HWSKUS = ['Arista-7060X6-64PE-C256S2', 'Arista-7060X6-64PE-C224O8',
                     'Arista-7060X6-64PE-B-C512S2', 'Arista-7060X6-64PE-B-C448O16']
NO_QOS_HWSKUS = ['Arista-7050CX3-32C-C28S16', 'Arista-7050CX3-32C-S128',
                 'Arista-7050CX3-32C-C6S104', 'Arista-720DT-G48S4',
                 'Arista-720DT-48S', 'Arista-720DT-MGX-G48S4']
