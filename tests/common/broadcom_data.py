SWITCH_HWSKUS = ["Force10-S6000", "Accton-AS7712-32X", "Celestica-DX010-C32",
                 "Seastone-DX010", "Celestica-E1031-T48S4"]

def is_broadcom_device(hwsku):
    return hwsku in SWITCH_HWSKUS
