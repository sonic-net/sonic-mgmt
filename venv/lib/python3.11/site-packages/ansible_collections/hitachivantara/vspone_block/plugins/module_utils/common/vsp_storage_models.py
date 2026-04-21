class VSPStorageModelsManager:

    direct_storage_models_mapping = {
        # The following models are present in GW
        "VSP_5100H": "VSP 5000 series hybrid",
        "VSP_5200H": "VSP 5000 series hybrid",
        "VSP_5500H": "VSP 5000 series hybrid",
        "VSP_5600H": "VSP 5000 series hybrid",
        "VSP_5100": "VSP 5000 series AFA",
        "VSP_5200": "VSP 5000 series AFA",
        "VSP_5500": "VSP 5000 series AFA",
        "VSP_5600": "VSP 5000 series AFA",
        "VSP_E1090": "VSP E1090",
        "VSP_E590": "VSP E590",
        "VSP_E790": "VSP E790",
        "VSP_E990": "VSP E990",
        "VSP_F350": "VSP F350",
        "VSP_F370": "VSP F370",
        "VSP_F400": "VSP F400",
        "VSP_F600": "VSP F600",
        "VSP_F700": "VSP F700",
        "VSP_F800": "VSP F800",
        "VSP_F900": "VSP F900",
        "VSP_G130": "VSP G130",
        # "VSP_G150" - Not found in the REST API guide
        "VSP_G200": "VSP G200",
        "VSP_G350": "VSP G350",
        "VSP_G370": "VSP G370",
        "VSP_G400": "VSP G400",
        "VSP_G600": "VSP G600",
        "VSP_G700": "VSP G700",
        "VSP_G800": "VSP G800",
        "VSP_G900": "VSP G900",
        # The following models are supported by GW just by device type field
        "VSP_G1000": "VSP G1000",
        "VSP_G1500": "VSP G1500",
        "VSP_F1500": "VSP F1500",
        # The following models are supported by GW by combination of device type and model fields
        "VSP_E1090H": "VSP E1090H",
        # The following models are not supported by GW
        "VSP_ONE_B28": "VSP One B28",
        "VSP_ONE_B26": "VSP One B26",
        "VSP_ONE_B24": "VSP One B24",
        "VSP_E790H": "VSP E790H",
        "VSP_E590H": "VSP E590H",
        # The following models are no longer supported by HV
        # "HUS_VM" : "HUS VM",
        # "VSP" : "VSP"
    }

    gw_storage_models_mapping = {
        # The following models are present in GW
        "VSP_5100H": "STORAGEDEVICEMODEL_VSP_5100H",
        "VSP_5200H": "STORAGEDEVICEMODEL_VSP_5200H",
        "VSP_5500H": "STORAGEDEVICEMODEL_VSP_5500H",
        "VSP_5600H": "STORAGEDEVICEMODEL_VSP_5600H",
        "VSP_5100": "STORAGEDEVICEMODEL_VSP_5100",
        "VSP_5200": "STORAGEDEVICEMODEL_VSP_5200",
        "VSP_5500": "STORAGEDEVICEMODEL_VSP_5500",
        "VSP_5600": "STORAGEDEVICEMODEL_VSP_5600",
        "VSP_E1090": "STORAGEDEVICEMODEL_VSP_E1090",
        "VSP_E590": "STORAGEDEVICEMODEL_VSP_E590",
        "VSP_E790": "STORAGEDEVICEMODEL_VSP_E790",
        "VSP_E990": "STORAGEDEVICEMODEL_VSP_E990",
        "VSP_F350": "STORAGEDEVICEMODEL_VSP_F350",
        "VSP_F370": "STORAGEDEVICEMODEL_VSP_F370",
        "VSP_F400": "STORAGEDEVICEMODEL_VSP_F400",
        "VSP_F600": "STORAGEDEVICEMODEL_VSP_F600",
        "VSP_F700": "STORAGEDEVICEMODEL_VSP_F700",
        "VSP_F800": "STORAGEDEVICEMODEL_VSP_F800",
        "VSP_F900": "STORAGEDEVICEMODEL_VSP_F900",
        "VSP_G130": "STORAGEDEVICEMODEL_VSP_G130",
        "VSP_G150": "STORAGEDEVICEMODEL_VSP_G150",
        "VSP_G200": "STORAGEDEVICEMODEL_VSP_G200",
        "VSP_G350": "STORAGEDEVICEMODEL_VSP_G350",
        "VSP_G370": "STORAGEDEVICEMODEL_VSP_G370",
        "VSP_G400": "STORAGEDEVICEMODEL_VSP_G400",
        "VSP_G600": "STORAGEDEVICEMODEL_VSP_G600",
        "VSP_G700": "STORAGEDEVICEMODEL_VSP_G700",
        "VSP_G800": "STORAGEDEVICEMODEL_VSP_G800",
        "VSP_G900": "STORAGEDEVICEMODEL_VSP_G900",
        # The following models are supported by GW just by device type field
        "VSP_G1000": "",
        "VSP_G1500": "",
        "VSP_F1500": "",
        # The following models are supported by GW by combination of device type and model fields
        "VSP_E1090H": "STORAGEDEVICEMODEL_VSP_E1090",
        # The following models are not supported by GW
        # "VSP_ONE_B28" : "VSP One B28",
        # "VSP_ONE_B26" : "VSP One B26",
        # "VSP_ONE_B24" : "VSP One B24",
        # "VSP_E790H" : "VSP E790H",
        # "VSP_E590H" : "VSP E590H",
        # The following models are no longer supported by HV
        # "HUS_VM" : "HUS VM",
        # "VSP" : "VSP"
    }

    gw_storage_model_to_device_type_mapping = {
        # The following models are present in GW
        "VSP_5100H": "STORAGEDEVICE_VSP_5X00H",
        "VSP_5200H": "STORAGEDEVICE_VSP_5X00H",
        "VSP_5500H": "STORAGEDEVICE_VSP_5X00H",
        "VSP_5600H": "STORAGEDEVICE_VSP_5X00H",
        "VSP_5100": "STORAGEDEVICE_VSP_5X00",
        "VSP_5200": "STORAGEDEVICE_VSP_5X00",
        "VSP_5500": "STORAGEDEVICE_VSP_5X00",
        "VSP_5600": "STORAGEDEVICE_VSP_5X00",
        "VSP_E1090": "STORAGEDEVICE_VSP_EX00",
        "VSP_E590": "STORAGEDEVICE_VSP_EX00",
        "VSP_E790": "STORAGEDEVICE_VSP_EX00",
        "VSP_E990": "STORAGEDEVICE_VSP_EX00",
        "VSP_F350": "STORAGEDEVICE_VSP_FX00",
        "VSP_F370": "STORAGEDEVICE_VSP_FX00",
        "VSP_F400": "STORAGEDEVICE_VSP_FX00",
        "VSP_F600": "STORAGEDEVICE_VSP_FX00",
        "VSP_F700": "STORAGEDEVICE_VSP_FX00",
        "VSP_F800": "STORAGEDEVICE_VSP_FX00",
        "VSP_F900": "STORAGEDEVICE_VSP_FX00",
        "VSP_G130": "STORAGEDEVICE_VSP_GX00",
        "VSP_G150": "STORAGEDEVICE_VSP_GX00",
        "VSP_G200": "STORAGEDEVICE_VSP_GX00",
        "VSP_G350": "STORAGEDEVICE_VSP_GX00",
        "VSP_G370": "STORAGEDEVICE_VSP_GX00",
        "VSP_G400": "STORAGEDEVICE_VSP_GX00",
        "VSP_G600": "STORAGEDEVICE_VSP_GX00",
        "VSP_G700": "STORAGEDEVICE_VSP_GX00",
        "VSP_G800": "STORAGEDEVICE_VSP_GX00",
        "VSP_G900": "STORAGEDEVICE_VSP_GX00",
        # The following models are supported by GW just by device type field
        "VSP_G1000": "STORAGEDEVICE_VSP_G1000",
        "VSP_G1500": "STORAGEDEVICE_VSP_G1500",
        "VSP_F1500": "STORAGEDEVICE_VSP_F1500",
        # The following models are supported by GW by combination of device type and model fields
        "VSP_E1090H": "STORAGEDEVICE_VSP_EX00H",
        # The following models are not supported by GW
        # "VSP_ONE_B28" : "VSP One B28",
        # "VSP_ONE_B26" : "VSP One B26",
        # "VSP_ONE_B24" : "VSP One B24",
        # "VSP_E790H" : "VSP E790H",
        # "VSP_E590H" : "VSP E590H",
        # The following models are no longer supported by HV
        # "HUS_VM" : "HUS VM",
        # "VSP" : "VSP"
    }

    @staticmethod
    def get_direct_storage_model(model):
        return VSPStorageModelsManager.direct_storage_models_mapping.get(model)

    @staticmethod
    def get_gw_storage_model(model):
        return VSPStorageModelsManager.gw_storage_models_mapping.get(model)

    @staticmethod
    def get_gw_storage_device_type(model):
        return VSPStorageModelsManager.gw_storage_model_to_device_type_mapping.get(
            model
        )
