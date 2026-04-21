from .storage_fault_domain_msg_catalog import StorageFaultDomainMsgCatalog as SFDMC


class StorageFaultDomainParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"StorageFaultDomain(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            if self.json_spec["pageSize"] <= 0:
                pageSizeStr = str(self.json_spec["pageSize"])
                raise ValueError("Invalid Page Size: " + pageSizeStr)
        else:
            raise ValueError("Provide Page Size")
        return True


class StorageFaultDomainInfoParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = json_spec

    def __str__(self):
        return (f"StorageDomain(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id_value = self.json_spec.get("id", None)
            page_size = self.json_spec.get("pageSize", None)

            if (id_value is not None and page_size is not None) or (id_value is None and page_size is None):
                raise ValueError(SFDMC.ERR_INVALID_SPEC_FIELDS.value)
            if id_value is not None:
                if not id_value or id_value.strip() == "":
                    raise ValueError(SFDMC.ERR_INVALID_ID.value)
            if page_size is not None:
                if page_size == "" or page_size is None:
                    raise ValueError(SFDMC.ERR_INVALID_SIZE.value)
                if isinstance(page_size, bool):
                    raise ValueError(SFDMC.ERR_INVALID_TYPE_PAGE_SIZE.value)
                if page_size <= 0:
                    raise ValueError(SFDMC.ERR_INVALID_SIZE.value.format(str(page_size)))
        return True


class CreateStorageFaultDomainParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = dict()
        self.json_spec["name"] = json_spec["name"]
        self.json_spec["tags"] = json_spec["tags"]

    def __str__(self):
        return (f"StorageDomain(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            name_value = self.json_spec.get("name", None)
            if not name_value or name_value.strip() == "":
                raise ValueError(SFDMC.ERR_INVALID_NAME_EMPTY.value)
        else:
            raise ValueError("Provide correct name")
        return True


class UpdateStorageFaultDomainParam:
    def __init__(self, conn_info, json_spec):
        self.connection_info = conn_info
        self.json_spec = dict()
        self.json_spec["name"] = json_spec["name"]
        self.json_spec["tags"] = json_spec["tags"]
        self.json_spec["id"] = json_spec["id"]

    def __str__(self):
        return (f"StorageDomain(connection_info={self.connection_info}, \
                json_spec={self.json_spec}")

    def validate(self):
        if self.json_spec is not None:
            id_value = self.json_spec.get("id", None)
            if not id_value or id_value.strip() == "":
                raise ValueError(SFDMC.ERR_INVALID_ID.value)
        else:
            raise ValueError("Provide correct ID and Name")
        return True
