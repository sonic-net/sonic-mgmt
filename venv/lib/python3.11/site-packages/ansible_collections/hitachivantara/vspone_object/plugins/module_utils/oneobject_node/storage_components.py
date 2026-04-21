import urllib.error
from .gateway_oo import (
    OOGateway
)
from ..common.hv_log import (
    Log
)
from ..common.ansible_common_constants import (
    MAPI_FULL_URL_TEMPLATE_HTTPS
)
from ..common.hv_utilities import (
    DictUtilities, StringUtilities, ErrorUtilities
)
from ..common.hv_constants import (
    StorageComponentConstants
)
from .storage_components_msg_catalog import (
    StorageComponentMsgCatalog as SCMC
)


class StorageComponentResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token
        self.id = "NA"
        self.storage_component = None

    def query_all_default(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_component/list"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def query_all_no_params(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(
            self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        json_spec = self.param.json_spec
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_component/list?pageSize="
        json_spec = {}
        json_spec["pageSize"] = json_spec.get("pageSize", 100)
        page_size = json_spec["pageSize"]
        url += str(page_size)
        logger.writeDebug("url_list_storage_components: {}".format(url))
        storage_components = {}
        storage_components.get("storageComponents", [])

        loop = True
        while loop:
            storage_component_list = storage_components.get("storage_components", [])
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_spec)
            try:
                logger.writeDebug(
                    "Storage component MAPI Response : {}".format(response))
            except Exception as e:
                logger.writeDebug(
                    "Exception: {}".format(e)
                )
            if response.get("page_token", None) is not None:
                storage_component_list += response.get("storage_components", [])
                storage_components["storage_components"] = storage_component_list
                json_spec["pageToken"] = response["page_token"]
                continue
            else:
                loop = False
                storage_component_list += response.get("storage_components", [])
                storage_components["storage_components"] = storage_component_list
                break

        logger.writeDebug("storage_components: {}".format(storage_components))

        return storage_components

    def query_all(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(
            self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        json_spec = self.param.json_spec
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_component/list?pageSize="
        if json_spec is None:
            json_spec = {}
        json_spec["pageSize"] = json_spec.get("pageSize", 100)
        page_size = json_spec["pageSize"]
        url += str(page_size)
        logger.writeDebug("url_list_storage_components: {}".format(url))
        storage_components = {}
        storage_components.get("storageComponents", [])

        loop = True
        while loop:
            storage_component_list = storage_components.get("storage_components", [])
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_spec)
            try:
                logger.writeDebug(
                    "Storage component MAPI Response : {}".format(response))
            except Exception as e:
                logger.writeDebug(
                    "Exception: {}".format(e)
                )
            if response.get("page_token", None) is not None:
                storage_component_list += response.get("storage_components", [])
                storage_components["storage_components"] = storage_component_list
                json_spec["pageToken"] = response["page_token"]
                continue
            else:
                loop = False
                storage_component_list += response.get("storage_components", [])
                storage_components["storage_components"] = storage_component_list
                break

        logger.writeDebug("storage_components: {}".format(storage_components))

        return storage_components

    def query_n(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(
            self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_component/list?pageSize="

        json_spec = DictUtilities.snake_to_camel(self.param.json_spec)

        logger.writeDebug("json_spec before setting pageSize: {}".format(json_spec))
        json_spec["pageSize"] = json_spec.get("pageSize", 100)
        json_spec.pop("query", None)
        page_size = json_spec["pageSize"]
        url += str(page_size)
        logger.writeDebug("url_list_storage_components: {}".format(url))
        storage_components = {}
        storage_components.get("storageComponents", [])
        response = gateway.http_pd(
            "POST",
            self.param.connection_info,
            url,
            self.token,
            data=json_spec)
        return response

    def get_capacity(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_component/get_capacity"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def create_one(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        storage_components = None
        spec_label = ""

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)
        logger.writeDebug("json_data : {}".format(json_data))

        storage_component_config = json_data.get(
            "storageComponentConfig", None)
        if storage_component_config:
            logger.writeDebug("found storage_component field")
            storage_component_config = DictUtilities.snake_to_camel(
                storage_component_config)
        logger.writeDebug(
            "storageComponentConfig : {}".format(storage_component_config))
        storage_component_config["connectionTTL"] = storage_component_config["connectionTtl"]
        storage_component_config.pop("connectionTtl", None)
        json_data["storageComponentConfig"] = storage_component_config
        spec_label = storage_component_config.get("label", "")

        storage_type = json_data.get("storageType", None)

        logger.writeDebug("storage_type : {}".format(storage_type))

        if self.id != "NA":
            if self.id is not None and self.id != "":
                self.id = self.id.strip()
                self.param.json_spec["id"] = self.id
                return self.update()

        if storage_type is not None and storage_type.strip() == "ARRAY":
            return self.create_one_array()

        try:
            storage_components = self.query_all_no_params()
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage component: {}".format(e))

        try:
            storage_components = storage_components.get("storage_components", [])
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage component array: {}".format(e))
            storage_components = []

        logger.writeDebug(
            "Storage components are: {}".format(storage_components))

        existing_component = False
        storage_component_item = None
        logger.writeDebug("label of storage component: {}".format(spec_label))

        logger.writeDebug("id of storage component: {}".format(self.id))

        for storage_component in storage_components:
            logger.writeDebug("storage_component:{}".format(storage_component))
            component_config = storage_component.get(
                "storage_component_config", None)
            label = None
            if component_config is not None:
                label = component_config.get("label", None)
                logger.writeDebug("storage component label: {}".format(label))
            if label:
                if label.strip() == spec_label:
                    storage_component_item = storage_component
                    existing_component = True
                    logger.writeDebug("storage component found as : {}".format(storage_component))
                    break

        if existing_component:
            self.param.json_spec["id"] = storage_component_item.get("id", "")
            self.storage_component = storage_component_item
            return self.update()

        url = f"{mapi_full_url}/mapi/v1/storage_component/create"

        required_conf = StorageComponentConstants.CREATE_REQUIRED_FIELDS

        for item in required_conf:
            item_value = storage_component_config.get(item, None)
            if item_value is None:
                key = StringUtilities.camel_to_snake(item)
                raise ValueError(SCMC.FIELDS_MISSING_CREATE.value.format(key))

        non_empty_fields = StorageComponentConstants.NON_EMPTY_FIELDS
        for item in non_empty_fields:
            item_value = storage_component_config.get(item, "")
            item_value = item_value.strip()
            if item_value == "":
                key = StringUtilities.camel_to_snake(item)
                raise ValueError(SCMC.FIELDS_MISSING_CREATE.value.format(key))

        response = None
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        response["changed"] = True
        return response

    def update(self):
        logger = Log()
        gateway = OOGateway()
        if self.storage_component is None:
            self.id = self.id.strip()
            self.storage_component = self.query_storage_comp_by_id(self.id)

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)
        logger.writeDebug("json_data : {}".format(json_data))

        storage_component_config = json_data.get(
            "storageComponentConfig", None)
        if storage_component_config:
            logger.writeDebug("found storage_component field")
            storage_component_config = DictUtilities.snake_to_camel(
                storage_component_config)
        patch_keys_popped = StorageComponentConstants.DELETE_PATCH_KEYS
        # storage_component_config["namespace"] = "ucp"
        storage_component_config["connectionTTL"] = storage_component_config["connectionTtl"]
        storage_component_config = DictUtilities.delete_keys(
            storage_component_config, patch_keys_popped
        )
        null_keys = []
        for key, value in storage_component_config.items():
            if value is None:
                null_keys.append(key)
        storage_component_config = DictUtilities.delete_keys(
            storage_component_config, null_keys
        )

        json_data["storageComponentConfig"] = storage_component_config
        # json_data = {k: v for k, v in json_data.items() if v is not None}
        url = f"{mapi_full_url}/mapi/v1/storage_component/update"
        response = None

        try:
            response = gateway.http_pd(
                "PATCH",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
            logger.writeDebug(
                "update storage_component response :{}".format(response))
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e

        changed = DictUtilities.is_subset_dict(
            self.storage_component, response
        )
        logger.writeDebug("respone of storage component update: {}".format(response))
        response["changed"] = not changed
        changed_component = not changed

        try:
            storage_custom_metadata_response = response.get("storage_custom_metadata", None)
            storage_custom_metadata_original = self.storage_component.get("storage_custom_metadata", None)
            is_same = DictUtilities.is_same_dict(
                storage_custom_metadata_response, storage_custom_metadata_original
            )
            if is_same:
                if not changed_component:
                    response["changed"] = False
                else:
                    response["changed"] = True
            else:
                response["changed"] = True

        except Exception as e:
            logger.writeDebug("Could not compare. Exception: {}".format(e))

        return response

    def activate_storage_component(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        spec_id = self.param.json_spec.get("id", "")
        try:
            storage_components = self.query_all_no_params()
            logger.writeDebug("inside activate storage component, storage_components : {}".format(storage_components))
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage component: {}".format(e))

        try:
            storage_components = storage_components.get("storage_components", [])
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage component array: {}".format(e))
            storage_components = []

        logger.writeDebug("spec_id : {}".format(spec_id))

        for storage_component in storage_components:
            logger.writeDebug("component : {}".format(storage_component))
            id = storage_component.get("id", None)
            logger.writeDebug("id : {}".format(id))
            if id is not None:
                if str(id) == str(spec_id):
                    comp_conf = storage_component.get(
                        "storage_component_config", None)
                    logger.writeDebug("comp_conf : {}".format(comp_conf))
                    if comp_conf is not None:
                        state = comp_conf.get("state", "")
                        if state == "ACTIVE":
                            message = SCMC.INFO_ACTIVE_STATE.value.format(id)
                            response = {}
                            response["changed"] = False
                            response["data"] = comp_conf
                            return response

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name
        )

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)

        url = f"{mapi_full_url}/mapi/v1/storage_component/activate"

        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            logger.writeDebug("Message from HTTPError: {}".format(e))
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        response_dict = {}
        response_dict["changed"] = True
        response_dict["data"] = response
        return response_dict

    def decomission_storage_component(self):
        logger = Log()
        gateway = OOGateway()
        if self.storage_component is None:
            self.id = self.param.json_spec["id"]
            self.id = self.id.strip()
            self.storage_component = self.query_storage_comp_by_id(self.id)

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = {}
        json_data["id"] = int(self.param.json_spec["id"])

        url = f"{mapi_full_url}/mapi/v1/storage_component/decommission"
        response = None
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        changed = DictUtilities.is_subset_dict(
            self.storage_component, response
        )
        response["changed"] = not changed
        return response

    def update_storage_component_state(self):
        logger = Log()
        gateway = OOGateway()
        if self.storage_component is None:
            self.id = self.param.json_spec["id"]
            self.id = self.id.strip()
            self.storage_component = self.query_storage_comp_by_id(self.id)

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)

        url = f"{mapi_full_url}/mapi/v1/storage_component/update_state"

        response = None
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e

        changed = DictUtilities.is_subset_dict(
            self.storage_component, response
        )
        response["changed"] = not changed
        return response

    def update_config(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)
        logger.writeDebug("json_data : {}".format(json_data))

        storage_component_config = json_data.get(
            "storageComponentConfig", None)
        if storage_component_config:
            logger.writeDebug("found storage_component field")
            storage_component_config = DictUtilities.snake_to_camel(
                storage_component_config)
        patch_keys_popped = StorageComponentConstants.DELETE_PATCH_KEYS
        # storage_component_config["namespace"] = "ucp"
        storage_component_config["connectionTTL"] = storage_component_config["connectionTtl"]
        storage_component_config = DictUtilities.delete_keys(
            storage_component_config, patch_keys_popped)

        json_data["storageComponentConfig"] = storage_component_config
        # json_data = {k: v for k, v in json_data.items() if v is not None}
        url = f"{mapi_full_url}/mapi/v1/storage_component/update"

        response = None
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        return response

    def query_storage_comp_by_id(self, id):
        logger = Log()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))
        try:
            storage_components = self.query_all_no_params()
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e))

        try:
            storage_components = storage_components.get("storage_components", [])
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage components: {}".format(e))
            storage_components = []

        for storage_component in storage_components:
            logger.writeDebug("storage_component:{}".format(storage_component))
            id_item = storage_component.get("id", None)
            if id_item is not None:
                if str(id_item) == str(id):
                    return storage_component
        return None

    def test_access(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)

        url = f"{mapi_full_url}/mapi/v1/storage_component/test"

        response = None

        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e

        return response

    def create_one_array(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        storage_components = None
        spec_label = ""

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(self.param.json_spec)
        logger.writeDebug("json_data : {}".format(json_data))

        storage_component_config = json_data.get(
            "storageComponentConfig", None)
        if storage_component_config:
            logger.writeDebug("found storage_component field")
            storage_component_config = DictUtilities.snake_to_camel(
                storage_component_config)
        logger.writeDebug(
            "storageComponentConfig : {}".format(storage_component_config))
        connection_ttl = storage_component_config.pop("connectionTtl", None)
        storage_component_config["connectionTTL"] = connection_ttl
        json_data["storageComponentConfig"] = storage_component_config
        spec_label = storage_component_config.get("label", "")

        storage_type = storage_component_config.get("storageType", None)
        logger.writeDebug("storage_type_create_one_array : {}".format(storage_type))

        if self.id != "NA":
            if self.id is not None and self.id != "":
                self.id = self.id.strip()
                self.param.json_spec["id"] = self.id

        try:
            storage_components = self.query_all_no_params()
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage component: {}".format(e))

        logger.writeDebug(
            "Storage components are: {}".format(storage_components))

        try:
            storage_components = storage_components.get("storage_components", [])
        except Exception as e:
            logger.writeDebug(
                "Failed to get the storage component array: {}".format(e))
            storage_components = []

        existing_component = False
        storage_component_item = None
        logger.writeDebug("label of storage component: {}".format(spec_label))

        logger.writeDebug("id of storage component: {}".format(self.id))

        for storage_component in storage_components:
            logger.writeDebug(storage_component)
            logger.writeDebug("storage_component:{}".format(storage_component))
            component_config = storage_component.get(
                "storage_component_config", None)
            label = None
            if component_config is not None:
                label = component_config.get("label", None)
                logger.writeDebug("storage component label: {}".format(label))
            if label:
                if label.strip() == spec_label:
                    storage_component_item = storage_component
                    existing_component = True
                    logger.writeDebug("storage component found as : {}".format(storage_component))
                    break

        if existing_component:
            self.param.json_spec["id"] = storage_component_item.get("id", "")
            self.storage_component = storage_component_item
            return self.update()

        url = f"{mapi_full_url}/mapi/v1/storage_component/create"

        required_conf = StorageComponentConstants.CREATE_REQUIRED_FIELDS_ARRAY

        logger.writeDebug("required_conf : {}".format(required_conf))

        for item in required_conf:
            item_value = storage_component_config.get(item, None)
            if item_value is None:
                key = StringUtilities.camel_to_snake(item)
                raise ValueError(SCMC.FIELDS_MISSING_CREATE.value.format(key))

        non_empty_fields = StorageComponentConstants.NON_EMPTY_FIELDS_ARRAY
        for item in non_empty_fields:
            item_value = storage_component_config.get(item, "")
            item_value = item_value.strip()
            if item_value == "":
                key = StringUtilities.camel_to_snake(item)
                raise ValueError(SCMC.FIELDS_MISSING_CREATE.value.format(key))

        response = None
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
        response["changed"] = True
        return response
