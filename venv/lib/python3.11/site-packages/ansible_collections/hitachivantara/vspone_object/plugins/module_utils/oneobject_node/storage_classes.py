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
from ..common.hv_constants import (
    Http as HttpConstants,
)
from ..common.hv_utilities import (
    DictUtilities, ErrorUtilities
)
from .common_msg_catalog import (
    CommonMsgCatalog as CMCA
)
from .storage_class_msg_catalog import (
    StorageClassMsgCatalog as SMCA
)


class StorageClassResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def __update_spec(self, json_spec=None):
        # Assgin default values to self.param.json_spec
        if json_spec is None:
            json_spec = {"pageSize": 1000}

        # Update self.param.json_spec with the values from json_spec
        self.param.json_spec = json_spec

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

        url = f"{mapi_full_url}/mapi/v1/storage_class/list?pageSize="
        page_size = str(json_spec["pageSize"])
        url += page_size
        storage_classes = {}
        storage_classes.get("storageClasses", [])

        loop = True
        while loop:
            storage_class_list = storage_classes.get("storageClasses", [])
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_spec)
            try:
                logger.writeDebug(
                    "Storage class MAPI Response : {}".format(response))
            except Exception as e:
                logger.writeDebug(
                    "Exception: {}".format(e)
                )
            if response.get("page_token", None) is not None:
                storage_class_list += response.get("storage_classes", [])
                storage_classes["storage_classes"] = storage_class_list
                json_spec["page_token"] = response["page_token"]
                continue
            else:
                loop = False
                storage_class_list += response.get("storage_classes", [])
                storage_classes["storage_classes"] = storage_class_list
                break

        logger.writeDebug("storage_classes: {}".format(storage_classes))

        return storage_classes

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
        json_spec = {}
        json_spec["pageSize"] = self.param.json_spec["pageSize"]
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_class/list?pageSize="
        url += str(json_spec["pageSize"])
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def create_one(self):
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

        self.__update_spec()

        # Check if the storage class already exists
        try:
            result = self.query_all()["storage_classes"]
            logger.writeDebug("result: {}".format(result))
        except Exception as err:
            error_message = "Failed to query storage classes."
            logger.writeDebug(error_message)
            logger.writeDebug(err)

        existing_storage_class = None
        if result is not None:
            existing_class = [
                item for item in result if item['name'].lower() == json_data['name'].lower()]
            if existing_class:
                existing_storage_class = existing_class[0]

            logger.writeDebug(
                "existing_storage: {}".format(existing_storage_class))
        if existing_storage_class:
            logger.writeDebug("Storage class already exists.")
            return existing_storage_class, False

        url = f"{mapi_full_url}/mapi/v1/storage_class/create"

        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
            logger.writeDebug(
                "create storage class response :{}".format(response))
            return response, True
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e

    def query_one(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        json_spec = self.param.json_spec
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)
        data = {}
        data["id"] = json_spec["id"]
        url = f"{mapi_full_url}/mapi/v1/storage_class/info"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=data
        )

    def query_default(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_class/default/get"

        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token
        )

    def handle_error(self, err, query_one=False):
        logger = Log()
        err_str = str(err)
        logger.writeDebug(err_str)
        id = self.param.json_spec.get("id", "")

        if str(HttpConstants.ERR_400) in err_str:
            err_msg = SMCA.ERR_INVALID_ID_VALUE.value.format(
                id) if query_one else err_str
            return err_msg

        if str(HttpConstants.ERR_404) in err_str:
            err_msg = SMCA.ERR_ID_NOT_FOUND.value.format(
                id) if query_one else err_str
            return err_msg

        return CMCA.HTTP_500_ERR.value

    def update_default(self):
        logger = Log()
        gateway = OOGateway()

        json_spec = self.param.json_spec

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug(
            "param: {}".format(
                self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        json_data = DictUtilities.snake_to_camel(json_spec)
        logger.writeDebug("json_data: {}".format(json_data))

        url = f"{mapi_full_url}/mapi/v1/storage_class/default/update"
        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
            logger.writeDebug(
                "update storage class response :{}".format(response))
            return response, True
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e

    def update_one(self):
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

        json_data = {
            "id": self.param.json_spec["id"],
            "name": self.param.json_spec["name"]}

        url = f"{mapi_full_url}/mapi/v1/storage_class/update"

        try:
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_data)
            logger.writeDebug(
                "update storage class response :{}".format(response))
            return response, True
        except urllib.error.HTTPError as e:
            ErrorUtilities.format_MAPI_http_error(e)
        except Exception as e:
            logger.writeDebug(
                "Exception: {}".format(e)
            )
            raise e
