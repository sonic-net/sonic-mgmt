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
    DictUtilities
)
from enum import Enum


class Operation(Enum):
    ADD = "present"
    PROMOTE = "promote"
    UPDATE = "modify"
    DELETE = "absent"


class KMIPServerResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_all(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/list_servers"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=None
        )

    def query_one(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = self.param.json_spec

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/get_server"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def kmip_operation(self):
        logger = Log()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        json_spec = self.param.json_spec

        existing_kmip = None
        changed = True

        try:
            existing_kmip = self.get_kmip(json_spec)
        except Exception as err:
            logger.writeDebug("kmip server not found: {}".format(err))

        response = None
        existing_kmip_is_primary = False
        if existing_kmip is not None:
            existing_kmip_is_primary = existing_kmip.get("is_primary", False)

        if json_spec["state"] == Operation.ADD.value:
            kmip_spec = json_spec
            kmip_spec.pop("state")
            kmip_spec = DictUtilities.snake_to_camel(kmip_spec)
            if existing_kmip is not None:
                existing_kmip_name = existing_kmip.get("name", "")
                if existing_kmip_name == kmip_spec.get("name", ""):
                    changed = False
            logger.writeDebug("kmip_spec: {}".format(kmip_spec))
            try:
                response = self.add_kmip(kmip_spec)
            except Exception as err:
                kmip_protocol = json_spec["kmip_protocol"]
                errorStr = str(err)
                if hasattr(err, 'read'):
                    errorStr = err.read().decode('utf-8')
                if f"Unexpected value '{kmip_protocol}'" in errorStr:
                    raise ValueError(f"Unsupported KMIP protocol {kmip_protocol}")
                logger.writeDebug("kmip_spec: {}".format(kmip_spec))
                logger.writeDebug("kmip_spec: {}".format(err))
                raise err
        elif json_spec["state"] == Operation.DELETE.value:
            kmip_spec = json_spec
            kmip_spec.pop("state")
            kmip_spec = DictUtilities.snake_to_camel(kmip_spec)
            logger.writeDebug("kmip_spec: {}".format(kmip_spec))
            try:
                response = self.delete_kmip(kmip_spec)
            except Exception as err:
                logger.writeDebug("kmip_spec: {}".format(kmip_spec))
                logger.writeDebug("kmip_spec: {}".format(err))
                raise err
        elif json_spec["state"] == Operation.PROMOTE.value:
            kmip_spec = json_spec
            kmip_spec.pop("state")
            kmip_spec = DictUtilities.snake_to_camel(kmip_spec)
            logger.writeDebug("kmip_spec: {}".format(kmip_spec))
            try:
                response = self.promote_kmip(kmip_spec)
                if existing_kmip_is_primary:
                    changed = False
            except Exception as err:
                logger.writeDebug("kmip_spec: {}".format(kmip_spec))
                logger.writeDebug("kmip_spec: {}".format(err))
                raise err
        elif json_spec["state"] == Operation.UPDATE.value:
            logger.writeDebug("Existing KMIP: {}".format(existing_kmip))
            kmip_spec = json_spec
            kmip_spec.pop("state")
            kmip_spec["is_tls12_enabled"] = kmip_spec.get("isTLS12Enabled", None)
            kmip_spec.pop("isTLS12Enabled", None)
            logger.writeDebug("kmip_spec: {}".format(kmip_spec))
            if existing_kmip is not None:
                existing_kmip_name = existing_kmip.get("name", "")
                if existing_kmip_name == kmip_spec.get("name", ""):
                    try:
                        params_match = DictUtilities.is_subset_dict(kmip_spec, existing_kmip)
                        if params_match:
                            changed = False
                            logger.writeDebug("No changes to KMIP spec")
                        else:
                            logger.writeDebug("Changes made to KMIP spec")
                        kmip_spec["uuid"] = existing_kmip.get("uuid", "")
                    except Exception as err:
                        logger.writeDebug("Error comparring KMIP dict: {}".format(err))
            kmip_spec["isTLS12Enabled"] = kmip_spec.pop("is_tls12_enabled", None)
            kmip_spec = DictUtilities.snake_to_camel(kmip_spec)
            logger.writeDebug("kmip_spec: {}".format(kmip_spec))
            try:
                response = self.update_kmip(kmip_spec)
            except Exception as err:
                logger.writeDebug("kmip_spec: {}".format(kmip_spec))
                logger.writeDebug("kmip_spec: {}".format(err))
                kmip_protocol = json_spec["kmip_protocol"]
                errorStr = str(err)
                if hasattr(err, 'read'):
                    errorStr = err.read().decode('utf-8')
                if f"Unexpected value '{kmip_protocol}'" in errorStr:
                    raise ValueError(f"Unsupported KMIP protocol {kmip_protocol}")
                logger.writeDebug("kmip_spec: {}".format(kmip_spec))
                logger.writeDebug("kmip_spec: {}".format(err))
                raise err
        return response, changed

    def add_kmip(self, kmip_spec: dict):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        kmip_spec.pop("uuid", None)

        json_spec = kmip_spec

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/add_server"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def delete_kmip(self, kmip_spec: dict):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = {}
        json_spec["name"] = kmip_spec.get("name", "")

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/delete_server"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def promote_kmip(self, kmip_spec: dict):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = {}
        json_spec["name"] = kmip_spec.get("name", "")

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/promote_server"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def get_kmip(self, kmip_spec: dict):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = {}
        json_spec["name"] = kmip_spec.get("name", "")

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/get_server"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def update_kmip(self, kmip_spec: dict):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name

        json_spec = kmip_spec

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(region=region, cluster_name=cluster_name)
        url = f"{mapi_full_url}/mapi/v1/kmip/update_server"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )
