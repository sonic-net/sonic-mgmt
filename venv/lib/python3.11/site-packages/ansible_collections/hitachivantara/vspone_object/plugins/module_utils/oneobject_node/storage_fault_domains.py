from .gateway_oo import (
    OOGateway
)
from ..common.hv_log import (
    Log
)
from ..common.ansible_common_constants import (
    MAPI_FULL_URL_TEMPLATE_HTTPS,
    DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE
)
from ..common.hv_constants import (
    Http as HttpConstants,
)
from .common_msg_catalog import (
    CommonMsgCatalog as CMCA
)
from .storage_fault_domain_msg_catalog import (
    StorageFaultDomainMsgCatalog as SFDMC
)


class StorageFaultDomainResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

    def query_one(self):
        logger = Log()

        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(
            self.param.json_spec))

        # return True
        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        json_spec = self.param.json_spec
        # mapi_full_url = f"https://admin.{region}.{cluster_name}"
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_fault_domain/info"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

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
        json_spec = {}
        json_spec["pageSize"] = self.param.json_spec.get(
            "pageSize", DEFAULT_STORAGE_FAULT_DOMAIN_PAGE_SIZE)
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/storage_fault_domain/list?pageSize="
        pageSize = str(json_spec["pageSize"])
        url += pageSize

        storage_fault_domains = {}
        storage_fault_domains.get("storageFaultDomains", [])

        loop = True
        while loop:
            storage_fault_domain_list = storage_fault_domains.get(
                "storage_fault_domains", [])
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_spec)
            if response.get("page_token", None) is not None:
                storage_fault_domain_list += response.get(
                    "storage_fault_domains", [])
                storage_fault_domains["storage_fault_domains"] = storage_fault_domain_list
                json_spec["pageToken"] = response["page_token"]
                continue
            else:
                loop = False
                storage_fault_domain_list += response.get(
                    "storage_fault_domains", [])
                storage_fault_domains["storage_fault_domains"] = storage_fault_domain_list
                break
        return storage_fault_domains

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

        url = f"{mapi_full_url}/mapi/v1/storage_fault_domain/list?pageSize="
        url += str(json_spec["pageSize"])
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def create(self):
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

        url = f"{mapi_full_url}/mapi/v1/storage_fault_domain/create"

        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def update(self):
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

        url = f"{mapi_full_url}/mapi/v1/storage_fault_domain/update"

        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def handle_error(self, err, query_one=False):
        logger = Log()
        err_str = str(err)
        logger.writeDebug(err_str)
        id = self.param.json_spec.get("id", "")

        if str(HttpConstants.ERR_400) in err_str:
            err_msg = SFDMC.ERR_INVALID_ID_VALUE.value.format(
                id) if query_one else err_str
            return err_msg

        if str(HttpConstants.ERR_404) in err_str:
            err_msg = SFDMC.ERR_ID_NOT_FOUND.value.format(
                id) if query_one else err_str
            return err_msg

        return CMCA.HTTP_500_ERR.value
