from .gateway_oo import (
    OOGateway
)
from ..common.hv_log import (
    Log
)
from ..common.ansible_common_constants import (
    MAPI_FULL_URL_TEMPLATE_HTTPS,
    DEFAULT_JOBS_PAGE_SIZE
)


class JobsResource:
    def __init__(self, param, token):
        self.param = param
        self.token = token

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
        if "bucket_name" in self.param.json_spec:
            json_spec = {
                "bucketName": self.param.json_spec["bucket_name"]
            }

        user_id = self.param.json_spec.get("user_id", None)
        if user_id is not None:
            json_spec["userId"] = {
                "id": user_id,
            }

        page_size = self.param.json_spec.get("page_size", None)
        page_size_set = False
        if page_size is not None:
            page_size_set = True
            json_spec["pageSize"] = page_size

        json_spec["pageSize"] = self.param.json_spec.get(
            "page_size", DEFAULT_JOBS_PAGE_SIZE)

        if json_spec["pageSize"] is None:
            json_spec["pageSize"] = DEFAULT_JOBS_PAGE_SIZE

        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/jobs/list"

        jobs = {}
        jobs.get("jobs", [])

        if page_size_set:
            logger.writeDebug("page_size is set to {}".format(page_size))
            return gateway.http_pd(
                "POST", self.param.connection_info, url, self.token, data=json_spec)

        loop = True
        while loop:
            jobs_list = jobs.get(
                "jobs", [])
            response = gateway.http_pd(
                "POST",
                self.param.connection_info,
                url,
                self.token,
                data=json_spec)
            if page_size is None:
                loop = False
                jobs_list += response.get(
                    "jobs", [])
                jobs["jobs"] = jobs_list
                break
            if response.get("page_token", None) is not None:
                jobs_list += response.get(
                    "jobs", [])
                jobs["jobs"] = jobs_list
                json_spec["pageToken"] = response["page_token"]
                continue
            else:
                loop = False
                jobs_list += response.get(
                    "jobs", [])
                jobs["jobs"] = jobs_list
                break
        return jobs

    def query_status(self):
        logger = Log()
        gateway = OOGateway()

        logger.writeDebug("param: {}".format(self.param.connection_info))
        logger.writeDebug("param: {}".format(
            self.param.connection_info.cluster_name))
        logger.writeDebug("param: {}".format(
            self.param.json_spec))

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        json_spec = {"jobId": {"id": self.param.json_spec["job_id"]}}
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/jobs/status"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )

    def query_status_by_id(self, id):
        logger = Log()
        gateway = OOGateway()

        region = self.param.connection_info.region
        cluster_name = self.param.connection_info.cluster_name
        json_spec = {"jobId": {"id": id}}
        logger.writeDebug("json_spec query_status_by_id: {}".format(json_spec))
        mapi_full_url = MAPI_FULL_URL_TEMPLATE_HTTPS.format(
            region=region, cluster_name=cluster_name)

        url = f"{mapi_full_url}/mapi/v1/jobs/status"
        return gateway.http_pd(
            "POST", self.param.connection_info, url, self.token, data=json_spec
        )
