from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
import json
import time
import urllib.error as urllib_error
from ansible.module_utils.urls import socket

import os
import mimetypes

try:
    from ..common.ansible_common import mask_token
    from ..common.hv_api_constants import API
    from ..common.hv_log import Log
    from ..common.vsp_constants import Endpoints
    from .ansible_url import open_url
    from .vsp_session_manager import SessionManager
    from ..model.common_base_models import ConnectionInfo
except ImportError:
    from common.ansible_common import mask_token
    from common.hv_api_constants import API
    from common.hv_log import Log
    from common.vsp_constants import Endpoints
    from .ansible_url import open_url
    from .vsp_session_manager import SessionManager
    from model.common_base_models import ConnectionInfo

logger = Log()


class SessionObject:
    def __init__(self, session_id, token):
        self.session_id = session_id
        self.token = token
        self.create_time = time.time()
        self.expiry_time = self.create_time + 99999999


class ConnectionManager(ABC):
    retryCount = 0
    server_busy_msg = "The server might be temporarily busy"

    def __init__(self, address, username=None, password=None, token=None):
        self.address = address
        self.username = username
        self.password = password
        self.token = token
        self.base_url = None

        if not self.base_url:
            self.base_url = self.form_base_url()

    @abstractmethod
    def form_base_url(self) -> str:
        return ""

    def getAuthToken(self) -> dict[str, str]:
        return {}

    def get_job(self, job_id) -> dict:
        """get job method"""
        return {}

    def _process_job_till_running_state(self, job_id):
        pass

    def _load_response(self, response, download=False):
        """returns dict if json, native string otherwise"""
        # logger.writeException("response = {}", response)
        if not download:
            try:
                text = response.read().decode("utf-8")
                if "token" not in text:
                    if "jobId" in text:
                        logger.writeDebug("Job response: {}", text)
                    else:
                        logger.writeDebug(f"{text[:5000]} ...")
                msg = {}
                raw_message = json.loads(text)
                if not len(raw_message):
                    if raw_message.get("errorSource"):
                        msg[API.CAUSE] = raw_message[API.CAUSE]
                        msg[API.SOLUTION] = raw_message[API.SOLUTION]
                        return msg
                return raw_message
            except Exception as e:
                logger.writeException("Exception = {}", e)
                text = response.read()
                return text
        else:
            return response.read()

    def _make_request(
        self, method, end_point, data=None, headers_input=None, download=False
    ):

        url = self.base_url + "/" + end_point
        logger.writeDebug("url = {}", url)

        if download:
            headers = {
                "Content-Length": 0,
            }
        elif headers_input and headers_input.get("Content-Length") == 0:
            headers = {
                "Content-Length": 0,
            }
        else:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }

            if headers_input is not None:
                headers.update(headers_input)

        if data is not None and headers.get("Content-Type") == "application/json":
            data = json.dumps(data)
            x = url.endswith("chap-users") or url.endswith("password")
            if not x:
                logger.writeDebug("data = {}", data)

        logger.writeDebug("method = {} URL ={}", method, url)
        logger.writeDebug("headers_input = {}", headers)

        MAX_TIME_OUT = 300

        try:
            response = open_url(
                url=url,
                method=method,
                headers=headers,
                data=data,
                use_proxy=False,
                timeout=MAX_TIME_OUT,
                url_username=self.username,
                url_password=self.password,
                force_basic_auth=True,
                validate_certs=False,
            )
        except socket.timeout as t_err:
            logger.writeError(f"ConnectionManager._make_request - TimeoutError {t_err}")
            raise Exception(t_err)
        except urllib_error.HTTPError as err:
            logger.writeError(f"ConnectionManager._make_request - HTTPError {err}")

            if err.code == 503:
                # 503 Service Unavailable
                # wait for 5 mins and try to re-authenticate, we will retry 5 times
                if self.retryCount < 5:
                    logger.writeDebug(
                        f"{self.server_busy_msg}, wait for 5 mins and try to generate session token again."
                    )
                    time.sleep(300)
                    self.retryCount += 1
                    return self._make_request(method, end_point, data)

            if hasattr(err, "read"):
                error_resp = json.loads(err.read().decode())
                logger.writeDebug(
                    f"ConnectionManager.error_resp - error_resp {error_resp}"
                )
                error_dtls = (
                    error_resp.get("message")
                    if error_resp.get("message")
                    else error_resp.get("errorMessage")
                )
                if error_resp.get("cause"):
                    error_dtls = error_dtls + " " + error_resp.get("cause")

                if error_resp.get("solution"):
                    error_dtls = error_dtls + " " + error_resp.get("solution")

                raise Exception(error_dtls)
            # if err.code == 400:
            #     error_resp = json.loads(err.read().decode())
            #     logger.writeDebug(
            #         f"ConnectionManager.error_resp - error_resp {error_resp}"
            #     )
            #     raise Exception(error_resp)
            else:
                raise Exception(err)
        except Exception as err:
            logger.writeException(err)
            logger.writeDebug("Failed err: {}", err)
            raise err

        if response.status not in (200, 201, 202, 204):
            error_msg = json.loads(response.read())
            logger.writeError("error_msg = {}", error_msg)
            # raise Exception(error_msg, response.status)
            raise Exception(error_msg)

        # logger.writeDebug(f"response = {response}")
        if response.status == 204:
            return response.read()
        return self._load_response(response, download)

    def create(self, endpoint, data):
        return self._make_request(method="POST", end_point=endpoint, data=data)

    def _process_job(self, job_id):
        response = None
        retryCount = 0
        while response is None and retryCount < 600:
            job_response = self.get_job(job_id)
            logger.writeDebug("_process_job: job_response = {}", job_response)
            job_status = job_response[API.STATUS]
            job_state = job_response[API.STATE]
            response = None
            if job_status == API.COMPLETED:
                if job_state == API.SUCCEEDED:
                    # For POST call to add chap user to port, affected resource is empty
                    # For PATCH port-auth-settings, affected resource is empty
                    if (
                        job_response[API.AFFECTED_RESOURCES]
                        and len(job_response[API.AFFECTED_RESOURCES]) > 0
                    ):
                        response = job_response[API.AFFECTED_RESOURCES][0]
                    else:
                        response = job_response["self"]
                else:
                    raise Exception(self.job_exception_text(job_response))
            else:
                retryCount = retryCount + 1
                time.sleep(retryCount * 1)

        if response is None:
            raise Exception(
                "Timeout Error! The tasks was not completed in 3005 minutes"
            )

        resourceId = response.split("/")[-1]
        logger.writeDebug("response = {}", response)
        logger.writeDebug("resourceId = {}", resourceId)
        return resourceId

    def post(self, endpoint, data, headers_input=None, long_running=None):

        post_response = self._make_request(
            method="POST", end_point=endpoint, data=data, headers_input=headers_input
        )
        logger.writeDebug("post_response = {}", post_response)
        if API.JOB_ID not in post_response:
            return post_response
        job_id = post_response[API.JOB_ID]
        if long_running is None or long_running is False:
            return self._process_job(job_id)
        else:
            return self._process_job_till_running_state(job_id)

    def post_wo_job(self, endpoint, data, headers_input=None):

        post_response = self._make_request(
            method="POST", end_point=endpoint, data=data, headers_input=headers_input
        )
        logger.writeDebug("post_response = {}", post_response)
        return post_response

    def patch(self, endpoint, data):
        patch_response = self._make_request(
            method="PATCH", end_point=endpoint, data=data
        )
        logger.writeDebug("patch_response = {}", patch_response)
        if API.JOB_ID not in patch_response:
            return patch_response
        job_id = patch_response[API.JOB_ID]
        return self._process_job(job_id)

    def job_exception_text(self, job_response):

        keys = job_response[API.ERROR].keys()
        logger.writeDebug("job_response_error_keys= {}", keys)
        result_text = ""
        if API.MESSAGE_ID in keys:
            result_text += job_response[API.ERROR][API.MESSAGE_ID] + " "
        if API.MESSAGE in keys:
            result_text += job_response[API.ERROR][API.MESSAGE] + " "
        if API.CAUSE in keys:
            result_text += job_response[API.ERROR][API.CAUSE] + " "
        if API.SOLUTION in keys:
            result_text += job_response[API.ERROR][API.SOLUTION] + " "
        if API.SOLUTION_TYPE in keys:
            result_text += job_response[API.ERROR][API.SOLUTION_TYPE] + " "
        if API.ERROR_CODE in keys:
            error_value = job_response[API.ERROR][API.ERROR_CODE]
            result_text += " " + "errorCode : " + str(error_value) + " "
        if API.DETAIL_CODE in keys:
            result_text += (
                "detailCode : " + job_response[API.ERROR][API.DETAIL_CODE] + " "
            )

        return result_text

    def read(self, endpoint):
        return self._make_request("GET", endpoint)

    def get(self, endpoint):
        return self._make_request("GET", endpoint)

    def update(self, endpoint, data):
        put_response = self._make_request(method="PUT", end_point=endpoint, data=data)
        job_id = put_response[API.JOB_ID]
        return self._process_job(job_id)

    def delete(self, endpoint, data=None):
        delete_response = self._make_request(
            method="DELETE", end_point=endpoint, data=data
        )
        logger.writeDebug(f"delete_response = {delete_response}")
        if delete_response == b"":
            return True
        job_id = delete_response[API.JOB_ID]
        return self._process_job(job_id)


class SDSBConnectionManager(ConnectionManager):
    boundary = "----AnsibleFormBoundary7MA4YWxkTrZu0gW"

    def form_base_url(self):
        return f"https://{self.address}/ConfigurationManager/simple"

    def get_job(self, job_id):
        end_point = "v1/objects/jobs/" + job_id
        return self._make_request("GET", end_point)

    def download_file(self, endpoint):
        return self._make_request("GET", endpoint, download=True)

    def _process_job_till_running_state(self, job_id):
        retry_count = 0

        time.sleep(5)
        while retry_count < 600:
            job_response = self.get_job(job_id)
            logger.writeDebug(
                "_process_job_till_running_state: job_response = {}", job_response
            )
            job_status = job_response[API.STATUS]
            job_state = job_response[API.STATE]

            if job_status == API.RUNNING and job_state == API.STARTED:
                return job_id
            elif job_status == API.COMPLETED and job_state == API.FAILED:
                raise ValueError(
                    self.job_exception_text(job_response) + f" job_id : {job_id}"
                )
            else:
                retry_count = retry_count + 1
                time.sleep(1)

    def build_multipart_form_data(
        self,
        setup_user_password=None,
        csv_path=None,
        exported_config_file=None,
        vm_configuration_file_s3_uri=None,
    ):
        boundary = self.boundary.encode("utf-8")
        body = bytearray()

        def add_field(name, value):
            body.extend(b"--" + boundary + b"\r\n")
            body.extend(
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8")
            )
            body.extend(value.encode("utf-8") if isinstance(value, str) else value)
            body.extend(b"\r\n")

        def add_file_field(field_name, file_path, file_content):
            filename = os.path.basename(file_path)
            content_type = (
                mimetypes.guess_type(filename)[0] or "application/octet-stream"
            )
            body.extend(b"--" + boundary + b"\r\n")
            body.extend(
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode(
                    "utf-8"
                )
            )
            body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
            body.extend(file_content)
            body.extend(b"\r\n")

        # Add text field
        if setup_user_password:
            add_field("setupUserPassword", setup_user_password)

        if vm_configuration_file_s3_uri:
            add_field("vmConfigurationFileS3Uri", vm_configuration_file_s3_uri)

        # Add files
        if csv_path:
            with open(csv_path, "rb") as f:
                add_file_field("configurationFile", csv_path, f.read())

        if exported_config_file:
            with open(exported_config_file, "rb") as f2:
                add_file_field(
                    "exportedConfigurationFile", exported_config_file, f2.read()
                )

        # Final boundary
        body.extend(b"--" + boundary + b"--\r\n")

        return bytes(body)

    def upload_file(
        self, end_point, file_to_upload, file_parameter_name, monitor_job=False
    ):
        response = self.upload_software_update_file(
            end_point, file_to_upload, file_parameter_name
        )
        if response:
            decoded = response.decode("utf-8")
            data = json.loads(decoded)
            job_id = data.get("jobId")
            if monitor_job:
                self._process_job(job_id)
            return job_id

    def upload_software_update_file(
        self, end_point, software_update_file, file_parameter_name=None
    ):
        import os
        import mimetypes
        import http.client
        import ssl
        from urllib.parse import urlparse

        try:
            url = urlparse(self.base_url + "/" + end_point)
            logger.writeDebug(
                "Uploading software update file to URL = {}", url.geturl()
            )

            boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
            filename = os.path.basename(software_update_file)
            content_type = (
                mimetypes.guess_type(filename)[0] or "application/octet-stream"
            )
            if file_parameter_name is None:
                file_parameter_name = "softwareUpdateFile"

            # Build multipart preamble and closing
            preamble = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{file_parameter_name}"; filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            ).encode("utf-8")
            closing = f"\r\n--{boundary}--\r\n".encode("utf-8")

            file_size = os.path.getsize(software_update_file)
            total_length = len(preamble) + file_size + len(closing)

            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(total_length),
            }

            # Pick connection type
            if url.scheme == "https":
                context = ssl._create_unverified_context()  # nosec
                # ignores cert validation like open_url(validate_certs=False)
                conn = http.client.HTTPSConnection(
                    url.hostname, url.port or 443, context=context, timeout=3000
                )
            else:
                conn = http.client.HTTPConnection(
                    url.hostname, url.port or 80, timeout=3000
                )

            # Send request headers
            conn.putrequest("POST", url.path or "/")
            for k, v in headers.items():
                conn.putheader(k, v)
            if self.username and self.password:
                import base64

                creds = f"{self.username}:{self.password}".encode("utf-8")
                auth_header = "Basic " + base64.b64encode(creds).decode("utf-8")
                conn.putheader("Authorization", auth_header)
            conn.endheaders()

            # Send preamble
            conn.send(preamble)

            # Send file in chunks
            with open(software_update_file, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    conn.send(chunk)

            # Send closing
            conn.send(closing)

            # Get response
            response = conn.getresponse()
            resp_body = response.read()
            logger.writeDebug(
                "upload_software_update_file response: status={}, body={}",
                response.status,
                resp_body,
            )

            if response.status not in (200, 201, 202, 204):
                raise Exception(
                    f"Failed upload: status={response.status}, body={resp_body}"
                )

            return resp_body

        except Exception as err:
            logger.writeException(err)
            raise err
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def put(self, endpoint, data):
        put_response = self._make_request(method="PUT", end_point=endpoint, data=data)
        logger.writeDebug("put_response = {}", put_response)
        if API.JOB_ID not in put_response:
            return put_response
        job_id = put_response[API.JOB_ID]
        return self._process_job(job_id)

    def add_storage_node(
        self,
        end_point,
        setup_user_password=None,
        config_file=None,
        exported_config_file=None,
        vm_configuration_file_s3_uri=None,
    ):

        # Encode form data
        body = self.build_multipart_form_data(
            setup_user_password,
            config_file,
            exported_config_file,
            vm_configuration_file_s3_uri,
        )

        # Headers
        headers = {
            "Content-Type": f"multipart/form-data; boundary={self.boundary}",
            "Expect": "",  # To suppress the "Expect: 100-continue"
        }
        try:
            resp = self._make_request_for_file(
                method="POST", end_point=end_point, data=body, headers_input=headers
            )
            logger.writeDebug(f"resp: {resp}")
            job_id = resp[API.JOB_ID]
            return self._process_job_till_running_state(job_id)
        except Exception as err:
            logger.writeException(err)
            raise err

    def remove_storage_node(self, endpoint, data=None):
        delete_response = self._make_request(
            method="DELETE", end_point=endpoint, data=data
        )
        job_id = delete_response[API.JOB_ID]
        return self._process_job_till_running_state(job_id)

    def _make_request_for_file(
        self, method, end_point, data=None, headers_input=None, download=False
    ):

        url = self.base_url + "/" + end_point
        logger.writeDebug("url = {}", url)

        # headers = {
        #     "Accept": "application/json",
        #     "Content-Type": "application/json",
        # }

        headers = {}
        if headers_input is not None:
            headers.update(headers_input)

        logger.writeDebug("method = {}", method)
        logger.writeDebug("headers = {}", headers)

        MAX_TIME_OUT = 3000

        try:
            response = open_url(
                url=url,
                method=method,
                headers=headers,
                data=data,
                use_proxy=False,
                timeout=MAX_TIME_OUT,
                url_username=self.username,
                url_password=self.password,
                force_basic_auth=True,
                validate_certs=False,
            )
        except socket.timeout as t_err:
            logger.writeError(f"ConnectionManager._make_request - TimeoutError {t_err}")
            raise Exception(t_err)
        except urllib_error.HTTPError as err:
            logger.writeError(f"ConnectionManager._make_request - HTTPError {err}")

            if err.code == 503:
                # 503 Service Unavailable
                # wait for 5 mins and try to re-authenticate, we will retry 5 times
                if self.retryCount < 5:
                    logger.writeDebug(
                        f"{self.server_busy_msg}, wait for 5 mins and try to generate session token again."
                    )
                    time.sleep(300)
                    self.retryCount += 1
                    return self._make_request_for_file(
                        method, end_point, data, headers, download
                    )
                else:
                    if hasattr(err, "read"):
                        error_resp = json.loads(err.read().decode())
                        logger.writeDebug(
                            f"ConnectionManager.error_resp - error_resp {error_resp}"
                        )
                        error_dtls = (
                            error_resp.get("message")
                            if error_resp.get("message")
                            else error_resp.get("errorMessage")
                        )
                        if error_resp.get("cause"):
                            error_dtls = error_dtls + " " + error_resp.get("cause")

                        if error_resp.get("solution"):
                            error_dtls = error_dtls + " " + error_resp.get("solution")

                        raise Exception(error_dtls)
            raise Exception(err)
        except Exception as err:
            logger.writeException(err)
            raise err

        if response.status not in (200, 201, 202, 204):
            error_msg = json.loads(response.read())
            logger.writeError("error_msg = {}", error_msg)
            # raise Exception(error_msg, response.status)
            raise Exception(error_msg)

        logger.writeDebug(f"response = {response}")
        return self._load_response(response, download)


class VSPConnectionManager(ConnectionManager):
    session = None
    retryCount = 0
    session_expired_msg = "The specified token is invalid"

    session_manager = SessionManager()

    def getAuthToken(self, retry=False):
        logger.writeDebug("Entering VSPConnectionManager.getAuthToken")
        if self.token is not None and (self.username is None or self.password is None):
            return {"Authorization": f"Session {self.token}"}
        connection_info = ConnectionInfo(
            address=self.address, username=self.username, password=self.password
        )
        if not retry:
            self.token = self.session_manager.get_current_session(connection_info)
        else:
            self.token = self.session_manager.renew_session(connection_info)
        headers = {"Authorization": "Session {0}".format(self.token)}
        return headers

    def get_lock_session_token(self):
        end_point = Endpoints.SESSIONS
        try:
            response = self._make_request(method="POST", end_point=end_point, data=None)

        except Exception as e:
            # can be due to wrong address or kong is not ready
            logger.writeException(e)
            err_msg = (
                "Failed to establish a connection, please check the Management System address or the credentials."
                + str(e)
            )
            raise Exception(err_msg)

        session_id = response.get(API.SESSION_ID)
        token = response.get(API.TOKEN)
        logger.writeDebug(
            "get_lock_session_token session id = {} token = {}",
            session_id,
            mask_token(token),
        )
        return session_id, token

    def form_base_url(self):
        return f"https://{self.address}/ConfigurationManager"

    def get_job(self, job_id):
        end_point = "v1/objects/jobs/{}".format(job_id)
        return self._make_vsp_request("GET", end_point)

    def create(self, endpoint, data, token=None):
        return self._make_vsp_request(
            method="POST", end_point=endpoint, data=data, token=token
        )

    def read(self, endpoint, headers_input=None, token=None):
        return self._make_vsp_request(
            "GET", endpoint, headers_input=headers_input, token=token
        )

    def update(self, endpoint, data, headers_input=None, token=None):
        put_response = self._make_vsp_request(
            method="PUT",
            end_point=endpoint,
            data=data,
            headers_input=headers_input,
            token=token,
        )
        job_id = put_response[API.JOB_ID]
        return self._process_job(job_id)

    def get(self, endpoint, headers_input=None, token=None):
        return self._make_vsp_request(
            "GET", endpoint, data=None, headers_input=headers_input, token=token
        )

    def get_with_headers(self, end_point, headers_input=None):
        return self._make_vsp_request("GET", end_point, None, headers_input)

    def delete_with_headers(self, end_point, headers=None):
        response = self._make_vsp_request("DELETE", end_point, None, headers)
        job_id = response[API.JOB_ID]
        return self._process_job(job_id)

    def pegasus_get(self, endpoint):
        return self._make_vsp_request("GET", endpoint)

    def pegasus_post(self, endpoint, data):
        post_response = self._make_vsp_request("POST", endpoint, data)
        if isinstance(post_response, list):
            post_response = post_response[0]
        job_id = post_response.get("statusResource").split("/")[-1]
        return self._process_pegasus_job(job_id)

    def pegasus_post_multi_resource(self, endpoint, data):
        post_response = self._make_vsp_request("POST", endpoint, data)
        affected_resources = []
        if isinstance(post_response, list):
            for response in post_response:
                job_id = response.get("statusResource").split("/")[-1]
                job_res = self._process_pegasus_job(job_id)
                affected_resources.append(job_res.split("/")[-1])
            return affected_resources
        else:
            job_id = response.get("statusResource").split("/")[-1]
            return self._process_pegasus_job(job_id)

    def pegasus_post_multi_jobs(self, endpoint, data):
        post_response = self._make_vsp_request("POST", endpoint, data)
        affected_resources = []
        error_responses = []
        if isinstance(post_response, list):
            for response in post_response:
                try:
                    job_id = response.get("statusResource").split("/")[-1]
                    job_res = self._process_pegasus_job(job_id)
                    affected_resources.append(job_res.split("/")[-1])
                except Exception as e:
                    logger.writeError(f"Failed to process job: {e}")
                    error_responses.append(str(e))

            return affected_resources, error_responses
        else:
            job_id = response.get("statusResource").split("/")[-1]
            return self._process_pegasus_job(job_id), error_responses

    def pegasus_patch(self, endpoint, data):
        patch_response = self._make_vsp_request("PATCH", endpoint, data)

        if patch_response.get("statusResource") is None:
            return patch_response
        job_id = patch_response.get("statusResource").split("/")[-1]
        return self._process_pegasus_job(job_id)

    def pegasus_delete(self, endpoint, data):
        delete_response = self._make_vsp_request("DELETE", endpoint, data)

        job_id = delete_response.get("statusResource").split("/")[-1]
        return self._process_pegasus_job(job_id)

    def pegasus_post_header(self, endpoint, data, headers_input):
        post_response = self._make_vsp_request("POST", endpoint, data, headers_input)

        job_id = post_response.get("statusResource").split("/")[-1]
        return self._process_pegasus_job(job_id)

    def _process_pegasus_job(self, job_id):
        response = None
        retryCount = 0
        while response is None and retryCount < 60:
            job_response = self.get_pegasus_job(job_id)
            job_status = job_response.get(API.STATUS)
            job_progress = job_response.get(API.PEGASUS_PROGRESS)
            logger.writeDebug("patch: job_response = {}", job_response)
            response = None
            if job_progress == API.PEGASUS_COMPLETED:
                if job_status == API.PEGASUS_NORMAL:
                    # For PATCH port-auth-settings, affected resource is empty
                    response = job_response.get(API.AFFECTED_RESOURCES)[0]
                else:
                    raise Exception(job_response.get(API.ERROR_MESSAGE))
            else:
                retryCount = retryCount + 1
                time.sleep(10)

        if response is None:
            raise Exception("Timeout Error! The tasks was not completed in 10 minutes")

        resourceId = response.split("/")[-1]
        logger.writeDebug("response = {}", response)
        logger.writeDebug("resourceId = {}", resourceId)
        return resourceId

    def get_pegasus_job(self, job_id):
        url = Endpoints.PEGASUS_JOB
        return self._make_vsp_request("GET", url.format(job_id))

    def delete(self, endpoint, data=None, headers_input=None, token=None):
        delete_response = self._make_vsp_request(
            method="DELETE",
            end_point=endpoint,
            data=data,
            headers_input=headers_input,
            token=token,
        )
        job_id = delete_response[API.JOB_ID]
        return self._process_job(job_id)

    def post(
        self,
        endpoint,
        data,
        headers_input=None,
        long_running=None,
        token=None,
        timeout=None,
    ):

        post_response = self._make_vsp_request(
            method="POST",
            end_point=endpoint,
            data=data,
            headers_input=headers_input,
            token=token,
            timeout=timeout,
        )
        logger.writeDebug("post_response = {}", post_response)
        job_id = post_response[API.JOB_ID]
        if long_running is None or long_running is False:
            return self._process_job(job_id)
        else:
            return self._process_job_till_running_state(job_id)

    def post_without_job(
        self, endpoint, data, headers_input=None, token=None, timeout=None
    ):

        post_response = self._make_vsp_request(
            method="POST",
            end_point=endpoint,
            data=data,
            headers_input=headers_input,
            token=token,
            timeout=timeout,
        )
        logger.writeDebug("post_response = {}", post_response)
        return post_response

    def post_wo_job(self, endpoint, data=None, headers_input=None, timeout=None):
        post_response = self._make_vsp_request(
            method="POST",
            end_point=endpoint,
            data=data,
            headers_input=headers_input,
            timeout=timeout,
        )
        logger.writeDebug("post_response = {}", post_response)
        return post_response

    def patch(self, endpoint, data):
        patch_response = self._make_vsp_request(
            method="PATCH", end_point=endpoint, data=data
        )
        job_id = patch_response[API.JOB_ID]
        return self._process_job(job_id)

    def patch_wo_job(self, endpoint, data):
        patch_response = self._make_vsp_request(
            method="PATCH", end_point=endpoint, data=data
        )
        return patch_response

    def _make_vsp_request(
        self,
        method,
        end_point,
        data=None,
        headers_input=None,
        token=None,
        retry=False,
        timeout=None,
    ):

        logger.writeDebug(
            f"VSPConnectionManager._make_vsp_request token= {mask_token(token)} self.token = {mask_token(self.token)}"
        )

        url = self.base_url + "/" + end_point
        headers = {}
        if token is None and self.token is None:
            headers = self.getAuthToken(retry)
        else:
            if token:
                headers = {"Authorization": "Session {0}".format(token)}
            elif self.token:
                headers = {"Authorization": "Session {0}".format(self.token)}

        headers["Content-Type"] = (
            "application/json"
            if headers_input is None or headers_input.get("Content-Type") is None
            else headers_input.get("Content-Type")
        )
        if headers_input is not None:
            headers.update(headers_input)

        logger.writeDebug("method = {} URL = {}", method, url)
        # logger.writeDebug("headers = {}", headers)

        if timeout:
            TIME_OUT = timeout
            logger.writeDebug(
                f"VSPConnectionManager._make_vsp_request TIME_OUT= {TIME_OUT}"
            )
        else:
            TIME_OUT = 300

        if (
            data is not None
            and retry is False
            and headers.get("Content-Type") == "application/json"
        ):
            data = json.dumps(data)
            logger.writeDebug("data = {}", data)
        try:

            response = open_url(
                url=url,
                method=method,
                headers=headers,
                data=data,
                use_proxy=False,
                url_username=None,
                url_password=None,
                force_basic_auth=False,
                validate_certs=False,
                timeout=TIME_OUT,
            )
        except socket.timeout as t_err:
            logger.writeError(str(t_err))
            raise Exception(t_err)
        except urllib_error.HTTPError as err:
            logger.writeError(
                f"VSPConnectionManager._make_vsp_request - HTTPError {err}"
            )
            if err.code == 503:
                # 503 Service Unavailable
                # wait for 5 mins and try to re-authenticate, we will retry 5 times
                if self.retryCount < 5:
                    logger.writeDebug(
                        f"{self.server_busy_msg}, wait for 5 mins and try to generate session token again."
                    )
                    time.sleep(300)
                    self.retryCount += 1
                    return self._make_vsp_request(
                        method, end_point, data, headers_input, token=None, retry=True
                    )
            else:
                if hasattr(err, "read"):
                    error_resp = json.loads(err.read().decode())
                    logger.writeDebug(
                        f"VSPConnectionManager.error_resp - error_resp {error_resp}"
                    )
                    error_dtls = (
                        error_resp.get("message")
                        if error_resp.get("message")
                        else error_resp.get("errorMessage")
                    )
                    if error_resp.get("cause"):
                        error_dtls = error_dtls + " " + error_resp.get("cause")

                    if error_resp.get("solution"):
                        error_dtls = error_dtls + " " + error_resp.get("solution")

                    if (
                        error_dtls
                        and self.session_expired_msg in error_dtls
                        and self.retryCount < 5
                    ):
                        logger.writeDebug(
                            "The specified token is invalid, trying to re-authenticate."
                        )
                        self.token = None
                        if self.session:
                            self.session.expiry_time = 0
                        self.retryCount += 1
                        return self._make_vsp_request(
                            method,
                            end_point,
                            data,
                            headers_input,
                            token=None,
                            retry=True,
                        )

                    else:
                        parsed_response = error_dtls if error_dtls else error_resp
                        raise Exception(parsed_response)
            raise Exception(err)
        except Exception as err:
            logger.writeException(err)
            raise err

        if response.status not in (200, 201, 202, 204):
            raise Exception(
                f"Failed to make {method} request to {url}: {response.read()}"
            )
        return self._load_response(response)

    def delete_current_session(self):
        session_id = self.session.session_id
        self.delete_session(session_id)

    def delete_session(self, session_id):
        try:
            endpoint = Endpoints.DELETE_SESSION.format(session_id)
            self.delete(endpoint)
        except Exception:
            logger.writeDebug(
                "VSPConnectionManager.delete_session - Could not discard the session."
            )
            # raise Exception("Could not discard the session.")

    # def __del__(self):
    #     logger.writeDebug("VSPConnectionManager - Destructor called.")
    #     if self.session:
    #         try:
    #            self.delete_current_session()
    #         except Exception:
    #             logger.writeDebug("VSPConnectionManager.__del__ - Could not discard the current session.")
    # raise Exception("Could not discard the current session.")

    def set_base_url_for_vsp_one_server(self):
        self.base_url = "https://{self.address}/ConfigurationManager/simple"

    def get_base_url(self):
        return self.base_url

    def set_base_url(self, url):
        self.base_url = url


# This class is added to use Administrator API for Storage Management
class AdministratorConnectionManager(VSPConnectionManager):
    def form_base_url(self):
        self.base_url = "https://{self.address}/ConfigurationManager/simple"
