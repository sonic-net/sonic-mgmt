#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import traceback
from urllib.parse import urlparse

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

from ansible_collections.community.okd.plugins.module_utils.openshift_docker_image import (
    parse_docker_image_ref,
)

try:
    from requests import request
    from requests.auth import HTTPBasicAuth

    HAS_REQUESTS_MODULE = True
    requests_import_exception = None
except ImportError as e:
    HAS_REQUESTS_MODULE = False
    requests_import_exception = e
    REQUESTS_MODULE_ERROR = traceback.format_exc()


class OpenShiftRegistry(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenShiftRegistry, self).__init__(**kwargs)
        self.check = self.params.get("check")

    def list_image_streams(self, namespace=None):
        kind = "ImageStream"
        api_version = "image.openshift.io/v1"

        params = dict(kind=kind, api_version=api_version, namespace=namespace)
        result = self.kubernetes_facts(**params)
        imagestream = []
        if len(result["resources"]) > 0:
            imagestream = result["resources"]
        return imagestream

    def find_registry_info(self):
        def _determine_registry(image_stream):
            public, internal = None, None
            docker_repo = image_stream["status"].get("publicDockerImageRepository")
            if docker_repo:
                ref, err = parse_docker_image_ref(docker_repo, self.module)
                public = ref["hostname"]

            docker_repo = image_stream["status"].get("dockerImageRepository")
            if docker_repo:
                ref, err = parse_docker_image_ref(docker_repo, self.module)
                internal = ref["hostname"]
            return internal, public

        # Try to determine registry hosts from Image Stream from 'openshift' namespace
        for stream in self.list_image_streams(namespace="openshift"):
            internal, public = _determine_registry(stream)
            if not public and not internal:
                self.fail_json(msg="The integrated registry has not been configured")
            return internal, public

        # Unable to determine registry from 'openshift' namespace, trying with all namespace
        for stream in self.list_image_streams():
            internal, public = _determine_registry(stream)
            if not public and not internal:
                self.fail_json(msg="The integrated registry has not been configured")
            return internal, public

        self.fail_json(
            msg="No Image Streams could be located to retrieve registry info."
        )

    def execute_module(self):
        result = {}
        (
            result["internal_hostname"],
            result["public_hostname"],
        ) = self.find_registry_info()

        if self.check:
            public_registry = result["public_hostname"]
            if not public_registry:
                result["check"] = dict(
                    reached=False, msg="Registry does not have a public hostname."
                )
            else:
                headers = {"Content-Type": "application/json"}
                params = {"method": "GET", "verify": False}
                if self.client.configuration.api_key:
                    headers.update(self.client.configuration.api_key)
                elif (
                    self.client.configuration.username
                    and self.client.configuration.password
                ):
                    if not HAS_REQUESTS_MODULE:
                        result["check"] = dict(
                            reached=False,
                            msg="The requests python package is missing, try `pip install requests`",
                            error=requests_import_exception,
                        )
                        self.exit_json(**result)
                    params.update(
                        dict(
                            auth=HTTPBasicAuth(
                                self.client.configuration.username,
                                self.client.configuration.password,
                            )
                        )
                    )

                # verify ssl
                host = urlparse(public_registry)
                if len(host.scheme) == 0:
                    registry_url = "https://" + public_registry

                if (
                    registry_url.startswith("https://")
                    and self.client.configuration.ssl_ca_cert
                ):
                    params.update(dict(verify=self.client.configuration.ssl_ca_cert))
                params.update(dict(headers=headers))
                last_bad_status, last_bad_reason = None, None
                for path in ("/", "/healthz"):
                    params.update(dict(url=registry_url + path))
                    response = request(**params)
                    if response.status_code == 200:
                        result["check"] = dict(
                            reached=True,
                            msg="The local client can contact the integrated registry.",
                        )
                        self.exit_json(**result)
                    last_bad_reason = response.reason
                    last_bad_status = response.status_code

                result["check"] = dict(
                    reached=False,
                    msg="Unable to contact the integrated registry using local client. Status=%d, Reason=%s"
                    % (last_bad_status, last_bad_reason),
                )

        self.exit_json(**result)
