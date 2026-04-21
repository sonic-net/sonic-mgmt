#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import datetime, timezone, timedelta
import copy

from ansible.module_utils._text import to_native
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils.six import iteritems

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

from ansible_collections.community.okd.plugins.module_utils.openshift_images_common import (
    OpenShiftAnalyzeImageStream,
    get_image_blobs,
    is_too_young_object,
    is_created_after,
)
from ansible_collections.community.okd.plugins.module_utils.openshift_docker_image import (
    parse_docker_image_ref,
    convert_storage_to_bytes,
)

try:
    from kubernetes import client
    from kubernetes.client import rest
    from kubernetes.dynamic.exceptions import (
        DynamicApiError,
        NotFoundError,
        ApiException,
    )
except ImportError:
    pass


ApiConfiguration = {
    "LimitRange": "v1",
    "Pod": "v1",
    "ReplicationController": "v1",
    "DaemonSet": "apps/v1",
    "Deployment": "apps/v1",
    "ReplicaSet": "apps/v1",
    "StatefulSet": "apps/v1",
    "Job": "batch/v1",
    "CronJob": "batch/v1beta1",
    "DeploymentConfig": "apps.openshift.io/v1",
    "BuildConfig": "build.openshift.io/v1",
    "Build": "build.openshift.io/v1",
    "Image": "image.openshift.io/v1",
    "ImageStream": "image.openshift.io/v1",
}


def read_object_annotation(obj, name):
    return obj["metadata"]["annotations"].get(name)


def determine_host_registry(module, images, image_streams):
    # filter managed images
    def _f_managed_images(obj):
        value = read_object_annotation(obj, "openshift.io/image.managed")
        return boolean(value) if value is not None else False

    managed_images = list(filter(_f_managed_images, images))

    # Be sure to pick up the newest managed image which should have an up to date information
    sorted_images = sorted(
        managed_images, key=lambda x: x["metadata"]["creationTimestamp"], reverse=True
    )
    docker_image_ref = ""
    if len(sorted_images) > 0:
        docker_image_ref = sorted_images[0].get("dockerImageReference", "")
    else:
        # 2nd try to get the pull spec from any image stream
        # Sorting by creation timestamp may not get us up to date info. Modification time would be much
        sorted_image_streams = sorted(
            image_streams,
            key=lambda x: x["metadata"]["creationTimestamp"],
            reverse=True,
        )
        for i_stream in sorted_image_streams:
            docker_image_ref = i_stream["status"].get("dockerImageRepository", "")
            if len(docker_image_ref) > 0:
                break

    if len(docker_image_ref) == 0:
        module.exit_json(changed=False, result="no managed image found")

    result, error = parse_docker_image_ref(docker_image_ref, module)
    return result["hostname"]


class OpenShiftAdmPruneImages(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenShiftAdmPruneImages, self).__init__(**kwargs)

        self.max_creation_timestamp = self.get_max_creation_timestamp()
        self._rest_client = None
        self.registryhost = self.params.get("registry_url")
        self.changed = False

    def list_objects(self):
        result = {}
        for kind, version in iteritems(ApiConfiguration):
            namespace = None
            if self.params.get("namespace") and kind.lower() == "imagestream":
                namespace = self.params.get("namespace")
            try:
                result[kind] = self.kubernetes_facts(
                    kind=kind, api_version=version, namespace=namespace
                ).get("resources")
            except DynamicApiError as e:
                self.fail_json(
                    msg="An error occurred while trying to list objects.",
                    reason=e.reason,
                    status=e.status,
                )
            except Exception as e:
                self.fail_json(
                    msg="An error occurred while trying to list objects.",
                    error=to_native(e),
                )
        return result

    def get_max_creation_timestamp(self):
        result = None
        if self.params.get("keep_younger_than"):
            dt_now = datetime.now(timezone.utc).replace(tzinfo=None)
            result = dt_now - timedelta(minutes=self.params.get("keep_younger_than"))
        return result

    @property
    def rest_client(self):
        if not self._rest_client:
            configuration = copy.deepcopy(self.client.configuration)
            validate_certs = self.params.get("registry_validate_certs")
            ssl_ca_cert = self.params.get("registry_ca_cert")
            if validate_certs is not None:
                configuration.verify_ssl = validate_certs
            if ssl_ca_cert is not None:
                configuration.ssl_ca_cert = ssl_ca_cert
            self._rest_client = rest.RESTClientObject(configuration)

        return self._rest_client

    def delete_from_registry(self, url):
        try:
            response = self.rest_client.DELETE(
                url=url, headers=self.client.configuration.api_key
            )
            if response.status == 404:
                # Unable to delete layer
                return None
            # non-2xx/3xx response doesn't cause an error
            if response.status < 200 or response.status >= 400:
                return None
            if response.status != 202 and response.status != 204:
                self.fail_json(
                    msg="Delete URL {0}: Unexpected status code in response: {1}".format(
                        response.status, url
                    ),
                    reason=response.reason,
                )
            return None
        except ApiException as e:
            if e.status != 404:
                self.fail_json(
                    msg="Failed to delete URL: %s" % url,
                    reason=e.reason,
                    status=e.status,
                )
        except Exception as e:
            self.fail_json(msg="Delete URL {0}: {1}".format(url, type(e)))

    def delete_layers_links(self, path, layers):
        for layer in layers:
            url = "%s/v2/%s/blobs/%s" % (self.registryhost, path, layer)
            self.changed = True
            if not self.check_mode:
                self.delete_from_registry(url=url)

    def delete_manifests(self, path, digests):
        for digest in digests:
            url = "%s/v2/%s/manifests/%s" % (self.registryhost, path, digest)
            self.changed = True
            if not self.check_mode:
                self.delete_from_registry(url=url)

    def delete_blobs(self, blobs):
        for blob in blobs:
            self.changed = True
            url = "%s/admin/blobs/%s" % (self.registryhost, blob)
            if not self.check_mode:
                self.delete_from_registry(url=url)

    def update_image_stream_status(self, definition):
        kind = definition["kind"]
        api_version = definition["apiVersion"]
        namespace = definition["metadata"]["namespace"]
        name = definition["metadata"]["name"]

        self.changed = True
        result = definition
        if not self.check_mode:
            try:
                result = self.request(
                    "PUT",
                    "/apis/{api_version}/namespaces/{namespace}/imagestreams/{name}/status".format(
                        api_version=api_version, namespace=namespace, name=name
                    ),
                    body=definition,
                    content_type="application/json",
                ).to_dict()
            except DynamicApiError as exc:
                msg = "Failed to patch object: kind={0} {1}/{2}".format(
                    kind, namespace, name
                )
                self.fail_json(msg=msg, status=exc.status, reason=exc.reason)
            except Exception as exc:
                msg = "Failed to patch object kind={0} {1}/{2} due to: {3}".format(
                    kind, namespace, name, exc
                )
                self.fail_json(msg=msg, error=to_native(exc))
        return result

    def delete_image(self, image):
        kind = "Image"
        api_version = "image.openshift.io/v1"
        resource = self.find_resource(kind=kind, api_version=api_version)
        name = image["metadata"]["name"]
        self.changed = True
        if not self.check_mode:
            try:
                delete_options = client.V1DeleteOptions(grace_period_seconds=0)
                return resource.delete(name=name, body=delete_options).to_dict()
            except NotFoundError:
                pass
            except DynamicApiError as exc:
                self.fail_json(
                    msg="Failed to delete object %s/%s due to: %s"
                    % (kind, name, exc.body),
                    reason=exc.reason,
                    status=exc.status,
                )
        else:
            existing = resource.get(name=name)
            if existing:
                existing = existing.to_dict()
            return existing

    def exceeds_limits(self, namespace, image):
        if namespace not in self.limit_range:
            return False
        docker_image_metadata = image.get("dockerImageMetadata")
        if not docker_image_metadata:
            return False
        docker_image_size = docker_image_metadata["Size"]

        for limit in self.limit_range.get(namespace):
            for item in limit["spec"]["limits"]:
                if item["type"] != "openshift.io/Image":
                    continue
                limit_max = item["max"]
                if not limit_max:
                    continue
                storage = limit_max["storage"]
                if not storage:
                    continue
                if convert_storage_to_bytes(storage) < docker_image_size:
                    # image size is larger than the permitted limit range max size
                    return True
        return False

    def prune_image_stream_tag(self, stream, tag_event_list):
        manifests_to_delete, images_to_delete = [], []
        filtered_items = []
        tag_event_items = tag_event_list["items"] or []
        prune_over_size_limit = self.params.get("prune_over_size_limit")
        stream_namespace = stream["metadata"]["namespace"]
        stream_name = stream["metadata"]["name"]
        for idx, item in enumerate(tag_event_items):
            if is_created_after(item["created"], self.max_creation_timestamp):
                filtered_items.append(item)
                continue

            if idx == 0:
                istag = "%s/%s:%s" % (
                    stream_namespace,
                    stream_name,
                    tag_event_list["tag"],
                )
                if istag in self.used_tags:
                    # keeping because tag is used
                    filtered_items.append(item)
                    continue

            if item["image"] not in self.image_mapping:
                # There are few options why the image may not be found:
                # 1. the image is deleted manually and this record is no longer valid
                # 2. the imagestream was observed before the image creation, i.e.
                #    this record was created recently and it should be protected by keep_younger_than
                continue

            image = self.image_mapping[item["image"]]
            # check prune over limit size
            if prune_over_size_limit and not self.exceeds_limits(
                stream_namespace, image
            ):
                filtered_items.append(item)
                continue

            image_ref = "%s/%s@%s" % (stream_namespace, stream_name, item["image"])
            if image_ref in self.used_images:
                # keeping because tag is used
                filtered_items.append(item)
                continue

            images_to_delete.append(item["image"])
            if self.params.get("prune_registry"):
                manifests_to_delete.append(image["metadata"]["name"])
                path = stream_namespace + "/" + stream_name
                image_blobs, err = get_image_blobs(image)
                if not err:
                    self.delete_layers_links(path, image_blobs)

        return filtered_items, manifests_to_delete, images_to_delete

    def prune_image_streams(self, stream):
        name = stream["metadata"]["namespace"] + "/" + stream["metadata"]["name"]
        if is_too_young_object(stream, self.max_creation_timestamp):
            # keeping all images because of image stream too young
            return None, []
        facts = self.kubernetes_facts(
            kind="ImageStream",
            api_version=ApiConfiguration.get("ImageStream"),
            name=stream["metadata"]["name"],
            namespace=stream["metadata"]["namespace"],
        )
        image_stream = facts.get("resources")
        if len(image_stream) != 1:
            # skipping because it does not exist anymore
            return None, []
        stream = image_stream[0]
        namespace = self.params.get("namespace")
        stream_to_update = not namespace or (
            stream["metadata"]["namespace"] == namespace
        )

        manifests_to_delete, images_to_delete = [], []
        deleted_items = False

        # Update Image stream tag
        if stream_to_update:
            tags = stream["status"].get("tags", [])
            for idx, tag_event_list in enumerate(tags):
                (
                    filtered_tag_event,
                    tag_manifests_to_delete,
                    tag_images_to_delete,
                ) = self.prune_image_stream_tag(stream, tag_event_list)
                stream["status"]["tags"][idx]["items"] = filtered_tag_event
                manifests_to_delete += tag_manifests_to_delete
                images_to_delete += tag_images_to_delete
                deleted_items = deleted_items or (len(tag_images_to_delete) > 0)

        # Deleting tags without items
        tags = []
        for tag in stream["status"].get("tags", []):
            if tag["items"] is None or len(tag["items"]) == 0:
                continue
            tags.append(tag)

        stream["status"]["tags"] = tags
        result = None
        # Update ImageStream
        if stream_to_update:
            if deleted_items:
                result = self.update_image_stream_status(stream)

            if self.params.get("prune_registry"):
                self.delete_manifests(name, manifests_to_delete)

        return result, images_to_delete

    def prune_images(self, image):
        if not self.params.get("all_images"):
            if read_object_annotation(image, "openshift.io/image.managed") != "true":
                # keeping external image because all_images is set to false
                # pruning only managed images
                return None

        if is_too_young_object(image, self.max_creation_timestamp):
            # keeping because of keep_younger_than
            return None

        # Deleting image from registry
        if self.params.get("prune_registry"):
            image_blobs, err = get_image_blobs(image)
            if err:
                self.fail_json(msg=err)
            # add blob for image name
            image_blobs.append(image["metadata"]["name"])
            self.delete_blobs(image_blobs)

        # Delete image from cluster
        return self.delete_image(image)

    def execute_module(self):
        resources = self.list_objects()
        if not self.check_mode and self.params.get("prune_registry"):
            if not self.registryhost:
                self.registryhost = determine_host_registry(
                    self.module, resources["Image"], resources["ImageStream"]
                )
            # validate that host has a scheme
            if "://" not in self.registryhost:
                self.registryhost = "https://" + self.registryhost
        # Analyze Image Streams
        analyze_ref = OpenShiftAnalyzeImageStream(
            ignore_invalid_refs=self.params.get("ignore_invalid_refs"),
            max_creation_timestamp=self.max_creation_timestamp,
            module=self.module,
        )
        self.used_tags, self.used_images, error = analyze_ref.analyze_image_stream(
            resources
        )
        if error:
            self.fail_json(msg=error)

        # Create image mapping
        self.image_mapping = {}
        for m in resources["Image"]:
            self.image_mapping[m["metadata"]["name"]] = m

        # Create limit range mapping
        self.limit_range = {}
        for limit in resources["LimitRange"]:
            namespace = limit["metadata"]["namespace"]
            if namespace not in self.limit_range:
                self.limit_range[namespace] = []
            self.limit_range[namespace].append(limit)

        # Stage 1: delete history from image streams
        updated_image_streams = []
        deleted_tags_images = []
        updated_is_mapping = {}
        for stream in resources["ImageStream"]:
            result, images_to_delete = self.prune_image_streams(stream)
            if result:
                updated_is_mapping[
                    result["metadata"]["namespace"] + "/" + result["metadata"]["name"]
                ] = result
                updated_image_streams.append(result)
            deleted_tags_images += images_to_delete

        # Create a list with images referenced on image stream
        self.referenced_images = []
        for item in self.kubernetes_facts(
            kind="ImageStream", api_version="image.openshift.io/v1"
        )["resources"]:
            name = "%s/%s" % (item["metadata"]["namespace"], item["metadata"]["name"])
            if name in updated_is_mapping:
                item = updated_is_mapping[name]
            for tag in item["status"].get("tags", []):
                self.referenced_images += [t["image"] for t in tag["items"] or []]

        # Stage 2: delete images
        images = []
        images_to_delete = [x["metadata"]["name"] for x in resources["Image"]]
        if self.params.get("namespace") is not None:
            # When namespace is defined, prune only images that were referenced by ImageStream
            # from the corresponding namespace
            images_to_delete = deleted_tags_images
        for name in images_to_delete:
            if name in self.referenced_images:
                # The image is referenced in one or more Image stream
                continue
            if name not in self.image_mapping:
                # The image is not existing anymore
                continue
            result = self.prune_images(self.image_mapping[name])
            if result:
                images.append(result)

        result = {
            "changed": self.changed,
            "deleted_images": images,
            "updated_image_streams": updated_image_streams,
        }
        self.exit_json(**result)
