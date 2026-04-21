#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy

from ansible.module_utils.parsing.convert_bool import boolean
from ansible.module_utils.six import string_types

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from kubernetes.dynamic.exceptions import DynamicApiError
except ImportError:
    pass

from ansible_collections.community.okd.plugins.module_utils.openshift_docker_image import (
    parse_docker_image_ref,
)

err_stream_not_found_ref = "NotFound reference"


def follow_imagestream_tag_reference(stream, tag):
    multiple = False

    def _imagestream_has_tag():
        for ref in stream["spec"].get("tags", []):
            if ref["name"] == tag:
                return ref
        return None

    def _imagestream_split_tag(name):
        parts = name.split(":")
        name = parts[0]
        tag = ""
        if len(parts) > 1:
            tag = parts[1]
        if len(tag) == 0:
            tag = "latest"
        return name, tag, len(parts) == 2

    content = []
    err_cross_stream_ref = (
        "tag %s points to an imagestreamtag from another ImageStream" % tag
    )
    while True:
        if tag in content:
            return (
                tag,
                None,
                multiple,
                "tag %s on the image stream is a reference to same tag" % tag,
            )
        content.append(tag)
        tag_ref = _imagestream_has_tag()
        if not tag_ref:
            return None, None, multiple, err_stream_not_found_ref

        if not tag_ref.get("from") or tag_ref["from"]["kind"] != "ImageStreamTag":
            return tag, tag_ref, multiple, None

        if (
            tag_ref["from"]["namespace"] != ""
            and tag_ref["from"]["namespace"] != stream["metadata"]["namespace"]
        ):
            return tag, None, multiple, err_cross_stream_ref

        # The reference needs to be followed with two format patterns:
        # a) sameis:sometag and b) sometag
        if ":" in tag_ref["from"]["name"]:
            name, tagref, result = _imagestream_split_tag(tag_ref["from"]["name"])
            if not result:
                return (
                    tag,
                    None,
                    multiple,
                    "tag %s points to an invalid imagestreamtag" % tag,
                )
            if name != stream["metadata"]["namespace"]:
                # anotheris:sometag - this should not happen.
                return tag, None, multiple, err_cross_stream_ref
            # sameis:sometag - follow the reference as sometag
            tag = tagref
        else:
            tag = tag_ref["from"]["name"]
        multiple = True


class OpenShiftImportImage(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenShiftImportImage, self).__init__(**kwargs)

        self._rest_client = None
        self.registryhost = self.params.get("registry_url")
        self.changed = False

        ref_policy = self.params.get("reference_policy")
        ref_policy_type = None
        if ref_policy == "source":
            ref_policy_type = "Source"
        elif ref_policy == "local":
            ref_policy_type = "Local"

        self.ref_policy = {"type": ref_policy_type}

        self.validate_certs = self.params.get("validate_registry_certs")
        self.cluster_resources = {}

    def create_image_stream_import(self, stream):
        isi = {
            "apiVersion": "image.openshift.io/v1",
            "kind": "ImageStreamImport",
            "metadata": {
                "name": stream["metadata"]["name"],
                "namespace": stream["metadata"]["namespace"],
                "resourceVersion": stream["metadata"].get("resourceVersion"),
            },
            "spec": {"import": True},
        }

        annotations = stream.get("annotations", {})
        insecure = boolean(
            annotations.get("openshift.io/image.insecureRepository", True)
        )
        if self.validate_certs is not None:
            insecure = not self.validate_certs
        return isi, insecure

    def create_image_stream_import_all(self, stream, source):
        isi, insecure = self.create_image_stream_import(stream)
        isi["spec"]["repository"] = {
            "from": {
                "kind": "DockerImage",
                "name": source,
            },
            "importPolicy": {
                "insecure": insecure,
                "scheduled": self.params.get("scheduled"),
            },
            "referencePolicy": self.ref_policy,
        }
        return isi

    def create_image_stream_import_tags(self, stream, tags):
        isi, streamInsecure = self.create_image_stream_import(stream)
        for k in tags:
            insecure = streamInsecure
            scheduled = self.params.get("scheduled")

            old_tag = None
            for t in stream.get("spec", {}).get("tags", []):
                if t["name"] == k:
                    old_tag = t
                    break

            if old_tag:
                insecure = insecure or old_tag["importPolicy"].get("insecure")
                scheduled = scheduled or old_tag["importPolicy"].get("scheduled")

            images = isi["spec"].get("images", [])
            images.append(
                {
                    "from": {
                        "kind": "DockerImage",
                        "name": tags.get(k),
                    },
                    "to": {"name": k},
                    "importPolicy": {"insecure": insecure, "scheduled": scheduled},
                    "referencePolicy": self.ref_policy,
                }
            )
            isi["spec"]["images"] = images
        return isi

    def create_image_stream(self, ref):
        """
        Create new ImageStream and accompanying ImageStreamImport
        """
        source = self.params.get("source")
        if not source:
            source = ref["source"]

        stream = dict(
            apiVersion="image.openshift.io/v1",
            kind="ImageStream",
            metadata=dict(
                name=ref["name"],
                namespace=self.params.get("namespace"),
            ),
        )
        if self.params.get("all") and not ref["tag"]:
            spec = dict(dockerImageRepository=source)
            isi = self.create_image_stream_import_all(stream, source)
        else:
            spec = dict(
                tags=[
                    {
                        "from": {"kind": "DockerImage", "name": source},
                        "referencePolicy": self.ref_policy,
                    }
                ]
            )
            tags = {ref["tag"]: source}
            isi = self.create_image_stream_import_tags(stream, tags)
        stream.update(dict(spec=spec))
        return stream, isi

    def import_all(self, istream):
        stream = copy.deepcopy(istream)
        # Update ImageStream appropriately
        source = self.params.get("source")
        docker_image_repo = stream["spec"].get("dockerImageRepository")
        if not source:
            if docker_image_repo:
                source = docker_image_repo
            else:
                tags = {}
                for t in stream["spec"].get("tags", []):
                    if t.get("from") and t["from"].get("kind") == "DockerImage":
                        tags[t.get("name")] = t["from"].get("name")
                if tags == {}:
                    msg = (
                        "image stream %s/%s does not have tags pointing to external container images"
                        % (stream["metadata"]["namespace"], stream["metadata"]["name"])
                    )
                    self.fail_json(msg=msg)
                isi = self.create_image_stream_import_tags(stream, tags)
                return stream, isi

        if source != docker_image_repo:
            stream["spec"]["dockerImageRepository"] = source
        isi = self.create_image_stream_import_all(stream, source)
        return stream, isi

    def import_tag(self, stream, tag):
        source = self.params.get("source")

        # Follow any referential tags to the destination
        final_tag, existing, multiple, err = follow_imagestream_tag_reference(
            stream, tag
        )
        if err:
            if err == err_stream_not_found_ref:
                # Create a new tag
                if not source and tag == "latest":
                    source = stream["spec"].get("dockerImageRepository")
                # if the from is still empty this means there's no such tag defined
                # nor we can't create any from .spec.dockerImageRepository
                if not source:
                    msg = (
                        "the tag %s does not exist on the image stream - choose an existing tag to import"
                        % tag
                    )
                    self.fail_json(msg=msg)
                existing = {
                    "from": {
                        "kind": "DockerImage",
                        "name": source,
                    }
                }
            else:
                self.fail_json(msg=err)
        else:
            # Disallow re-importing anything other than DockerImage
            if (
                existing.get("from", {})
                and existing["from"].get("kind") != "DockerImage"
            ):
                msg = "tag {tag} points to existing {kind}/={name}, it cannot be re-imported.".format(
                    tag=tag,
                    kind=existing["from"]["kind"],
                    name=existing["from"]["name"],
                )
            # disallow changing an existing tag
            if not existing.get("from", {}):
                msg = (
                    "tag %s already exists - you cannot change the source using this module."
                    % tag
                )
                self.fail_json(msg=msg)
            if source and source != existing["from"]["name"]:
                if multiple:
                    msg = "the tag {0} points to the tag {1} which points to {2} you cannot change the source using this module".format(
                        tag, final_tag, existing["from"]["name"]
                    )
                else:
                    msg = (
                        "the tag %s points to %s you cannot change the source using this module."
                        % (tag, final_tag)
                    )
                self.fail_json(msg=msg)

            # Set the target item to import
            source = existing["from"].get("name")
            if multiple:
                tag = final_tag

            # Clear the legacy annotation
            tag_to_delete = "openshift.io/image.dockerRepositoryCheck"
            if existing["annotations"] and tag_to_delete in existing["annotations"]:
                del existing["annotations"][tag_to_delete]

            # Reset the generation
            existing["generation"] = 0

        new_stream = copy.deepcopy(stream)
        new_stream["spec"]["tags"] = []
        for t in stream["spec"]["tags"]:
            if t["name"] == tag:
                new_stream["spec"]["tags"].append(existing)
            else:
                new_stream["spec"]["tags"].append(t)

        # Create accompanying ImageStreamImport
        tags = {tag: source}
        isi = self.create_image_stream_import_tags(new_stream, tags)
        return new_stream, isi

    def create_image_import(self, ref):
        kind = "ImageStream"
        api_version = "image.openshift.io/v1"

        # Find existing Image Stream
        params = dict(
            kind=kind,
            api_version=api_version,
            name=ref.get("name"),
            namespace=self.params.get("namespace"),
        )
        result = self.kubernetes_facts(**params)
        if not result["api_found"]:
            msg = 'Failed to find API for resource with apiVersion "{0}" and kind "{1}"'.format(
                api_version, kind
            )
            self.fail_json(msg=msg)
        imagestream = None
        if len(result["resources"]) > 0:
            imagestream = result["resources"][0]

        stream, isi = None, None
        if not imagestream:
            stream, isi = self.create_image_stream(ref)
        elif self.params.get("all") and not ref["tag"]:
            # importing the entire repository
            stream, isi = self.import_all(imagestream)
        else:
            # importing a single tag
            stream, isi = self.import_tag(imagestream, ref["tag"])
        return isi

    def parse_image_reference(self, image_ref):
        result, err = parse_docker_image_ref(image_ref, self.module)
        if result.get("digest"):
            self.fail_json(
                msg="Cannot import by ID, error with definition: %s" % image_ref
            )
        tag = result.get("tag") or None
        if not self.params.get("all") and not tag:
            tag = "latest"
        source = self.params.get("source")
        if not source:
            source = image_ref
        return dict(name=result.get("name"), tag=tag, source=image_ref)

    def execute_module(self):
        names = []
        name = self.params.get("name")
        if isinstance(name, string_types):
            names.append(name)
        elif isinstance(name, list):
            names = name
        else:
            self.fail_json(msg="Parameter name should be provided as list or string.")

        images_refs = [self.parse_image_reference(x) for x in names]
        images_imports = []
        for ref in images_refs:
            isi = self.create_image_import(ref)
            images_imports.append(isi)

        # Create image import
        kind = "ImageStreamImport"
        api_version = "image.openshift.io/v1"
        namespace = self.params.get("namespace")
        try:
            resource = self.find_resource(kind=kind, api_version=api_version, fail=True)
            result = []
            for isi in images_imports:
                if not self.check_mode:
                    isi = resource.create(isi, namespace=namespace).to_dict()
                result.append(isi)
            self.exit_json(changed=True, result=result)
        except DynamicApiError as exc:
            msg = "Failed to create object {kind}/{namespace}/{name} due to: {error}".format(
                kind=kind, namespace=namespace, name=isi["metadata"]["name"], error=exc
            )
            self.fail_json(
                msg=msg,
                error=exc.status,
                status=exc.status,
                reason=exc.reason,
            )
        except Exception as exc:
            msg = "Failed to create object {kind}/{namespace}/{name} due to: {error}".format(
                kind=kind, namespace=namespace, name=isi["metadata"]["name"], error=exc
            )
            self.fail_json(msg=msg)
