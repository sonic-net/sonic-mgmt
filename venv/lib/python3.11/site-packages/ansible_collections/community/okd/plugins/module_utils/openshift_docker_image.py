#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re


def convert_storage_to_bytes(value):
    keys = {
        "Ki": 1024,
        "Mi": 1024 * 1024,
        "Gi": 1024 * 1024 * 1024,
        "Ti": 1024 * 1024 * 1024 * 1024,
        "Pi": 1024 * 1024 * 1024 * 1024 * 1024,
        "Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
    }
    for k in keys:
        if value.endswith(k) or value.endswith(k[0]):
            idx = value.find(k[0])
            return keys.get(k) * int(value[:idx])
    return int(value)


def is_valid_digest(digest):
    digest_algorithm_size = dict(
        sha256=64,
        sha384=96,
        sha512=128,
    )

    m = re.match(r"[a-zA-Z0-9-_+.]+:[a-fA-F0-9]+", digest)
    if not m:
        return "Docker digest does not match expected format %s" % digest

    idx = digest.find(":")
    # case: "sha256:" with no hex.
    if idx < 0 or idx == (len(digest) - 1):
        return "Invalid docker digest %s, no hex value define" % digest

    algorithm = digest[:idx]
    if algorithm not in digest_algorithm_size:
        return "Unsupported digest algorithm value %s for digest %s" % (
            algorithm,
            digest,
        )

    hex_value = digest[idx + 1:]  # fmt: skip
    if len(hex_value) != digest_algorithm_size.get(algorithm):
        return "Invalid length for digest hex expected %d found %d (digest is %s)" % (
            digest_algorithm_size.get(algorithm),
            len(hex_value),
            digest,
        )


def parse_docker_image_ref(image_ref, module=None):
    """
    Docker Grammar Reference
    Reference => name [ ":" tag ] [ "@" digest ]
    name => [hostname '/'] component ['/' component]*
        hostname => hostcomponent ['.' hostcomponent]* [':' port-number]
            hostcomponent => /([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])/
            port-number   => /[0-9]+/
        component        => alpha-numeric [separator alpha-numeric]*
            alpha-numeric => /[a-z0-9]+/
            separator     => /[_.]|__|[-]*/
    """
    idx = image_ref.find("/")

    def _contains_any(src, values):
        return any(x in src for x in values)

    result = {"tag": None, "digest": None}
    default_domain = "docker.io"
    if idx < 0 or (
        not _contains_any(image_ref[:idx], ":.") and image_ref[:idx] != "localhost"
    ):
        result["hostname"], remainder = default_domain, image_ref
    else:
        result["hostname"], remainder = image_ref[:idx], image_ref[idx + 1:]  # fmt: skip

    # Parse remainder information
    idx = remainder.find("@")
    if idx > 0 and len(remainder) > (idx + 1):
        # docker image reference with digest
        component, result["digest"] = remainder[:idx], remainder[idx + 1:]  # fmt: skip
        err = is_valid_digest(result["digest"])
        if err:
            if module:
                module.fail_json(msg=err)
            return None, err
    else:
        idx = remainder.find(":")
        if idx > 0 and len(remainder) > (idx + 1):
            # docker image reference with tag
            component, result["tag"] = remainder[:idx], remainder[idx + 1:]  # fmt: skip
        else:
            # name only
            component = remainder
    v = component.split("/")
    namespace = None
    if len(v) > 1:
        namespace = v[0]
    result.update({"namespace": namespace, "name": v[-1]})

    return result, None
