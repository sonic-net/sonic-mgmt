# Copyright 2022 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
import tarfile

from ansible.module_utils.common.text.converters import to_native


class ImageArchiveManifestSummary(object):
    '''
    Represents data extracted from a manifest.json found in the tar archive output of the
    "docker image save some:tag > some.tar" command.
    '''

    def __init__(self, image_id, repo_tags):
        '''
        :param image_id:  File name portion of Config entry, e.g. abcde12345 from abcde12345.json
        :type image_id: str
        :param repo_tags  Docker image names, e.g. ["hello-world:latest"]
        :type repo_tags: list[str]
        '''

        self.image_id = image_id
        self.repo_tags = repo_tags


class ImageArchiveInvalidException(Exception):
    def __init__(self, message, cause):
        '''
        :param message: Exception message
        :type message: str
        :param cause: Inner exception that this exception wraps
        :type cause: Exception | None
        '''

        super(ImageArchiveInvalidException, self).__init__(message)

        # Python 2 does not support causes
        self.cause = cause


def api_image_id(archive_image_id):
    '''
    Accepts an image hash in the format stored in manifest.json, and returns an equivalent identifier
    that represents the same image hash, but in the format presented by the Docker Engine API.

    :param archive_image_id: plain image hash
    :type archive_image_id: str

    :returns: Prefixed hash used by REST api
    :rtype: str
    '''

    return 'sha256:%s' % archive_image_id


def load_archived_image_manifest(archive_path):
    '''
    Attempts to get image IDs and image names from metadata stored in the image
    archive tar file.

    The tar should contain a file "manifest.json" with an array with one or more entries,
    and every entry should have a Config field with the image ID in its file name, as
    well as a RepoTags list, which typically has only one entry.

    :raises:
        ImageArchiveInvalidException: A file already exists at archive_path, but could not extract an image ID from it.

    :param archive_path: Tar file to read
    :type archive_path: str

    :return: None, if no file at archive_path, or a list of ImageArchiveManifestSummary objects.
    :rtype: ImageArchiveManifestSummary
    '''

    try:
        # FileNotFoundError does not exist in Python 2
        if not os.path.isfile(archive_path):
            return None

        tf = tarfile.open(archive_path, 'r')
        try:
            try:
                ef = tf.extractfile('manifest.json')
                try:
                    text = ef.read().decode('utf-8')
                    manifest = json.loads(text)
                except Exception as exc:
                    raise ImageArchiveInvalidException(
                        "Failed to decode and deserialize manifest.json: %s" % to_native(exc),
                        exc
                    )
                finally:
                    # In Python 2.6, this does not have __exit__
                    ef.close()

                if len(manifest) == 0:
                    raise ImageArchiveInvalidException(
                        "Expected to have at least one entry in manifest.json but found none",
                        None
                    )

                result = []
                for index, meta in enumerate(manifest):
                    try:
                        config_file = meta['Config']
                    except KeyError as exc:
                        raise ImageArchiveInvalidException(
                            "Failed to get Config entry from {0}th manifest in manifest.json: {1}".format(index + 1, to_native(exc)),
                            exc
                        )

                    # Extracts hash without 'sha256:' prefix
                    try:
                        # Strip off .json filename extension, leaving just the hash.
                        image_id = os.path.splitext(config_file)[0]
                    except Exception as exc:
                        raise ImageArchiveInvalidException(
                            "Failed to extract image id from config file name %s: %s" % (config_file, to_native(exc)),
                            exc
                        )

                    for prefix in (
                        'blobs/sha256/',  # Moby 25.0.0, Docker API 1.44
                    ):
                        if image_id.startswith(prefix):
                            image_id = image_id[len(prefix):]

                    try:
                        repo_tags = meta['RepoTags']
                    except KeyError as exc:
                        raise ImageArchiveInvalidException(
                            "Failed to get RepoTags entry from {0}th manifest in manifest.json: {1}".format(index + 1, to_native(exc)),
                            exc
                        )

                    result.append(ImageArchiveManifestSummary(
                        image_id=image_id,
                        repo_tags=repo_tags
                    ))
                return result

            except ImageArchiveInvalidException:
                raise
            except Exception as exc:
                raise ImageArchiveInvalidException(
                    "Failed to extract manifest.json from tar file %s: %s" % (archive_path, to_native(exc)),
                    exc
                )

        finally:
            # In Python 2.6, TarFile does not have __exit__
            tf.close()

    except ImageArchiveInvalidException:
        raise
    except Exception as exc:
        raise ImageArchiveInvalidException("Failed to open tar file %s: %s" % (archive_path, to_native(exc)), exc)


def archived_image_manifest(archive_path):
    '''
    Attempts to get Image.Id and image name from metadata stored in the image
    archive tar file.

    The tar should contain a file "manifest.json" with an array with a single entry,
    and the entry should have a Config field with the image ID in its file name, as
    well as a RepoTags list, which typically has only one entry.

    :raises:
        ImageArchiveInvalidException: A file already exists at archive_path, but could not extract an image ID from it.

    :param archive_path: Tar file to read
    :type archive_path: str

    :return: None, if no file at archive_path, or the extracted image ID, which will not have a sha256: prefix.
    :rtype: ImageArchiveManifestSummary
    '''

    results = load_archived_image_manifest(archive_path)
    if results is None:
        return None
    if len(results) == 1:
        return results[0]
    raise ImageArchiveInvalidException(
        "Expected to have one entry in manifest.json but found %s" % len(results),
        None
    )
