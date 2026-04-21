#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2015 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2013, Benno Joy <benno@ansible.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: object
short_description: Create or delete Swift objects in OpenStack clouds
author: OpenStack Ansible SIG
description:
   - Create or delete Swift objects in OpenStack clouds
options:
  container:
    description:
      - The name (and ID) of the container in which to create the object in.
      - This container will not be created if it does not exist already.
    required: true
    type: str
  data:
    description:
      - The content to upload to the object.
      - Mutually exclusive with I(filename).
      - This attribute cannot be updated.
    type: str
  filename:
    description:
      - The path to the local file whose contents will be uploaded.
      - Mutually exclusive with I(data).
    type: str
  name:
    description:
      - Name (and ID) of the object.
    required: true
    type: str
  state:
    description:
      - Whether the object should be C(present) or C(absent).
    choices: ['present', 'absent']
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
object:
  description: Dictionary describing the object.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    accept_ranges:
      description: The type of ranges that the object accepts.
      type: str
    access_control_allow_origin:
      description: CORS for RAX (deviating from standard)
      type: str
    content_disposition:
      description: If set, specifies the override behavior for the browser.
                   For example, this header might specify that the browser use
                   a download program to save this file rather than show the
                   file, which is the default. If not set, this header is not
                   returned by this operation.
      type: str
    content_encoding:
      description: If set, the value of the Content-Encoding metadata.
                   If not set, this header is not returned by this operation.
      type: str
    content_length:
      description: HEAD operations do not return content. However, in this
                   operation the value in the Content-Length header is not the
                   size of the response body. Instead it contains the size of
                   the object, in bytes.
      type: str
    content_type:
      description: The MIME type of the object.
      type: int
    copy_from:
      description: If set, this is the name of an object used to create the new
                   object by copying the X-Copy-From object. The value is in
                   form {container}/{object}. You must UTF-8-encode and then
                   URL-encode the names of the container and object before you
                   include them in the header. Using PUT with X-Copy-From has
                   the same effect as using the COPY operation to copy an
                   object.
      type: str
    delete_after:
      description: Specifies the number of seconds after which the object is
                   removed. Internally, the Object Storage system stores this
                   value in the X-Delete-At metadata item.
      type: int
    delete_at:
      description: If set, the time when the object will be deleted by the
                   system in the format of a UNIX Epoch timestamp. If not set,
                   this header is not returned by this operation.
      type: str
    etag:
      description: For objects smaller than 5 GB, this value is the MD5
                   checksum of the object content. The value is not quoted.
                   For manifest objects, this value is the MD5 checksum of the
                   concatenated string of MD5 checksums and ETags for each of
                   the segments in the manifest, and not the MD5 checksum of
                   the content that was downloaded. Also the value is enclosed
                   in double-quote characters.
                   You are strongly recommended to compute the MD5 checksum of
                   the response body as it is received and compare this value
                   with the one in the ETag header. If they differ, the content
                   was corrupted, so retry the operation.
      type: str
    expires_at:
      description: Used with temporary URLs to specify the expiry time of the
                   signature. For more information about temporary URLs, see
                   OpenStack Object Storage API v1 Reference.
      type: str
    id:
      description: ID of the object. Equal to C(name).
      type: str
    if_match:
      description: See U(http://www.ietf.org/rfc/rfc2616.txt).
      type: list
    if_modified_since:
      description: See U(http://www.ietf.org/rfc/rfc2616.txt).
      type: str
    if_none_match:
      description: "In combination with C(Expect: 100-Continue), specify an
                    C(If-None-Match: *) header to query whether the server
                    already has a copy of the object before any data is sent."
      type: list
    if_unmodified_since:
      description: See U(http://www.ietf.org/rfc/rfc2616.txt).
      type: str
    is_content_type_detected:
      description: If set to true, Object Storage guesses the content type
                   based on the file extension and ignores the value sent in
                   the Content-Type header, if present.
      type: bool
    is_newest:
      description: If set to True, Object Storage queries all replicas to
                   return the most recent one. If you omit this header, Object
                   Storage responds faster after it finds one valid replica.
                   Because setting this header to True is more expensive for
                   the back end, use it only when it is absolutely needed.
      type: bool
    is_static_large_object:
      description: Set to True if this object is a static large object manifest
                   object.
      type: bool
    last_modified_at:
      description: The date and time that the object was created or the last
                   time that the metadata was changed.
      type: str
    manifest:
      description: If present, this is a dynamic large object manifest object.
                   The value is the container and object name prefix of the
                   segment objects in the form container/prefix.
      type: str
    multipart_manifest:
      description: If you include the multipart-manifest=get query parameter
                   and the object is a large object, the object contents are
                   not returned. Instead, the manifest is returned in the
                   X-Object-Manifest response header for dynamic large objects
                   or in the response body for static large objects.
      type: str
    name:
      description: Name of the object.
      returned: success
      type: str
    object_manifest:
      description: If set, to this is a dynamic large object manifest object.
                   The value is the container and object name prefix of the
                   segment objects in the form container/prefix.
      type: str
    range:
      description: TODO.
      type: dict
    signature:
      description: Used with temporary URLs to sign the request. For more
                   information about temporary URLs, see OpenStack Object
                   Storage API v1 Reference.
      type: str
    symlink_target:
      description: If present, this is a symlink object. The value is the
                   relative path of the target object in the format
                   <container>/<object>.
      type: str
    symlink_target_account:
      description: If present, and X-Symlink-Target is present, then this is a
                   cross-account symlink to an object in the account specified
                   in the value.
      type: str
    timestamp:
      description: The timestamp of the transaction.
      type: str
    transfer_encoding:
      description: Set to chunked to enable chunked transfer encoding. If used,
                   do not set the Content-Length header to a non-zero value.
      type: str
'''

EXAMPLES = r'''
- name: Create a object named 'fstab' in the 'config' container
  openstack.cloud.object:
    cloud: mordred
    container: config
    filename: /etc/fstab
    name: fstab
    state: present

- name: Delete a container called config and all of its contents
  openstack.cloud.object:
    cloud: rax-iad
    container: config
    state: absent
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class ObjectModule(OpenStackModule):
    argument_spec = dict(
        container=dict(required=True),
        data=dict(),
        filename=dict(),
        name=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
    )

    module_kwargs = dict(
        mutually_exclusive=[
            ('data', 'filename'),
        ],
        required_if=[
            ('state', 'present', ('data', 'filename'), True),
        ],
        supports_check_mode=True
    )

    def run(self):
        state = self.params['state']
        object = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, object))

        if state == 'present' and not object:
            # Create object
            object = self._create()
            self.exit_json(changed=True,
                           # metadata is not returned by
                           # to_dict(computed=False) so return it explicitly
                           object=dict(metadata=object.metadata,
                                       **object.to_dict(computed=False)))

        elif state == 'present' and object:
            # Update object
            update = self._build_update(object)
            if update:
                object = self._update(object, update)

            self.exit_json(changed=bool(update),
                           # metadata is not returned by
                           # to_dict(computed=False) so return it explicitly
                           object=dict(metadata=object.metadata,
                                       **object.to_dict(computed=False)))

        elif state == 'absent' and object:
            # Delete object
            self._delete(object)
            self.exit_json(changed=True)

        elif state == 'absent' and not object:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, object):
        update = {}

        container_name = self.params['container']

        filename = self.params['filename']
        if filename is not None:
            if self.conn.object_store.is_object_stale(container_name,
                                                      object.id, filename):
                update['filename'] = filename

        return update

    def _create(self):
        name = self.params['name']
        container_name = self.params['container']

        kwargs = dict((k, self.params[k])
                      for k in ['data', 'filename']
                      if self.params[k] is not None)

        object = self.conn.object_store.create_object(container_name, name,
                                                      **kwargs)
        if not object:
            object = self._find()
        return object

    def _delete(self, object):
        container_name = self.params['container']
        self.conn.object_store.delete_object(object.id,
                                             container=container_name)

    def _find(self):
        name_or_id = self.params['name']
        container_name = self.params['container']
        # openstacksdk has no object_store.find_object() function
        try:
            return self.conn.object_store.get_object(name_or_id,
                                                     container=container_name)
        except self.sdk.exceptions.ResourceNotFound:
            return None

    def _update(self, object, update):
        filename = update.get('filename')
        if filename:
            container_name = self.params['container']
            object = self.conn.object_store.create_object(container_name,
                                                          object.id,
                                                          filename=filename)

        return object

    def _will_change(self, state, object):
        if state == 'present' and not object:
            return True
        elif state == 'present' and object:
            return bool(self._build_update(object))
        elif state == 'absent' and object:
            return True
        else:
            # state == 'absent' and not object:
            return False


def main():
    module = ObjectModule()
    module()


if __name__ == "__main__":
    main()
