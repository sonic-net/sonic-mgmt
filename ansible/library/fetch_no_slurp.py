# This is a virtual module that is entirely implemented as an action plugin.
# For actual implementation, please refer to ansible/plugins/action/fetch_no_slurp.py

DOCUMENTATION = r'''
module: fetch_no_slurp.py
short_description: fetch file from remote controller to host without using ansible.builtin.slurp
description:
    - This module behaves like ansible.builtin.fetch but will not trigger ansible.builtin.slurp when become=True, which
      will significantly increases our performance.
    - For example: 1.4 GB file with original fetch when use with become=True will take 4 hours whereas this will take
      1.5 minutes with become=True given the same parameters
options:
  src:
    description:
    - The file on the remote system to fetch.
    - This I(must) be a file, not a directory.
    - Recursive fetching may be supported in a later release.
    required: yes
  dest:
    description:
    - A directory to save the file into.
    - For example, if the O(dest) directory is C(/backup) a O(src) file named C(/etc/profile) on host
      C(host.example.com), would be saved into C(/backup/host.example.com/etc/profile).
      The host name is based on the inventory name.
    required: yes
  fail_on_missing:
    version_added: '1.1'
    description:
    - When set to V(true), the task will fail if the remote file cannot be read for any reason.
    - Prior to Ansible 2.5, setting this would only fail if the source file was missing.
    - The default was changed to V(true) in Ansible 2.5.
    type: bool
    default: yes
  validate_checksum:
    version_added: '1.4'
    description:
    - Verify that the source and destination checksums match after the files are fetched.
    type: bool
    default: yes
  flat:
    version_added: '1.2'
    description:
    - Allows you to override the default behavior of appending hostname/path/to/file to the destination.
    - If O(dest) ends with '/', it will use the basename of the source file, similar to the copy module.
    - This can be useful if working with a single host, or if retrieving files that are uniquely named per host.
    - If using multiple hosts with the same filename, the file will be overwritten for each host.
    type: bool
    default: no
extends_documentation_fragment:
    - action_common_attributes
    - action_common_attributes.files
    - action_common_attributes.flow
attributes:
  action:
    support: full
  async:
    support: none
  bypass_host_loop:
    support: none
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: posix, windows
  safe_file_operations:
    support: none
  vault:
    support: none
'''

EXAMPLES = r'''
- name: Store file from DUT to current folder
  fetch_no_slurp:
    src: /tmp/remote_file
    dest: /tmp/local_folder
    flat: True

Which is equivalent to
'''


TEST_EXAMPLE = r'''
duthost.fetch_no_slurp(src="/tmp/remove_file", dest="/tmp/local_folder", flat=True)
'''
