# Copyright: (c) 2021, Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class CoreException(Exception):
    pass


class ResourceTimeout(CoreException):
    def __init__(self, message="", result=None):
        self.result = result or {}
        super().__init__(message)
