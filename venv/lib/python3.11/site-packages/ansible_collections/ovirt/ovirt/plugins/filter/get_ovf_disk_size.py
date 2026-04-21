"Module to create filter to find ovf disk size from xml"
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleFilterError

import xml.etree.ElementTree as ET


def get_ovf_disk_size(data):
    try:
        root = ET.fromstring(data)
        for child in root:
            for element in child:
                if element.tag == "Disk":
                    return element.attrib.get(
                        "{http://schemas.dmtf.org/ovf/envelope/1/}size"
                    )
    except Exception as e:
        raise AnsibleFilterError(
            "Error in get_ovf_disk_size filter plugin:\n%s" % e
        )


class FilterModule(object):
    """OVF disk size filter"""

    def filters(self):
        return {
            "get_ovf_disk_size": get_ovf_disk_size
        }
