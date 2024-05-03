#!/usr/bin/env python

# Quick and dirty python script to get the image of a swi file. `unzip` could
# be used for this, but it's currently not installed on sonic-mgmt containers
# today.

import zipfile
import sys

with zipfile.ZipFile(sys.argv[1], "r") as zip_ref:
    print(str(zip_ref.read(".imagehash"), encoding='utf-8').strip())
