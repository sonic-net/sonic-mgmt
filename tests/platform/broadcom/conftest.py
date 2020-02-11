import os
import sys
import pytest

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/../../' )
from fixtures.ssh_timeout import pause_testbed_ssh_timeout
