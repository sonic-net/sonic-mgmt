import sys
import os

# FIXME to the right path for trex_stl_lib
cur_dir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(cur_dir, os.pardir))

STL_PROFILES_PATH = os.path.join(os.path.join(cur_dir, os.pardir), 'profiles')
