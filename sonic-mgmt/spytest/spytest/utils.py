from utilities import common as base

def filter_and_select(output, select=None, match=None):
  return base.filter_and_select(output, select, match)
def random_vlan_list(count=1, exclude=[]):
  return base.random_vlan_list(count, exclude)
def exec_foreach (use_threads, items, func, *args, **kwargs):
  return base.exec_foreach (use_threads, items, func, *args, **kwargs)
def exec_all(use_threads, entries, first_on_main=False):
  return base.exec_all(use_threads, entries, first_on_main)
def poll_wait(method, timeout, *args, **kwargs):
  return base.poll_wait(method, timeout, *args, **kwargs)

