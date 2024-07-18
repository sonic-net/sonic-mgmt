import os

_profile_support = 0
_profiler = None


def init_profile():
    global _profile_support
    try:
        _profile_support = int(os.getenv("SPYTEST_CPROFILE_SUPPORT", "0"))
    except Exception:
        _profile_support = 0


def cprofile_init():
    if not _profile_support:
        return
    global _profiler
    import cProfile
    _profiler = cProfile.Profile()


def cprofile_start():
    if not _profile_support:
        return
    if not _profiler:
        cprofile_init()
    _profiler.enable()


def cprofile_stop(file_path=None):
    if not _profile_support:
        return
    _profiler.disable()
    if file_path:
        cprofile_stats(file_path)
        cprofile_process(file_path)


def cprofile_stats(file_path):
    if not _profile_support:
        return
    _profiler.dump_stats(file_path + ".dump")
    return file_path


def cprofile_process(file_path):
    if not _profile_support:
        return
    import pstats
    from io import StringIO
    stream = StringIO()
    ps = pstats.Stats(file_path + ".dump", stream=stream)
    # ps.strip_dirs()
    ps.sort_stats("cumtime")
    # ps.print_stats(500)
    ps.print_stats(500, "spytest")
    # func_list = ["modify_tests", "build_dependency"]
    func_list = ["_load", "_dump"]
    # func_list.append("_add_dependency")
    for func in func_list:
        ps.print_callers(func)
        ps.print_callees(func)
    stream.seek(0)
    data = stream.read()
    print(data)
    fd = open(file_path + ".stats", "w")
    fd.write(data)
    fd.close()
