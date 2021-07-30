import pytest
import spytest.framework as stf
from utilities.common import get_proc_name

def trace(fmt, *args):
    if args:
        stf.dtrace(fmt % args)
    else:
        stf.dtrace(fmt)

def unused_pytest_collect_file(parent, path):
    trace("\n%s: start", get_proc_name())
    trace("{} {}".format(parent, path))
    trace("%s: end\n", get_proc_name())

def pytest_itemcollected(item):
    trace("\n%s: start", get_proc_name())
    trace("{} {} {}".format(item.name, item.fspath, item.nodeid))
    stf.collect_test(item)
    trace("%s: end\n", get_proc_name())

@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(items))
    stf.modify_tests(config, items)
    trace("%s: end\n", get_proc_name())

@pytest.hookimpl(trylast=True)
def pytest_generate_tests(metafunc):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(metafunc))
    stf.generate_tests(metafunc.config, metafunc)
    trace("%s: end\n", get_proc_name())

def unused_pytest_runtest_logstart(nodeid, location):
    trace("\n%s: start", get_proc_name())
    trace("{} {}".format(nodeid, location))
    trace("%s: end\n", get_proc_name())

# this gets called in xdist for every test completion
def pytest_runtest_logreport(report):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(report))
    stf.log_report(report)
    trace("%s: end\n", get_proc_name())

def pytest_runtest_makereport(item, call):
    trace("\n%s: start", get_proc_name())
    trace("{} {}".format(item, call))
    stf.make_report(item, call)
    trace("%s: end\n", get_proc_name())

def unused_pytest_runtest_setup(item):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(item))
    trace("%s: end\n", get_proc_name())

def unused_pytest_runtest_call(item):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(item))
    trace("%s: end\n", get_proc_name())

@pytest.hookspec(firstresult=True)
def unused_pytest_runtest_protocol(item, nextitem):
    print("\n%s: start", get_proc_name())
    print("{}".format(item))
    print("{}".format(nextitem))
    print("%s: end\n", get_proc_name())

def pytest_addoption(parser):
    trace("\n%s: start", get_proc_name())
    stf.add_options(parser)
    trace("%s: end\n", get_proc_name())

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(config))
    stf.configure(config)
    trace("%s: end\n", get_proc_name())

def pytest_unconfigure(config):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(config))
    stf.unconfigure(config)
    trace("%s: end\n", get_proc_name())

@pytest.hookimpl(tryfirst=True)
def pytest_xdist_setupnodes(config, specs):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(config))
    stf.configure_nodes(config, specs)
    trace("%s: end\n", get_proc_name())

def pytest_configure_node(node):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(node))
    stf.configure_node(node)
    trace("%s: end\n", get_proc_name())

def pytest_xdist_newgateway(gateway):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(gateway))
    stf.begin_node(gateway)
    trace("%s: end\n", get_proc_name())

def pytest_testnodedown(node, error):
    trace("\n%s: start", get_proc_name())
    trace("{} {}".format(node, error))
    stf.finish_node(node, error)
    trace("%s: end\n", get_proc_name())

def pytest_exception_interact(node, call, report):
    trace("\n%s: start", get_proc_name())
    if report.failed:
        stf.log_test_exception(call.excinfo)
    trace("%s: end\n", get_proc_name())

def pytest_xdist_make_scheduler(config, log):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(config))
    rv = stf.make_scheduler(config, log)
    trace("%s: end\n", get_proc_name())
    return rv

@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef, request):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(fixturedef))
    trace("{}".format(request))
    stf.fixture_setup(fixturedef, request)
    yield
    stf.fixture_setup_finish(fixturedef, request)
    trace("\n%s: end", get_proc_name())
    trace("{}".format(fixturedef))
    trace("{}".format(request))

@pytest.hookimpl(tryfirst=True)
@pytest.hookspec(firstresult=True)
def unused_pytest_fixture_setup(fixturedef, request):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(fixturedef))
    trace("{}".format(request))
    rv = stf.fixture_setup(fixturedef, request)
    return rv

def pytest_fixture_post_finalizer(fixturedef, request):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(fixturedef))
    trace("{}".format(request))
    stf.fixture_post_finalizer(fixturedef, request)
    trace("%s: end\n", get_proc_name())

def pytest_sessionstart(session):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(session))
    stf.session_start(session)
    trace("%s: end\n", get_proc_name())

def pytest_sessionfinish(session, exitstatus):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(session))
    trace("{}".format(exitstatus))
    stf.session_finish(session, exitstatus)
    trace("%s: end\n", get_proc_name())

def unused_pytest_keyboard_interrupt(excinfo):
    trace("\n%s: start", get_proc_name())
    trace("{}".format(excinfo))
    trace("%s: end\n", get_proc_name())

@pytest.hookimpl(hookwrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    trace("\n%s: prolog", get_proc_name())
    stf.pyfunc_call(pyfuncitem, False)
    yield
    stf.pyfunc_call(pyfuncitem, True)
    trace("\n%s: epilog", get_proc_name())

@pytest.fixture(autouse=True)
def global_repeat_request(request):
    trace("\n----------global repeat start------------\n")
    rv = stf.global_repeat_request(request)
    trace("\n----------global repeat end------------\n")
    return rv

@pytest.fixture(scope="session", autouse=True)
def global_session_request(request):
    trace("\n----------global session start------------\n")
    stf.fixture_callback(request, "session", False)
    yield
    stf.fixture_callback(request, "session", True)
    trace("\n----------global session end------------\n")

@pytest.fixture(scope="module", autouse=True)
def global_module_hook(request):
    trace("\n----------global module start------------\n")
    rv = stf.fixture_callback(request, "module", False)
    if rv:
        return rv
    def fin():
        rv = stf.fixture_callback(request, "module", True)
        trace("\n----------global module end------------\n")
        return rv
    request.addfinalizer(fin)

@pytest.fixture(scope="function", autouse=True)
def global_function_hook(request):
    trace("\n----------global test start------------\n")
    stf.fixture_callback(request, "function", False)
    yield
    stf.fixture_callback(request, "function", True)
    trace("\n----------global test end------------\n")

