import pytest


@pytest.fixture(scope="module", autouse=True)
def skip_test_module_over_backend_topologies(request, tbinfo):
    """Skip testcases in the test module if the topo is storage backend."""
    if "backend" in tbinfo["topo"]["name"]:
        module_filename = request.module.__name__.split(".")[-1]
        pytest.skip("Skip %s. Unsupported topology %s." % (module_filename, tbinfo["topo"]["name"]))
