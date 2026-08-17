"""Prevent mock UT/IT test collection in nightly pipeline runs.

Mock tests (under it/ and ut/) are for probe development only:
- UT: Unit tests for individual probe components
- IT: Integration tests for probe algorithms with mocked PTF

These tests use local pytest.ini with testpaths=. and are designed
to run directly from their own directories:
    cd tests/saitests/mock/it && pytest .
    cd tests/saitests/mock/ut && pytest .

When pytest collects from tests/ (nightly/CI), the mock test files
cause collection errors because their import-time path manipulation
(sys.path.insert for probe/, PTF mock injection) runs before
conditional_mark can apply skip marks. This conftest prevents
pytest from even entering the mock subdirectories during nightly
collection, avoiding both collection errors and false test failures.

Related: https://msazure.visualstudio.com/One/_workitems/edit/38000718
"""


def pytest_ignore_collect(collection_path, config):
    """Skip all mock test subdirectories during nightly collection.

    This hook runs during collection, before test file import,
    so it prevents the import-time errors that bypass YAML-based
    conditional skip marks.

    When running directly from mock/it/ or mock/ut/ (with their own
    pytest.ini setting rootdir=.), this conftest is outside the
    rootdir and is NOT loaded, so local development runs unaffected.
    """
    return True
