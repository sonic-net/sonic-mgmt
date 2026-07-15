# Copilot Instructions for sonic-mgmt

## Source of Truth

Use the repository documentation as the source of truth. Start with
[`docs/README.md`](../docs/README.md), which links to the testbed, test-writing,
test-execution, and reporting documentation.

- Before adding or changing a command in this file, verify it against the
  current documentation on the target branch.
- Do not copy long procedures or the pull request template into this file.
  Link to their authoritative locations so they do not drift.
- If documentation and implementation disagree, do not invent a workaround.
  Identify the discrepancy and update the appropriate documentation or code.

## Repository Overview

`sonic-mgmt` contains SONiC testbed deployment, setup, pytest-based testing,
and test-report processing. Ansible provides testbed deployment and device
interaction, while pytest and pytest-ansible provide the primary test
framework.

Important directories:

- `ansible/`: testbed deployment, setup, inventory, and Ansible modules
- `docs/`: repository documentation
- `spytest/`: SPyTest framework and tests
- `test_reporting/`: test-result processing and upload
- `tests/`: pytest infrastructure, fixtures, helpers, and test cases

For more detail, see [`docs/README.md`](../docs/README.md).

## Code and Test Guidelines

Follow these public repository guides:

- [`docs/code-review-guidlines.md`](../docs/code-review-guidlines.md)
- [`docs/tests/guidelines.md`](../docs/tests/guidelines.md)
- [`docs/tests/styleguide.md`](../docs/tests/styleguide.md)
- [`docs/tests/writing.tests.help.md`](../docs/tests/writing.tests.help.md)

In particular:

- Follow PEP 8, except where the repository style guide explicitly documents
  an exception.
- Use self-descriptive names and logging instead of print statements.
- Avoid hardcoded values; define constants or derive values from fixtures and
  testbed data.
- Add the appropriate topology marker to every test case.
- Use `pytest_assert` for test assertions as described in the test-writing
  guide.
- Use pytest fixtures for setup and teardown so cleanup still runs when a test
  fails.
- Handle return values and exceptions, and clean up state under error
  conditions.
- Consider multi-ASIC devices and declare every supported topology for new
  tests.
- Do not add secrets, credentials, internal addresses, or other private
  environment information.

## Testbed and Container Setup

Use the complete
[`docs/testbed/README.testbed.VsSetup.md`](../docs/testbed/README.testbed.VsSetup.md)
guide for KVM/VS setup. It covers supported Ubuntu versions, image placement,
inventory and credential configuration, topology deployment, IPv6-only
management, and cleanup.

The documented host preparation command is:

```bash
git clone https://github.com/sonic-net/sonic-mgmt
cd sonic-mgmt/ansible
sudo -H ./setup-management-network.sh
```

Create and enter the sonic-mgmt container as documented in
[`docs/testbed/README.testbed.VsSetup.md`](../docs/testbed/README.testbed.VsSetup.md)
and [`docs/testbed/README.testbed.Docker.md`](../docs/testbed/README.testbed.Docker.md):

```bash
cd sonic-mgmt
./setup-container.sh -n <container name> -d /data
docker exec --user $USER -it <container name> bash
```

After completing the documented image, inventory, credential, and password
file preparation, the documented cEOS T0 deployment commands are:

```bash
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb add-topo vms-kvm-t0 password.txt
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-t0 veos_vtb password.txt
```

The documented cleanup command is:

```bash
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos remove-topo vms-kvm-t0 password.txt
```

Do not treat these examples as a replacement for the full setup guide. Follow
the documented procedure for the topology and neighbor type being configured.

## Running Tests

Use [`tests/run_tests.sh`](../tests/run_tests.sh) as the normal test runner.
See [`docs/tests/pytest.run.md`](../docs/tests/pytest.run.md) for supported
options and examples.

The VS setup guide provides this example from the `tests/` directory:

```bash
./run_tests.sh -n vms-kvm-t0 -d vlab-01 -c bgp/test_bgp_fact.py -f vtestbed.yaml -i ../ansible/veos_vtb
```

Direct `pytest` execution is optional and is documented separately in
[`docs/tests/pytest.run.md`](../docs/tests/pytest.run.md). When using it,
follow that guide's argument-order requirements: place test files or
directories before sonic-mgmt-specific options so the relevant `conftest.py`
files are loaded.

Choose validation according to
[`docs/code-review-guidlines.md`](../docs/code-review-guidlines.md):

- A new test should pass at least three times on a supported topology.
- An infrastructure change should run each impacted test successfully at
  least once.
- For a new test suite, support at least one test on VS.
- Run the repository pre-commit checker before uploading the pull request.

## Pull Requests

Follow the contribution guidance in [`README.md`](../README.md), including
commit-message structure, sign-off, CLA, and normal GitHub pull request flow.

Always use the current
[`.github/PULL_REQUEST_TEMPLATE.md`](PULL_REQUEST_TEMPLATE.md) from the target
branch. Fill every applicable section and checklist item. Do not reproduce the
template here, because supported release branches and backport requirements
change over time.
