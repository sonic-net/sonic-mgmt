# Contributing to this project

In this guide, you will find information relevant for code contributions, though any other kinds of contribution mentioned in the [Ansible Contributing guidelines](https://docs.ansible.com/ansible/devel/community/index.html) are equally appreciated and valuable.

If you have any questions after reading, please contact the community via one or more of the [available channels](https://github.com/ansible-collections/community.postgresql#communication). Any feedback on this guide is very welcome.

## Reviewing open issue and pull requests

Refer to the [review checklist](https://docs.ansible.com/ansible/devel/community/collection_contributors/collection_reviewing.html) when triaging issues or reviewing pull requests (hereinafter PRs).

Most important things to pay attention to:

- Do not let major/breaking changes sneak into a minor/bugfix release! All such changes should be discussed in a dedicated issue, added to a corresponding milestone (which can be found or created in the project's Issues), and merged right before the major release. Take a look at similar issues to see what needs to be done and reflect on the steps you did/need to do in the issue.
- Every PR (except doc, refactoring, test-related, or a PR containing a new module/plugin) contains a [changelog fragment](https://docs.ansible.com/ansible/latest/community/development_process.html#creating-a-changelog-fragment). Let's give users a chance to know about the changes.
- Every new module `DOCUMENTATION` section contains the `version_added: 'x.y.z'` field. Besides the informative purpose, it is used by the changelog-generating tool to add a corresponding entry to the changelog. As the project follows SemVer, it is typically a next minor (x.y.0) version.
- Every new module argument contains the `version_added: 'x.y.z'` field. As the project follows SemVer, it is typically a next minor (x.y.0) version.
- Non-refactoring code changes (bugfixes, new features) are covered with, at least, integration tests! There can be exceptions but generally it is a requirement.

## Code contributions

If you want to submit a bugfix or new feature, refer to the [Quick-start development guide](https://docs.ansible.com/ansible/devel/community/create_pr_quick_start.html) first.

## Project-specific info

We assume you have read the [Quick-start development guide](https://docs.ansible.com/ansible/devel/community/create_pr_quick_start.html).

In order for any submitted PR to get merged, this project requires sanity, unit, and integration tests to pass.
Codecov job is there but not required.
We use the Azure Pipelines platform to run the tests.
You can see the result in the bottom of every PR in the box listing the jobs and their results:

- Green checkmark: the test has been passed, no more action is needed.
- Red cross: the test has failed. You can see the reason by clicking the ``Details`` link. Fix them locally and push the commit.

Generally, all jobs must be green.
Sometimes, there can be failures unrelated to a PR, for example, when a test container is unavailable or there is another part of the code that does not satisfy recently introduced additional sanity checks.
If you think the failure does not relate to your changes, put a comment about it.

## CI testing

The jobs are launched automatically by Azure Pipelines in every PR based on the [matrix](https://github.com/ansible-collections/community.postgresql/blob/main/.azure-pipelines/azure-pipelines.yml).

As the project is included in `ansible` community package, it is a requirement for us to test against all supported `ansible-core` versions and corresponding Python versions.
To keep the matrix relevant, we are subscribed to the [news-for-maintainers](https://github.com/ansible-collections/news-for-maintainers) repository and the [Collection maintainers & contributors](https://forum.ansible.com/g/CollectionMaintainer) forum group to track announcements affecting CI.

If our matrix is permanently outdated, for example, when supported `ansible-core` versions are missed, the collections can get excluded from the package, so keep it updated!

## Adding tests

If you are new here, read the [Quick-start development guide](https://docs.ansible.com/ansible/devel/community/create_pr_quick_start.html) first.

When fixing a bug, first reproduce it by adding a task as reported to a suitable file under the ``tests/integration/targets/<module_name>/tasks/`` directory and run the integration tests as described below. The same is relevant for new features.

It is not necessary but if you want you can also add unit tests to a suitable file under the ``tests/units/`` directory and run them as described below.

## Checking your code locally

It will make your and other people's life a bit easier if you run the tests locally and fix all failures before pushing. If you're unable to run the tests locally, please create your PR as a **draft** to avoid reviewers being added automatically.

If you are new here, read the [Quick-start development guide](https://docs.ansible.com/ansible/devel/community/create_pr_quick_start.html) first.

We assume you [prepared your local environment](https://docs.ansible.com/ansible/devel/community/create_pr_quick_start.html#prepare-your-environment) as described in the guide before running the following commands. Otherwise, the command will fail.

### Sanity tests

``` console
$ ansible-test sanity path/to/changed_file.py --docker -v
```

### Integration tests

``` console
$ ansible-test integration <module_name you changed> --docker <container, e.g. ubuntu2204> -v
```

### Unit tests

``` console
$ ansible-test units tests/unit/plugins/unit_test_file.py --docker
```

### tox

You can run flake8 with tox to verify the quality of your code. For that you
can simply call tox with that command:
``` console
$ tox -e lint
```

If tox is missing on your environment you can probably install it through
your package manager (for example, `sudo apt install tox`) or with pip (within a
virtualenv):

``` console
$ python3 -m venv .venv
$ source .venv
$ pip install tox
```

### Automatically for each commit

This repo contains some pre-commit configuration to automatically check your
code foreach commit. To use that configuration you should "install" it by
running:

``` console
$ pre-commit install
```

Then autoflake, flake8, isort and codespell must run when you add some commits.
You can also force them to run with this command:

``` console
$ pre-commit run --all-file
```

If pre-commit is missing on your system, you can install it (on Debian based
system) with `apt`:

``` console
$ sudo apt install pre-commit
```
