# Maintainer Documentation

## See CONTRIBUTING.md for more tasks

[CONTRIBUTING.md](./CONTRIBUTING.md) contains more instructions that could
apply to contributors and not just maintainers (e.g. update ansible-core version).

## CI GCP Project Configuration

To enable running integration tests, a test GCP project must be provided.

There is a Google-maintained CI project, `ansible-gcp-ci`, that is used for this purpose. For any questions or modification to this project, please contact a maintainer who is employed by Google.

## Reviewing PRs

### Merging PRs

Since running the full set of integration tests requires the usage of GCP
credentials which are stored as a secret, maintainers must verify that tests pass the integration test run that runs on push to the master branch after accepting a change.

## Release Process

### Overview

The process is as follows:

1. Update the version of the collection.
1. Update the changelog.
2. Create a GitHub release to tag the repo and begin the publishing process.

### Steps

#### Update Collection Version

Modify the [galaxy.yaml](./galaxy.yml) file to the desired collection version:

```yaml
version: {NEW_VERSION}
```

Ansible collection versions [must follow SEMVER](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections_distributing.html#collection-versions).

Alpha / beta releases are optional.

#### Update the changelog

Providing a valid [CHANGELOG.rst](./CHANGELOG.rst) is required for a certifiable
collection release.

Use the [antsibull-changelog](https://github.com/ansible-community/antsibull-changelog)
tool to generate the changelog:

```sh
pip install antsibull-changelog
antsibull-changelog release
```

This will remove all the changelog fragments from ./changelogs/fragments and
merge them into CHANGELOG.rst.

### Send a PR and merge

Send a PR with these changes and merge them.

### Create a new GitHub release

Creating

- [publish to Ansible Galaxy](./.github/workflows/pythonpublish.yml).

### Publish to Automation Hub

*note*: As automation Hub only accepts production releases, this step
is only required for new full releases.

This step does not use GitHub actions, as API keys for Automation Hub
expire after 30 days of no use, and a maintainer may find themselves
refreshing tokens every time anyway.

Steps:

1. Build the package locally: `ansible-galaxy collection build .`
1. [Go to the Automation Hub my-namespaces page, then click on Google](https://console.redhat.com/ansible/automation-hub/repo/published/my-namespaces/google/)
1. Publish the package