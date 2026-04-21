# Contributing to the google.cloud collection

## Workflow summary

1. [Clone the repository](#cloning).
1. Make the desired code change.
1. Add a [changelog fragment](https://docs.ansible.com/ansible/devel/community/development_process.html#changelogs-how-to) to describe your change.
1. [Run integration tests locally and ensure they pass](running-integration-tests).
1. Create a PR.

## Cloning

The `ansible-test` command expects that the repository is in a directory that matches it's collection,
under a directory `ansible_collections`. Clone ensuring that hierarchy:

```shell
mkdir -p $TARGET_DIR/ansible_collections/google
git clone <url> $TARGET_DIR/ansible_collections/google/cloud
```

Then set up your Python virtual environment:

```shell
cd $TARGET_DIR/ansible_collections/google/cloud
python3 -m venv venv
. ./venv/bin/activate
pip3 install -r requirements.txt
pip3 install -r requirements-test.txt
pip3 install ansible
```

## Running tests

### Prequisites for all tests

- Install `gcloud` following [these instructions](https://cloud.google.com/sdk/docs/install).
- Install the `ansible` package.
- Some container runtime is necessary (e.g. `podman` or `docker`). The instructions use podman.

## Running integration tests

### Integration testing prequisites

#### Authentication with personal GCP credentials

If you are running the integration tests locally the easiest way to
authenticate to GCP is using [application default credentials](https://cloud.google.com/sdk/docs/authorizing#adc).
Once you have installed `gcloud` and performed basic initialization (via `gcloud init`) run:

```shell
gcloud auth application-default login
```

#### Authentication with service account credentials

A service account may also be used to run the integration tests. You can create one using `gcloud`:

```shell
gcloud iam service-accounts create ansible-test-account \
    --description="For running Anisble integration tests" \
    --display-name="Ansible Test Account"
```

You'll also need to export a key file. Here and below `$SERVICE_ACCOUNT_NAME`
is the full email address of the service account, in the form
`EMAIL@PROJECT_ID.iam.gserviceaccount.com`, e.g., if you used the
account name `ansible-test-account` as suggested above and your project
ID is `my-test-project`, use `ansible-test-account@my-test-project.iam.gserviceaccount.com`.

```shell
gcloud iam service-accounts keys create /path/to/cred/file.json \
    --iam-account=ansible-test-account@my-test-project.iam.gserviceaccount.com
chmod 0600 /path/to/cred/file.json
```

Read the [best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
to learn how to keep your service account key and your GCP resources safe.

#### Configuring test credentials

The integration tests for this module require the use of real GCP credentials, and must provide
ansible-test those values. They can be added by creating the file `tests/integration/cloud-config-gcp.ini`.

If you are using personal (i.e., application default) credentials, add:

```
[default]
gcp_project: $PROJECT_ID
gcp_cred_kind: application
gcp_folder_id: $TEST_FOLDER (to create test projects)
```

If you are using a service account for credentials, add:

```
[default]
gcp_project: $PROJECT_ID
gcp_cred_file: /path/to/cred/file.json
gcp_cred_kind: serviceaccount
gcp_folder_id: $TEST_FOLDER (to create test projects)
```

#### Setting up the project for testing

Some of the setup of the project itself is done outside of the test,
and is expected to be configured beforehand.

For convenience, a bootstrap script is provided.

NOTE: running this script will make irreversible changes in your
GCP project (e.g. create an AppEngine project). You can omit
`$SERVICE_ACCOUNT_NAME` is you are using application default credentials.

```bash
bash ./scripts/bootstrap-project.sh $PROJECT_ID $SERVICE_ACCOUNT_NAME
```

### Running

Run `ansible-test integration`. Currently some tests are disabled as [test are being verified and added](https://github.com/ansible-collections/google.cloud/issues/499).

## Role tests

### Prequisites for role tests

If you would like to use podman, you must
install the `molecule-plugins[podman]` package in PyPI:

```
pip install --upgrade molecule-plugins[podman]
```

### Running role tests

Ansible roles are tested via molecule.

```sh
module debug --test -s ${ROLE}
```

Role is the name of the role (e.g. gcloud, gcsfuse).

Add `-d podman` if you would like to use the podman driver.

If the linting fails, that is generally due to `ansible-lint`, which can be run directly:

```
ansible-lint
```

## Specific Tasks

The following enumerates detailed documentation for specific tasks related to
the codebase.

### Updating the supported ansible-core version

1. modify the [ansible-integration-tests.yaml](.github/workflows/ansible-integration-tests.yml) to the version of ansible-core that you would like to test against.
1. (optional) update the version of ansible-core version required in [meta/runtime.yaml](meta/runtime.yml).