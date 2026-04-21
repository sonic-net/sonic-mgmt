.PHONY: molecule

# Also needs to be updated in galaxy.yml
VERSION = 5.0.0

SANITY_TEST_ARGS ?= --docker --color
UNITS_TEST_ARGS ?= --docker --color
PYTHON_VERSION ?= `python3 -c 'import platform; print("{0}.{1}".format(platform.python_version_tuple()[0], platform.python_version_tuple()[1]))'`

clean:
	rm -f community-okd-$(VERSION).tar.gz
	rm -f redhat-openshift-$(VERSION).tar.gz
	rm -rf ansible_collections

build: clean
	ansible-galaxy collection build

install: build
	ansible-galaxy collection install --force -p ansible_collections community-okd-$(VERSION).tar.gz

sanity: install
	cd ansible_collections/community/okd && ansible-test sanity -v --python $(PYTHON_VERSION) $(SANITY_TEST_ARGS)

units: install
	cd ansible_collections/community/okd && ansible-test units -v --python $(PYTHON_VERSION) $(UNITS_TEST_ARGS)

molecule: install
	molecule test

test-integration: upstream-test-integration downstream-test-integration

test-sanity: upstream-test-sanity downstream-test-sanity

test-units: upstream-test-units downstream-test-units

test-integration-incluster:
	./ci/incluster_integration.sh

upstream-test-sanity: sanity

upstream-test-units: units

upstream-test-integration: molecule

downstream-test-sanity:
	./ci/downstream.sh -s

downstream-test-units:
	./ci/downstream.sh -u

downstream-test-integration:
	./ci/downstream.sh -i

downstream-build:
	./ci/downstream.sh -b
