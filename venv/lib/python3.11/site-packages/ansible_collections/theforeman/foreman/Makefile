PYTHON_COMMAND ?= python
NAMESPACE := $(shell $(PYTHON_COMMAND) -c 'import yaml; print(yaml.safe_load(open("galaxy.yml"))["namespace"])')
NAME := $(shell $(PYTHON_COMMAND) -c 'import yaml; print(yaml.safe_load(open("galaxy.yml"))["name"])')
VERSION := $(shell $(PYTHON_COMMAND) -c 'import yaml; print(yaml.safe_load(open("galaxy.yml"))["version"])')
MANIFEST := build/collections/ansible_collections/$(NAMESPACE)/$(NAME)/MANIFEST.json

ROLES := $(wildcard roles/*)
PLUGIN_TYPES := $(filter-out __%,$(notdir $(wildcard plugins/*)))
RUNTIME_YML := meta/runtime.yml
METADATA := galaxy.yml LICENSE README.md $(RUNTIME_YML) requirements.txt changelogs/changelog.yaml CHANGELOG.rst bindep.txt PSF-license.txt meta/execution-environment.yml
TESTDATA := .ansible-lint Makefile pytest.ini $(shell find tests/ ! -type d ! -path '*/__pycache__/*' ! -path '*/test_playbooks/fixtures/*' ! -path '*/fixtures/apidoc/*')
$(foreach PLUGIN_TYPE,$(PLUGIN_TYPES),$(eval _$(PLUGIN_TYPE) := $(filter-out %__init__.py,$(wildcard plugins/$(PLUGIN_TYPE)/*.py)) $(wildcard plugins/$(PLUGIN_TYPE)/*.yml)))
DEPENDENCIES := $(METADATA) $(foreach PLUGIN_TYPE,$(PLUGIN_TYPES),$(_$(PLUGIN_TYPE))) $(foreach ROLE,$(ROLES),$(wildcard $(ROLE)/*/*)) $(foreach ROLE,$(ROLES),$(ROLE)/README.md) $(TESTDATA)

PYTHON_VERSION = $(shell $(PYTHON_COMMAND) -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')
COLLECTION_COMMAND ?= ansible-galaxy
SANITY_OPTS = --venv
TEST =
FLAGS =
PYTEST_COMMAND ?= $(PYTHON_COMMAND) -m pytest
PYTEST = $(PYTEST_COMMAND) -n 4 --forked
# PYTEST_ADDOPTS is exported to sub-shells and picked up by *all* pytest invocations
PYTEST_ADDOPTS ?= -vv
export PYTEST_ADDOPTS

APIPIE_VERSION ?= v0.7.0

default: help
help:
	@echo "Please use \`make <target>' where <target> is one of:"
	@echo "  help             to show this message"
	@echo "  info             to show infos about the collection"
	@echo "  lint             to run code linting"
	@echo "  test             to run unit tests"
	@echo "  livetest         to run test playbooks live (without vcr)"
	@echo "  sanity           to run santy tests"
	@echo "  setup            to set up test, lint"
	@echo "  test-setup       to install test dependencies"
	@echo "  lint-setup       to install lint dependencies"
	@echo "  test_<test>      to run a specific unittest"
	@echo "  livetest_<test>  to run a specific unittest live (without vcr)"
	@echo "  record_<test>    to (re-)record the server answers for a specific test"
	@echo "  clean_<test>     to run a specific test playbook with the teardown and cleanup tags"
	@echo "  dist             to build the collection artifact"

info:
	@echo "Building collection $(NAMESPACE)-$(NAME)-$(VERSION)"
	@echo -e "  roles:\n $(foreach ROLE,$(notdir $(ROLES)),   - $(ROLE)\n)"
	@echo -e " $(foreach PLUGIN_TYPE,$(PLUGIN_TYPES), $(PLUGIN_TYPE):\n $(foreach PLUGIN,$(basename $(notdir $(_$(PLUGIN_TYPE)))),   - $(PLUGIN)\n)\n)"

lint: $(MANIFEST) $(RUNTIME_YML) | tests/test_playbooks/vars/server.yml
	yamllint -f parsable tests/test_playbooks roles
	ansible-lint -v --offline
	ansible-playbook --syntax-check tests/test_playbooks/*.yml | grep -v '^$$'
	flake8 --ignore=E402,W503 --max-line-length=160 plugins/ tests/
	@echo "Check that there are no changes to $(RUNTIME_YML)"
	git diff --exit-code $(RUNTIME_YML)

galaxy-importer: $(MANIFEST)
	GALAXY_IMPORTER_CONFIG=tests/galaxy-importer.cfg $(PYTHON_COMMAND) -m galaxy_importer.main $(NAMESPACE)-$(NAME)-$(VERSION).tar.gz

sanity: $(MANIFEST)
	# Fake a fresh git repo for ansible-test
	cd $(<D) ; git init ; echo tests > .gitignore ; ansible-test sanity $(SANITY_OPTS) --python $(PYTHON_VERSION)

test: $(MANIFEST) | tests/test_playbooks/vars/server.yml
	$(PYTEST) $(TEST)

test-crud: $(MANIFEST) | tests/test_playbooks/vars/server.yml
	$(PYTEST) 'tests/test_crud.py::test_crud' 'tests/test_crud.py::test_inventory'

test-check-mode: $(MANIFEST) | tests/test_playbooks/vars/server.yml
	$(PYTEST) 'tests/test_crud.py::test_check_mode'

test-other:
	$(PYTEST) -k 'not test_crud.py'

livetest: $(MANIFEST) | tests/test_playbooks/vars/server.yml
	$(PYTEST_COMMAND) 'tests/test_crud.py::test_crud' --vcrmode live $(FLAGS)

test_%: FORCE $(MANIFEST) | tests/test_playbooks/vars/server.yml
	$(PYTEST_COMMAND) 'tests/test_crud.py::test_crud[$*]' 'tests/test_crud.py::test_check_mode[$*]' $(FLAGS)

livetest_%: FORCE $(MANIFEST) | tests/test_playbooks/vars/server.yml
	$(PYTEST_COMMAND) 'tests/test_crud.py::test_crud[$*]' --vcrmode live $(FLAGS)

record_%: FORCE $(MANIFEST)
	$(RM) tests/test_playbooks/fixtures/$*-*.yml
	$(PYTEST_COMMAND) 'tests/test_crud.py::test_crud[$*]' --vcrmode record $(FLAGS)

clean_%: FORCE $(MANIFEST)
	ansible-playbook --tags teardown,cleanup -i tests/inventory/hosts 'tests/test_playbooks/$*.yml'

setup: test-setup

lint-setup: | tests/test_playbooks/vars/server.yml
	$(PYTHON_COMMAND) -m pip install --upgrade pip
	$(PYTHON_COMMAND) -m pip install --upgrade -r requirements-lint.txt

test-setup: | tests/test_playbooks/vars/server.yml
	$(PYTHON_COMMAND) -m pip install --upgrade pip
	$(PYTHON_COMMAND) -m pip install --upgrade -r requirements-dev.txt

tests/test_playbooks/vars/server.yml:
	cp $@.example $@
	@echo "For recording, please adjust $@ to match your reference server."

dist-test: $(MANIFEST)
	FOREMAN_SERVER_URL=https://foreman.example.test ansible -m $(NAMESPACE).$(NAME).organization -a "username=admin password=changeme name=collectiontest" localhost | grep -q "Failed to connect to Foreman server.*foreman.example.test"
	FOREMAN_SERVER_URL=https://foreman.example.test ansible -m $(NAMESPACE).$(NAME).foreman_organization -a "username=admin password=changeme name=collectiontest" localhost | grep -q "Failed to connect to Foreman server.*foreman.example.test"
	FOREMAN_SERVER_URL=http://foreman.example.test ansible -m $(NAMESPACE).$(NAME).organization -a "username=admin password=changeme name=collectiontest" localhost 2>&1| grep -q "You have configured a plain HTTP server URL."
	ansible-doc $(NAMESPACE).$(NAME).organization | grep -q "Manage Organization"

$(MANIFEST): $(NAMESPACE)-$(NAME)-$(VERSION).tar.gz
	ansible-galaxy collection install -p build/collections $< --force

build/src/%: %
	install -m 644 -DT $< $@

build/src/tests/test_%.py: FORCE
	install -m 644 -DT tests/test_$*.py $@

$(NAMESPACE)-$(NAME)-$(VERSION).tar.gz: $(addprefix build/src/,$(DEPENDENCIES))
	ansible-galaxy collection build build/src --force

dist: $(NAMESPACE)-$(NAME)-$(VERSION).tar.gz

publish: $(NAMESPACE)-$(NAME)-$(VERSION).tar.gz
	ansible-galaxy collection publish --api-key $(GALAXY_API_KEY) $<

clean:
	rm -rf build docs/plugins

doc-setup:
	$(PYTHON_COMMAND) -m pip install --upgrade -r docs/requirements.txt
doc: $(MANIFEST)
	mkdir -p ./docs/plugins ./docs/roles
	cat ./docs/roles.rst.template > ./docs/roles/index.rst
	for role_readme in roles/*/README.md; do \
		ln -f -s ../../$$role_readme ./docs/roles/$$(basename $$(dirname $$role_readme)).md; \
		echo " * :doc:\`$$(basename $$(dirname $$role_readme))\`" >> ./docs/roles/index.rst; \
	done
	antsibull-docs collection --use-current --squash-hierarchy --dest-dir ./docs/plugins $(NAMESPACE).$(NAME)
	make -C docs html

vendor:
	git clone --depth=1 --branch=$(APIPIE_VERSION) https://github.com/Apipie/apypie/ build/apypie-git
	$(PYTHON_COMMAND) vendor.py build/apypie-git/apypie/*.py > plugins/module_utils/_apypie.py

$(RUNTIME_YML): FORCE
	$(PYTHON_COMMAND) generate_action_groups.py

FORCE:

.PHONY: help dist lint sanity test test-crud test-check-mode test-other livetest setup test-setup lint-setup doc-setup doc publish FORCE
