# setup commands
.PHONY: upgrade-collections
upgrade-collections:
	ansible-galaxy collection install --upgrade -p ~/.ansible/collections .

.PHONY: install-collection-python-reqs
install-collection-python-reqs:
	pip install -r requirements.txt

.PHONY: install-integration-reqs
install-integration-reqs: install-collection-python-reqs
	pip install -r tests/integration/requirements.txt; \
	ansible-galaxy collection install --upgrade -p ~/.ansible/collections -r tests/integration/requirements.yml

tests/integration/integration_config.yml:
	chmod +x ./tests/integration/generate_integration_config.sh; \
	./tests/integration/generate_integration_config.sh

# test commands
.PHONY: linters
linters:  ## Run extra linter tests
	@pip install -r linters.requirements.txt; err=0; echo "\nStart tests.\n"; \
	black --check --diff --color . || err=1; \
	if [ "$$err" = 1 ]; then echo "\nAt least one linter failed\n" >&2; exit 1; fi

.PHONY: sanity
sanity: upgrade-collections
	cd ~/.ansible/collections/ansible_collections/vmware/vmware_rest; \
	ansible-test sanity -v --color --coverage --junit --docker default

.PHONY: eco-vcenter-ci
eco-vcenter-ci: tests/integration/integration_config.yml install-integration-reqs upgrade-collections
	rm -rf ~/.ansible/collections/ansible_collections/cloud/common; \
	cd ~/.ansible/collections/ansible_collections/vmware/vmware_rest; \
	ansible --version; \
	ansible-test --version; \
	ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections/ansible_collections ansible-galaxy collection list; \
	chmod +x tests/integration/run_eco_vcenter_ci.sh; \
	ANSIBLE_ROLES_PATH=~/.ansible/collections/ansible_collections/vmware/vmware_rest/tests/integration/targets \
		ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections/ansible_collections \
		./tests/integration/run_eco_vcenter_ci.sh
