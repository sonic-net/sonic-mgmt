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
.PHONY: sanity
sanity: upgrade-collections
	cd ~/.ansible/collections/ansible_collections/vmware/vmware; \
	ansible-test sanity -v --color --coverage --junit --docker default

.PHONY: units
units: upgrade-collections
	cd ~/.ansible/collections/ansible_collections/vmware/vmware; \
	ansible-test units --docker --python 3.12 --coverage; \
	ansible-test coverage combine --export tests/output/coverage/; \
	ansible-test coverage report --docker --omit 'tests/*' --show-missing


.PHONY: integration
integration: install-integration-reqs upgrade-collections
	cd ~/.ansible/collections/ansible_collections/vmware/vmware; \
	ansible --version; \
	ansible-test --version; \
	ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections/ansible_collections ansible-galaxy collection list; \
	ANSIBLE_ROLES_PATH=~/.ansible/collections/ansible_collections/vmware/vmware/tests/integration/targets \
		ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections/ansible_collections \
		ansible-test integration $(CLI_ARGS);

.PHONY: eco-vcenter-ci
eco-vcenter-ci: tests/integration/integration_config.yml install-integration-reqs upgrade-collections
	cd ~/.ansible/collections/ansible_collections/vmware/vmware; \
	ansible --version; \
	ansible-test --version; \
	ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections/ansible_collections ansible-galaxy collection list; \
	chmod +x tests/integration/run_eco_vcenter_ci.sh; \
	ANSIBLE_ROLES_PATH=~/.ansible/collections/ansible_collections/vmware/vmware/tests/integration/targets \
		ANSIBLE_COLLECTIONS_PATH=~/.ansible/collections/ansible_collections \
		./tests/integration/run_eco_vcenter_ci.sh
