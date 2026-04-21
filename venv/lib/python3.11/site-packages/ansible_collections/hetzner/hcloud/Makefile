SHELL := bash
.PHONY: vendor clean dev

dev:
	cat tests/integration/cloud-config-hcloud.ini.in | envsubst > tests/integration/cloud-config-hcloud.ini

vendor:
	python3 scripts/vendor.py

vendor-check:
	python3 scripts/vendor.py --check

venv:
	python3 -m venv venv
	venv/bin/pip install -r requirements.txt -r requirements-dev.txt

lint: venv
	venv/bin/pylint plugins

lint-docs: venv
	venv/bin/antsibull-docs lint-collection-docs \
		--plugin-docs \
		--validate-collection-refs self \
		--check-extra-docs-refs \
		.

clean:
	git clean -xdf

sanity:
	ansible-test sanity --color --truncate 0 -v \
		--exclude plugins/module_utils/vendor/ \
		--exclude scripts/ \
		--exclude tests/utils/ \
		--docker default \
		--allow-disabled

units:
	ansible-test units --color --truncate 0 -v \
		--docker default

integration:
	ansible-test integration --color --truncate 0 -v \
		--docker default \
		--allow-disabled
