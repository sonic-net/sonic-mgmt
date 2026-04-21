SHELL := /bin/bash

# To tell ansible-test and Make to not kill the containers on failure or
# end of tests. Disabled by default.
ifdef keep_containers_alive
	_keep_containers_alive = --docker-terminate never
endif

# This match what GitHub Action will do. Disabled by default.
ifdef continue_on_errors
	_continue_on_errors = --continue-on-error
endif

# Set command variables based on database engine
# Required for MariaDB 11+ which no longer includes mysql named compatible
# executable symlinks
ifeq ($(db_engine_name),mysql)
	_command = mysqld
	_health_cmd = mysqladmin
else
	_command = mariadbd
	_health_cmd = mariadb-admin
endif

.PHONY: test-integration
test-integration:
	@echo -n $(db_engine_name) > tests/integration/db_engine_name
	@echo -n $(db_engine_version) > tests/integration/db_engine_version
	@echo -n $(connector_name) > tests/integration/connector_name
	@echo -n $(connector_version) > tests/integration/connector_version
	@echo -n $(ansible) > tests/integration/ansible

	# Create podman network for systems missing it. Error can be ignored
	podman network create podman || true
	podman run \
		--detach \
		--replace \
		--name primary \
		--env MARIADB_ROOT_PASSWORD=msandbox \
		--env MYSQL_ROOT_PASSWORD=msandbox \
		--network podman \
		--publish 3307:3306 \
		--health-cmd '$(_health_cmd) ping -P 3306 -pmsandbox | grep alive || exit 1' \
		docker.io/library/$(db_engine_name):$(db_engine_version) \
		$(_command)
	podman run \
		--detach \
		--replace \
		--name replica1 \
		--env MARIADB_ROOT_PASSWORD=msandbox \
		--env MYSQL_ROOT_PASSWORD=msandbox \
		--network podman \
		--publish 3308:3306 \
		--health-cmd '$(_health_cmd) ping -P 3306 -pmsandbox | grep alive || exit 1' \
		docker.io/library/$(db_engine_name):$(db_engine_version) \
		$(_command)
	podman run \
		--detach \
		--replace \
		--name replica2 \
		--env MARIADB_ROOT_PASSWORD=msandbox \
		--env MYSQL_ROOT_PASSWORD=msandbox \
		--network podman \
		--publish 3309:3306 \
		--health-cmd '$(_health_cmd) ping -P 3306 -pmsandbox | grep alive || exit 1' \
		docker.io/library/$(db_engine_name):$(db_engine_version) \
		$(_command)
	# Setup replication and restart containers using the same subshell to keep variables alive
	db_ver=$(db_engine_version); \
	maj="$${db_ver%.*.*}"; \
	maj_min="$${db_ver%.*}"; \
	min="$${maj_min#*.}"; \
	if [[ "$(db_engine_name)" == "mysql" && "$$maj" -eq 8 && "$$min" -ge 2 ]]; then \
		prima_conf='[mysqld]\\nserver-id=1\\nlog-bin=/var/lib/mysql/primary-bin\\nmysql-native-password=1'; \
		repl1_conf='[mysqld]\\nserver-id=2\\nlog-bin=/var/lib/mysql/replica1-bin\\nmysql-native-password=1'; \
		repl2_conf='[mysqld]\\nserver-id=3\\nlog-bin=/var/lib/mysql/replica2-bin\\nmysql-native-password=1'; \
	else \
		prima_conf='[mysqld]\\nserver-id=1\\nlog-bin=/var/lib/mysql/primary-bin'; \
		repl1_conf='[mysqld]\\nserver-id=2\\nlog-bin=/var/lib/mysql/replica1-bin'; \
		repl2_conf='[mysqld]\\nserver-id=3\\nlog-bin=/var/lib/mysql/replica2-bin'; \
	fi; \
	podman exec -e cnf="$$prima_conf" primary bash -c 'echo -e "$${cnf//\\n/\n}" > /etc/mysql/conf.d/replication.cnf'; \
	podman exec -e cnf="$$repl1_conf" replica1 bash -c 'echo -e "$${cnf//\\n/\n}" > /etc/mysql/conf.d/replication.cnf'; \
	podman exec -e cnf="$$repl2_conf" replica2 bash -c 'echo -e "$${cnf//\\n/\n}" > /etc/mysql/conf.d/replication.cnf'
	# Don't restart a container unless it is healthy
	while ! podman healthcheck run primary && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	podman restart -t 30 primary
	while ! podman healthcheck run replica1 && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	podman restart -t 30 replica1
	while ! podman healthcheck run replica2 && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	podman restart -t 30 replica2
	while ! podman healthcheck run primary && [[ "$$SECONDS" -lt 120 ]]; do sleep 1; done
	mkdir -p .venv/$(ansible)
	python$(local_python_version) -m venv .venv/$(ansible)

	# Start venv (use `; \` to keep the same shell)
	source .venv/$(ansible)/bin/activate; \
	python$(local_python_version) -m ensurepip; \
	python$(local_python_version) -m pip install --disable-pip-version-check \
	https://github.com/ansible/ansible/archive/$(ansible).tar.gz; \
	set -x; \
	ansible-test integration $(target) -v --color --coverage --diff \
	--docker ubuntu2204 \
	--docker-network podman $(_continue_on_errors) $(_keep_containers_alive); \
	set +x
	# End of venv

	rm tests/integration/db_engine_name
	rm tests/integration/db_engine_version
	rm tests/integration/connector_name
	rm tests/integration/connector_version
	rm tests/integration/ansible
ifndef keep_containers_alive
	podman stop --time 0 --ignore primary replica1 replica2
	podman rm --ignore --volumes primary replica1 replica2
endif
