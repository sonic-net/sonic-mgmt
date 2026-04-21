# Also needs to be updated in galaxy.yml
VERSION = 6.2.0

TEST_ARGS ?= ""
PYTHON_VERSION ?= `python -c 'import platform; print(".".join(platform.python_version_tuple()[0:2]))'`

clean:
	rm -f kubernetes-core-${VERSION}.tar.gz
	rm -rf ansible_collections
	rm -rf tests/output

build: clean
	ansible-galaxy collection build

release: build
	ansible-galaxy collection publish kubernetes-core-${VERSION}.tar.gz

install: build
	ansible-galaxy collection install -p ansible_collections kubernetes-core-${VERSION}.tar.gz

test-sanity:
	ansible-test sanity --docker -v --color --python $(PYTHON_VERSION) $(?TEST_ARGS)

test-integration:
	ansible-test integration --diff --no-temp-workdir --color --skip-tags False --retry-on-error --continue-on-error --python $(PYTHON_VERSION) -v --coverage $(?TEST_ARGS)

test-unit:
	ansible-test units --docker -v --color --python $(PYTHON_VERSION) $(?TEST_ARGS)
