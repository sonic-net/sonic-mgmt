#!/usr/bin/env bash

source "$(pwd)/tools/includes/utils.sh"

source "./tools/includes/logging.sh"

# output the heading
heading "Grafana Ansible Collection" "Performing Setup Checks"

# make sure Node exists
info "Checking to see if Node is installed"
if [[ "$(command -v node)" = "" ]]; then
  warning "node is required if running lint locally, see: (https://nodejs.org) or run: brew install nvm && nvm install 18";
else
  success "node is installed"
fi

# make sure yarn exists
info "Checking to see if yarn is installed"
if [[ "$(command -v yarn)" = "" ]]; then
  warning "yarn is required if running lint locally, see: (https://yarnpkg.com) or run: brew install yarn";
else
  success "yarn is installed"
fi

# make sure shellcheck exists
info "Checking to see if shellcheck is installed"
if [[ "$(command -v shellcheck)" = "" ]]; then
  warning "shellcheck is required if running lint locally, see: (https://shellcheck.net) or run: brew install nvm && nvm install 18";
else
  success "shellcheck is installed"
fi

# make sure pipenv exists
if [[ "$(command -v pipenv)" = "" ]]; then
  warning "pipenv command is required, see (https://pipenv.pypa.io/en/latest/) or run: brew install pipenv";
else
  success "pipenv is installed"
fi
