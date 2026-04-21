#!/usr/bin/env bash
# Hold mongodb-org packages on RHEL and Debian based systems

set -e;
set -u;

HOLD="$1";
PACKAGE_NAME="mongodb-org*"

if [[ "$HOLD" == "HOLD" ]]; then
  if command -v dnf &> /dev/null; then
    dnf install "dnf-command(versionlock)"
    dnf versionlock "$PACKAGE_NAME" && touch /root/mongo_version_lock.success;
  elif command -v yum &> /dev/null; then
    yum versionlock "$PACKAGE_NAME" && touch /root/mongo_version_lock.success;
  elif command -v apt-mark  &> /dev/null; then
    apt-mark hold "$PACKAGE_NAME" && touch /root/mongo_version_lock.success;
  fi;
elif [[ "$HOLD" == "NOHOLD" ]]; then
  if command -v dnf &> /dev/null; then
    dnf install "dnf-command(versionlock)"
    dnf versionlock delete "$PACKAGE_NAME" || true && rm -rf /root/mongo_version_lock.success;
  elif command -v yum &> /dev/null; then
    yum versionlock delete "$PACKAGE_NAME" || true && rm -rf /root/mongo_version_lock.success;
  elif command -v apt-mark  &> /dev/null; then
    apt-mark unhold "$PACKAGE_NAME" && rm -rf /root/mongo_version_lock.success;
  fi;
else
  echo "No action taken";
fi;
