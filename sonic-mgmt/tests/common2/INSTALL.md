# Setup Instructions

## Automatic Installation

A script `setup_environment.sh` is available to setup the development environment. This installs the required software and pre-commit hooks that are used to validate commits made to tests/common2 directory.

## Manual Installation

Alternatively to manually install the software packages follow the steps below.

### 1. Python

Version: Python 3.9 or higher
Install from: https://www.python.org/downloads/

### 2. pip (Python package manager)

Usually comes with Python
Verify with: `pip --version`

### 3. pre-commit

Used to run automated checks before commits
Install via pip: `pip install pre-commit`

### 4. pylint and penchant

Install pylint and pyenchant required for pylint and spelling linters.
Install via pip: `pip install pylint penchant`

### 5. aspell (for spelling checks)

On Ubuntu/Debian:
```
sudo apt-get install libenchant-2-2 libenchant-2-dev
sudo apt-get install aspell aspell-en
```

## Initial Setup Steps

Once the required software is installed, follow these steps:

### 1. Install Pre-commit Hooks
Run this command in the root of the repository:
```
pre-commit install
```

This sets up the Git hook to run pre-commit checks automatically before each commit.

### 2. Run Pre-commit Manually (Optional)
To run only on staged files:
```
pre-commit run --files $(git diff --cached --name-only)
```
