#!/bin/bash

# Setup script for tests/common2/ development environment
# Based on requirements in INSTALL.md

set -e  # Exit on any error

echo "=== Setting up development environment for tests/common2/ ==="
echo

# Check if Python 3.9+ is available
echo "1. Checking Python version..."
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
required_version="3.9"

if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
    echo "✓ Python $python_version is installed (>= 3.9)"
else
    echo "✗ Python 3.9 or higher is required. Current version: $python_version"
    echo "  Please install Python 3.9+ from https://www.python.org/downloads/"
    exit 1
fi
echo

# Check if pip is available
echo "2. Checking pip..."
if command -v pip3 &> /dev/null; then
    pip_version=$(pip3 --version | cut -d' ' -f2)
    echo "✓ pip $pip_version is available"
else
    echo "✗ pip is not available"
    echo "  Please install pip (usually comes with Python)"
    exit 1
fi
echo

# Install system dependencies for enchant/aspell (Ubuntu/Debian)
echo "3. Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    echo "Detected apt-get, installing enchant and aspell dependencies..."
    sudo apt-get update
    sudo apt-get install -y libenchant-2-2 libenchant-2-dev aspell aspell-en
    echo "✓ System dependencies installed"
elif command -v yum &> /dev/null; then
    echo "Detected yum, installing enchant and aspell dependencies..."
    sudo yum install -y enchant2-devel aspell aspell-en
    echo "✓ System dependencies installed"
elif command -v brew &> /dev/null; then
    echo "Detected brew (macOS), installing enchant and aspell dependencies..."
    brew install enchant aspell
    echo "✓ System dependencies installed"
else
    echo "⚠ Could not detect package manager. Please manually install:"
    echo "  - enchant development libraries"
    echo "  - aspell and aspell-en"
    echo "  See INSTALL.md for details."
fi
echo

# Install Python packages
echo "4. Installing Python packages..."
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
requirements_file="$script_dir/requirements.txt"

if [ -f "$requirements_file" ]; then
    echo "Installing packages from requirements.txt..."
    pip3 install -r "$requirements_file"
    echo "✓ Python packages installed"
else
    echo "requirements.txt not found, installing packages individually..."
    pip3 install pre-commit pylint pyenchant black mypy reorder-python-imports flake8 types-PyYAML types-six types-paramiko
    echo "✓ Python packages installed"
fi
echo

# Navigate to repository root and install pre-commit hooks
echo "5. Setting up pre-commit hooks..."
# Find the repository root (look for .git directory)
repo_root="$script_dir"
while [ "$repo_root" != "/" ] && [ ! -d "$repo_root/.git" ]; do
    repo_root="$(dirname "$repo_root")"
done

if [ -d "$repo_root/.git" ]; then
    echo "Found git repository at: $repo_root"
    cd "$repo_root"

    # Install pre-commit hooks
    if [ -f ".pre-commit-config.yaml" ]; then
        pre-commit install
        echo "✓ Pre-commit hooks installed"

        # Optional: run pre-commit on all files to verify setup
        echo
        read -p "Would you like to run pre-commit on all files to verify the setup? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Running pre-commit on all files..."
            pre-commit run tests/common2 || echo "⚠ Some hooks failed - this is normal for initial setup"
        fi
    else
        echo "⚠ .pre-commit-config.yaml not found in repository root"
        echo "  Please ensure you're in the correct repository"
    fi
else
    echo "⚠ Could not find git repository root"
    echo "  Please run this script from within the git repository"
fi
echo

echo "=== Setup complete! ==="
echo
echo "Next steps:"
echo "1. Your development environment is ready"
echo "2. Pre-commit hooks will run automatically on git commits"
echo "3. To run pre-commit manually: pre-commit run --files <file1> <file2>"
echo "4. To run on staged files only: pre-commit run"
echo
echo "For more information, see INSTALL.md"
