#!/bin/bash

# TODO: Add a cleanup option to remove only relevant ansible changes.

set -e

program=$(readlink -f $0)

# Get testbed-files and git root directory
tb_dir=$(dirname $program)
root=$(dirname $tb_dir)
trim=$(dirname $root)
def_sonic_mgmt=${root}/sonic-mgmt


# Options
is_help=no
is_verbose=no
is_backup=no
is_list=no
# Options with parameters
is_sm=no
sm_dir="$def_sonic_mgmt"
is_host=no
host=$(hostname)

# Positional
has_branch=no
while test $# -gt 0; do
    case "$1" in
        -h|--help)
            is_help=yes
            shift 1
            ;;
        -v|--verbose)
            is_verbose=yes
            shift 1
            ;;
        -s|--sonic_mgmt)
            is_sm=yes
            if test -z $2; then
                echo "--sonic_mgmt requires a parameter"
                exit 1
            fi
            sm_dir=$2
            shift 2
            ;;
        --host)
            is_host=yes
            if test -z $2; then
                echo "--host requires a parameter"
                exit 1
            fi
            host=$2
            shift 2
            ;;
        -b|--backup)
            is_backup=yes
            shift 1
            ;;
        -l|--list)
            is_list=yes
            shift 1
            ;;
        -*)
            echo "Invalid option $1"
            exit 1
            ;;
        *)
            if test $has_branch = "yes"; then
                echo "Too many args, unexpected '$1'"
                exit 1
            fi
            has_branch=yes
            branch=$1
            shift 1
            ;;
    esac
done

verb() {
    if test "$is_verbose" = "yes"; then
        echo "DEBUG: $1"
    fi
}

verb "Program: $program"
verb "Root dir: $root"
verb "TB files dir: $tb_dir"
verb "default sm dir: $def_sonic_mgmt"

USAGE_STRING="Usage:
  ./copy_files.sh <branch> [options]

    <branch> is the branch version for this TB to copy ansible files from. Different
    branches like '202012' vs '202311' have their own ansible file requirements.

Options:
  -b|--backup            Backup the current ansible files in the sonic-mgmt directory instead of copying them out.
  -s|--sonic_mgmt <dir>  Set the sonic-mgmt dir, default is $def_sonic_mgmt
     --host <host>       Override the host name from defaulting to the current host ($(hostname))
  -l|--list              List available branches for this host
  -v|--verbose           Turn on debugging logs
  -h|--help              This help log"

if test $is_help = "yes"; then
    echo "$USAGE_STRING"
    exit 0
fi

# Requires base of filename to match the name of the backed-up file.
all_files="
ansible/lab
ansible/veos
ansible/group_vars/all/ceos.yml
ansible/group_vars/eos/creds.yml
ansible/group_vars/vm_host/creds.yml
ansible/group_vars/lab/lab.yml
ansible/group_vars/vm_host/main.yml
ansible/files/lab_connection_graph.xml
ansible/files/sonic_lab_links.csv
ansible/files/sonic_lab_devices.csv
ansible/testbed.csv
ansible/testbed.yaml
ansible/group_vars/sonic/variables
ansible/host_vars/${host}.yml
"

# Some files are useful for specific situations, but not required everwhere. Allow
# specific files to be missing from a copy/backup operation.
optional_files="
ansible/group_vars/eos/creds.yml
"

is_optional() {
    is_optional=no
    for f in $optional_files; do
        if test $1 = $f; then
            echo yes
            return
        fi
    done
    echo no
}

# TODO: sonic-mgmt version to select these files
# Old: <=202305
# ansible/testbed.csv
# ansible/files/lab_connection_graph.xml
# New: >=202311
# ansible/files/sonic_lab_links.csv
# ansible/files/sonic_lab_devices.csv
# ansible/testbed.yaml


list_branches() {
    if test ! -d $tb_dir/data/$host; then
        echo "No branches available, no host directory for this UCS yet (${host})"
        exit 1
    else
        echo "Possible branches to provide:"
        ls $tb_dir/data/$host
    fi
}

if test "$is_list" = "yes"; then
    list_branches
    exit 0
fi

if test $has_branch != "yes"; then
    echo "Missing required <branch> argument"
    list_branches
    exit 1
fi

data_dir=$tb_dir/data/$host/$branch
if test ! -d $data_dir; then
    echo "Data directory $data_dir does not exist"
    if test $is_backup = "yes"; then
        echo -n "Would you like to create it and continue backup? (y/n) "
        read answer
        while true; do
            case "$answer" in
                y|yes)
                    mkdir -p $data_dir
                    break
                    ;;
                n|no|q|quit)
                    echo "Exiting"
                    exit 0
                    ;;
                *)
                    echo "Invalid option"
                    ;;
            esac
            echo -n "Would you like to create it and continue backup? (y/n) "
            read answer
        done
    else
        echo "Copy failed"
        exit 1
    fi
fi

if test ! -d $sm_dir; then
    echo "Sonic-mgmt directory $sm_dir does not exist"
    exit 1
fi

sm_dir=$(readlink -f $sm_dir) # Could be a relative link, bad for git status check

# Src dst interpretation
src=$data_dir
dst=$sm_dir
if test $is_backup = "yes"; then
    action="Backing up testbed files from $dst to $src"
else
    action="Copying testbed files from $src to $dst"
fi
echo $action

# Iterate over sonic-mgmt file-names
for sm_fname in $all_files; do
    src_file=${data_dir}/${sm_fname}
    dst_file=${sm_dir}/${sm_fname}
    if test $is_backup = "yes"; then
        # Invert src/dst
        tmp_src_file=$src_file
        src_file=$dst_file
        dst_file=$tmp_src_file
    fi

    verb "Source file: $src_file"
    verb "Dest file:   $dst_file"

    # Check if source exists
    if test ! -f $src_file; then
        # Check if this is an optional file
        is_opt=$(is_optional $sm_fname)
        verb "Optional: $is_opt"
        if test $is_opt = yes; then
            echo "Skipping missing optional source file $src_file"
            continue
        fi
        # Required file, fail
        echo "ERROR: Missing required ansible file $src_file"
        exit 1
    fi

    # Copy the src file if the destination doesn't exist or if the checksum doesn't match
    if test -f $dst_file; then
        if test "$(cksum $src_file | cut -d ' ' -f1)" != "$(cksum $dst_file | cut -d ' ' -f1)"; then
            overwrite=yes
            # This operation overwrites a file, which may lose git changes, possibly by
            # accident. Prompt user to confirm overwrite. Use a sub-shell and change
            # directory in case destination is in another repository.
            is_modified=$($(cd $(dirname $dst_file) && git diff -s --exit-code $dst_file) && echo no || echo yes)
            if test $is_modified = yes; then
                msg="WARNING: File $dst_file has uncommitted changes! Overwrite? (yes/no/quit)"
                echo -n $msg
                read answer
                while true; do
                    case "$answer" in
                        y|yes)
                            overwrite=yes
                            break
                            ;;
                        n|no)
                            overwrite=no
                            break
                            ;;
                        q|quit)
                            echo "Exiting"
                            exit 0
                            ;;
                        *)
                            echo "Invalid option"
                            ;;
                    esac
                    echo -n $msg
                    read answer
                done

            fi

            if test $overwrite = yes; then
                echo "Updating $dst_file with $src_file"
                cp $src_file $dst_file
            else
                echo "Skipping file overwrite due to git changes"
            fi
        else
            echo "Already up-to-date: $dst_file"
        fi
    else
        dst_dir=$(dirname $dst_file)
        if test ! -d $dst_dir; then
            echo "Creating directory $dst_dir"
            mkdir -p $dst_dir
        fi
        echo "Creating $dst_file from $src_file"
        cp $src_file $dst_file
    fi
done

# TODO: Manage password file
echo cisco123 > $dst/ansible/password.txt
