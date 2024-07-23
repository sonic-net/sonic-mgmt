# Introduction

The `testbed-files` directory contains a series of ansible files in various directories
for quick setup of new sonic-test repositories and testbeds.

The main script is `copy_files.sh`, with the following usage:

```
sonic-test/testbed-files$ ./copy_files.sh -h
Usage:
  ./copy_files.sh <branch> [options]

    <branch> is the branch version for this TB to copy ansible files from. Different
    branches like '202012' vs '202311' have their own ansible file requirements.

Options:
  -b|--backup            Backup the current ansible files in the sonic-mgmt directory instead of copying them out.
  -s|--sonic_mgmt <dir>  Set the sonic-mgmt dir, default is /home/sonic/rapittma/sonic-test/sonic-mgmt
     --host <host>       Override the host name from defaulting to the current host (sonic-ucs-m6-13)
  -l|--list              List available branches for this host
  -v|--verbose           Turn on debugging logs
  -h|--help              This help log
```


The data directory contains ansible files based on UCS hostname and sonic-test branch version.
For example, here is the structure of one of the hosts/branch-versions:
```
sonic-test/testbed-files/data$ find . -type f -name "*"
./sonic-ucs-m6-13/202311/ansible/group_vars/vm_host/creds.yml
./sonic-ucs-m6-13/202311/ansible/group_vars/vm_host/main.yml
./sonic-ucs-m6-13/202311/ansible/group_vars/lab/lab.yml
./sonic-ucs-m6-13/202311/ansible/group_vars/all/ceos.yml
./sonic-ucs-m6-13/202311/ansible/group_vars/sonic/variables
./sonic-ucs-m6-13/202311/ansible/testbed.yaml
./sonic-ucs-m6-13/202311/ansible/testbed.csv
./sonic-ucs-m6-13/202311/ansible/veos
./sonic-ucs-m6-13/202311/ansible/host_vars/sonic-ucs-m6-13.yml
./sonic-ucs-m6-13/202311/ansible/lab
./sonic-ucs-m6-13/202311/ansible/files/sonic_lab_links.csv
./sonic-ucs-m6-13/202311/ansible/files/sonic_lab_devices.csv
./sonic-ucs-m6-13/202311/ansible/files/lab_connection_graph.xml
```


Since branch names are encoded into the directory structure, separate per-TB or
per-sonic-test-version branches are not needed to hold these files. Therefore, all files
present in this directory should be identical across all sonic-test branches. An example
workflow for committing new files is detailed [here](#backup-and-commit-process-for-new-files).


# Backup and commit process for new files

1) Ensure the ansible files are present in your sonic-mgmt/ansible directory and are ready to
be backed up.

2) Determine a branch name that clarifies the ansible files for this UCS. This would
typically be the base branch version of sonic-mgmt. For example, `202305` or `202311`.

3) Assuming the branch these ansible files are based on is `202405`, execute the following
command. When prompted, provide `y` to create the new 202405 directory to house these
files. (Click the arrow to see output)

<details>
<summary>

#### ./copy_files.sh 202405 --backup

</summary>

```
Data directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405 does not exist
Would you like to create it and continue backup? (y/n) y
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/lab from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/lab
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/veos from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/veos
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/all
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/all/ceos.yml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/all/ceos.yml
Skipping missing optional source file /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/eos/creds.yml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/vm_host
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/vm_host/creds.yml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/vm_host/creds.yml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/lab
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/lab/lab.yml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/lab/lab.yml
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/vm_host/main.yml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/vm_host/main.yml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/files
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/files/lab_connection_graph.xml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/files/sonic_lab_links.csv from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/files/sonic_lab_devices.csv from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/testbed.csv from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/testbed.csv
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/testbed.yaml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/testbed.yaml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/sonic
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/group_vars/sonic/variables from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/sonic/variables
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/host_vars
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202405/ansible/host_vars/sonic-ucs-m6-13.yml from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/host_vars/sonic-ucs-m6-13.yml
```
</details>

The script will now scan your current sonic-mgmt directory and backup the required files,
while also skipping files deemed optional.

4) Save and commit these files to a new master branch using the appropriate git
command sequence. For example:

```
git checkout master
git pull origin master
git checkout -b <my_username>/m6_13_202405_ansible
git add data/sonic-ucs-m6-13/202405
git commit -m "New ansible files for sonic-ucs-m6-13 based on 202405 branch."
git push origin <my_username>/m6_13_202405_ansible
```

5) File a PR for this branch against `master`.

6) Double commit the master PR hash to any applicable branch versions.  For example, if the
commit hash from the master merge is `1234abcd` (can be seen on the PR page after merge)
and we would like to double commit this change to 202405, the following commands can be
used:

```
git checkout 202405
git pull origin 202405
git checkout -b <my_username>/m6_13_202405_ansible_to_202405
git cherry-pick 1234abcd
git push origin <my_username>/m6_13_202405_ansible_to_202405
```

Then a PR for this branch can be filed against 202405.

# Example Workflows


## Copying saved ansible files to sonic-mgmt

Ansible files must be present in the data directory for this host and branch.
Check your hostname's data directory to see what versions are available:

```
sonic-test/testbed-files$ ./copy_files.sh -l
Possible branches to provide:
202311
```

If the branch you'd like to copy is present, the copy can be executed as:

```
sonic-test/testbed-files$ ./copy_files.sh 202311
Updating /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/lab with /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/lab
Updating /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/veos with /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/veos
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/all/ceos.yml
...
```

## Updating ansible file backup

After copying ansible, if you determine an update is needed to the ansible files that
needs to be committed, first make the change to the sonic-mgmt directory file and verify
it is correct, then use the `--backup` option. In this example, the ansible/lab file was
modified, so the script reports the file that was changed during the backup:

```
sonic-test/testbed-files$ ./copy_files.sh 202311 --backup
Updating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/lab with /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/lab
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/veos
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ceos.yml
...
```

The files in the `data` directory should then be committed to the `master` branch and
double committed to `202311` or other branches as needed.

## Copying ansible files from a different host

If a new TB needs ansible files, a copy can still be performed from other hosts as a
convenient starting point.  Suppose `sonic-ucs-other` is another UCS that has 202311
ansible files and we'd like to copy them despite the current host being
`sonic-ucs-m6-13`. We can provide the "--host" option to override the copy source
directory:
```
sonic-test/testbed-files$ ./copy_files.sh --host sonic-ucs-other 202311
Updating /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/lab with /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-other/202311/lab
Updating /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/veos with /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-other/202311/veos
...
```

Once the ansible files are modified to work for this host, the files can be backed up to a new directory via:
```
sonic-test/testbed-files$ ./copy_files.sh 202311 --backup
Data directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311 does not exist
Would you like to create it and continue backup? (y/n) y
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/lab from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/lab
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/veos from /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/veos
```

Note that because the directory doesn't exist yet, the script will prompt to create a new
directory `sonic-ucs-m6-13` and `202311` before continuing.

## Copying ansible files from a separate local repo

To copy ansible files for backup from another directory, use the `--sonic_mgmt`
option. When used in conjunction with `--backup` in this example, the script copies from
the provided sonic-mgmt directory over to a new backup location for 202311 in the current
repo.

```
 ./copy_files.sh 202311 --backup --sonic_mgmt ~/202311_whitebox/sonic-test/sonic-mgmt
Data directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311 does not exist
Would you like to create it and continue backup? (y/n) y
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/lab from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/lab
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/veos from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/veos
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/all
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/all/ceos.yml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/group_vars/all/ceos.yml
Skipping missing optional source file /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/group_vars/eos/creds.yml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/vm_host
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/vm_host/creds.yml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/group_vars/vm_host/creds.yml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/lab
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/lab/lab.yml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/group_vars/lab/lab.yml
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/vm_host/main.yml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/group_vars/vm_host/main.yml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/lab_connection_graph.xml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/sonic_lab_links.csv from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/sonic_lab_devices.csv from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/files/sonic_lab_devices.csv
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/testbed.csv from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/testbed.csv
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/testbed.yaml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/testbed.yaml
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/sonic
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/sonic/variables from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/group_vars/sonic/variables
Creating directory /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/host_vars
Creating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/host_vars/sonic-ucs-m6-13.yml from /home/sonic/202311_whitebox/sonic-test/sonic-mgmt/ansible/host_vars/sonic-ucs-m6-13.yml
```

# Technical notes

## Optional files

Note that the script only treats specific source files as optional, if a mandatory file is
missing the script will exit with an error.  The file `ansible/group_vars/eos/creds.yml`
is the only file considered optional. On the other hand, the `veos` file is not. Here is
an example output during a backup where the veos file has not been provided:

```
$ ./copy_files.sh 202311 -b
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/lab
ERROR: Missing required ansible file /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/veos
```

## Operational safety

The script actively checks git statuses to ensure the user is aware that uncommitted
changes are about to be overwritten.

Suppose we have copied the ansible files, then decided that the sonic_lab_links.csv file
needs an update. We go and modify the file, then try to backup the files. During the
backup however, we accidentally forget to include the `--backup` option. The script will
detect that 1) the source and destination do not match, and 2) the destination has
uncommitted git changes. It will then prompt the user to overwrite the file, where we can
then abort the operation with `no` or `quit`.

```
$ ./copy_files.sh 202311
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/lab
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/veos
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/all/ceos.yml
Skipping missing optional source file /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/eos/creds.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/vm_host/creds.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/lab/lab.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/group_vars/vm_host/main.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/lab_connection_graph.xml
WARNING: File /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv has uncommitted changes! Overwrite? (yes/no/quit)q
Exiting
```

If we instead decided that this is a known file change and are sure we want to delete it,
we could respond yes to overwrite the file:

```
WARNING: File /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv has uncommitted changes! Overwrite? (yes/no/quit)yes
Updating /home/sonic/rapittma/sonic-test/sonic-mgmt/ansible/files/sonic_lab_links.csv with /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/sonic_lab_links.csv
```

Another possible accidental use-case would be attempting to backup ansible files from a
different repo and not including the `--backup` flag. This could result in overwriting a
potentially clean repository's changes, so this also flags the changed git status before
overwriting.

In this example, a relative path is provided to a different git repo
`sonic-test-other`. The script changes directories to the other git repo to find its
status and flag a warning:

```
$ ./copy_files.sh 202311 --sonic_mgmt ../../sonic-test-other/sonic-mgmt
Copying testbed files from /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311 to /home/sonic/rapittma/sonic-test-other/sonic-mgmt
Already up-to-date: /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/lab
Already up-to-date: /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/veos
Already up-to-date: /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/group_vars/all/ceos.yml
Skipping missing optional source file /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/eos/creds.yml
Already up-to-date: /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/group_vars/vm_host/creds.yml
WARNING: File /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/group_vars/lab/lab.yml has uncommitted changes! Overwrite? (yes/no/quit)q
Exiting
```

Instead, if the `--backup` option is provided, the script will copy the remote directory
and update the local files as long as the locals do not have git changes:

```
$ ./copy_files.sh 202311 --sonic_mgmt ../../sonic-test-other/sonic-mgmt --backup
Backing up testbed files from /home/sonic/rapittma/sonic-test-other/sonic-mgmt to /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/lab
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/veos
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/all/ceos.yml
Skipping missing optional source file /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/group_vars/eos/creds.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/vm_host/creds.yml
Updating /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/lab/lab.yml with /home/sonic/rapittma/sonic-test-other/sonic-mgmt/ansible/group_vars/lab/lab.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/vm_host/main.yml
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/lab_connection_graph.xml
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/sonic_lab_links.csv
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/files/sonic_lab_devices.csv
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/testbed.csv
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/testbed.yaml
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/sonic/variables
Already up-to-date: /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/host_vars/sonic-ucs-m6-13.yml
```

If the local backup file also had changes about to be overwritten, this would be flagged as well:
```
./copy_files.sh 202311 --sonic_mgmt ../../sonic-test-other/sonic-mgmt --backup
...
WARNING: File /home/sonic/rapittma/sonic-test/testbed-files/data/sonic-ucs-m6-13/202311/ansible/group_vars/lab/lab.yml has uncommitted changes! Overwrite? (yes/no/quit)no
Skipping file overwrite due to git changes
...
```
