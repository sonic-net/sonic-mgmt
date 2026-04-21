mongodb_linux
=============

A simple role to configure Linux Operating System settings, for Debian and RedHat systems, as advised in the [MongoDB Production Notes](https://docs.mongodb.com/manual/administration/production-notes/).

A brief description of what we do in this role:

* Set swappiness.
* Ensure NTP (or equivalent) service is installed and running.
* Ensure GNU C Library is the latest available.
* Disable NUMA reclaim zone.
* Add script to disable transparent-huge-pages and setup as a service.
* Set pam limits.
* Set various sysctl values.

Role Variables
--------------

swappiness: OS swappiness value. Default "1".
mongodb_ntp_package: Name of ntp package. Default depends on OS-specific vars.
mongodb_ntp_service: Name of ntp service. Default depends on OS-specific vars.
mongodb_gnu_c_lib: Name of the GNU C lib. Default depends on OS-specific vars.

* On RedHat 8 and higher systems ntp_package and ntp_service are set to chrony and chronyd respectively.

Example Playbook
----------------

```yaml
    - hosts: servers
      roles:
         - mongodb_linux
```

License
-------

BSD

Author Information
------------------

Rhys Campbell (https://github.com/rhysmeister)
