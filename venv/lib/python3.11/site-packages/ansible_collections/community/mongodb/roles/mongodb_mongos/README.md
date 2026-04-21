mongodb_mongos
==============

A role to setup a mongos server for a MongoDB sharded cluster.

Requirements
------------

Any pre-requisites that may not be covered by Ansible itself or the role should
be mentioned here. For instance, if the role uses the EC2 module, it may be a
good idea to mention in this section that the boto package is required.

Role Variables
--------------

* `mongos_port`: The port used by the mongos process. Default `27017`.
* `mongos_service`: The name of the mongos service. Default `mongos`.
* `mongodb_user`: The Linux OS user for MongoDB. Default `mongod`.
* `mongodb_group`: The Linux OS user group for MongoDB. Default `mongod`.
* `pid_file`: The pid file for mongos. Default `/run/mongodb/mongos.pid`.
* `bind_ip`: The IP address mongos will bind to. Default `0.0.0.0`.
* `bind_ip_all`: Have mongos bind to all IP addresses instead of specifying `bind_ip`. Default `false`.
* `log_path`: Path of the log file. Default: `/var/log/mongodb/mongos.log`.
* `mypy`: Python interpretor. Default `python`.
* `mongos_package`: The name of the mongos installation package. Default `mongodb-org-mongos`.
* `config_repl_set_name`: The name of the config server replicaset. Default `cfg`.
* `config_servers`: "config1:27019, config2:27019, config3:27019"
* `openssl_keyfile_content`: The kexfile content that MongoDB uses to authenticate within a replicaset. Generate with cmd: openssl rand -base64 756.
* `openssl_keyfile_path`: Put the openssl_keyfile at this path. Default: `/etc/keyfile`.
* `net_compressors`: If this is set, this sets `net.compression.compressors` in mongos.conf.
* `mongos_config_template`: If defined allows to override path to mongod config template with custom configuration. Default `mongos.conf.j2`.
* `skip_restart`: If set to `true` will skip restarting mongos service when config file or the keyfile content changes. Default `true`.
* `mongodb_use_tls`: Whether to use tls. Default `false`.
* `mongodb_disabled_tls_protocols`: The tls protocols to be disabled. Leave blank to let MongoDB decide which protocols to allow according to the ones available on the system; check the [official docs](https://www.mongodb.com/docs/v6.0/reference/configuration-options/#mongodb-setting-net.tls.disabledProtocols) for details. Default "".
* `mongodb_allow_connections_without_certificates`: When enabled allows to bypass the certificate validation for clients that do not present a certificate, if a certificate is provided it _must_ be valid. Default `false`.
* `mongodb_certificate_key_file`: Path to the PEM-file containing the certficate and private key.
* `mongodb_certificate_ca_file`:  Path to the CA-file.

Dependencies
------------

mongodb_repository

Example Playbook
----------------

```yaml
    - hosts: servers
      roles:
         - mongodb_repository
         - mongodb_mongos
```

License
-------

BSD

Author Information
------------------

Rhys Campbell (https://github.com/rhysmeister)
