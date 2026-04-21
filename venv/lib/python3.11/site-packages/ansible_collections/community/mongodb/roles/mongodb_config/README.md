mongodb_config
==============

A simple role to aid in setting up a CSRS Config Server Replicaset for a MongoDB sharded cluster.

Role Variables
--------------

* `config_port`: The port used by the mongos process. Default `27019`.
* `mongod_service`: The name of the mongod service. Default `mongod`.
* `mongodb_user`: The Linux OS user for MongoDB. Default `mongod`.
* `mongodb_group`: The Linux OS user group for MongoDB. Default `mongod`.
* `pid_file`: The pid file for mongos. Default `/run/mongodb/mongos.pid`.
* `log_path`: Path of the log file. Default `/var/log/mongodb/mongod.log`.
* `bind_ip`: The IP address mongod will bind to. Default `0.0.0.0`.
* `bind_ip_all`: Have mongod bind to all IP addresses instead of specifying `bind_ip`. Default `false`.
* `config_repl_set_name`: The replicaset name for the config servers. Default `cfg`.
* `authorization`: Enable authorization. Default `enabled`.
* `openssl_keyfile_content`: The kexfile content that MongoDB uses to authenticate within a replicaset. Generate with cmd: openssl rand -base64 756.
* `openssl_keyfile_path`: Put the openssl_keyfile at this path. Default: `/etc/keyfile`.
* `mongod_package`: The name of the mongod installation package. Default `mongodb-org-server`.
replicaset: When enabled add a replication section to the configuration. Default `true`.
* `net_compressors`: If this is set, this sets `net.compression.compressors` in mongod.conf.
* `mongod_config_template`: If defined allows to override path to mongod config template with custom configuration. Default `mongod.conf.j2`.
* `skip_restart`: If set to `true` will skip restarting mongod service when config file or the keyfile content changes. Default `true`.
* `db_path`: Path to database data location. Default `/var/lib/mongodb` on Debian based distributions, `/var/lib/mongo` for others.
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

Including an example of how to use your role (for instance, with variables
passed in as parameters) is always nice for users too:


```yaml
    - hosts: servers
      roles:
         - { role: mongodb_repository }
         - { role: mongodb_config, config_repl_set_name: "mycustomrs" }
```

License
-------

BSD

Author Information
------------------

Rhys Campbell (https://github.com/rhysmeister)
