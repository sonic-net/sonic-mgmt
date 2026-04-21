# gcsfuse

This role configures the gcsfuse repository, and installs gcsfuse on your host.
gcsfuse is a user-space file system for working with
[Google Cloud Storage](https://cloud.google.com/storage/).

**Important:** You should run gcsfuse as the user who will be using the file
system, not as the root user. Do not use sudo either.

After installed you can use it to mount by command:
`gcsfuse bucket-name /mount/point`

## Example Playbook

Including an example of how to use your role (for instance, with variables
passed in as parameters) is always nice for users too:

```yaml
- hosts: servers
  tasks:
    - include_role:
        name: google.cloud.gcsfuse
```

## License

GPLv3

## Author Information

[ericsysmin](https://ericsysmin.com)
