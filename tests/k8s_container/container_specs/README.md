# Container Specifications

Each YAML file is owned by the container family and contains only:

- Exact `soniccr1` golden images by architecture.
- Native Kubernetes `containers` entries.
- HostPath volumes required by those container mounts.

Framework code owns DaemonSet metadata, namespace, labels, node selection, host
networking, host PID, hostname, service-account behavior, image pull policy,
architecture aliases, common SONiC environment, and test-owned path values.

Use Kubernetes field names in the YAML. The loader infers runtime placeholders.
A placeholder in a HostPath must occupy the full path, name one
`host_path_overrides` contract, and use the lifecycle-owned prefix.

To add a family, add one `<family>.yaml` file. The generic loader does not use a
central registry.

The loader rejects aliases, anchors, explicit tags, merge keys, duplicate keys,
and non-scalar mapping keys. Keep declarations direct and reviewable.

Keep source history, compatibility evidence, and production differences in the
change record. Do not put that review metadata in the deployment specification.
