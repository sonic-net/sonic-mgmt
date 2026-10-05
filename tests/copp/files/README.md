# CoPP NN-agent offline bundle

`copp-nn-agent-bundle-amd64.tar.gz` lets the shared CoPP fixture install the
DUT-side PTF NN agent without network access from the running `syncd`
container.

The bundle contains:

- Debian `libnanomsg5` 1.1.5+dfsg-1.1+b1 for amd64;
- nnpy 1.4.2 and its CPython stable-ABI extension;
- cffi 2.1.1 backends for CPython 3.11 and 3.13;
- pycparser 3.0;
- `ptf_nn_agent.py` and `ptf/afpacket.py` pinned to p4lang/ptf commit
  `9d41838d634c479fc24fac7a527ec5ee2d0ce8eb`; and
- the corresponding upstream license texts and a version manifest.

The installer verifies the container architecture and Python ABI before it
changes the container. Add a matching backend and update `manifest.json`
before supporting another ABI or architecture.

Current SHA-256:

```
b80eb699076f90059e830ae70c8b6da16c2ea6a834a138f2e571c308e76d9ab3
```
