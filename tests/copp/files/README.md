# CoPP NN-agent offline bundle

The shared CoPP fixture builds the DUT-side PTF NN-agent runtime on the
sonic-mgmt runner, then installs it in `syncd` without giving that container
network access.

`build_nn_agent_bundle.sh` starts a throwaway `debian:<codename>-slim`
container matching the target `syncd` Debian release. It builds and packages:

- nnpy 1.4.2;
- cffi 2.1.1;
- pycparser 3.0;
- the target release's `libnanomsg5` Debian package; and
- `ptf_nn_agent.py` and `ptf/afpacket.py` pinned to p4lang/ptf commit
  `9d41838d634c479fc24fac7a527ec5ee2d0ce8eb`.

The generated tarball records its Debian codename, architecture, and Python
ABI. `install_nn_agent_bundle.sh` requires all three values to match the
running `syncd` container before installing anything.

The fixture currently uses this path for amd64 Bookworm and Trixie syncd
containers. It caches one bundle per codename/architecture/Python-ABI tuple
for the pytest process. Unsupported targets or local build failures retain the
legacy installer as a fallback.

The builder requires Internet access and a working Docker socket on the
sonic-mgmt runner; `syncd` itself remains offline.
