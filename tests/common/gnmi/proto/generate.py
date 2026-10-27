"""Regenerate the checked-in messages with grpcio-tools==1.62.3.

Only this maintenance command downloads sources. Normal client use is offline.
"""

import hashlib
from importlib.metadata import version
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.request import urlopen


REVISION = "c1b4525a810ffdaa3f4960d3cd88987a58d8e204"  # openconfig/gnmi v0.8.0
SOURCES = {
    "proto/gnmi/gnmi.proto": "8ac4f4d15eaa0d1ed082b8e5c8105e9a5ddeacb64365b601a90ae3865e734c20",
    "proto/gnmi_ext/gnmi_ext.proto": "f99eb223b7fb1f9c34714ae143f278e241f3803b1e74e92bcce48b8f0deee410",
    "LICENSE": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
}


def main():
    if version("grpcio-tools") != "1.62.3":
        raise RuntimeError("Regenerate with grpcio-tools==1.62.3")
    destination = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for path, digest in SOURCES.items():
            url = f"https://raw.githubusercontent.com/openconfig/gnmi/{REVISION}/{path}"
            with urlopen(url, timeout=30) as response:
                content = response.read()
            if hashlib.sha256(content).hexdigest() != digest:
                raise RuntimeError(f"Upstream checksum mismatch: {path}")
            # Only the import path changes; message names/fields stay upstream.
            content = content.replace(
                b'"github.com/openconfig/gnmi/proto/gnmi_ext/gnmi_ext.proto"', b'"gnmi_ext.proto"'
            )
            (root / Path(path).name).write_bytes(content)
        subprocess.run([
            sys.executable, "-m", "grpc_tools.protoc", f"-I{root}",
            f"--python_out={root}", f"--grpc_python_out={root}",
            str(root / "gnmi.proto"), str(root / "gnmi_ext.proto"),
        ], check=True)
        for filename in ("gnmi_pb2.py", "gnmi_ext_pb2.py", "gnmi_pb2_grpc.py"):
            content = (root / filename).read_text()
            content = content.replace("import gnmi_ext_pb2 as", "from . import gnmi_ext_pb2 as")
            content = content.replace("import gnmi_pb2 as", "from . import gnmi_pb2 as")
            if filename.endswith("_pb2.py"):
                content = content.replace("from google.protobuf import descriptor_pool as _descriptor_pool",
                                          "from .pool import POOL")
                content = content.replace("_descriptor_pool.Default()", "POOL")
            (destination / filename).write_text(content)
        (destination / "LICENSE").write_bytes((root / "LICENSE").read_bytes())


if __name__ == "__main__":
    main()
