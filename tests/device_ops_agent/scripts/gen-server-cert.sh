#!/usr/bin/env bash
# Retrofit a SAN onto the SONiC streaming-telemetry server cert so
# that Go-based gRPC servers (device-ops-agent, v2 HwProxy, ...) can
# present it without Go's TLS stack rejecting it.
#
# Background. The legacy on-device mint produces
# /etc/sonic/telemetry/streamingtelemetryserver.{cer,key} as a CN-only,
# self-signed cert (subject == issuer == "ndastreamingservertest", no
# X509v3 extensions). Go's crypto/tls refuses to match such a cert
# against a hostname / IP at handshake time ("x509: certificate
# relies on legacy Common Name field, use SANs instead"). The Python
# streamingtelemetry server tolerates it.
#
# This script overwrites streamingtelemetryserver.{cer,key} in place
# with a fresh keypair + leaf cert that:
#   * has a proper subjectAltName (DNS + IP), and
#   * is signed by the SONiC root CA (dsmsroot),
# so both the existing Python telemetry server and the new Go-based
# device-ops-agent can use it.
#
# Inputs (env, all optional):
#   OUT_DIR        default /etc/sonic/telemetry  (the canonical SONiC
#                                                 PKI dir; container
#                                                 bind-mounts r/o)
#   CA_CER         default /etc/sonic/telemetry/dsmsroot.cer
#   CA_KEY         default /etc/sonic/telemetry/dsmsroot.key
#   DEVICE_NAME    default $(hostname)
#   VALID_DAYS     default 30
#
# Outputs (overwritten in place):
#   ${OUT_DIR}/streamingtelemetryserver.cer  (PEM, 0644)
#   ${OUT_DIR}/streamingtelemetryserver.key  (PEM, 0600)
#
# The minted leaf has:
#   Subject:               CN=device-ops-agent
#   X509v3 SAN:            DNS:${DEVICE_NAME}, DNS:localhost, IP:127.0.0.1
#   X509v3 EKU:            serverAuth
#   X509v3 KU:             digitalSignature, keyEncipherment
#   Signed by:             ${CA_CER} / ${CA_KEY}
#   Validity:              ${VALID_DAYS} days
#
# Trust model is unchanged from telemetry: the CA is dsmsroot.cer; the
# server presents this freshly-minted leaf; clients (smoke, HwProxy
# in v2) chain through dsmsroot.cer. No -insecure required.

set -euo pipefail

# Quiet by default. Pass -v / --verbose as the first argument to echo every
# command before execution (handy for demos and debugging).
if [[ "${1:-}" == "-v" || "${1:-}" == "--verbose" ]]; then
    shift
    set -x
fi

OUT_DIR="${OUT_DIR:-/etc/sonic/telemetry}"
CA_CER="${CA_CER:-/etc/sonic/telemetry/dsmsroot.cer}"
CA_KEY="${CA_KEY:-/etc/sonic/telemetry/dsmsroot.key}"
DEVICE_NAME="${DEVICE_NAME:-$(hostname)}"
VALID_DAYS="${VALID_DAYS:-30}"

if [[ ! -r "${CA_CER}" ]]; then
    echo "FATAL: cannot read CA cert ${CA_CER}" >&2
    exit 1
fi
if [[ ! -r "${CA_KEY}" ]]; then
    echo "FATAL: cannot read CA key ${CA_KEY} (must run as root, or fix bind-mount)" >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"

# Temp scratch dir for OpenSSL config + CSR + serial; cleaned via trap.
TMP_DIR="$(mktemp -d -t dops-cert.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/san.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions     = v3
prompt             = no

[req_dn]
CN = device-ops-agent

[v3]
subjectAltName     = DNS:${DEVICE_NAME},DNS:localhost,IP:127.0.0.1
extendedKeyUsage   = serverAuth
keyUsage           = digitalSignature,keyEncipherment
EOF

# Generate fresh leaf key (idempotent: overwrite any prior file).
openssl genrsa -out "${OUT_DIR}/streamingtelemetryserver.key" 2048 2>/dev/null
chmod 0600 "${OUT_DIR}/streamingtelemetryserver.key"

# CSR carries the SAN extension (via -reqexts v3 -config).
openssl req -new \
    -key "${OUT_DIR}/streamingtelemetryserver.key" \
    -out "${TMP_DIR}/streamingtelemetryserver.csr" \
    -config "${TMP_DIR}/san.cnf" \
    -reqexts v3 2>/dev/null

# Sign with dsmsroot, copying the v3 extensions (SAN/EKU/KU) into the leaf.
openssl x509 -req \
    -in "${TMP_DIR}/streamingtelemetryserver.csr" \
    -CA "${CA_CER}" -CAkey "${CA_KEY}" -CAcreateserial \
    -CAserial "${TMP_DIR}/dsmsroot.srl" \
    -out "${OUT_DIR}/streamingtelemetryserver.cer" \
    -days "${VALID_DAYS}" \
    -sha256 \
    -extfile "${TMP_DIR}/san.cnf" \
    -extensions v3 2>/dev/null

chmod 0644 "${OUT_DIR}/streamingtelemetryserver.cer"

# Sanity-check: the minted leaf MUST carry SAN. If openssl ever drops
# the extension copy (we've seen it on old openssl), fail loudly here
# rather than letting Go's TLS stack fail at handshake time with the
# cryptic "legacy Common Name field" message.
if ! openssl x509 -in "${OUT_DIR}/streamingtelemetryserver.cer" -noout -text | grep -qE "Subject Alternative Name"; then
    echo "FATAL: minted ${OUT_DIR}/streamingtelemetryserver.cer has no SAN (openssl extension copy failed)" >&2
    openssl x509 -in "${OUT_DIR}/streamingtelemetryserver.cer" -noout -text >&2
    exit 1
fi

echo "gen-server-cert: minted ${OUT_DIR}/streamingtelemetryserver.cer (CN=device-ops-agent, SAN=DNS:${DEVICE_NAME},DNS:localhost,IP:127.0.0.1, signed by ${CA_CER}, ${VALID_DAYS} days)"
