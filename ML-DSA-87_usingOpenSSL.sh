#!/bin/bash

set -euo pipefail

PQC_DIR="${HOME}/PQC"
MIN_OPENSSL_MAJOR=3
MIN_OPENSSL_MINOR=5

echo "Checking OpenSSL version..."

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: OpenSSL is not installed or is not in PATH." >&2
    exit 1
fi

OPENSSL_VERSION="$(openssl version -v)"
echo "Detected: ${OPENSSL_VERSION}"

OPENSSL_NUMERIC_VERSION="$(openssl version | awk '{print $2}' | sed 's/[^0-9.].*$//')"
OPENSSL_MAJOR="$(printf '%s\n' "${OPENSSL_NUMERIC_VERSION}" | cut -d. -f1)"
OPENSSL_MINOR="$(printf '%s\n' "${OPENSSL_NUMERIC_VERSION}" | cut -d. -f2)"

if [[ -z "${OPENSSL_MAJOR}" || -z "${OPENSSL_MINOR}" ]] ||
   (( OPENSSL_MAJOR < MIN_OPENSSL_MAJOR )) ||
   (( OPENSSL_MAJOR == MIN_OPENSSL_MAJOR && OPENSSL_MINOR < MIN_OPENSSL_MINOR )); then
    echo "ERROR: OpenSSL 3.5 or newer is required to support PQC." >&2
    echo "Please upgrade OpenSSL and run the script again." >&2
    exit 1
fi

echo "OpenSSL version requirement satisfied."

if [[ -d "${PQC_DIR}" ]]; then
    echo
    echo "WARNING: ${PQC_DIR} already exists."
    read -r -p "Proceed and overwrite its contents? Type YES to continue: " confirmation

    if [[ "${confirmation}" != "YES" ]]; then
        echo "Operation cancelled. Existing directory was not changed."
        exit 0
    fi

    echo "Removing existing ${PQC_DIR} directory..."
    rm -rf -- "${PQC_DIR}"
elif [[ -e "${PQC_DIR}" ]]; then
    echo "ERROR: ${PQC_DIR} exists but is not a directory." >&2
    exit 1
fi

echo "Create sub-directory to generate three files: .pem, .crt and .p12"
mkdir -p -- "${PQC_DIR}"

echo "Generate ML-DSA-87_PrivateKey.pem and corresponding ML-DSA-87_PublicKeyCertificate.crt"
openssl req -x509 -nodes -days 365 \
    -utf8 \
    -newkey ML-DSA-87 \
    -keyout "${PQC_DIR}/ML-DSA-87_PrivateKey.pem" \
    -out "${PQC_DIR}/ML-DSA-87_PublicKeyCertificate.crt" \
    -subj "/C=AU/ST=WA/L=Perth/O=贵公司名称 Your Company Name/OU=IT 部门/CN=YourDomain.local" \
    -addext "subjectAltName=email:support@YourDomain.local"

echo "Generate password-protected ML-DSA-87_PKCS12.p12 binary archive to store private key and public key certificate"
openssl pkcs12 -export \
    -inkey "${PQC_DIR}/ML-DSA-87_PrivateKey.pem" \
    -in "${PQC_DIR}/ML-DSA-87_PublicKeyCertificate.crt" \
    -out "${PQC_DIR}/ML-DSA-87_PKCS12.p12" \
    -keypbe AES-256-CBC \
    -certpbe AES-256-CBC \
    -macalg SHA256 \
    -iter 100000 \
    -name "YourDomain.local"

echo
echo "Generated files:"
ls -latr -- "${PQC_DIR}"

# OPTIONAL: Extract ML-DSA-87_PublicKey.pem from its Public Key Certificate  
# openssl x509 -in "${PQC_DIR}/ML-DSA-87_PublicKeyCertificate.crt" \
#    -pubkey -noout > "${PQC_DIR}/ML-DSA-87_PublicKey.pem"

echo
echo "Revoke read, write and execute permissions from Group and Others"
chmod -R go-rwx -- "${PQC_DIR}"
ls -latr -- "${PQC_DIR}"

echo
echo "Done."
