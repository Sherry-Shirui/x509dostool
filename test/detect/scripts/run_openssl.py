#!/usr/bin/env python3

import os
import sys
import shutil
import tempfile
import subprocess

def main():
    # check if openssl is installed
    if shutil.which("openssl") is None:
        print("error: openssl is not installed.", file=sys.stderr)
        sys.exit(1)

    # ensure a certificate file is provided
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <certificate>", file=sys.stderr)
        sys.exit(1)

    cert_file = sys.argv[1]

    with open(cert_file, 'r') as f:
        content = f.read()

    # check if the file is a public key
    if "BEGIN PUBLIC KEY" in content and "END PUBLIC KEY" in content:
        subprocess.run(["openssl", "pkey", "-pubin", "-in", cert_file, "-pubcheck"])
        sys.exit(1)

    # ensure the provided certificate is in PEM format
    if "BEGIN CERTIFICATE" not in content or "END CERTIFICATE" not in content:
        print("error: the provided file is not a certificate in PEM format.", file=sys.stderr)
        sys.exit(1)

    # count the number of certificates in the file
    cert_count = content.count("BEGIN CERTIFICATE")

    if cert_count == 1:
        # run single certificate parsing
        subprocess.run(["openssl", "x509", "-in", cert_file, "-text", "-noout"])
    else:
        # extract the leaf certificate (first one)
        leaf_cert_lines = []
        capturing = False
        for line in content.splitlines():
            if "BEGIN CERTIFICATE" in line:
                capturing = True
                leaf_cert_lines = []
            if capturing:
                leaf_cert_lines.append(line)
            if "END CERTIFICATE" in line:
                capturing = False
                break

        leaf_cert_content = "\n".join(leaf_cert_lines) + "\n"

        # run certificate chain verification using a temp file for the leaf cert
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as tmp:
            tmp.write(leaf_cert_content)
            tmp_path = tmp.name

        try:
            subprocess.run(["openssl", "verify", "-policy_check", "-CAfile", cert_file, tmp_path])
        finally:
            os.unlink(tmp_path)

if __name__ == "__main__":
    main()
