#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess

def main():
    # check if botan is installed
    if shutil.which("botan") is None:
        print("error: botan is not installed.", file=sys.stderr)
        sys.exit(1)

    # check if directories exist
    script_dir = os.path.dirname(os.path.realpath(__file__))
    temp_dir = os.path.join(script_dir, "tmp")
    os.makedirs(temp_dir, exist_ok=True)

    # ensure a certificate file is provided
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <certificate>", file=sys.stderr)
        sys.exit(1)

    cert_file = sys.argv[1]

    with open(cert_file, 'r') as f:
        content = f.read()

    # ensure the provided certificate is in PEM format
    if "BEGIN CERTIFICATE" not in content or "END CERTIFICATE" not in content:
        print("error: the provided file is not a certificate in PEM format.", file=sys.stderr)
        sys.exit(1)

    # count the number of certificates in the file
    cert_count = content.count("BEGIN CERTIFICATE")

    if cert_count == 1:
        # run single certificate parsing
        subprocess.run(["botan", "cert_info", cert_file])
    else:
        # split the certificates and store them in a list
        certs = []
        cert_lines = []
        capturing = False
        for line in content.splitlines():
            if "-----BEGIN CERTIFICATE-----" in line:
                capturing = True
                cert_lines = []
            if capturing:
                cert_lines.append(line)
            if "-----END CERTIFICATE-----" in line:
                capturing = False
                certs.append("\n".join(cert_lines) + "\n")

        # write each certificate to a temp file
        cert_files = []
        for i, cert in enumerate(certs):
            cert_path = os.path.join(temp_dir, f"cert_{i}.crt")
            with open(cert_path, 'w') as f:
                f.write(cert)
            cert_files.append(cert_path)

        # first certificate is the subject, the rest are CA certs
        subject_cert = cert_files[0]
        ca_certs = cert_files[1:]

        # verify the certificate chain
        cmd = ["botan", "cert_verify", subject_cert] + ca_certs
        subprocess.run(cmd)

if __name__ == "__main__":
    main()
