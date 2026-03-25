#!/usr/bin/env python3

import sys
import shutil
import subprocess

def main():
    # check if gnutls is installed
    if shutil.which("certtool") is None:
        print("error: certtool is not installed.", file=sys.stderr)
        sys.exit(1)

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
        subprocess.run(["certtool", "-i", "--infile", cert_file])
    else:
        # run certificate chain verification
        subprocess.run(["certtool", "-e", "--infile", cert_file])

if __name__ == "__main__":
    main()
