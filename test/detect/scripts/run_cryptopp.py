#!/usr/bin/env python3

import os
import sys
import subprocess

def main():
    # check if crypto++ is installed
    dpkg_result = subprocess.run(
        ["dpkg", "-s", "libcrypto++-dev"],
        capture_output=True, text=True
    )
    if dpkg_result.returncode != 0:
        print("crypto++ is not installed.", file=sys.stderr)
        sys.exit(1)

    script_dir = os.path.dirname(os.path.realpath(__file__))
    temp_dir = os.path.join(script_dir, "tmp")
    os.makedirs(temp_dir, exist_ok=True)

    temp_file = os.path.join(temp_dir, "Main.cpp")

    # ensure a certificate file is provided
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <certificate>", file=sys.stderr)
        sys.exit(1)

    cert_file = sys.argv[1]
    edited_cert_file = os.path.join(temp_dir, "test.crt")

    with open(cert_file, 'r') as f:
        content = f.read()

    # ensure the provided certificate is in PEM format
    if "BEGIN CERTIFICATE" not in content or "END CERTIFICATE" not in content:
        print("error: the provided file is not a certificate in PEM format.", file=sys.stderr)
        sys.exit(1)

    # count the number of certificates in the file
    cert_count = content.count("BEGIN CERTIFICATE")

    if cert_count > 1:
        print("error: testing certificate chains for crypto++ is not supported currently.", file=sys.stderr)
        sys.exit(1)

    # run the x509dostool commands and determine the type
    cert_type = ""

    result = subprocess.run(
        f"timeout 1s x509dostool edit -in {cert_file!r} -outform der -out {edited_cert_file!r} --pubout tbs spki ecdsa_fp -order 1",
        shell=True, capture_output=True
    )
    if result.returncode == 0:
        cert_type = "ecdsa_fp"
    else:
        result = subprocess.run(
            f"timeout 1s x509dostool edit -in {cert_file!r} -outform der -out {edited_cert_file!r} --pubout tbs spki ecdsa_f2m_tp -order 1",
            shell=True, capture_output=True
        )
        if result.returncode == 0:
            cert_type = "ecdsa_f2m_tp"
        else:
            result = subprocess.run(
                f"timeout 1s x509dostool edit -in {cert_file!r} -outform der -out {edited_cert_file!r} --pubout tbs spki ecdsa_f2m_pp -order 1",
                shell=True, capture_output=True
            )
            if result.returncode == 0:
                cert_type = "ecdsa_f2m_pp"

    if not cert_type:
        print(
            "error: to facilitate testing for crypto++, only ecdsa public keys with explicitly included curve parameters are supported currently.",
            file=sys.stderr
        )
        sys.exit(1)

    # create PUBKEY_FILE by changing the extension to .pub
    base, _ = os.path.splitext(edited_cert_file)
    pubkey_file = base + ".pub"

    # write corresponding C++ code to temp_file
    if cert_type == "ecdsa_fp":
        cpp_code = f"""#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main()
{{
    DL_PublicKey_EC<ECP> pubKey;

    FileSource fs("{pubkey_file}", true);

    pubKey.Load(fs);

    return 0;
}}
"""
    elif cert_type in ("ecdsa_f2m_pp", "ecdsa_f2m_tp"):
        cpp_code = f"""#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

int main()
{{
    DL_PublicKey_EC<EC2N> pubKey;

    FileSource fs("{pubkey_file}", true);

    pubKey.Load(fs);

    return 0;
}}
"""
    else:
        print("error: unsupported type", file=sys.stderr)
        sys.exit(1)

    with open(temp_file, 'w') as f:
        f.write(cpp_code)

    # compile the C++ code
    compile_result = subprocess.run(
        ["g++", "-o", os.path.join(temp_dir, "Main"), temp_file, "-lcrypto++"],
        capture_output=True, text=True
    )
    if compile_result.returncode == 0:
        # run the compiled executable
        subprocess.run([os.path.join(temp_dir, "Main")])
    else:
        print("error: compilation failed.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
