#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess

def main():
    # check if x509dostool is installed
    if shutil.which("x509dostool") is None:
        print("error: x509dostool is not installed.", file=sys.stderr)
        sys.exit(1)

    # specify the directory to store the certificates
    script_dir = os.path.dirname(os.path.realpath(__file__))
    cert_path = os.path.join(script_dir, "certs")

    if not os.path.isdir(cert_path):
        # initialize certificates for editing
        test_generate_commands = [
            f"x509dostool generate -out {cert_path}/test.crt test0",
            f"x509dostool generate -out {cert_path}/test_rsa.crt test0 -algo rsa",
            f"x509dostool generate -out {cert_path}/test_dsa.crt test0 -algo dsa",
            f"x509dostool generate -out {cert_path}/test_ecdsa.crt test0 -algo ecdsa",
            f"x509dostool generate -out {cert_path}/test_ecdsa_fp.crt test0 -algo ecdsa --explicit",
            f"x509dostool generate -out {cert_path}/test_ecdsa_f2m_tp.crt test0 -algo ecdsa -name sect233r1 --explicit",
            f"x509dostool generate -out {cert_path}/test_ecdsa_f2m_pp.crt test0 -algo ecdsa -name sect283r1 --explicit",
        ]

        print("initializing...")
        os.makedirs(cert_path, exist_ok=True)
        for cmd in test_generate_commands:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"initialization failed: {cmd}\n")
                sys.exit(1)

        print("the certificate to be used has been successfully generated.\n")
    else:
        print("the `certs` directory already exists, skipping the initialization phase.\n")

    # define the list of commands for editing
    test_edit_commands = [
        f"x509dostool edit -in {cert_path}/test.crt -out edited_test.crt tbs ver -ver 1023",
        f"x509dostool edit -in {cert_path}/test.crt -out edited_test.crt tbs sn -sn 1023",
        f"x509dostool edit -in {cert_path}/test.crt -out edited_test.crt tbs sig -algo 1.2.1023",
        f"x509dostool edit -in {cert_path}/test.crt -out edited_test.crt tbs issuer -types 1.2.1023 1.2.65535 -values test1 test2",
        f"x509dostool edit -in {cert_path}/test.crt -out edited_test.crt tbs subject -types 1.2.1023 1.2.65535 -values test1 test2",
        f"x509dostool edit -in {cert_path}/test_rsa.crt -out edited_test.crt tbs spki rsa -algo 1.2.1023 -n 1023 -e 1023",
        f"x509dostool edit -in {cert_path}/test_dsa.crt -out edited_test.crt tbs spki dsa -algo 1.2.1023 -p 1023 -q 1023 -g 1023 -pub 2**20-1",
        f"x509dostool edit -in {cert_path}/test_ecdsa.crt -out edited_test.crt tbs spki ecdsa -algo 1.2.1023 -name secp256k1 -P 040102030405060708090A --compressed",
        f"x509dostool edit -in {cert_path}/test_ecdsa_fp.crt -out edited_test.crt tbs spki ecdsa_fp -algo 1.2.1023 -p 1023 -a 1023 -b 1023 -G 040102030405060708090A -order 1023 -cofactor 1023 -seed 2**50-1 -P 040102030405060708090A --balanced --compressed",
        f"x509dostool edit -in {cert_path}/test_ecdsa_f2m_tp.crt -out edited_test.crt tbs spki ecdsa_f2m_tp -algo 1.2.1023 -m 1023 -t 1023 -a 1023 -b 1023 -G 040102030405060708090A -order 1023 -cofactor 1023 -seed 2**50-1 -P 040102030405060708090A --balanced --compressed",
        f"x509dostool edit -in {cert_path}/test_ecdsa_f2m_pp.crt -out edited_test.crt tbs spki ecdsa_f2m_pp -algo 1.2.1023 -m 1023 -t3 1023 -t2 1023 -t1 1023 -a 1023 -b 1023 -G 040102030405060708090A -order 1023 -cofactor 1023 -seed 2**50-1 -P 040102030405060708090A --balanced --compressed",
    ]

    # check for the --verbose flag
    verbose = len(sys.argv) > 1 and sys.argv[1] == "--verbose"
    if verbose:
        print("verbose mode enabled.")

    # initialize counters for statistics
    total_count = 0
    success_count = 0
    failure_count = 0

    # loop through each command in the list
    for cmd in test_edit_commands:
        total_count += 1

        # always output the command in the screen, regardless of verbose
        print(f"\033[32mrunning\033[0m: {cmd}")

        # execute the command to edit the certificate
        if verbose:
            result = subprocess.run(cmd, shell=True, capture_output=False)
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        # check if the command executed successfully
        if result.returncode != 0:
            failure_count += 1
            print(f"error: command failed: {cmd}\n")
            continue

        # check if the certificate was successfully edited
        if not os.path.isfile("edited_test.crt"):
            failure_count += 1
            print(f"error: certificate not edited by command: {cmd}\n")
            continue

        # try to parse the edited certificate with openssl asn1parse for other tests
        print("parsing the certificate with openssl asn1parse...")
        parse_result = subprocess.run(
            ["openssl", "asn1parse", "-in", "edited_test.crt"],
            capture_output=True, text=True
        )
        parse_output = parse_result.stdout + parse_result.stderr

        if parse_result.returncode == 0:
            success_count += 1
            print("successfully parsed the certificate.")
        else:
            failure_count += 1
            print("error: failed to parse the certificate.")

        # output the parse result in verbose mode
        if verbose:
            print(parse_output)

        # add a newline after each test command (for readability)
        print("")

        # optional: clean up the edited certificate for the next test
        if os.path.isfile("edited_test.crt"):
            os.remove("edited_test.crt")

    # output the final statistics
    print("-----")
    print(f"total commands: {total_count}")
    print(f"successful commands: {success_count}")
    print(f"failed commands: {failure_count}")

    # check if all tests passed
    if failure_count == 0:
        print("all tests passed")
    else:
        print("some tests failed")

if __name__ == "__main__":
    main()
