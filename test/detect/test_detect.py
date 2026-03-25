#!/usr/bin/env python3

import os
import sys
import signal
import shutil
import subprocess

def find_jar(pattern):
    """Find a jar file matching the given name pattern under /."""
    result = subprocess.run(
        ["find", "/", "-type", "f", "-name", pattern],
        capture_output=True, text=True
    )
    matches = [line for line in result.stdout.splitlines() if line]
    return matches[0] if matches else None

def main():
    # check if x509dostool is installed
    if shutil.which("x509dostool") is None:
        print("error: x509dostool is not installed.", file=sys.stderr)
        sys.exit(1)

    # specify the directory to store the certificates
    script_dir = os.path.dirname(os.path.realpath(__file__))
    cert_path = os.path.join(script_dir, "certs")

    if not os.path.isdir(cert_path):
        # initialize certificates for detecting libraries
        test_commands = [
            f"x509dostool generate -out {cert_path}/01-a.pem test1 -m 0x7FFFFF --balanced --compressed",
            f"x509dostool generate -out {cert_path}/01-b.pem test1 -m 0x5FFFFFFF",
            f"x509dostool generate -out {cert_path}/02.pem test2 -m 74 -t 233 --compressed",
            f"x509dostool generate -out {cert_path}/03-a.pem test3 --balanced",
            f"x509dostool generate -out {cert_path}/03-b.pem test3 -p '(2**127-1)**2' --balanced",
            f"x509dostool generate -out {cert_path}/04-a.pem test4 -p '2**86243-1' -algo rsa",
            f"x509dostool edit -in {cert_path}/04-a.pem -out {cert_path}/04-a.pem --pubout",
            f"x509dostool generate -out {cert_path}/04-b.pem test4 -p '2**86243-1'",
            f"x509dostool generate -out {cert_path}/05.pem test5 -sans 60000",
            f"x509dostool generate -out {cert_path}/06.pem test6",
            f"x509dostool generate -out {cert_path}/07.pem test7",
            f"x509dostool generate -out {cert_path}/08.pem test8 -num 4",
            f"x509dostool generate -out {cert_path}/09.pem test9 -num 32 --mapping",
            f"x509dostool generate -out {cert_path}/10.pem test10 ",
        ]

        print("initializing...")
        os.makedirs(cert_path, exist_ok=True)
        for cmd in test_commands:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"initialization failed: {cmd}\n")
                sys.exit(1)

        print("the certificate to be used has been successfully generated.\n")
    else:
        print("the `certs` directory already exists, skipping the initialization phase.\n")

    print("checking the installation status of the library...")
    print("-" * 80)

    # initialize an empty list to store the found libraries
    installed_libraries = []

    # check if openssl is installed
    if shutil.which("openssl") is None:
        print("openssl is not installed.", file=sys.stderr)
    else:
        openssl_version = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True
        ).stdout.strip()
        print(f"found openssl installed: {openssl_version}")
        installed_libraries.append("openssl")

    # check if botan is installed
    if shutil.which("botan") is None:
        print("botan is not installed.", file=sys.stderr)
    else:
        botan_version = subprocess.run(
            ["botan", "version"], capture_output=True, text=True
        ).stdout.strip()
        print(f"found botan installed: {botan_version}")
        installed_libraries.append("botan")

    # check if bouncy castle is installed
    bcprov_jar_path = find_jar("bcprov*.jar")
    bcpkix_jar_path = find_jar("bcpkix*.jar")

    if bcprov_jar_path and os.path.isfile(bcprov_jar_path):
        # extract version from MANIFEST.MF inside the jar
        manifest_result = subprocess.run(
            ["unzip", "-p", bcprov_jar_path, "META-INF/MANIFEST.MF"],
            capture_output=True, text=True
        )
        bc_version = ""
        for line in manifest_result.stdout.splitlines():
            if line.lower().startswith("implementation-version"):
                bc_version = line.split(" ", 1)[1].strip() if " " in line else ""
                break

        if bcpkix_jar_path and os.path.isfile(bcpkix_jar_path):
            print(f"found bouncy castle installed: {bc_version}")
            installed_libraries.append("bouncycastle")
        else:
            print("bouncy castle (prov) is not installed.", file=sys.stderr)
    else:
        print("bouncy castle (pkix) is not installed.", file=sys.stderr)

    # check if gnutls is installed
    if shutil.which("certtool") is None:
        print("gnutls is not installed.", file=sys.stderr)
    else:
        certtool_version = subprocess.run(
            ["certtool", "--version"], capture_output=True, text=True
        ).stdout.splitlines()[0]
        print(f"found gnutls installed: {certtool_version}")
        installed_libraries.append("gnutls")

    # check if phpseclib is installed
    phpseclib_result = subprocess.run(
        ["find", "/", "-type", "f", "-path", "*/phpseclib-*/vendor/autoload.php"],
        capture_output=True, text=True
    )
    phpseclib_matches = [l for l in phpseclib_result.stdout.splitlines() if l]
    phpseclib_path = phpseclib_matches[0] if phpseclib_matches else None

    if phpseclib_path:
        import re
        version_match = re.search(r'/phpseclib-([0-9]+\.[0-9]+\.[0-9]+)/vendor/autoload\.php', phpseclib_path)
        version = version_match.group(1) if version_match else ""
        print(f"found phpseclib installed: {version}")
        installed_libraries.append("phpseclib")
    else:
        print("phpseclib is not installed.", file=sys.stderr)

    # check if crypto++ is installed
    dpkg_result = subprocess.run(
        ["dpkg", "-s", "libcrypto++-dev"],
        capture_output=True, text=True
    )
    if dpkg_result.returncode == 0:
        cryptopp_version = ""
        for line in dpkg_result.stdout.splitlines():
            if line.startswith("Version:"):
                cryptopp_version = line.split()[1]
                break
        print(f"found crypto++ installed: {cryptopp_version}")
        installed_libraries.append("cryptopp")
    else:
        print("crypto++ is not installed.", file=sys.stderr)

    # output the list of installed libraries
    print("-" * 80)
    print(f"\033[32minstalled libraries:\033[0m {' '.join(installed_libraries)}")

    # execute x509dostool detect for each installed library using the crafted certificates
    def handle_sigint(sig, frame):
        print("exiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    scripts_dir = os.path.join(script_dir, "scripts")
    for x in installed_libraries:
        script_path = os.path.join(scripts_dir, f"run_{x}.py")
        print("-" * 80)
        if os.path.isfile(script_path):
            print(f"executing: x509dostool detect -libs {script_path} -certs {cert_path}")
            subprocess.run(["x509dostool", "detect", "-libs", script_path, "-certs", cert_path])
        else:
            print(f"script not found for library: {script_path}")

if __name__ == "__main__":
    main()
