#!/usr/bin/env python3

import sys
import subprocess

def find_autoload():
    """Find phpseclib autoload.php path."""
    result = subprocess.run(
        ["find", "/", "-type", "f", "-path", "*/phpseclib-*/vendor/autoload.php"],
        capture_output=True, text=True
    )
    matches = [line for line in result.stdout.splitlines() if line]
    return matches[0] if matches else None

def main():
    # set phpseclib autoload path
    php_autoload_path = find_autoload()

    if not php_autoload_path:
        print("error: phpseclib is not installed.", file=sys.stderr)
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
        php_code = f"""
require '{php_autoload_path}';
use phpseclib3\\File\\X509;

$certContent = file_get_contents('{cert_file}');
$x509 = new X509();
$x509->loadX509($certContent);
$x509->getPublicKey();
"""
        subprocess.run(["php", "-r", php_code])
    else:
        # run certificate chain verification
        php_code = f"""
require '{php_autoload_path}';
use phpseclib3\\File\\X509;

$certContent = file_get_contents('{cert_file}');
$certs = explode('-----END CERTIFICATE-----', $certContent);
$x509 = new X509();

$first = true;
foreach ($certs as $certData) {{
    $certData = trim($certData);
    if (empty($certData)) continue;
    $certData .= '-----END CERTIFICATE-----';
    if ($first) {{
        $x509->loadX509($certData);
        $first = false;
    }} else {{
        $x509->loadCA($certData);
    }}
}}

$valid = $x509->validateSignature();
echo $valid ? 'valid' : 'invalid';
"""
        subprocess.run(["php", "-r", php_code])

if __name__ == "__main__":
    main()
