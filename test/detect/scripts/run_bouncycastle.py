#!/usr/bin/env python3

import os
import sys
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
    # check if directories exist and if bouncy castle files are present
    bcprov_path = find_jar("bcprov*.jar")
    bcpkix_path = find_jar("bcpkix*.jar")

    if not bcprov_path:
        print("error: bouncy castle (prov) is not installed.", file=sys.stderr)
        sys.exit(1)

    if not bcpkix_path:
        print("error: bouncy castle (pkix) is not installed.", file=sys.stderr)
        sys.exit(1)

    script_dir = os.path.dirname(os.path.realpath(__file__))
    temp_dir = os.path.join(script_dir, "tmp")
    os.makedirs(temp_dir, exist_ok=True)

    temp_file = os.path.join(temp_dir, "Main.java")

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
        java_code = f"""import java.io.FileInputStream;
    import java.security.Security;
    import java.security.cert.X509Certificate;
    import java.security.cert.CertificateFactory;

    import org.bouncycastle.jce.provider.BouncyCastleProvider;

    public class Main {{
        public static void main(String[] args) throws Exception {{

            Security.addProvider(new BouncyCastleProvider());

            FileInputStream fis = new FileInputStream("{cert_file}");

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fis);

            certificate.getPublicKey(); // infinite loop
        }}
    }}"""

        with open(temp_file, 'w') as f:
            f.write(java_code)

        # run single certificate parsing
        subprocess.run(["java", f"--class-path={bcprov_path}", temp_file])
    else:
        java_code = f"""import java.io.*;
    import java.security.Security;
    import java.security.cert.*;
    import java.util.*;
    import org.bouncycastle.jce.provider.BouncyCastleProvider;
    import org.bouncycastle.pkix.jcajce.PKIXCertPathReviewer;

    public class Main {{
        public static void main(String[] args) throws Exception {{
            Security.addProvider(new BouncyCastleProvider());

            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            List<X509Certificate> certChain = new ArrayList<>();

            try (FileInputStream fis = new FileInputStream("{cert_file}")) {{
                Collection<? extends Certificate> certs = cf.generateCertificates(fis);
                for (Certificate cert : certs) {{
                    certChain.add((X509Certificate) cert);
                }}
            }}

            X509Certificate root = certChain.get(certChain.size() - 1);

            CertPath cp = cf.generateCertPath(certChain);
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(new TrustAnchor(root, null));
            PKIXParameters params = new PKIXParameters(trustAnchors);

            PKIXCertPathReviewer certPathReviewer = new PKIXCertPathReviewer();
            certPathReviewer.init(cp, params);

            certPathReviewer.isValidCertPath();
        }}
    }}"""

        with open(temp_file, 'w') as f:
            f.write(java_code)

        # verify the certificate chain
        subprocess.run(["java", f"--class-path={bcprov_path}:{bcpkix_path}", temp_file])

if __name__ == "__main__":
    main()
