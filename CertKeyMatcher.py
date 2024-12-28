"""
Certificate and Key Matching Program

Description:
This program matches private keys with their corresponding certificates in binary data. It performs the following:
1. Extracts certificates and keys from a file.
2. Compares public key values of private keys and certificates to find matches.
3. Outputs matched pairs along with details like subject, issuer, and validity dates.

Use Case:
Helpful in verifying integrity and relationships between keys and certificates during cryptographic analysis.

Dependencies:
- cryptography: For parsing certificates and keys.
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
import os
import glob

def load_private_key(filename):
    with open(filename, 'r') as file:
        key_data = file.read()
    private_key = serialization.load_pem_private_key(
        key_data.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key

def load_certificate(cert_data):
    try:
        certificate = load_pem_x509_certificate(
            cert_data.encode(),
            default_backend()
        )
        return certificate
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return None

def compare_key_and_certificate(private_key, certificate):
    private_key_public_numbers = private_key.public_key().public_numbers()
    cert_public_numbers = certificate.public_key().public_numbers()
    return private_key_public_numbers == cert_public_numbers

def read_certificates(filename):
    certificates = []
    with open(filename, 'r') as file:
        lines = file.read().splitlines()
        cert_data = {}
        cert_content = []
        for line in lines:
            if line.startswith("-----BEGIN CERTIFICATE-----"):
                cert_content = [line]
            elif line.startswith("-----END CERTIFICATE-----"):
                cert_content.append(line)
                cert_data["certificate"] = "\n".join(cert_content)
                cert_content = []
            elif ": " in line:
                key, value = line.split(": ", 1)
                cert_data[key.lower().replace(" ", "_")] = value
            elif line == "--------------------------------------------------------------------------------":
                if "certificate" in cert_data:
                    certificates.append(cert_data)
                    print(f"Loaded certificate content:\n{cert_data['certificate']}")
                cert_data = {}
    return certificates

def match_keys_to_certificates(certificates, private_keys_folder):
    private_key_files = glob.glob(f"{private_keys_folder}/*.pem")
    matches = []
    for cert in certificates:
        cert_pem = cert['certificate']
        cert_obj = load_certificate(cert_pem)
        if cert_obj is None:
            matches.append((cert, None, None))
            continue
        private_key_found = None
        private_key_content = None
        for private_key_file in private_key_files:
            try:
                private_key_obj = load_private_key(private_key_file)
                if compare_key_and_certificate(private_key_obj, cert_obj):
                    private_key_found = private_key_file
                    with open(private_key_file, 'r') as file:
                        private_key_content = file.read()
                    break
            except Exception as e:
                print(f"Error processing private key {private_key_file}: {e}")
        matches.append((cert, private_key_found, private_key_content))
    return matches

def main():
    certificates_filename = "certificates_with_details.txt"
    private_keys_folder = "pemkeys"
    certificates = read_certificates(certificates_filename)
    matches = match_keys_to_certificates(certificates, private_keys_folder)
    for cert, key_file, key_content in matches:
        print(cert['certificate'])
        print(f"Address in memory: {cert.get('adress')}")
        print(f"Subject: {cert.get('subject')}")
        print(f"Issuer: {cert.get('issuer')}")
        print(f"Validity Start: {cert.get('validity_start')}")
        print(f"Validity End: {cert.get('validity_end')}")
        print(f"Serial Number: {cert.get('serial_number')}")
        print(f"Signature Algorithm: {cert.get('signature_algorithm')}")
        print(f"Version: {cert.get('version')}")
        if key_file and key_content:
            print(f"\nPrivate key found in file: {key_file}")
            print(f"Private key contents:\n{key_content}")
        else:
            print("\nPrivate key not found.")
        print("--------------------------------------------------------------------------------")

if __name__ == "__main__":
    main()
