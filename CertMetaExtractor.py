"""
Certificate Metadata Extractor

Description:
This program parses and extracts metadata from X.509 certificates in a PEM or DER format. It performs the following:
1. Reads certificate and related data from a file.
2. Extracts metadata such as subject, issuer, validity dates, serial number, and public key.
3. Saves the parsed metadata and certificate details to an output folder for further analysis.

Use Case:
Useful in digital certificate analysis for validating certificate properties during cybersecurity audits or cryptographic research.

Dependencies:
- cryptography: For parsing X.509 certificates.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
import os

def clean_certificate_text(cert_text):
    cert_text = cert_text.strip()
    if not cert_text.startswith("-----BEGIN CERTIFICATE-----"):
        cert_text = "-----BEGIN CERTIFICATE-----\n" + cert_text
    if not cert_text.endswith("-----END CERTIFICATE-----"):
        cert_text = cert_text + "\n-----END CERTIFICATE-----"
    return cert_text

def get_certificate_details(cert_pem, address):
    details = f"Address: {address}\n"
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        details += f"Subject: {cert.subject}\n"
        details += f"Issuer: {cert.issuer}\n"
        details += f"Validity Start: {cert.not_valid_before}\n"
        details += f"Validity End: {cert.not_valid_after}\n"
        details += f"Serial Number: {cert.serial_number}\n"
        details += f"Signature Algorithm: {cert.signature_hash_algorithm.name}\n"
        details += f"Version: {cert.version}\n"
        details += "-" * 80 + "\n"
    except Exception as e:
        details += f"Failed to parse certificate: {e}\n"
        details += "-" * 80 + "\n"
    return details

def main():
    input_file = 'certificates.txt'
    output_folder = 'cert_details'
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    with open(input_file, 'r') as file:
        cert_data = file.read()
    pattern = re.compile(
        r"adress: (0x[0-9A-F]{8} - 0x[0-9A-F]{8})\s*(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        re.DOTALL
    )
    matches = pattern.findall(cert_data)
    for address, cert_pem in matches:
        cert_pem = clean_certificate_text(cert_pem)
        details = get_certificate_details(cert_pem, address)
        with open(os.path.join(output_folder, f"{address}.txt"), 'w') as output_file:
            output_file.write(details)

if __name__ == "__main__":
    main()
