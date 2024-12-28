"""
Binary Pattern Finder and Extractor

Description:
This program searches a binary file for specific patterns, such as RSA keys, certificates, or passwords. The program performs the following:
1. Opens a binary file and searches for user-defined patterns using regular expressions.
2. Extracts data matching the patterns and saves it to separate files.
3. Provides useful debugging information about the offsets and types of matched patterns.

Use Case:
The tool is ideal for extracting sensitive information from binary files during reverse engineering or malware analysis.

Patterns Supported:
- RSA private/public keys (PEM format)
- EC private keys (PEM format)
- X.509 certificates (PEM and DER formats)
- Embedded passwords
"""
import re
import os

def find_patterns(bin_file_path, patterns):
    results = []
    with open(bin_file_path, 'rb') as f:
        content = f.read()
        for pattern_name, pattern in patterns.items():
            for match in re.finditer(pattern, content):
                start, end = match.span()
                results.append((pattern_name, start, end, content[start:end]))
    return results

def save_results(results, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    for i, (pattern_name, start, end, data) in enumerate(results):
        file_name = f"{pattern_name}_{i+1}_{start}.bin"
        file_path = os.path.join(output_folder, file_name)
        with open(file_path, 'wb') as f:
            f.write(data)
        print(f"Saved {pattern_name} data at offset {start} to {file_path}")

def main():
    bin_file_path = 'example.bin'
    output_folder = 'secrets'
    patterns = {
        'RSA_PRIVATE_KEY_PEM': re.compile(b'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----', re.DOTALL),
        'RSA_PUBLIC_KEY_PEM': re.compile(b'-----BEGIN RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----', re.DOTALL),
        'EC_PRIVATE_KEY_PEM': re.compile(b'-----BEGIN EC PRIVATE KEY-----.*?-----END EC PRIVATE KEY-----', re.DOTALL),
        'CERTIFICATE_PEM': re.compile(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.DOTALL),
        'PRIVATE_KEY_DER': re.compile(b'\x30\x82[\x00-\xff]{2}\x02\x01\x00\x02'),
        'PUBLIC_KEY_DER': re.compile(b'\x30\x82[\x00-\xff]{2}\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03'),
        'CERTIFICATE_DER': re.compile(b'\x30\x82[\x00-\xff]{2}\x30\x82[\x00-\xff]{2}\xA0\x03\x02\x01\x02\x02'),
        'PASSWORD': re.compile(b'password=[^\x00-\x20]+'),
        'PASSWD': re.compile(b'passwd=[^\x00-\x20]+'),
        'PWD': re.compile(b'pwd=[^\x00-\x20]+')
    }
    if not os.path.isfile(bin_file_path):
        print(f"File {bin_file_path} does not exist.")
        return
    results = find_patterns(bin_file_path, patterns)
    if not results:
        print("No patterns found.")
        return
    save_results(results, output_folder)

if __name__ == "__main__":
    main()
