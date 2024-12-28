"""
Vigenère Cipher Decryption Program

Description:
This program attempts to decrypt a ciphertext that has been encrypted twice using the Vigenère cipher. It performs the following:
1. Reads a list of possible keys from a local file.
2. Reads the ciphertext from a separate file.
3. Iterates over each key to decrypt the ciphertext twice.
4. Writes the decrypted messages along with the keys that produced them to an output file if they match specific patterns (e.g., containing 'htb{').

Use Case:
Useful in cryptanalysis tasks, especially for CTF challenges, where the decryption process involves brute-forcing keys against known patterns.

Dependencies:
- Basic Python libraries.
"""
def decrypt_vigenere(ciphertext, key):
    ciphertext = ciphertext.lower()
    plaintext = ''
    for i, ch in enumerate(ciphertext):
        if ch.isalpha():
            nch = ord(ch) - 97
            nk = ord(key[i % len(key)]) - 97
            plaintext += chr((nch - nk + 26) % 26 + 97)
        else:
            plaintext += ch
    return plaintext

def read_keys_from_file(file_path):
    with open(file_path, 'r') as f:
        keys = f.read().splitlines()
    return keys

def read_ciphertext_from_file(file_path):
    with open(file_path, 'r') as f:
        ciphertext = f.read().strip()
    return ciphertext

def main():
    key_file_path = '10k-most-common.txt'
    ciphertext_file_path = 'ciphertext.txt'
    output_file_path = 'decrypted_messages.txt'
    keys = read_keys_from_file(key_file_path)
    ciphertext = read_ciphertext_from_file(ciphertext_file_path)
    with open(output_file_path, 'w') as output_file:
        for key in keys:
            key = key.strip()
            if key.isalpha():
                decrypted_once = decrypt_vigenere(ciphertext, key)
                decrypted_twice = decrypt_vigenere(decrypted_once, key)
                if 'htb{' in decrypted_twice:
                    output_file.write(f"Key: {key}\nDecrypted Message: {decrypted_twice}\n\n")
                    print(f"Key: {key} -> Decrypted message found!")

if __name__ == '__main__':
    main()
