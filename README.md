# OhMyHackingTools - A Collection of Hacking and Analysis Utilities

Welcome to **CyberSecTools**, a repository containing six powerful utilities designed for cybersecurity enthusiasts, reverse engineers, and analysts. These tools focus on analyzing binary data, extracting patterns, decrypting ciphertext, and working with certificates and keys. Each tool is tailored for a specific purpose, ensuring efficiency and simplicity.

---

## 🔧 Tools Overview

### 1. **FileEntropyAnalysis**
- **Purpose:** Analyze and visualize the randomness (entropy) of a binary file.
- **Key Features:**
  - Calculates entropy for chunks of data.
  - Visualizes entropy trends in a plot.
- **Use Case:** Identify encrypted or compressed regions in binary files.

---

### 2. **BinaryPatternExtractor**
- **Purpose:** Search and extract specific patterns (e.g., keys, passwords, certificates) from binary files.
- **Key Features:**
  - Supports regex-based pattern matching.
  - Extracts sensitive data and saves it as individual files.
- **Use Case:** Extract cryptographic materials or sensitive information from firmware or memory dumps.

---

### 3. **PartitionTableExtractor**
- **Purpose:** Parse and extract partitions from a binary file using its partition table.
- **Key Features:**
  - Reads partition names, offsets, and sizes.
  - Extracts each partition to a separate file.
- **Use Case:** Analyze firmware or embedded systems' partitions.

---

### 4. **CertKeyMatcher**
- **Purpose:** Match private keys to their corresponding certificates.
- **Key Features:**
  - Compares public keys in certificates and private keys.
  - Extracts certificate metadata (e.g., subject, issuer, validity).
- **Use Case:** Validate cryptographic relationships between keys and certificates.

---

### 5. **VigenereCipherDecrypt**
- **Purpose:** Decrypt ciphertext encrypted twice using the Vigenère cipher.
- **Key Features:**
  - Brute-forces decryption using a list of keys.
  - Finds decrypted messages matching specific patterns.
- **Use Case:** Solve CTF challenges or analyze simple encrypted messages.

---

### 6. **CertMetaExtractor**
- **Purpose:** Parse and extract metadata from X.509 certificates.
- **Key Features:**
  - Reads PEM or DER formatted certificates.
  - Extracts details like subject, issuer, and validity dates.
- **Use Case:** Analyze certificates for audits or cryptographic research.

---

## 📂 File Structure
```plaintext
CyberSecTools/
├── FileEntropyAnalysis.py       # Entropy analysis for binary files.
├── BinaryPatternExtractor.py    # Extracts patterns from binary files.
├── PartitionTableExtractor.py   # Extracts partitions based on a partition table.
├── CertKeyMatcher.py            # Matches private keys to certificates.
├── VigenereCipherDecrypt.py     # Decrypts Vigenère cipher-encrypted messages.
├── CertMetaExtractor.py         # Extracts metadata from certificates.
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Libraries:
  - `numpy`
  - `matplotlib`
  - `cryptography`

Install required libraries:
```bash
pip install numpy matplotlib cryptography
```

---

### Usage

#### Run a tool:
```bash
python <ToolName>.py
```

#### Example:
```bash
python FileEntropyAnalysis.py
```

---

## ⚠️ Disclaimer

These tools are intended for educational and ethical purposes only. Use them responsibly and with proper authorization. The authors are not liable for any misuse of these tools.

---

## 🤝 Contributions

Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request.

---

## 📜 License

This repository is licensed under the [MIT License](LICENSE).

---

Happy hacking! 🚀
