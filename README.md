# 🔐 CipherVault — Cryptography Security Lab

### Understand. Test. Secure.

CipherVault is a web-based cybersecurity project designed to help users understand, test, and analyze cryptographic concepts through an interactive security laboratory.

The project combines secure cryptographic implementation, weak cryptography detection, educational cryptanalysis, hashing experiments, password-based key derivation, entropy analysis, and security scoring in one platform.

---

## 🚀 Live Demo

🔗 Live Application: YOUR_RENDER_URL_HERE

---

## 📌 Project Overview

Cryptography is an important part of modern cybersecurity. However, using weak algorithms, poor key management, weak passwords, or insecure configurations can introduce security risks.

CipherVault provides an interactive environment where users can:

- Perform secure encryption and decryption
- Detect weak cryptographic algorithms
- Experiment with hashing algorithms
- Understand basic cryptanalysis
- Demonstrate password-based key derivation
- Analyze entropy
- Generate a cryptographic security score
- Generate security reports

The project is designed mainly for cybersecurity learning and demonstration purposes.

---

## ✨ Features

### 🔒 1. Secure Encryption Lab

Provides secure message encryption and decryption using:

- AES-256-GCM
- Random nonce generation
- Authenticated encryption
- Secure cryptographic implementation

---

### ⚠️ 2. Weak Crypto Detector

Detects commonly known weak or outdated cryptographic algorithms such as:

- MD5
- SHA-1
- DES
- 3DES
- RC4

The system also provides recommendations for stronger alternatives.

---

### 🧪 3. Cryptanalysis Lab

Provides an educational Caesar Cipher brute-force simulator.

Users can:

- Enter encrypted text
- Test possible Caesar shifts
- Compare resulting plaintexts
- Understand the weakness of simple substitution ciphers

This module is intended for educational purposes.

---

### #️⃣ 4. Hash Playground

Supports hashing experiments using:

- SHA-256
- SHA-512

The module also demonstrates the avalanche effect by showing how small input changes can produce significantly different hash values.

---

### 📊 5. Crypto Security Score

CipherVault provides a rule-based security score based on selected cryptographic practices.

The score is intended as an educational security assessment and is not an industry certification.

---

### 🔑 6. Password → Key Demonstrator

Demonstrates the process:

Password  
↓  
Random Salt  
↓  
PBKDF2-HMAC-SHA256  
↓  
Derived Key  
↓  
AES-GCM Encryption

PBKDF2 is configured with 600,000 iterations.

---

### 📈 7. Entropy Visualizer

Provides an educational demonstration of password and character entropy.

It helps users understand why larger and more varied passwords generally provide a larger search space.

---

### 💥 8. Hash Collision Lab

Demonstrates the concept of hash collisions using a small educational toy hash.

This module does NOT attempt to break SHA-256 or other modern cryptographic hash functions.

---

### 📄 9. Security Report Generator

Generates a summary of the cryptographic security analysis performed in CipherVault.

---

## 🛡️ Security Features

CipherVault includes several application-level security measures:

- CSRF protection using Flask-WTF
- Password hashing
- Session protection
- Secure HTTP response headers
- Input validation
- Maximum input-size limits
- Strict Base64 validation
- Secure random nonce generation
- Secure random salt generation
- HTTPOnly session cookies
- SameSite cookie protection
- Environment-based secret key configuration

---

## 🧰 Technologies Used

### Frontend
- HTML5
- CSS3
- JavaScript

### Backend
- Python
- Flask

### Security Libraries
- Cryptography
- Flask-WTF
- WTForms

### Database
- SQLite

### Deployment
- Render
- Gunicorn

### Development Tools
- Visual Studio Code
- Git
- GitHub

---

## 📂 Project Structure

```text
CipherVault/
│
├── app/
│   ├── __init__.py
│   ├── routes.py
│   ├── crypto.py
│   └── database.py
│
├── static/
│   └── css/
│       └── style.css
│
├── templates/
│   ├── components/
│   │   └── navbar.html
│   ├── index.html
│   ├── secure_message.html
│   ├── weak_crypto.html
│   ├── hash_playground.html
│   ├── attack_simulator.html
│   ├── security_score.html
│   ├── key_derivation.html
│   ├── entropy.html
│   ├── hash_collision.html
│   ├── security_report.html
│   ├── login.html
│   └── register.html
│
├── instance/
│   └── users.db
│
├── .env
├── .gitignore
├── requirements.txt
└── run.py
