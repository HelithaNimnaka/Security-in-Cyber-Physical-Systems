# Security-in-Cyber-Physical-Systems
EN4720 - Security in Cyber-Physical Systems  
University of Moratuwa, Department of Electronic and Telecommunication Engineering

---

### Milestone 1 Securing a Smart Building System 🏢🔐
[Analyzed cybersecurity vulnerabilities in Honeywell smart building systems.](Milestone_1.pdf)
- Identified threats:
  - Weak encryption & poor key management 🔓
  - Weak password policies & improper access controls 🚫

- Mitigation strategies & best practices:
  - Enhanced encryption (AES-256, TLS 1.3) 🔐
  - Multi-factor Authentication (MFA) and strong passwords 🛡️
  - Regular updates & Network Segmentation 🌐
  - Zero Trust Architecture (ZTA) 🔍
  - Real-time Intrusion Detection & Security audits 🔒

---

### Milestone 2: Cryptographic API Implementation 🔑💻
[Developed a secure Cryptographic API for encryption, decryption, and hashing.](Cryptographic-API-Implementation)
- Implemented features:
  - RSA and AES key generation 🔑
  - RSA encryption/decryption (with OAEP padding) 🔒
  - Hashing (SHA-256, SHA-512) for integrity checks ✅

- Security enhancements:
  - Secure key management and storage 💼
  - Access control and authentication mechanisms 🔑
  - Robust error handling ⚙️

---

  ### Tech Stack:
  - FastAPI & Swagger UI🐍
  - Postman (API Testing & Validation) 🧪
  - OpenSSL (Cryptographic Operations) 🛠️
  - Python Libraries: PyCryptodome, Cryptography 📚

---

### Milestone 3: Identify Vulnerabilities in Existing Smart Home System 🏠⚠️
[Performed a comprehensive security analysis of APIs in a real-world smart home ecosystem.](Milestone_3.pdf)

- Found issues:
  - Unencrypted (HTTP) communication 📡
  - Weak/missing authentication & access control 🚫
  - Poor input validation (injection risks) 🦠
  - No brute-force protection or rate limiting 🛑
  - Use of default credentials & predictable IDs 🔢
  - Insecure firmware update process 🪛

- Recommendations:
  - Use HTTPS everywhere 🔒
  - Strong authentication & authorization (JWT, MFA) ✅
  - Enforce input validation and password policies 🛡️
  - Add rate limiting & anti-bot protections 🧱
  - Secure firmware updates (signing, validation) 🔏
  - Monitor and log all activities 📊
