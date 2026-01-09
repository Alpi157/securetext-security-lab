# SecureText Security Lab (3-Part Hardening Series)

SecureText is a **console-based client/server messenger** built on purpose to be insecure first, then progressively hardened. This repo documents a **3-part security lab** where I:

- **identified vulnerabilities**
- **demonstrated realistic attacks**
- **implemented secure fixes**
- **validated the improvements** with evidence (logs, screenshots, and reports)

The end result is a practical, hands-on showcase of **application security + authentication + applied cryptography** in Python.

---

## What You’ll Find in This Repo

- A runnable messenger application (TCP sockets + JSON protocol)
- Three lab parts that build on each other:
  1) security vulnerability discovery + foundational fixes  
  2) modern authentication + Zero Trust controls  
  3) end-to-end encryption + secure session lifecycle  
- Reports and deliverables (implementation + writeups + evidence)

> **Security Note:** Some versions in this lab intentionally include insecure designs for learning and demonstration. Run only in a local/lab environment.

---

## Learning Objectives

By working through this lab, I got hands-on experience with:

- Vulnerability discovery and secure design thinking
- Password security (hashing, salting, migration)
- Network security (traffic capture, eavesdropping, tampering)
- Message integrity (MAC pitfalls vs secure HMAC)
- MFA using TOTP and rate limiting
- OAuth 2.0 login flow (console-compatible) with CSRF protections (state) and optional PKCE
- Zero Trust principles (RBAC, re-auth for sensitive actions, session limits, logging/monitoring)
- Applied cryptography for secure communication (ECDH, HKDF, AES-GCM)
- Key/session lifecycle management and secure cleanup

---

## Lab Structure

This lab is divided into **three parts**, each expanding the security posture of SecureText.

### Part 1 — Foundations: Vulnerabilities, Password Security, Network Attacks, and MACs

**Focus:** identify real weaknesses, exploit them, then fix them.

**Part 1A — Vulnerability Analysis**
- Ran the base application and mapped the attack surface
- Identified major issues across:
  - authentication / authorization
  - data protection (password storage)
  - confidentiality and integrity on the wire
  - privacy (user enumeration)
  - availability (resource exhaustion)
- Documented realistic exploitation scenarios for each finding

**Part 1B — Password Security (Data at Rest)**
- Replaced plaintext password storage with:
  - a fast hash baseline (to show why it’s insufficient)
  - a slow adaptive hash (bcrypt recommended)
- Implemented per-user salts (bcrypt includes salt)
- Added a migration strategy to upgrade legacy stored passwords
- Demonstrated password cracking differences (dictionary/rainbow-table resistance + timing impact)

**Part 1C — Network Security + Message Authentication Codes**
- Demonstrated plaintext traffic exposure via packet capture tools (Wireshark/tcpdump)
- Implemented an intentionally flawed MAC construction (to show pitfalls)
- Demonstrated how some MAC constructions are breakable (e.g., length extension risk in hash-prefix MACs)
- Replaced the flawed MAC with a secure construction (HMAC-SHA-256)
- Validated that forged/tampered messages are rejected

---

### Part 2 — Modern Authentication & Zero Trust Controls

**Focus:** strengthen identity, access control, and monitoring.

**Part 2A — MFA with TOTP**
- Added TOTP-based MFA using `pyotp`
- Generated per-user TOTP secrets during enrollment
- Provided QR onboarding (console-friendly ASCII QR)
- Added usability/security features:
  - clock-skew tolerance
  - rate limiting for TOTP attempts
  - generic error responses to reduce credential oracle leaks
- Demonstrated how MFA blocks account takeover when passwords are compromised

**Part 2B — OAuth 2.0 Login (Console-Compatible)**
- Implemented GitHub OAuth login via a console-friendly flow:
  - open the authorization URL in browser
  - user pastes redirect URL back into the console
  - app extracts the authorization code and validates `state`
  - exchanges code for access token and retrieves user identity
- Security features:
  - random `state` parameter to prevent CSRF
  - optional PKCE (S256) to reduce authorization code interception risk
  - no persistent token storage (tokens treated as short-lived)
- Hybrid support:
  - local username/password login
  - OAuth login (with optional account linking if desired)

**Part 2C — Zero Trust Enhancements**
- Implemented “never trust, always verify” patterns:
  - Challenge-response authentication (HMAC-based)
  - Role-Based Access Control (RBAC): `user` vs `admin`
  - Sensitive action protection (re-authentication required)
  - Session security:
    - inactivity timeout
    - action-count limits (auto-logout)
  - Logging & basic monitoring:
    - auth attempt logs (success/failure)
    - command execution logs
    - warnings after repeated failed attempts
    - logs for denied admin actions

---

### Part 3 — End-to-End Encryption (E2EE) & Secure Session Lifecycle

**Focus:** make the server blind to message contents while preserving integrity and usability.

**Part 3A — ECDH Key Exchange + HKDF**
- Implemented elliptic-curve Diffie–Hellman (P-256 / secp256r1)
- Derived symmetric keys using HKDF-SHA-256 from shared secrets
- Designed the flow so clients can establish shared keys without exposing key material to the server

**Part 3B — AES-256-GCM Authenticated Encryption**
- Implemented per-message encryption using AES-GCM:
  - random nonces per message
  - integrity via GCM authentication tag
- Ensured that:
  - ciphertext differs even for identical plaintext (fresh randomness)
  - tampering causes decryption failure (InvalidTag)

**Part 3C — Session Management & Secure Cleanup**
- Implemented session expiration and lifecycle controls to reduce key exposure:
  - inactivity timeout (e.g., 30 minutes)
  - pre-expiration warning (e.g., 5 minutes remaining)
  - forced re-authentication after expiry
  - secure cleanup of cryptographic state on both sides (wipe cached key material)
- Demonstrated:
  - server stores/relays only encrypted blobs
  - message history is unreadable on the server side

---

## Repository Layout

```text

├── README.md
├── part1/
│   ├── README.md
│   ├── Part1_Report.md
│   └── deliverables/
├── part2/
│   ├── README.md
│   ├── Part2_Report.md
│   └── deliverables/
├── part3/
│   ├── README.md
│   ├── Part3_Report.md
│   └── deliverables/
├── src/
│   └── securetext.py
└── .gitignore

```text
---

## Getting Started

### Prerequisites

- Python 3.7+
- Basic networking knowledge (sockets, ports, localhost)
- Git
- Familiarity with command-line tools

### Install / Setup

Clone the repo:

```bash
git clone https://github.com/Alpi157/securetext-security-lab.git
cd YOUR_REPO
```

(Recommended) Create a branch for your changes:

```bash
git checkout -b lab-work
```

### Run the Base Application

Start the server:

```bash
python3 src/securetext.py server
```

Start a client (run multiple terminals for different users):

```bash
python3 src/securetext.py
```

Create accounts and send messages to explore how the system behaves.

---

## Tools Used in This Lab

### Network Analysis
- Wireshark
- tcpdump
- netstat / lsof

### Cryptography / Security Utilities
- OpenSSL
- hashcat
- hash_extender / HashPump

---

## Safety & Responsible Use

This lab includes insecure components and attack demonstrations strictly for educational purposes.

- Run only in local/lab environments
- Do not use these techniques on systems you don’t own or have explicit permission to test
- Do not expose the vulnerable versions to the public internet

---

## Outcomes

By the end of the lab, SecureText evolves from an insecure messaging app into a prototype with:

- Strong password storage (bcrypt + migration)
- MFA (TOTP) and enhanced login protections
- OAuth-based login (console-compatible)
- Zero Trust controls (RBAC, re-auth, session limits, logging)
- End-to-end encryption using ECDH + HKDF + AES-GCM
- A session lifecycle that reduces long-term key exposure
