# Password-Auditor
A Python security tool that audits password strength, cracks hashes using dictionary attacks, estimates crack times, and generates HTML audit reports.

**⚠️ For authorized security testing and educational use only.**

## Features
- MD5, SHA-1, SHA-256, and bcrypt hash cracking
- Dictionary attack using rockyou.txt or built-in wordlist
- Password entropy scoring (0–100) with letter grades
- Crack time estimation based on GPU attack speeds
- Weak pattern detection (keyboard walks, leet speak, year suffixes)
- Professional HTML report generation

## Installation
```bash
git clone https://github.com/YOURUSERNAME/password-auditor
cd password-auditor
pip install -r requirements.txt
```

## Usage
```bash
# Run demo
python auditor.py --demo

# Audit a password
python auditor.py --password "hello123"

# Crack a hash
python auditor.py --hash 482c811da5d5b4bc6d497ffa98491e38

# Crack with rockyou.txt
python auditor.py --hash [HASH] --wordlist rockyou.txt

# Audit file + generate report
python auditor.py --file passwords.txt --report report.html
```

## Tech Stack
Python 3.10+ | hashlib | bcrypt | rich | argparse

## Legal Disclaimer
This tool is intended for authorized penetration testing, CTF challenges,
and security education only. Never use on systems you don't own.
