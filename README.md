# 🔍 Origin Finder - Advanced Origin IP Discovery Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-green.svg)](https://openssl.org)

A comprehensive, 30-method origin IP discovery tool written in pure C with **NO external command dependencies**.

## ✨ Features

- **30 Native Methods** - All implemented in pure C
- **No External Commands** - Doesn't call dig, curl, openssl, whois, jq
- **CDN Detection & Bypass** - Cloudflare, Akamai, Fastly, CloudFront
- **Mathematical Validation** - Fuzzy HTML hashing, error page matching
- **Timing Attacks** - Proxy penalty detection
- **SSRF Listener** - Built-in pingback receiver
- **Stealth Mode** - Rate limiting and delays

## 🚀 Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install build-essential libcurl4-openssl-dev libssl-dev

# Arch Linux
sudo pacman -S gcc curl openssl

# macOS
brew install curl openssl
```
## Compilation
```bash
gcc -o origin_finder origin_finder.c -lcurl -lssl -lcrypto -lpthread -O2 -lm
```
## Usage
```bash
# Basic scan
./origin_finder target.com

# Deep scan with aggressive mode
./origin_finder target.com --deep --aggressive

# Disable stealth (faster)
./origin_finder target.com --no-stealth

# Debug mode
./origin_finder target.com --debug
```
## 📋 Methods Overview
**Phase 1: Original Discovery (20 Methods)**

- CNAME Recursion Analysis
- SSL Certificate SAN Analysis
- IPv6 Leak Detection
- DNS Bruteforce
- Historical DNS Analysis
- Certificate Transparency (crt.sh)
- HTTP Redirect Analysis
- X-Header Leak Detection
- robots.txt & sitemap.xml Analysis
- Host Header Injection
- CDN Detection

**Phase 2: Advanced Modules (4 Methods)**

- Subnet Neighbor Scanner
- Favicon MurmurHash3 Fingerprinting
- Absolute URL Path Bypass
- mTLS Probing
- SNI Default Misconfiguration Probe

**Phase 3: Mathematical Validation (6 Methods)**

- Fuzzy HTML Structural Hashing
- Timing Attack (Proxy Penalty Detection)
- Cross-Protocol Service Correlation
- Alternative Services Probing
- Error Page Fingerprinting
- Header Normalization Check

## 📊 Output
The tool generates:
- Console output with color-coded results
- ```origin_discovery.log``` - Detailed scan log
- ```origin_report.txt``` - Comprehensive final report

## ⚠️ Disclaimer
**This tool is for educational purposes and authorized security testing only.
Use only on domains you own or have explicit permission to test.**

## 📝 License
**MIT License - See LICENSE file for details**

## 👨‍💻 Author
**Rehan Malek - [GitHub](https://github.com/Rehan137)**

## 🤝 Contributing
**Contributions welcome! Please open an issue or pull request.**
