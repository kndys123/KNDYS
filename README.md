# KNDYS Framework

<div align="center">

**Advanced Penetration Testing & Red Team Operations Framework**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)]()

** [Complete Module Guide](GUIA_COMPLETA_MODULOS.md) - Step-by-step guide for ALL modules**

</div>

---

## Overview

KNDYS is a comprehensive penetration testing framework designed for security professionals, red teamers, and ethical hackers. It provides a unified interface for reconnaissance, vulnerability assessment, exploitation, and post-exploitation activities through 53 integrated modules.

### 53 Integrated Modules
- **Reconnaissance:** Port scanning, subdomain discovery, network mapping, OS detection, web crawling
- **Vulnerability Assessment:** SQL injection, XSS, CSRF, SSL/TLS, directory traversal, command injection
- **Web Exploitation:** SQL injection exploitation, XSS attacks, file upload bypass, XXE injection
- **Network Attacks:** ARP spoofing, DNS spoofing, packet sniffing, SSL stripping, DHCP attacks
- **Wireless Security:** WiFi scanning, cracking, rogue AP, network mapping
- **Social Engineering:** Phishing, credential harvesting, website cloning, SMS spoofing, pretexting, mass mailing
- **Post-Exploitation:** Credential dumping, privilege escalation, persistence, pivoting, lateral movement
- **Utilities:** Hash cracking, brute force, API fuzzing, JWT attacks, QR code generation, reverse shells, reporting

---

## Installation

### Simplest Method (Recommended)

Clone and run - dependencies install automatically on first launch:

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
chmod +x kndys.py && ./kndys.py
```

**First run takes 2-3 minutes** to auto-install dependencies. After that, it starts instantly.

### Alternative Methods

**If auto-install fails:**
```bash
pip3 install -r requirements.txt
# or on newer systems:
pip3 install --break-system-packages -r requirements.txt
```

**Using install script:**
```bash
chmod +x install.sh && ./install.sh
```

**For detailed installation help:** See [INSTALL.md](INSTALL.md)

---

## Basic Usage

```bash
# Start the framework
./kndys.py

# View all available modules
kndys> show modules

# Select a module
kndys> use scanner/sql_injection

# View module options
kndys(scanner/sql_injection)> show options

# Configure target
kndys(scanner/sql_injection)> set target http://example.com/page?id=1

# Run the scan
kndys(scanner/sql_injection)> run
```

**Quick Examples:**

```bash
# SQL Injection scan
./kndys.py
use scanner/sql_injection
set target http://testphp.vulnweb.com/artists.php?artist=1
run

# Port scan
use reconnaissance/port_scanner
set target scanme.nmap.org
set ports 1-1000
run

# XSS scan
use scanner/xss
set target http://example.com/search
set param q
run
```

**More examples:** See [QUICKSTART.md](QUICKSTART.md)

---

## Module Categories

| Category | Description | Modules |
|----------|-------------|---------|
| **Reconnaissance** | Information gathering | Port scanner, Subdomain enum, Web crawler, Network mapper |
| **Scanners** | Vulnerability assessment | SQL injection, XSS, CSRF, Directory traversal, SSL/TLS |
| **Exploits** | Active exploitation | SQL injection, Command injection, File upload, XSS |
| **Post-Exploitation** | Post-compromise ops | Credential dumper, Persistence, Privilege escalation, Pivoting |
| **Password Attacks** | Credential attacks | Brute force, Hash cracker, Password spray, Credential stuffing |
| **Wireless** | WiFi security testing | WiFi scanner, WPA cracker, Rogue AP |
| **Social Engineering** | Human-targeting attacks | Phishing, Credential harvester, Website cloner, QR generator |
| **Network Attacks** | Network-level attacks | ARP spoofing, DNS spoofing, SSL stripping, Packet sniffing |
| **Web Application** | Modern web testing | JWT cracker, API fuzzer, CORS scanner, NoSQL injection, GraphQL |

## Requirements

- **Python**: 3.8 or higher
- **OS**: Linux or macOS
- **Privileges**: Root/sudo (for network modules)

### Dependencies
```
requests
beautifulsoup4
colorama
selenium
scapy
cryptography
pycryptodome
jwt
qrcode
```

See `requirements.txt` for complete list.

## Configuration Examples

```bash
# Global configuration
set lhost 192.168.1.100
set lport 4444
set threads 10
set timeout 30

# Module-specific
use scanner/sql_injection
set target http://target.com/page?id=1
set method GET
set deep true
run
```

## Legal Disclaimer

 **CRITICAL**: This tool is for **authorized security testing only**.

- Use only on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- Users are solely responsible for compliance with all applicable laws
- Developers assume NO liability for misuse or damage

See [DISCLAIMER.md](DISCLAIMER.md) for complete legal information.

---

## Documentation

- **[Complete Module Guide](GUIA_COMPLETA_MODULOS.md)** - Step-by-step guide for ALL 53 modules
- **[Quick Start](INICIO_RAPIDO.md)** - Get started in 5 minutes
- **[Usage Examples](EJEMPLOS_USO.md)** - Practical examples for all modules
- **[Installation Help](INSTALL.md)** - Detailed installation guide
- **[Technical Analysis](ANALISIS_COMPLETO_MODULOS.md)** - In-depth module analysis
- **[Changelog](CHANGELOG.md)** - Version history

---

## Module Overview

**Reconnaissance (5 modules):**
Port Scanner, Subdomain Scanner, Web Crawler, Network Mapper, OS Detection

**Vulnerability Assessment (5 modules):**
SQL Scanner, XSS Scanner, SSL/TLS Scanner, Vulnerability Scanner, CSRF Scanner

**Web Exploitation (5 modules):**
SQL Injection, XSS Exploit, Command Injection, Directory Traversal, File Upload

**Network Attacks (5 modules):**
ARP Spoofing, DNS Spoofing, Packet Sniffer, SSL Strip, DHCP Starvation

**Wireless Security (3 modules):**
WiFi Scanner, WiFi Cracker, Rogue AP

**Social Engineering (6 modules):**
Phishing, Credential Harvester, Website Cloner, SMS Spoofing, Pretexting, Mass Mailer

**Post-Exploitation (4 modules):**
Credential Dumper, Privilege Escalation, Persistence, Pivot

**Password Attacks (3 modules):**
Hash Cracker, Brute Force, Spray Attack

**Advanced Testing (7 modules):**
JWT Cracker, API Fuzzer, CORS Scanner, NoSQL Injection, GraphQL Introspection, Buffer Overflow, Credential Stuffing

**Utilities (5 modules):**
QR Generator, USB Payload, Fake Update, Report Generator, Evidence Collector

**System Tools (3 modules):**
Shell, File Explorer, Multi-Handler

---

## Contributing

Contributions welcome! Please ensure:
- Code follows existing patterns
- Proper error handling included
- Testing in authorized environments only
- Documentation updated

## License

MIT License - See [LICENSE](LICENSE) file.

## Acknowledgments

Built for the security community. Thanks to all contributors and the open-source security tools that inspired this project.

---

<div align="center">

**Use Responsibly • Test Ethically • Secure The Future**

Made with care for security professionals

</div>
