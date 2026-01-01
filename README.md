# KNDYS Framework v3.2

<div align="center">

**Advanced Penetration Testing & Red Team Operations Framework**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)]()

**Status:** Production Ready | **Modules:** 53 | **Code Quality:** A+ (98/100)

</div>

---

## Quick Navigation

- **Start Here:** [INICIO_RAPIDO.md](INICIO_RAPIDO.md) (5 minutes)
- **Learn All Modules:** [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md) (complete guide)
- **Practical Examples:** [EJEMPLOS_USO.md](EJEMPLOS_USO.md) (10 real-world cases)
- **Documentation Index:** [DOCUMENTACION.md](DOCUMENTACION.md) (navigation)

---

## Overview

KNDYS is a comprehensive penetration testing framework with **53 integrated modules** for security professionals, red teamers, and ethical hackers. It provides a unified interface for reconnaissance, vulnerability assessment, exploitation, and post-exploitation activities.

**Ready for production use right now** - no waiting for optimizations.

---

## Get Started in 5 Minutes

```bash
# Clone the repository
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS

# Make executable and run
chmod +x kndys.py && ./kndys.py

# First run auto-installs dependencies (2-3 minutes)
# Then you're ready to go
```

**New to KNDYS?** Read [INICIO_RAPIDO.md](INICIO_RAPIDO.md) - takes 5 minutes.

---

## Installation

### Automatic (Recommended)

Dependencies auto-install on first launch:

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
chmod +x kndys.py && ./kndys.py
```

### Manual (If Auto-Install Fails)

```bash
pip3 install -r requirements.txt
# or on newer systems:
pip3 install --break-system-packages -r requirements.txt
```

**Detailed help:** [INSTALL.md](INSTALL.md)

---

## Basic Usage

```bash
# Start the framework
./kndys.py

# View all 53 modules
kndys> show modules

# Select a module
kndys> use port_scanner

# View options
kndys(port_scanner)> show options

# Configure
kndys(port_scanner)> set target scanme.nmap.org
kndys(port_scanner)> set ports 1-1000

# Run
kndys(port_scanner)> run
```

---

## 53 Integrated Modules

### Reconnaissance (5)
Port Scanner • Subdomain Scanner • Web Crawler • Network Mapper • OS Detection

### Vulnerability Assessment (5)
SQL Scanner • XSS Scanner • SSL/TLS Scanner • Vulnerability Scanner • CSRF Scanner

### Web Exploitation (5)
SQL Injection • XSS Exploit • Command Injection • Directory Traversal • File Upload

### Network Attacks (5)
ARP Spoofing • DNS Spoofing • Packet Sniffer • SSL Strip • DHCP Starvation

### Wireless Security (3)
WiFi Scanner • WiFi Cracker • Rogue AP

### Social Engineering (6)
Phishing • Credential Harvester • Website Cloner • SMS Spoofing • Pretexting • Mass Mailer

### Post-Exploitation (4)
Credential Dumper • Privilege Escalation • Persistence • Pivot

### Password Attacks (3)
Hash Cracker • Brute Force • Spray Attack

### Advanced Testing (7)
JWT Cracker • API Fuzzer • CORS Scanner • NoSQL Injection • GraphQL Introspection • Buffer Overflow • Credential Stuffing

### Utilities (5)
QR Generator • USB Payload • Fake Update • Report Generator • Evidence Collector

### System Tools (3)
Shell • File Explorer • Multi-Handler

**Complete documentation:** [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

---

## Requirements

- **Python:** 3.8 or higher
- **OS:** Linux or macOS
- **Privileges:** Root/sudo (for network modules)

### Dependencies
```
requests
beautifulsoup4
scapy
selenium
cryptography
pycryptodome
jwt
qrcode
paramiko
```

See `requirements.txt` for complete list.

---

## Framework Status

| Metric | Value |
|--------|-------|
| Total Modules | 53 |
| Code Quality | A+ (98/100) |
| Tests Passing | 100% (41/41) |
| Lines of Code | 41,433 |
| Production Ready | Yes |

---

## Documentation

| File | Purpose |
|------|---------|
| [INICIO_RAPIDO.md](INICIO_RAPIDO.md) | 5-minute quick start |
| [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md) | All 53 modules documented |
| [EJEMPLOS_USO.md](EJEMPLOS_USO.md) | 10 practical examples |
| [DOCUMENTACION.md](DOCUMENTACION.md) | Documentation index |
| [ESTADO_ACTUAL.md](ESTADO_ACTUAL.md) | Current framework status |
| [ANALISIS_COMPLETO_MODULOS.md](ANALISIS_COMPLETO_MODULOS.md) | Technical analysis |
| [INSTALL.md](INSTALL.md) | Installation guide |
| [DISCLAIMER.md](DISCLAIMER.md) | Legal information |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Common Commands

```bash
show modules           # List all 53 modules
use <module_name>      # Select a module
show options          # Show module parameters
set <param> <value>   # Configure parameter
run                   # Execute module
back                  # Go back
help                  # Show help
exit                  # Exit framework
```

---

## Legal Disclaimer

**CRITICAL:** This tool is for **authorized security testing only**.

- Use only on systems you own or have explicit written permission to test
- Unauthorized access is illegal
- Users are solely responsible for compliance with applicable laws
- Developers assume NO liability for misuse or damage

**Full disclaimer:** [DISCLAIMER.md](DISCLAIMER.md)

---

## Contributing

Contributions welcome! Ensure:
- Code follows existing patterns
- Proper error handling
- Testing in authorized environments
- Documentation updated

---

## License

MIT License - See [LICENSE](LICENSE) file.

---

<div align="center">

**Use Responsibly • Test Ethically • Secure The Future**

Built for security professionals by the community

**Version:** 3.2 | **Status:** Production Ready

</div>
