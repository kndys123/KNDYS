# KNDYS Quick Start Guide

## Installation (2 Commands!)

```bash
# Clone and run
git clone https://github.com/kndys123/KNDYS.git && cd KNDYS
chmod +x kndys.py && ./kndys.py
```

**That's it!** Dependencies install automatically on first run.

## Alternative Methods

```bash
# If auto-install fails:
pip3 install -r requirements.txt
# or
pip3 install --break-system-packages -r requirements.txt
```

---

## Basic Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `show modules` | List all modules |
| `use <module>` | Select a module |
| `set <option> <value>` | Configure option |
| `run` | Execute module |
| `back` | Return to main menu |
| `exit` | Quit framework |

---

## Quick Examples

### 1. SQL Injection Scan

```bash
kndys> use scanner/sql_injection
kndys(scanner/sql_injection)> set target http://testphp.vulnweb.com/artists.php?artist=1
kndys(scanner/sql_injection)> set method GET
kndys(scanner/sql_injection)> run
```

### 2. Web Crawler

```bash
kndys> use reconnaissance/web_crawler
kndys(reconnaissance/web_crawler)> set target https://example.com
kndys(reconnaissance/web_crawler)> set max_pages 50
kndys(reconnaissance/web_crawler)> run
```

### 3. XSS Scanner

```bash
kndys> use scanner/xss
kndys(scanner/xss)> set target http://example.com/search
kndys(scanner/xss)> set param q
kndys(scanner/xss)> run
```

### 4. Port Scanner

```bash
kndys> use reconnaissance/port_scanner
kndys(reconnaissance/port_scanner)> set target scanme.nmap.org
kndys(reconnaissance/port_scanner)> set ports 1-1000
kndys(reconnaissance/port_scanner)> run
```

---

## Configuration

### Global Settings

```bash
kndys> set lhost 192.168.1.100 # Your IP address
kndys> set lport 4444 # Listening port
kndys> set threads 10 # Concurrent threads
```

### View Current Configuration

```bash
kndys> show options
```

---

## Tips

1. **Tab Completion**: Press Tab to autocomplete commands
2. **Command History**: Use ↑/↓ arrows for command history
3. **Module Info**: Type `info` after selecting a module
4. **Quick Exit**: Press Ctrl+C or type `exit`

---

## Need Help?

- Type `help` for command list
- Type `show modules` to see all available modules
- Visit documentation for detailed module guides
