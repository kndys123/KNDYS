# Getting Started with KNDYS

Welcome to KNDYS! This guide will get you up and running in minutes.

---

## 1️⃣ Installation (One-Liner)

```bash
git clone https://github.com/kndys123/KNDYS.git && cd KNDYS && chmod +x kndys.py && ./kndys.py
```

That's it! On first run, KNDYS automatically installs all dependencies (takes 2-3 minutes).

---

## 2️⃣ Your First Scan

After installation, try this SQL injection test:

```bash
# Start KNDYS
./kndys.py

# In the framework:
kndys> use scanner/sql_injection
kndys(scanner/sql_injection)> set target http://testphp.vulnweb.com/artists.php?artist=1
kndys(scanner/sql_injection)> run
```

You'll see real-time results as KNDYS tests for SQL injection vulnerabilities!

---

## 3️⃣ Understanding the Interface

### Main Menu

```
kndys>
```

This is your main prompt. From here you can:
- `show modules` - List all available tools
- `use <module>` - Select a tool
- `help` - View commands
- `exit` - Quit

### Module Menu

```
kndys(scanner/sql_injection)>
```

When you're in a module, you can:
- `show options` - View required settings
- `set <option> <value>` - Configure the module
- `run` - Execute the scan/attack
- `back` - Return to main menu
- `info` - Show module details

---

## 4️⃣ Common Commands

| Command | What it does |
|---------|--------------|
| `show modules` | List all available modules |
| `use <module>` | Select a module to use |
| `show options` | View module settings |
| `set <option> <value>` | Configure a setting |
| `run` | Execute the selected module |
| `back` | Return to main menu |
| `sessions` | View active sessions |
| `exit` | Quit KNDYS |

---

## 5️⃣ Essential Modules to Try

### Reconnaissance

**Port Scanner** - Find open ports and services
```bash
use reconnaissance/port_scanner
set target scanme.nmap.org
set ports 1-1000
run
```

**Subdomain Scanner** - Discover subdomains
```bash
use reconnaissance/subdomain_scanner
set target example.com
run
```

**Web Crawler** - Map website structure
```bash
use reconnaissance/web_crawler
set target https://example.com
set max_pages 50
run
```

### Vulnerability Scanning

**SQL Injection** - Test for SQL injection
```bash
use scanner/sql_injection
set target http://testphp.vulnweb.com/artists.php?artist=1
set method GET
run
```

**XSS Scanner** - Find cross-site scripting
```bash
use scanner/xss
set target http://example.com/search
set param q
run
```

**CSRF Scanner** - Check CSRF protection
```bash
use scanner/csrf
set url http://example.com
run
```

### Password Attacks

**Hash Cracker** - Crack password hashes
```bash
use password/hash_cracker
set hash 5f4dcc3b5aa765d61d8327deb882cf99
set hash_type md5
run
```

**Brute Force** - Dictionary attack
```bash
use password/brute_force
set target http://example.com/login
set username admin
set wordlist passwords.txt
run
```

---

## 6️⃣ Configuration Tips

### Set Global Options

```bash
kndys> set lhost 192.168.1.100 # Your IP
kndys> set lport 4444 # Your listening port
kndys> set threads 10 # Concurrent threads
```

### View Current Config

```bash
kndys> show options
```

### Save Session

All scan results are automatically saved to JSON files in the current directory with timestamps.

---

## 7️⃣ Legal & Ethical Use

 **IMPORTANT:**

- Only test systems you own or have written permission to test
- Unauthorized penetration testing is illegal
- KNDYS is for ethical hacking and security research only
- Always follow responsible disclosure practices

See [DISCLAIMER.md](DISCLAIMER.md) for full legal information.

---

## 8️⃣ Need Help?

### In the Framework
- Type `help` for command list
- Type `info` after selecting a module for details
- Type `show options` to see what settings are needed

### Documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick reference guide
- [INSTALL.md](INSTALL.md) - Detailed installation help
- [README.md](README.md) - Full feature list
- [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) - All docs

### Troubleshooting
- Check [INSTALL.md](INSTALL.md) for common installation issues
- Run with `python3 kndys.py` if `./kndys.py` doesn't work
- Some modules need root: `sudo ./kndys.py`

---

## 9️⃣ Pro Tips

1. **Tab Completion:** Press Tab to autocomplete commands and module names

2. **Command History:** Use ↑/↓ arrows to scroll through previous commands

3. **Quick Module Access:** You can load and run in one session:
 ```bash
 ./kndys.py
 use scanner/sql_injection
 set target http://example.com?id=1
 run
 exit
 ```

4. **Multiple Targets:** Create a targets file and loop through them

5. **Results Location:** All scan results save to the current directory with timestamps

6. **Update KNDYS:**
 ```bash
 cd KNDYS
 git pull
 ```

---

## Next Steps

1. Install KNDYS
2. Run your first scan
3. Read [QUICKSTART.md](QUICKSTART.md) for more examples
4. Explore all modules with `show modules`
5. Learn about specific modules in [MODULES_GUIDE_v3.1.md](MODULES_GUIDE_v3.1.md)
6. Start your security testing journey!

---

**Happy Hacking! **

Remember: With great power comes great responsibility. Use KNDYS ethically and legally.
