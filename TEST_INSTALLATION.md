# KNDYS Installation Test Guide

## How to Verify Installation Works

### Quick Test

```bash
# After cloning KNDYS:
cd KNDYS
./kndys.py
```

### Expected Behavior

#### First Run (with missing dependencies):
```
[!] First run detected - installing X dependencies...
[*] This is a one-time setup and will take a few minutes.

[] All dependencies installed successfully!

╔══════════════════════════════════════════════════╗
║ KNDYS FRAMEWORK ║
║ Penetration Testing Framework v3.1 ║
╚══════════════════════════════════════════════════╝
```

#### Subsequent Runs:
```
╔══════════════════════════════════════════════════╗
║ KNDYS FRAMEWORK ║
║ Penetration Testing Framework v3.1 ║
╚══════════════════════════════════════════════════╝

kndys>
```

### Test Commands

Once in the framework, try these:

```bash
# List all modules
kndys> show modules

# Try loading a module
kndys> use scanner/sql_injection

# View options
kndys(scanner/sql_injection)> show options

# Return to main menu
kndys(scanner/sql_injection)> back

# Exit
kndys> exit
```

### Verification Checklist

- [ ] `./kndys.py` runs without errors
- [ ] KNDYS banner displays
- [ ] `kndys>` prompt appears
- [ ] `show modules` lists 50+ modules
- [ ] Can load a module with `use`
- [ ] `show options` displays module settings
- [ ] `exit` quits cleanly

### Troubleshooting

**If auto-install fails:**
```bash
# Method 1: Manual install
pip3 install -r requirements.txt

# Method 2: With break-system-packages flag
pip3 install --break-system-packages -r requirements.txt

# Method 3: Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./kndys.py
```

**If permission denied:**
```bash
chmod +x kndys.py
# or
python3 kndys.py
```

**If Python version error:**
```bash
# Check version (need 3.8+)
python3 --version

# Update Python if needed:
# Debian/Ubuntu/Kali:
sudo apt update && sudo apt install python3.10

# macOS:
brew install python@3.10
```

### Test Scan (Optional)

Run a real scan to verify everything works:

```bash
./kndys.py
kndys> use reconnaissance/port_scanner
kndys(reconnaissance/port_scanner)> set target scanme.nmap.org
kndys(reconnaissance/port_scanner)> set ports 80,443
kndys(reconnaissance/port_scanner)> run
```

Expected: Port scan results showing open/closed ports

### Success Indicators

 No Python import errors
 All modules load correctly
 Can configure module options
 Scans produce JSON output files
 Clean exit with Ctrl+C or `exit`

### Report Issues

If you encounter problems:

1. Check Python version: `python3 --version` (need 3.8+)
2. Check pip: `pip3 --version`
3. Try manual install: `pip3 install -r requirements.txt`
4. Check permissions: `ls -la kndys.py` (should have execute bit)
5. Report issue with error message and Python/OS version

---

**Installation successful?** → See [GETTING_STARTED.md](GETTING_STARTED.md) for next steps!
