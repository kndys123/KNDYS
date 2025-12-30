# KNDYS Installation Guide

## 🎯 Simplest Method (Recommended)

Just clone and run! All dependencies install automatically:

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
chmod +x kndys.py
./kndys.py
```

**First run only:** The framework will automatically detect and install missing Python packages (takes 2-3 minutes). After that, it starts instantly every time.

---

## ⚙️ Alternative Installation Methods

### Method 1: Manual pip install

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
pip3 install -r requirements.txt
./kndys.py
```

### Method 2: For "externally-managed-environment" errors

On newer systems (Debian 12, Ubuntu 23.04+, Kali 2023+), use:

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
pip3 install --break-system-packages -r requirements.txt
./kndys.py
```

### Method 3: Virtual environment (cleanest)

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
./kndys.py
```

### Method 4: Using install.sh script

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
chmod +x install.sh
./install.sh
```

---

## 🐛 Troubleshooting

### Issue: "pip3 not found"

**Solution:**
```bash
# Debian/Ubuntu/Kali
sudo apt update && sudo apt install python3-pip

# macOS
brew install python3
```

### Issue: "Permission denied"

**Solution:**
```bash
chmod +x kndys.py
# Or run with:
python3 kndys.py
```

### Issue: "No module named 'requests'"

**Solution:** The auto-installer should handle this, but if it fails:
```bash
pip3 install -r requirements.txt
# or
pip3 install --break-system-packages -r requirements.txt
```

### Issue: Network modules require root

**Solution:** Some modules (packet sniffing, ARP spoofing) need root:
```bash
sudo ./kndys.py
```

---

## 📋 Requirements

- **Python:** 3.8 or higher
- **OS:** Linux, macOS, or WSL2
- **Internet:** Required for first-time dependency installation
- **Disk Space:** ~200MB for framework + dependencies
- **Privileges:** Root/sudo for network attack modules only

---

## ✅ Verification

After installation, verify everything works:

```bash
./kndys.py
# Inside the framework:
kndys> show modules
kndys> use reconnaissance/port_scanner
kndys> info
kndys> exit
```

If you see the module list and info, you're all set!

---

## 🚀 Quick Start

Once installed, see [QUICKSTART.md](QUICKSTART.md) for usage examples.

---

## 💡 Pro Tips

1. **Add to PATH** for system-wide access:
   ```bash
   sudo ln -s $(pwd)/kndys.py /usr/local/bin/kndys
   # Now run from anywhere:
   kndys
   ```

2. **Create alias** for quick access:
   ```bash
   echo "alias kndys='cd ~/KNDYS && ./kndys.py'" >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Update framework:**
   ```bash
   cd KNDYS
   git pull
   ```

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/kndys123/KNDYS/issues)
- **Documentation:** See [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)
- **Quick Reference:** See [QUICKSTART.md](QUICKSTART.md)
