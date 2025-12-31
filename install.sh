#!/bin/bash

# KNDYS Framework Installer
# Automated installation script for KNDYS penetration testing framework

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          KNDYS FRAMEWORK INSTALLER               ║"
echo "║      Penetration Testing Framework Setup         ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root for network modules
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Not running as root. Some network modules may require sudo.${NC}"
fi

# Check Python version
echo -e "${CYAN}[*] Checking Python version...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    REQUIRED_VERSION="3.8"
    
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
        echo -e "${GREEN}[✓] Python $PYTHON_VERSION detected${NC}"
    else
        echo -e "${RED}[✗] Python 3.8+ required. Found: $PYTHON_VERSION${NC}"
        exit 1
    fi
else
    echo -e "${RED}[✗] Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check pip
echo -e "${CYAN}[*] Checking pip...${NC}"
if command -v pip3 &>/dev/null; then
    echo -e "${GREEN}[✓] pip3 found${NC}"
else
    echo -e "${YELLOW}[!] pip3 not found. Installing...${NC}"
    python3 -m ensurepip --upgrade
fi

# Install system dependencies (optional)
echo -e "${CYAN}[*] Checking system dependencies...${NC}"
if command -v apt-get &>/dev/null; then
    echo -e "${YELLOW}[?] Install system dependencies? (y/n)${NC}"
    read -r install_deps
    if [[ $install_deps == "y" ]]; then
        echo -e "${CYAN}[*] Installing system packages...${NC}"
        sudo apt-get update
        sudo apt-get install -y python3-pip python3-dev libssl-dev libffi-dev build-essential
    fi
fi

# Install Python dependencies
echo -e "${CYAN}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Dependencies installed successfully${NC}"
else
    echo -e "${RED}[✗] Failed to install dependencies${NC}"
    exit 1
fi

# Rename main file if needed
if [ -f "tt" ] && [ ! -f "kndys.py" ]; then
    echo -e "${CYAN}[*] Renaming main script...${NC}"
    mv tt kndys.py
    echo -e "${GREEN}[✓] Renamed tt -> kndys.py${NC}"
fi

# Make executable
if [ -f "kndys.py" ]; then
    chmod +x kndys.py
    echo -e "${GREEN}[✓] Made kndys.py executable${NC}"
fi

# Create symbolic link (optional)
echo -e "${YELLOW}[?] Create symbolic link /usr/local/bin/kndys? (requires sudo) (y/n)${NC}"
read -r create_link
if [[ $create_link == "y" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    sudo ln -sf "$SCRIPT_DIR/kndys.py" /usr/local/bin/kndys
    echo -e "${GREEN}[✓] Symbolic link created. You can now run 'kndys' from anywhere${NC}"
fi

# Success message
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     INSTALLATION COMPLETED SUCCESSFULLY!         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${YELLOW}1.${NC} Run the framework: ${GREEN}python3 kndys.py${NC}"
echo -e "  ${YELLOW}2.${NC} Type ${GREEN}help${NC} to see available commands"
echo -e "  ${YELLOW}3.${NC} Type ${GREEN}show modules${NC} to list all modules"
echo ""
echo -e "${YELLOW}⚠  IMPORTANT:${NC}"
echo -e "  - Read ${CYAN}DISCLAIMER.md${NC} before use"
echo -e "  - Only test systems you own or have permission to test"
echo -e "  - Unauthorized access is illegal"
echo ""
echo -e "${CYAN}Documentation:${NC}"
echo -e "  - README.md"
echo -e "  - DOCUMENTATION_INDEX.md"
echo -e "  - IMPLEMENTATION_SUMMARY_v3.1.md"
echo ""
echo -e "${GREEN}Happy (ethical) hacking! 🔒${NC}"
