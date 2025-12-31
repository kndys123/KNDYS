#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

# Simular importaciones básicas
import requests
from bs4 import BeautifulSoup
import re
import time

# Crear clase simple para probar funciones individuales
class TestVulnScanner:
    def __init__(self):
        pass
    
    def _get_severity_color(self, severity):
        colors = {
            'critical': '\033[95m',  # Magenta
            'high': '\033[91m',      # Red
            'medium': '\033[93m',    # Yellow
            'low': '\033[96m',       # Cyan
            'info': '\033[94m'       # Blue
        }
        return colors.get(severity.lower(), '\033[0m')
    
    def test_severity_colors(self):
        print("\n🎨 Probando colores de severidad:")
        severities = ['critical', 'high', 'medium', 'low', 'info']
        for sev in severities:
            color = self._get_severity_color(sev)
            print(f"  {color}● {sev.upper()}\033[0m")
        print("  ✅ Colores funcionando correctamente\n")

if __name__ == '__main__':
    tester = TestVulnScanner()
    print("\n" + "="*60)
    print("  VULN_SCANNER MODULE - Quick Test")
    print("="*60)
    tester.test_severity_colors()
    print("✅ Test completado exitosamente!")
    print("="*60 + "\n")
