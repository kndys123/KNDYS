# KNDYS Framework - Changelog

## v3.1 - Expansión de Módulos SET-Inspired (Enero 2025)

### 🔥 Módulos Mejorados - Reconstrucciones Completas

#### 📧 credential_harvester (v3.0) - COMPLETO ✅
- **Transformación:** 42 líneas → 900+ líneas (2,043% aumento)
- **15 templates profesionales:** Office365, Google, Gmail, Facebook, LinkedIn, PayPal, Amazon, Apple, Twitter, Instagram, Microsoft, Dropbox, GitHub, Netflix, Adobe
- **Servidor Flask multi-threaded** con threading.Thread
- **Base de datos SQLite** con 2 tablas (campaigns, credentials)
- **47 tests** con 100% de cobertura (47/47 passed)
- **Exportación** CSV/JSON/HTML con reportes profesionales
- **Características:** Logging, QR codes, SSL/TLS, custom templates, analytics en tiempo real
- **Seguridad:** Input validation, XSS prevention, SQL injection prevention
- **Documentación:** CREDENTIAL_HARVESTER_IMPLEMENTATION_REPORT.md

#### 📧 phishing (v3.0) - COMPLETO ✅
- **Transformación:** 32 líneas → 675+ líneas (2,009% aumento)
- **20 templates profesionales:** Office365, Google, PayPal, Amazon, LinkedIn, Facebook, Apple, Banking, Dropbox, DocuSign, UPS, FedEx, Zoom, Slack, Teams, HR, IT, Invoice, Wire Transfer, COVID
- **Sistema SMTP multi-threaded** con queue.Queue
- **Base de datos SQLite** con 3 tablas (campaigns, targets, tracking)
- **Email tracking:** Opens (pixels), clicks (URL wrapping)
- **Personalización:** 8 variables (first_name, last_name, email, company, position, domain, username, tracking_id)
- **25 tests** con 100% de cobertura (25/25 passed)
- **Exportación** CSV/JSON/HTML con reportes profesionales
- **Rate limiting:** Configurable (10 emails/min por defecto)
- **Attachments:** Soporte para archivos adjuntos
- **Seguridad:** Email validation (regex + consecutive dots check), HTML injection prevention, SQL injection prevention
- **Configuración:** 30+ opciones (SMTP, tracking, threading, rate limiting, export)
- **Documentación:** PHISHING_MODULE_IMPLEMENTATION_REPORT.md

### 🚀 Nuevos Módulos

#### 📧 Social Engineering - Expansión SET-Inspired (6 nuevos)
1. **mass_mailer** - Sistema de campañas de email masivo
   - Templates profesionales: invoice, shipping, password_reset, security_alert
   - Variables dinámicas: {link}, {random}, {tracking}, {amount}, {location}, {time}
   - Control de delay entre envíos
   - Configuración SMTP flexible

2. **qr_generator** - Generador de códigos QR maliciosos
   - Generación con librería qrcode
   - Preview ASCII cuando qrcode no está instalado
   - Casos de uso: physical security, parking lot drops, fake WiFi posters

3. **usb_payload** - Generador BadUSB/Rubber Ducky
   - Soporte para Windows (PowerShell reverse shell, credential harvester)
   - Soporte para Linux (bash reverse shell)
   - Compatible: USB Rubber Ducky, Bash Bunny, Teensy, Arduino BadUSB
   - Scripts en formato Rubber Ducky

4. **fake_update** - Generador de páginas de actualización falsas
   - Templates: Chrome, Firefox, Flash Player, Windows Update
   - HTML/CSS profesional con styling realista
   - Servidor HTTP integrado
   - Delivery: watering hole, compromised sites, malicious ads

5. **sms_spoofing** - Campañas SMS con integración Twilio
   - Integración completa con Twilio API para envío real
   - Templates profesionales: DHL, bancos, PayPal, Amazon, Netflix
   - Variables dinámicas: {link}, {random}, {name}
   - Control de delay entre mensajes y contador de éxito/fallos
   - Formato de targets CSV con creación automática de ejemplo
   - Documentación de APIs (Twilio, Nexmo, AWS SNS)

6. **pretexting** - Generador de escenarios de ingeniería social
   - Escenarios: IT Support, Vendor, Executive, HR, Security Officer
   - Scripts completos: opening, urgency, request, alternative
   - Tips de social engineering
   - Variables personalizables (company, urgency level)

#### 🌐 Network Attacks (5 nuevos módulos)
1. **arp_spoof** - ARP spoofing / Man-in-the-Middle
   - Implementación Python con Scapy
   - Configuración de IP forwarding
   - Integración con packet_sniffer, ssl_strip, dns_spoof

2. **dns_spoof** - DNS spoofing attack
   - Herramientas: dnsspoof (dsniff), Bettercap, Scapy
   - Configuración de dominio y fake IP
   - Targets comunes preconfigurados

3. **dhcp_starvation** - Ataque de agotamiento DHCP
   - Herramientas: Yersinia (GUI), DHCPig
   - Preparación para rogue DHCP server

4. **ssl_strip** - SSL stripping attack
   - Configuración completa con iptables
   - Integración con ARP spoofing
   - Notas sobre HSTS protection

5. **packet_sniffer** - Sniffer de paquetes avanzado
   - Filtros BPF preconfigurados: HTTP, HTTPS, FTP/SSH, DNS, SYN packets
   - Soporte tcpdump y tshark
   - Herramientas de análisis: Wireshark, NetworkMiner, Bro/Zeek

#### 🔐 Web Application Testing (5 nuevos módulos)
1. **jwt_cracker** - JWT security tester
   - Ataques: None algorithm, algorithm confusion (RS256→HS256), weak secrets
   - JWT decoder integrado (Base64)
   - Herramientas: jwt_tool, jwt.io, hashcat
   - Ejemplos de explotación

2. **api_fuzzer** - REST API fuzzer
   - Endpoints comunes: /api/v1/*, /api/internal, /api/debug, swagger.json, graphql
   - Técnicas: HTTP method fuzzing, path traversal, SQL injection, XXE, auth bypass
   - Herramientas: ffuf, wfuzz, Burp Suite Intruder, OWASP ZAP

3. **cors_scanner** - CORS misconfiguration scanner
   - Detección de wildcard CORS (*)
   - Detección de origin reflection
   - Detección de credentials habilitados
   - Código de explotación PoC incluido

4. **nosql_injection** - NoSQL injection tester
   - Soporte MongoDB, CouchDB
   - Payloads: auth bypass ($ne, $gt), JavaScript injection, blind injection, array injection
   - Operadores: $ne, $gt, $gte, $lt, $lte, $in, $nin, $regex, $where, $exists
   - Herramientas: NoSQLMap, Burp extensions

5. **graphql_introspection** - GraphQL schema introspection
   - Query de introspección completo
   - Exportación a JSON
   - Ataques comunes: introspection, nested queries (DoS), batch attacks, field suggestion
   - Herramientas: GraphQL Voyager, Altair, InQL Scanner

### 📊 Estadísticas v3.1
- **Módulos totales**: 54+ (anteriormente 35)
- **Nuevos módulos**: 19 profesionales
- **Categorías nuevas**: 2 (network, webapp)
- **Módulos sociales**: 3 → 9
- **Líneas de código agregadas**: ~800 líneas

### 🎨 Mejoras de Interfaz
- Menú de ayuda actualizado con categorías network y webapp
- Contadores de módulos por categoría `[9 modules]`, `[NEW - 5 modules]`
- Todos los módulos usan formato Unicode consistente
- Códigos de ejemplo y scripts integrados en outputs

---

## v3.0 - Rediseño Completo (Diciembre 2025)

### 🎨 Mejoras Implementadas

### 🎨 Interfaz y Diseño Minimalista

#### Banner Principal
- **Banner rediseñado** con líneas box-drawing Unicode más limpias
- Subtítulo profesional: "Professional Penetration Testing v3.0"
- Eliminación de información innecesaria del sistema (Session ID, IP local, tiempo)

#### Quick Start Guide
- Guía de inicio rápido en el banner con los 3 comandos más importantes
- Formato de caja con caracteres box-drawing
- Indicadores visuales con símbolos `→` para mejor lectura

#### Prompt Mejorado
```
┌─[kndys]
└─►

┌─[kndys]─[module_name]
└─►
```
- Prompt multi-línea con diseño de árbol
- Muestra el módulo activo de forma clara
- Uso de colores: Cyan para estructura, Rojo para nombre, Amarillo para módulo

### ✨ Mensajes y Feedback

#### Iconos Unicode
- `✓` (checkmark) - Operaciones exitosas
- `✗` (cross) - Errores
- `⚠` (warning) - Información importante  
- `ℹ` (info) - Información
- `⟳` (circular arrows) - Progreso/cargando
- `→` (arrow) - Indicador de acción
- `⊘` (prohibition) - Cancelación

#### Mensajes Estructurados
```
╔══════════════════════════════════════════════════╗
║            SECCIÓN TÍTULO                        ║
╚══════════════════════════════════════════════════╝

┌─[ CATEGORÍA ]──────────────────────────────
│ contenido aquí
└────────────────────────────────────────────
```

### 🔧 Mejoras Funcionales

#### Sistema de Help Reorganizado
- Dividido en secciones claras con cajas
- Ejemplos prácticos incluidos
- Descripción detallada de cada categoría de módulos
- Formato tabular con mejor legibilidad

#### Visualización de Módulos
- Formato de caja por categoría
- Alineación consistente de nombres y descripciones
- Separadores visuales entre categorías

#### Visualización de Wordlists
- Estado visual con ✓/✗
- Información compacta pero completa
- Tamaño alineado a la derecha
- Aliases limitados a 3 para mejor visualización
- Instrucciones claras de descarga con ejemplos

#### Descarga de Wordlists
- Información de descarga en formato de caja
- Barra de progreso con porcentaje y MB descargados
- Confirmación visual con ubicación y tamaño del archivo
- Sugerencia de alias para usar
- Manejo de errores mejorado con sugerencias

#### Opciones de Módulos
- Tabla con encabezados
- Separador visual entre columnas
- Colores diferenciados: Verde para opciones, Blanco para valores

#### Ejecución de Módulos
- Separador visual antes de ejecutar
- Título claro "Executing: módulo"
- Separador también después de completar

#### Escáner de Puertos
- Indicador visual de inicio con línea separadora
- Formato mejorado: `✓ Port  80/TCP OPEN → HTTP`
- Información de banner indentada con `└─`

#### Hash Cracker
- Contador de intentos cada 1000 hashes
- Banner ASCII para hash crackeado exitoso
- Formato claro con resultado resaltado

#### Escáner de Vulnerabilidades
- Separador de sección
- Contador de vulnerabilidades con color (verde si 0, amarillo/rojo si >0)
- Formato `→ Report saved:` para archivos generados

### 🎯 Mensajes de Error Mejorados

#### Comando Desconocido
```
✗ Unknown command: comando
ℹ  Type help for available commands
```

#### Módulo No Encontrado
```
✗ Module not found: modulo
ℹ  Use show modules to list available modules
```

#### Opción Inválida
```
✗ Invalid option: opcion
ℹ  Available options: opt1, opt2, opt3
```

#### Wordlist No Encontrada
```
✗ Unknown wordlist: nombre
ℹ  Use show wordlists to see available lists
```

### 📊 Mejoras en Progreso y Estado

#### Indicadores de Progreso
- Barra de progreso en descargas: `⟳ Progress: 45.2% (5MB / 11MB)`
- Contador en hash cracking: `⟳ Tested: 15,000 hashes...`
- Uso de comas en números grandes para mejor legibilidad

#### Mensajes de Confirmación
- Estado actual claramente visible
- Ubicación de archivos generados
- Tamaño de archivos descargados
- Sugerencias de siguiente paso

### 🌈 Esquema de Colores Consistente

- **Cyan**: Estructura, bordes, títulos principales
- **Green**: Éxito, nombres de módulos, comandos disponibles
- **Yellow**: Información importante
- **Red**: Errores, nombre del framework
- **Blue**: Información adicional, sugerencias
- **White**: Texto general, valores
- **Magenta**: Categorías especiales

### 🚀 Experiencia de Usuario

#### Mensajes de Salida
```
══════════════════════════════════════════════════
Thank you for using KNDYS Framework
══════════════════════════════════════════════════
```

#### Información de Dependencias
- Agrupación de dependencias faltantes
- Comando único para instalar todas
- Formato compacto: `⚠  Optional dependencies missing: ...`

#### Flujo de Trabajo Intuitivo
1. Banner informativo
2. Quick start guide visible
3. Comandos con autocompletado mental (help, show, use, set, run)
4. Feedback inmediato en cada acción
5. Sugerencias contextuales en errores

---

## Resumen de Cambios Técnicos

### Archivos Modificados
- `/workspaces/KNDYS/tt` - Framework principal con todas las mejoras

### Funciones Mejoradas
1. `display_banner()` - Banner y quick start
2. `show_modules()` - Visualización de módulos
3. `show_wordlists()` - Catálogo de wordlists
4. `download_wordlist()` - Descarga con progreso
5. `show_options()` - Opciones en tabla
6. `use_module()` - Carga de módulos
7. `set_option()` - Configuración con feedback
8. `show_help()` - Help reorganizado
9. `run_module()` - Ejecución con separadores
10. `run_port_scanner()` - Scanner con formato mejorado
11. `run_hash_cracker()` - Cracker con progreso
12. `run_vuln_scanner()` - Scanner de vulnerabilidades
13. `run()` - Loop principal con nuevo prompt

### Compatibilidad
- ✓ Todas las funcionalidades existentes mantenidas
- ✓ 35 módulos funcionando correctamente
- ✓ Sistema de wordlists operativo
- ✓ Descarga y gestión de diccionarios
- ✓ Logging y reporting funcional

---

## Próximos Pasos Sugeridos

Para el usuario:
1. Explorar módulos con `show modules`
2. Descargar wordlists necesarias con `download wordlist <alias>`
3. Configurar opciones globales con `setg`

Para desarrollo futuro:
- Añadir más wordlists especializadas
- Implementar caché de resultados
- Añadir sistema de plugins
- Mejorar reporting con gráficos
- Añadir modo interactivo avanzado

---

**Versión**: 3.0  
**Fecha**: Diciembre 2025  
**Estado**: Funcional y Optimizado
