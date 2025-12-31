# 📚 KNDYS Framework v3.1 - Índice de Documentación

## 🎯 Guía Rápida de Navegación

Este índice te ayudará a encontrar la documentación que necesitas según tu rol y necesidad.

---

## 👤 PARA USUARIOS FINALES

### 🚀 Primeros Pasos
1. **README_v3.1.md** ⭐ EMPEZAR AQUÍ
   - Resumen ejecutivo de la expansión v3.1
   - 19 nuevos módulos explicados
   - Ejemplos de uso rápido
   - Casos de uso corporativos

### 📖 Uso Diario
2. **USAGE_GUIDE.md**
   - Manual de uso del framework original
   - Comandos básicos
   - Flujo de trabajo estándar

3. **MODULES_GUIDE_v3.1.md** ⭐ GUÍA COMPLETA DE NUEVOS MÓDULOS
   - Documentación detallada de 19 módulos nuevos
   - Ejemplos paso a paso
   - 3 escenarios corporativos completos
   - Consideraciones legales

### 📧 Reportes de Implementación de Módulos Mejorados
4. **CREDENTIAL_HARVESTER_IMPLEMENTATION_REPORT.md** ⭐ MÓDULO CREDENTIAL_HARVESTER
   - Transformación completa (42 → 900+ líneas)
   - 15 templates profesionales
   - 47 tests con 100% de cobertura
   - Servidor Flask multi-threaded
   - Exportación CSV/JSON/HTML
   
5. **PHISHING_MODULE_IMPLEMENTATION_REPORT.md** ⭐ MÓDULO PHISHING
   - Transformación completa (32 → 675+ líneas)
   - 20 templates profesionales (Office365, Google, PayPal, etc.)
   - Sistema multi-threaded SMTP
   - Base de datos SQLite con 3 tablas
   - Email tracking (opens/clicks)
   - 25 tests con 100% de cobertura

### 🔍 Consulta Rápida
```bash
# Ver todos los módulos
show modules

# Ver categoría específica
show modules social    # 9 módulos
show modules network   # 5 módulos
show modules webapp    # 5 módulos

# Ayuda general
help
```

---

## 👨‍💻 PARA ADMINISTRADORES Y RESPONSABLES

### 📋 Decisiones de Implementación
1. **README_v3.1.md**
   - Resumen ejecutivo
   - Estadísticas de expansión
   - Capacidades añadidas

2. **RESUMEN_MEJORAS.md**
   - Historial completo v3.0 → v3.1
   - Mejoras de interfaz
   - Estadísticas comparativas

### 🎯 Casos de Uso Empresariales
3. **MODULES_GUIDE_v3.1.md** - Sección "Escenarios Prácticos"
   - Scenario 1: Security Awareness Campaign
   - Scenario 2: Network Security Assessment
   - Scenario 3: Web Application Pentest

### ⚖️ Compliance y Legal
4. **MODULES_GUIDE_v3.1.md** - Sección "Consideraciones Legales"
   - Uso autorizado exclusivamente
   - Advertencias por módulo
   - Responsabilidad legal

---

## 🔧 PARA DESARROLLADORES

### 📝 Cambios Técnicos
1. **CHANGELOG.md** ⭐ HISTORIAL TÉCNICO COMPLETO
   - v3.1: Expansión de módulos (último)
   - v3.0: Rediseño completo de interfaz
   - Cambios línea por línea

2. **IMPLEMENTATION_SUMMARY_v3.1.md** ⭐ DETALLES DE IMPLEMENTACIÓN
   - Estructura del código
   - Métricas de calidad
   - Detalles de testing
   - Roadmap futuro

### 🧪 Testing y Validación
3. **IMPLEMENTATION_SUMMARY_v3.1.md** - Sección "Pruebas Realizadas"
   - Tests exitosos
   - Módulos verificados
   - Resultados de testing

### 🏗️ Arquitectura
```python
# Estructura del código en tt (5038 líneas)
Lines    630-850:  Module definitions (social, network, webapp)
Lines  1300-1450:  Module handlers dictionary
Lines  3930-4830:  Module implementations (19 nuevas funciones)
Lines  3211-3310:  Help menu (actualizado con nuevas categorías)
```

---

## 📑 TABLA DE CONTENIDOS POR DOCUMENTO

### README_v3.1.md (340 líneas)
```
✓ Resumen de cambios
✓ 19 módulos implementados (lista completa)
✓ Mejoras de interfaz
✓ Documentación nueva
✓ Pruebas realizadas
✓ Casos de uso corporativos
✓ Cómo usar los nuevos módulos (3 ejemplos)
✓ Consideraciones legales
✓ Estadísticas finales
```

### MODULES_GUIDE_v3.1.md (580 líneas)
```
✓ Social Engineering (6 módulos detallados)
  - mass_mailer, qr_generator, usb_payload
  - fake_update, sms_spoofing, pretexting

✓ Network Attacks (5 módulos detallados)
  - arp_spoof, dns_spoof, dhcp_starvation
  - ssl_strip, packet_sniffer

✓ Web Application Testing (5 módulos detallados)
  - jwt_cracker, api_fuzzer, cors_scanner
  - nosql_injection, graphql_introspection

✓ 3 Escenarios Prácticos Corporativos
✓ Consideraciones Legales y Éticas
✓ Referencias y Recursos
```

### IMPLEMENTATION_SUMMARY_v3.1.md (500 líneas)
```
✓ Estadísticas de expansión
✓ 19 módulos con detalles técnicos
✓ Mejoras de interfaz
✓ Documentación nueva
✓ Pruebas realizadas y resultados
✓ Casos de uso corporativos
✓ Detalles técnicos de implementación
✓ Métricas de calidad
✓ Próximos pasos recomendados
```

### CHANGELOG.md (380 líneas)
```
✓ v3.1 - Expansión de módulos (último)
  - 6 módulos social engineering
  - 5 módulos network attacks
  - 5 módulos web application testing
  - Estadísticas y mejoras de interfaz

✓ v3.0 - Rediseño completo
  - Interfaz minimalista
  - 35 módulos originales mejorados
  - Sistema de mensajes con Unicode
```

### RESUMEN_MEJORAS.md (410 líneas)
```
✓ v3.0 - Mejoras completas documentadas
✓ v3.1 - Expansión documentada
✓ Casos de uso corporativos
✓ Estadísticas comparativas
✓ Notas legales actualizadas
```

---

## 🎯 NAVEGACIÓN POR NECESIDAD

### "Quiero empezar a usar KNDYS v3.1"
→ **README_v3.1.md** (Sección: "CÓMO USAR LOS NUEVOS MÓDULOS")

### "Necesito documentación de un módulo específico"
→ **MODULES_GUIDE_v3.1.md** (Buscar por nombre del módulo)

### "¿Qué cambió desde v3.0?"
→ **CHANGELOG.md** (Sección: "v3.1")

### "Quiero saber detalles técnicos de implementación"
→ **IMPLEMENTATION_SUMMARY_v3.1.md** (Sección: "Detalles Técnicos")

### "Necesito ejemplos de uso corporativo"
→ **MODULES_GUIDE_v3.1.md** (Sección: "Escenarios Prácticos")

### "Información sobre legalidad y ética"
→ **MODULES_GUIDE_v3.1.md** (Sección: "Consideraciones Legales")

### "¿Cómo funciona la interfaz del framework?"
→ **RESUMEN_MEJORAS.md** (Sección: "Interfaz y Diseño")

---

## 📊 ESTADÍSTICAS DE DOCUMENTACIÓN

| Archivo | Líneas | Tamaño | Propósito |
|---------|--------|--------|-----------|
| **README_v3.1.md** | 340 | 9.4 KB | Guía de inicio rápido v3.1 |
| **MODULES_GUIDE_v3.1.md** | 580 | 13 KB | Documentación completa de módulos |
| **IMPLEMENTATION_SUMMARY_v3.1.md** | 500 | 13 KB | Detalles técnicos de implementación |
| **CHANGELOG.md** | 380 | 12 KB | Historial de cambios técnicos |
| **RESUMEN_MEJORAS.md** | 410 | 14 KB | Resumen de mejoras v3.0 + v3.1 |
| **USAGE_GUIDE.md** | 300 | 9.9 KB | Manual de uso original |
| **README.md** | 100 | 3.1 KB | Readme original |
| **TOTAL** | **2610** | **74.4 KB** | **Documentación completa** |

---

## 🗂️ ESTRUCTURA DE ARCHIVOS

```
KNDYS/
│
├── 📄 tt (5038 líneas)                      # Framework principal
│
├── 📚 DOCUMENTACIÓN PRINCIPAL
│   ├── README_v3.1.md ⭐                     # EMPEZAR AQUÍ
│   ├── MODULES_GUIDE_v3.1.md ⭐             # Guía completa de módulos
│   ├── IMPLEMENTATION_SUMMARY_v3.1.md      # Detalles técnicos
│   └── CHANGELOG.md                         # Historial de cambios
│
├── 📖 DOCUMENTACIÓN COMPLEMENTARIA
│   ├── RESUMEN_MEJORAS.md                   # Resumen v3.0 + v3.1
│   ├── USAGE_GUIDE.md                       # Manual de uso
│   └── README.md                            # Readme original
│
├── 🗂️ WORDLISTS
│   ├── rockyou.txt
│   ├── password.lst
│   └── xato-net-10-million-passwords-1000000.txt
│
├── 🌐 PHISHING SITE
│   └── phish_site/
│       └── index.html
│
└── 📋 OTROS
    ├── requirements.txt
    └── test_modules.sh
```

---

## 🔍 BÚSQUEDA RÁPIDA POR PALABRA CLAVE

### Módulos Sociales
```bash
grep -n "mass_mailer\|qr_generator\|usb_payload\|fake_update\|sms_spoofing\|pretexting" MODULES_GUIDE_v3.1.md
```

### Módulos Network
```bash
grep -n "arp_spoof\|dns_spoof\|dhcp_starvation\|ssl_strip\|packet_sniffer" MODULES_GUIDE_v3.1.md
```

### Módulos WebApp
```bash
grep -n "jwt_cracker\|api_fuzzer\|cors_scanner\|nosql_injection\|graphql_introspection" MODULES_GUIDE_v3.1.md
```

### Legal/Ético
```bash
grep -n "legal\|autorizado\|illegal\|ethical" MODULES_GUIDE_v3.1.md
```

---

## 💡 TIPS DE USO

### Para nuevos usuarios
1. Leer **README_v3.1.md** primero (10 min)
2. Revisar **MODULES_GUIDE_v3.1.md** sección de escenarios (15 min)
3. Ejecutar `python3 tt` y explorar con `show modules`

### Para usuarios experimentados
1. Ir directo a **MODULES_GUIDE_v3.1.md**
2. Buscar módulo específico
3. Copiar ejemplos de uso

### Para administradores
1. Revisar **README_v3.1.md** sección estadísticas
2. Leer **MODULES_GUIDE_v3.1.md** sección legal
3. Revisar casos de uso corporativos

### Para desarrolladores
1. **IMPLEMENTATION_SUMMARY_v3.1.md** para arquitectura
2. **CHANGELOG.md** para cambios técnicos
3. Buscar en código `grep -n "def run_" tt`

---

## 🆘 SOPORTE Y AYUDA

### Dentro del framework
```bash
# Ayuda general
help

# Info de módulo específico
use social/mass_mailer
options

# Ver todas las categorías
show modules
```

### Documentación
- **Dudas de uso**: MODULES_GUIDE_v3.1.md
- **Dudas técnicas**: IMPLEMENTATION_SUMMARY_v3.1.md
- **Historial**: CHANGELOG.md
- **Legal**: MODULES_GUIDE_v3.1.md (sección final)

### Recursos externos
- OWASP Testing Guide
- Red Team Field Manual
- PTES Standard
- Social Engineering Toolkit (SET) docs

---

## 📌 ENLACES RÁPIDOS

### Documentos principales
- [README v3.1](README_v3.1.md) - Guía de inicio
- [Guía de Módulos](MODULES_GUIDE_v3.1.md) - Documentación completa
- [Resumen de Implementación](IMPLEMENTATION_SUMMARY_v3.1.md) - Detalles técnicos

### Por categoría
- **Social Engineering**: MODULES_GUIDE_v3.1.md líneas 1-200
- **Network Attacks**: MODULES_GUIDE_v3.1.md líneas 201-350
- **Web Application**: MODULES_GUIDE_v3.1.md líneas 351-500

### Legal y ético
- **Consideraciones Legales**: MODULES_GUIDE_v3.1.md líneas 520-580

---

## ✅ CHECKLIST DE LECTURA RECOMENDADA

### Usuario Básico
- [ ] README_v3.1.md (completo)
- [ ] MODULES_GUIDE_v3.1.md (sección de interés)
- [ ] Ejecutar `help` en el framework

### Usuario Avanzado
- [ ] MODULES_GUIDE_v3.1.md (completo)
- [ ] CHANGELOG.md (sección v3.1)
- [ ] Probar los 3 escenarios corporativos

### Administrador
- [ ] README_v3.1.md (estadísticas)
- [ ] MODULES_GUIDE_v3.1.md (legal + casos de uso)
- [ ] RESUMEN_MEJORAS.md (métricas)

### Desarrollador
- [ ] IMPLEMENTATION_SUMMARY_v3.1.md (completo)
- [ ] CHANGELOG.md (detalles técnicos)
- [ ] Revisar código en `tt` líneas 3930-4830

---

## 🎓 RECURSOS DE APRENDIZAJE

### Documentación oficial
1. README_v3.1.md - Overview
2. MODULES_GUIDE_v3.1.md - Deep dive
3. IMPLEMENTATION_SUMMARY_v3.1.md - Technical details

### Inspiración
- Social Engineering Toolkit (SET)
- Metasploit Framework
- OWASP Testing Guide
- Bettercap documentation

### Comunidad
- r/netsec
- OWASP Community
- HackerOne
- Bugcrowd

---

## 🚀 EMPEZAR AHORA

```bash
# 1. Leer resumen ejecutivo
cat README_v3.1.md | less

# 2. Ver módulos disponibles
python3 tt
> show modules social
> show modules network
> show modules webapp

# 3. Probar un módulo nuevo
> use social/qr_generator
> set url http://phishing.test
> run

# 4. Consultar guía completa
cat MODULES_GUIDE_v3.1.md | less
```

---

**KNDYS Framework v3.1**  
*Professional Penetration Testing*  
*54+ Modules | 10 Categories | 2610 Lines of Documentation*

**Documentación Completa**: 74.4 KB  
**Última Actualización**: Diciembre 2025

---

*Todo lo que necesitas saber sobre KNDYS v3.1 en un solo lugar.*  
*Usa este índice como punto de partida para navegar la documentación.*

📖 **¡Feliz pentesting responsable!** 🔒
