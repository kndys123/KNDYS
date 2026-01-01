# KNDYS Framework - Inicio Rápido (Quick Start)

Comienza a usar KNDYS en 5 minutos.

---

## 1. Instalación (30 segundos)

```bash
git clone https://github.com/kndys123/KNDYS.git
cd KNDYS
chmod +x kndys.py
./kndys.py
```

**Primera ejecución:** Instala automáticamente todas las dependencias (2-3 minutos).

---

## 2. Primer Comando (1 minuto)

```bash
# Una vez en la consola KNDYS
kndys> show modules

# Verás la lista completa de 53 módulos
```

---

## 3. Escanear un Sitio Web (2 minutos)

```bash
# Selecciona módulo de port scanner
kndys> use port_scanner

# Configura el objetivo
kndys(port_scanner)> set target scanme.nmap.org
kndys(port_scanner)> set ports 1-1000

# Ejecuta el escaneo
kndys(port_scanner)> run

# Verás puertos abiertos encontrados
```

---

## 4. Ver Documentación Completa

Para una guía detallada de todos los 53 módulos:

```bash
# Ver archivo de guía completa
cat GUIA_COMPLETA_MODULOS.md

# O abrirlo en un editor
nano GUIA_COMPLETA_MODULOS.md
```

---

## Módulos Más Usados

| Módulo | Para | Comando |
|--------|------|---------|
| **Port Scanner** | Encontrar puertos abiertos | `use port_scanner` |
| **Subdomain Scanner** | Descubrir subdominios | `use subdomain_scanner` |
| **Web Crawler** | Mapear sitio web | `use web_crawler` |
| **SQL Scanner** | Detectar inyecciones SQL | `use sql_scanner` |
| **XSS Scanner** | Encontrar vulnerabilidades XSS | `use xss_scanner` |
| **Hash Cracker** | Crackear hashes | `use hash_cracker` |
| **Brute Force** | Ataques de fuerza bruta | `use brute_force` |
| **Report Generator** | Generar reportes | `use report_generator` |

---

## Comandos Básicos

```bash
kndys> help                    # Ver ayuda
kndys> show modules            # Listar todos los módulos
kndys> use <módulo>            # Seleccionar módulo
kndys> show options            # Ver parámetros del módulo
kndys> set <param> <value>     # Configurar parámetro
kndys> run                      # Ejecutar módulo
kndys> back                     # Volver atrás
kndys> exit                     # Salir
```

---

## Ejemplo Completo

```bash
# Escanear example.com
kndys> use port_scanner
kndys(port_scanner)> set target example.com
kndys(port_scanner)> set threads 50
kndys(port_scanner)> run

# Descubrir subdominios
kndys> use subdomain_scanner
kndys(subdomain_scanner)> set target example.com
kndys(subdomain_scanner)> run

# Rastrear sitio
kndys> use web_crawler
kndys(web_crawler)> set target http://example.com
kndys(web_crawler)> run

# Escanear vulnerabilidades
kndys> use vuln_scanner
kndys(vuln_scanner)> set target http://example.com
kndys(vuln_scanner)> run
```

---

## ¿Necesitas Ayuda?

- **Guía Completa:** [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)
- **Ejemplos Prácticos:** [EJEMPLOS_USO.md](EJEMPLOS_USO.md)
- **Instalación:** [INSTALL.md](INSTALL.md)
- **Análisis Técnico:** [ANALISIS_COMPLETO_MODULOS.md](ANALISIS_COMPLETO_MODULOS.md)

---

## Próximos Pasos

1. Lee la [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md) para aprender todos los módulos
2. Practica con los ejemplos en [EJEMPLOS_USO.md](EJEMPLOS_USO.md)
3. Explora módulos específicos según tus necesidades
4. Consulta la documentación técnica si es necesario

---

**Versión:** 3.2  
**Estado:** Listo para usar  
**Módulos:** 53 disponibles
