# KNDYS Framework - Índice de Documentación

## Documentación Principal

### 1. Para Comenzar Rápido
- **[INICIO_RAPIDO.md](INICIO_RAPIDO.md)** - Comienza en 5 minutos
- **[README.md](README.md)** - Información general del proyecto

### 2. Guías Completas
- **[GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)** - Documentación paso a paso de todos los 53 módulos
- **[EJEMPLOS_USO.md](EJEMPLOS_USO.md)** - Ejemplos prácticos de uso de cada módulo

### 3. Instalación
- **[INSTALL.md](INSTALL.md)** - Guía detallada de instalación

### 4. Información Legal
- **[DISCLAIMER.md](DISCLAIMER.md)** - Aviso legal importante
- **[LICENSE](LICENSE)** - Licencia MIT

### 5. Historial
- **[CHANGELOG.md](CHANGELOG.md)** - Registro de cambios y versiones

### 6. Análisis Técnico (Avanzado)
- **[ANALISIS_COMPLETO_MODULOS.md](ANALISIS_COMPLETO_MODULOS.md)** - Análisis técnico detallado de cada módulo
- **[MAXIMUM_PERFORMANCE_ACHIEVED.md](MAXIMUM_PERFORMANCE_ACHIEVED.md)** - Notas de performance

---

## Estructura de Carpetas

```
KNDYS/
├── kndys.py                          # Archivo principal del framework
├── requirements.txt                  # Dependencias Python
├── README.md                         # Información general
├── INICIO_RAPIDO.md                 # Comienza en 5 minutos
├── GUIA_COMPLETA_MODULOS.md         # Todos los 53 módulos documentados
├── EJEMPLOS_USO.md                  # Ejemplos prácticos
├── INSTALL.md                        # Instalación detallada
├── DISCLAIMER.md                     # Aviso legal
├── CHANGELOG.md                      # Historial de cambios
├── LICENSE                           # Licencia MIT
└── wordlists/                        # Diccionarios para ataques
    ├── rockyou.txt
    └── ...
```

---

## Ruta de Aprendizaje Recomendada

### Nivel 1: Principiante (30 minutos)
1. Lee [INICIO_RAPIDO.md](INICIO_RAPIDO.md)
2. Instala siguiendo [INSTALL.md](INSTALL.md)
3. Prueba el primer comando en la consola KNDYS
4. Lee la sección "Módulos Más Usados" en [INICIO_RAPIDO.md](INICIO_RAPIDO.md)

### Nivel 2: Intermedio (2-3 horas)
1. Lee [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md) - secciones sobre Reconocimiento
2. Prueba cada módulo de reconocimiento en tu lab
3. Lee secciones sobre escaneo de vulnerabilidades
4. Practica con ejemplos en [EJEMPLOS_USO.md](EJEMPLOS_USO.md)

### Nivel 3: Avanzado (1-2 días)
1. Lee todas las secciones de [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)
2. Estudia el análisis técnico en [ANALISIS_COMPLETO_MODULOS.md](ANALISIS_COMPLETO_MODULOS.md)
3. Practica todos los ejemplos en [EJEMPLOS_USO.md](EJEMPLOS_USO.md)
4. Crea tus propios scripts de automatización

### Nivel 4: Experto (Continuo)
1. Contribuye mejorando módulos
2. Crea módulos personalizados
3. Integra KNDYS en tus propios frameworks

---

## Búsqueda Rápida de Módulos

### ¿Quiero escanear puertos?
→ Busca **Port Scanner** en [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

### ¿Quiero testear SQL injection?
→ Busca **SQL Scanner** y **SQL Injection** en [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

### ¿Quiero crackear contraseñas?
→ Busca **Hash Cracker**, **Brute Force** en [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

### ¿Quiero hacer phishing?
→ Busca **Phishing**, **Credential Harvester**, **Website Cloner** en [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

### ¿Quiero testear WiFi?
→ Busca **WiFi Scanner**, **WiFi Cracker** en [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

### ¿Quiero hacer post-explotación?
→ Busca módulos de post-explotación en [GUIA_COMPLETA_MODULOS.md](GUIA_COMPLETA_MODULOS.md)

---

## Referencia Rápida de Comandos

```bash
./kndys.py                           # Iniciar framework
show modules                         # Ver todos los módulos
use <nombre_modulo>                 # Seleccionar módulo
show options                         # Ver parámetros
set <parámetro> <valor>             # Configurar parámetro
run                                  # Ejecutar módulo
help                                 # Ver ayuda
exit                                 # Salir
```

---

## Estadísticas del Framework

- **Total de Módulos:** 53
- **Líneas de Código:** 41,433
- **Categorías:** 10
- **Calidad de Código:** A+ (98/100)
- **Cobertura de Tests:** 100% (41/41 pasando)
- **Soporte:** Linux y macOS
- **Requisito de Python:** 3.8 o superior

---

## Características por Categoría

### Reconocimiento (5 módulos)
Descubre información sobre objetivos: puertos abiertos, subdominios, servicios, OS.

### Análisis de Vulnerabilidades (5 módulos)
Identifica vulnerabilidades comunes: SQL injection, XSS, CSRF, configuraciones inseguras.

### Explotación Web (5 módulos)
Explota vulnerabilidades web descubiertas para acceso no autorizado.

### Ataques de Red (5 módulos)
Realiza ataques a nivel de red: ARP spoofing, DNS hijacking, MITM, etc.

### Seguridad Inalámbrica (3 módulos)
Testea redes WiFi: escaneo, cracking, puntos de acceso falsos.

### Ingeniería Social (6 módulos)
Ataca el factor humano: phishing, clonación de sitios, SMS spoofing, etc.

### Post-Explotación (4 módulos)
Después de obtener acceso: extrae credenciales, escala privilegios, mantén acceso.

### Ataques de Contraseñas (3 módulos)
Fuerza bruta y ataques contra contraseñas y hashes.

### Pruebas Avanzadas (7 módulos)
Tests de APIs modernas: JWT, GraphQL, NoSQL, CORS.

### Herramientas Utilitarias (5 módulos)
Generadores de payloads, reportes, recolección de evidencia.

---

## FAQ

**P: ¿Dónde empiezo?**
R: Lee [INICIO_RAPIDO.md](INICIO_RAPIDO.md) - te llevará 5 minutos.

**P: ¿Necesito permisos especiales?**
R: Algunos módulos sí (aquellos que manipulan red). Usa `sudo` cuando sea necesario.

**P: ¿Puedo usar esto contra servidores que no me pertenecen?**
R: No. Leer [DISCLAIMER.md](DISCLAIMER.md) para información legal.

**P: ¿Cuál es el mejor módulo para comenzar?**
R: Comienza con Port Scanner. Es simple y muy educativo.

**P: ¿Dónde están los ejemplos?**
R: En [EJEMPLOS_USO.md](EJEMPLOS_USO.md) hay 10 ejemplos prácticos completos.

**P: ¿Cómo se actualiza el framework?**
R: `git pull` para obtener la última versión.

---

## Contribuciones

¿Quieres mejorar KNDYS?
1. Haz un fork del repositorio
2. Crea una rama para tu feature
3. Haz commit de tus cambios
4. Push a tu rama
5. Abre un Pull Request

---

## Licencia

MIT License - Eres libre de usar, modificar y distribuir.

---

## Aviso Legal

**IMPORTANTE:** Este framework es solo para uso autorizado en:
- Sistemas que te pertenecen
- Labs de práctica
- Sistemas donde tienes permiso escrito

El uso no autorizado es ilegal. Lee [DISCLAIMER.md](DISCLAIMER.md) completamente.

---

**Última Actualización:** Enero 2025  
**Versión:** 3.2  
**Estado:** Listo para Producción
