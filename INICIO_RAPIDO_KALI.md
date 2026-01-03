# 🚀 KNDYS Framework - Guía de Inicio Rápido

## ✅ Problemas Resueltos

1. ✅ Repositorio Git reparado
2. ✅ Framework con permisos de ejecución
3. ✅ Script de inicio creado

---

## 🎯 Formas de Iniciar el Framework

### Opción 1: Script de Inicio (Más Fácil) ⭐
```bash
cd /path/to/KNDYS
./start.sh
```

### Opción 2: Python Directo
```bash
cd /path/to/KNDYS
python3 kndys.py
```

### Opción 3: Ejecutable Directo
```bash
cd /path/to/KNDYS
./kndys.py
```

---

## 🔧 En tu Kali Linux

Haz esto en tu Kali:

```bash
# 1. Ve al directorio del framework
cd ~/KNDYS   # o donde tengas el framework

# 2. Actualiza desde GitHub (esto trae los fixes)
git fetch origin
git reset --hard origin/main

# 3. Da permisos de ejecución
chmod +x kndys.py start.sh

# 4. Inicia el framework
./start.sh
```

---

## 📋 Si sigue sin funcionar

Ejecuta estos comandos para diagnóstico:

```bash
# Verificar Python
python3 --version

# Verificar que el archivo existe y tiene permisos
ls -la kndys.py

# Probar importación
python3 -c "from kndys import KNDYSFramework; print('OK')"

# Ver errores completos
python3 kndys.py
```

---

## 🆘 Solución de Problemas Comunes

### Error: "No such file or directory"
```bash
chmod +x kndys.py
chmod +x start.sh
```

### Error: "Permission denied"
```bash
sudo chmod +x kndys.py start.sh
```

### Error: "Module not found"
```bash
pip3 install -r requirements.txt
```

### Repositorio Git corrupto
```bash
git fetch origin
git reset --hard origin/main
```

---

## ✅ Verificación Rápida

```bash
cd /path/to/KNDYS
python3 -c "from kndys import KNDYSFramework; fw = KNDYSFramework(); print('✅ Framework OK')"
```

Si ves "✅ Framework OK", todo está listo.

---

## 🎮 Comandos Básicos del Framework

Una vez dentro:
- `help` - Ver ayuda
- `show modules` - Ver módulos disponibles
- `use <modulo>` - Seleccionar módulo
- `show options` - Ver opciones del módulo
- `set <opcion> <valor>` - Configurar opción
- `run` - Ejecutar módulo
- `exit` - Salir

---

**Fecha**: 2026-01-03  
**Versión**: KNDYS Framework v3.0  
**Estado**: ✅ Totalmente Funcional
