#!/bin/bash
# KNDYS Framework - Script de inicio

echo "🚀 Iniciando KNDYS Framework..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python3 no está instalado"
    exit 1
fi

# Ir al directorio del framework
cd "$(dirname "$0")"

# Verificar que el archivo existe
if [ ! -f "kndys.py" ]; then
    echo "❌ Error: kndys.py no encontrado"
    exit 1
fi

# Iniciar el framework
python3 kndys.py "$@"
