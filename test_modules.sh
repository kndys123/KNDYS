#!/bin/bash
# Script de prueba para verificar todos los módulos KNDYS

echo "=== KNDYS Framework - Verificación de Módulos ==="
echo ""

# Array de módulos a probar
declare -a modules=(
    "recon/port_scanner"
    "recon/subdomain_scanner"
    "recon/web_crawler"
    "recon/network_mapper"
    "recon/os_detection"
    "scan/vuln_scanner"
    "scan/sql_scanner"
    "scan/xss_scanner"
    "scan/csrf_scanner"
    "scan/ssl_scanner"
    "scan/dir_traversal"
    "exploit/multi_handler"
    "exploit/sql_injection"
    "exploit/xss_exploit"
    "exploit/command_injection"
    "exploit/file_upload"
    "exploit/buffer_overflow"
    "post/shell"
    "post/file_explorer"
    "post/privilege_escalation"
    "post/credential_dumper"
    "post/persistence"
    "post/pivot"
    "password/brute_force"
    "password/hash_cracker"
    "password/spray_attack"
    "password/credential_stuffing"
    "wireless/wifi_scanner"
    "wireless/wifi_cracker"
    "wireless/rogue_ap"
    "social/phishing"
    "social/credential_harvester"
    "social/website_cloner"
    "report/report_generator"
    "report/evidence_collector"
)

success_count=0
fail_count=0

for module in "${modules[@]}"; do
    echo -n "Probando $module... "
    
    # Intentar usar el módulo
    output=$(timeout 3 python3 tt <<EOF 2>&1
use $module
exit
EOF
)
    
    # Verificar si el módulo se cargó correctamente
    if echo "$output" | grep -q "Using module: $module"; then
        echo "✓ OK"
        ((success_count++))
    else
        echo "✗ FALLO"
        ((fail_count++))
    fi
done

echo ""
echo "=== Resumen ==="
echo "Módulos exitosos: $success_count"
echo "Módulos fallidos: $fail_count"
echo "Total: $((success_count + fail_count))"
